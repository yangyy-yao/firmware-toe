#include <pthread.h>
#include <sched.h>
#include <zconf.h>
#include <assert.h>
#include <linux/ethtool.h>

#include <rte_ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <pci-ep.h>
#include <agiep_virtio.h>
#include <agiep_vring.h>
#include <agiep_reg_poller.h>
#include <agiep_virtio_legacy.h>
#include <agiep_mng.h>
#include "agiep_virtio_net.h"
#include "agiep_frep.h"
#include "agiep_virtio_rxtx.h"


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

static __rte_always_inline void *
virtio_net_get_config_addr(struct agiep_virtio_device *vdev)
{
	return RTE_PTR_ADD(legacy_get_ioaddr(vdev),
		VIRTIO_PCI_CONFIG_OFF(vdev));
}

#define VIRTIO_095_HARDWARE_FEATURES \
	((1 << VIRTIO_NET_F_MTU)	|  \
	(1 << VIRTIO_NET_F_MAC)		|  \
	(1 << VIRTIO_NET_F_MRG_RXBUF)	|  \
	(1 << VIRTIO_NET_F_STATUS)	|  \
	(1 << VIRTIO_NET_F_CTRL_VQ)	|  \
	(1 << VIRTIO_NET_F_CTRL_RX)	|  \
	(1 << VIRTIO_NET_F_MQ)		|  \
	(1 << VIRTIO_F_ANY_LAYOUT))	|  \
	(1 << VIRTIO_NET_F_PREDICT)



#define VIRTIO_QUEUE_SIZE (1024 * 4)

#define MAX_QUEUE_PAIRS 3

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = VIRTIO_QUEUE_SIZE,
	.nb_min = VIRTIO_QUEUE_SIZE,
	.nb_align = 8,

};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = VIRTIO_QUEUE_SIZE,
	.nb_min = VIRTIO_QUEUE_SIZE,
	.nb_align = 8,

};
static const uint64_t flow_type_rss_offloads = ETH_RSS_IP;
TAILQ_HEAD(virtio_netdev_list ,agiep_virtio_netdev) virtio_netdev_list ;
enum agiep_frep_t agile_netdev_tab[MAX_PF][MAX_VF];
static pthread_mutex_t vnlist_lock = PTHREAD_MUTEX_INITIALIZER;


static void virtio_ctrl_GC(void *data);
static void virtio_ctrl_release(struct agiep_net_ctrl *ctrl);

static void
virtio_net_handle_pci_status(struct agiep_virtio_device *vdev, uint8_t device_status)
{
	int ret;
	struct agiep_virtio_netdev *ndev = vdev->dev;

	if (device_status == VIRTIO_CONFIG_S_RESET) {
		ret = virtio_net_dev_softreset(ndev->fdev->eth_dev);
		if (ret)
			AGIEP_LOG_ERR("virtio_net_dev_softreset fail: %d", ret);
	} else if (device_status & VIRTIO_CONFIG_S_DRIVER_OK) {
		 ndev->fdev->eth_dev->dev_ops->link_update(ndev->fdev->eth_dev, 0);
	}
}


void virtio_net_ctrl_process(void * arg __rte_unused)
{
	struct agiep_virtio_netdev *ndev;
	if (TAILQ_EMPTY(&virtio_netdev_list))
		return;
	pthread_mutex_lock(&vnlist_lock);
	TAILQ_FOREACH(ndev, &virtio_netdev_list, entry) {
		agiep_virtio_cmd_process(ndev);
	}
	pthread_mutex_unlock(&vnlist_lock);
}

void virtio_net_config_notify(struct agiep_virtio_device *vdev)
{
	agiep_virtio_msix_raise(vdev, vdev->config_vector);
}

inline static uint16_t agiep_virtio_notify(struct virtqueue *vq)
{
	return rte_atomic16_exchange(&vq->notify, 0);
}

static inline uint8_t agiep_virtio_with_feature_ctrl_vq(uint64_t feature)
{
	return ((feature & (1 << VIRTIO_NET_F_CTRL_VQ)) == (1 << VIRTIO_NET_F_CTRL_VQ));
}

static uint8_t virtio_net_check_pfn_set_complete(struct agiep_virtio_device *vdev)
{
	if (agiep_virtio_with_feature_ctrl_vq(vdev->dev_feature)) {
		if (vdev->set_num < vdev->vq_num) {
			return 0;
		}
	} else {
		/*no ctrl queue, ctrl queue id == dev->vq_num - 1, set_num not record crtl queue*/
		if (vdev->set_num < vdev->vq_num - 1) {
			return 0;
		}

		/*no ctrl queue, need do start dev*/
		virtio_set_dev_start_no_ctrl(vdev);
	}

	return 1;
}


static void virtio_net_do_config_after_set_feature(struct agiep_virtio_device *vdev)
{
	if (NULL == vdev) {
		return;
	}

	struct virtqueue *vq;
	int i = 0;
	int max_num = vdev->vq_num;

	if (!agiep_virtio_with_feature_ctrl_vq(vdev->dev_feature)) {
		/*no ctrl*/
		max_num -= 1;
	}

	for (i = 0; i < max_num; ++i) {
		vq = vdev->vq[i];
		if (!vq) {
			continue;
		}

		vq->cb(vq->cb_data);
	}

	return;
}

static void virtio_net_ctrl_enable_handler(void *data)
{
	struct agiep_virtio_netdev *ndev = data;
	if (agiep_virtio_with_feature(ndev->vdev, VIRTIO_NET_F_PREDICT))
		virtqueue_set_predict_mode(ndev->port.ctrl->cvq, VRING_F_RING_PREDICT);
}
static int virtio_net_ctrl_configure(struct rte_eth_dev *dev, struct agiep_virtio_netdev *ndev)
{
	struct agiep_net_ctrl *ctrl;
	struct agiep_virtio_device *vdev;
	struct virtqueue *cvq = NULL;
	struct rte_ring *rr = NULL;
	struct rte_ring *cr = NULL;
	struct rte_mempool *cmdpool = NULL;
	struct agiep_dma *dma = NULL;
	uint64_t desc;
	char ring_name[RTE_RING_NAMESIZE];
	uint16_t nb_desc;
	int vq_idx;

	ctrl = ndev->port.ctrl;
	vdev = ndev->vdev;
	vq_idx = 2 * dev->data->nb_rx_queues;
	nb_desc = VIRTIO_QUEUE_SIZE;
	cvq = virtqueue_create(vq_idx, nb_desc, VQ_SPLIT, 0);

	if (cvq == NULL) {
		RTE_LOG(ERR, PMD, "ctrl virtqueue create fail\n");
		goto failed;
	}

	dma = agiep_dma_create(ndev->port.fdev->pf, ndev->port.fdev->vf);
	if (dma == NULL) {
		AGIEP_LOG_ERR("DMA create error %d %d", ndev->port.fdev->pf, ndev->port.fdev->vf);
		goto failed;
	}
	cvq->dma = dma;
	cvq->cb_data = ndev;
	cvq->cb = virtio_net_ctrl_enable_handler;
	virtqueue_set_dma(cvq, cvq->dma);
	ctrl->priv = &ndev->port;
	cvq->priv = &ndev->port;
	cvq->notify_cb = agiep_virtio_notify;

	snprintf(ring_name, sizeof(ring_name), "rq_ring_%d_%lx", dev->data->port_id, rte_rdtsc());
	rr = rte_ring_create(ring_name, VIRTIO_NET_CTRL_DESC_NUM, SOCKET_ID_ANY, 0);
	snprintf(ring_name, sizeof(ring_name), "cq_ring_%d_%lx", dev->data->port_id, rte_rdtsc());
	cr = rte_ring_create(ring_name, VIRTIO_NET_CTRL_DESC_NUM, SOCKET_ID_ANY, 0);

	if (rr == NULL || cr == NULL)
		goto failed;
	ctrl->rr = rr;
	ctrl->cr = cr;

	snprintf(ring_name, sizeof(ring_name), "ctrl_cmd_%d_%lx", dev->data->port_id, rte_rdtsc());
	cmdpool = rte_mempool_create(ring_name, nb_desc,
			sizeof(struct virtio_net_command), 0, 0, NULL, NULL, NULL,
			NULL, 0, 0);
	if (cmdpool == NULL)
		goto failed;
	ctrl->cmdpool = cmdpool;

	desc = vdev->desc_addr[2 * dev->data->nb_rx_queues];
	cvq->notify = 1;
	if (desc){
		virtqueue_set_pci_addr(cvq, desc);
	}
	agiep_virtio_reset_vector(ndev->vdev, vdev->config_vector);
	cvq->flags |= VRING_F_CACHE_FORCE;
	vdev->vq[2 * dev->data->nb_rx_queues] = cvq;
	ctrl->cvq = cvq;
	ctrl->bvq = cvq;

	ctrl->ctl_type = CTRL_VIRTIO;

	return 0;
failed:
	if (rr)
		rte_ring_free(rr);
	if (cr)
		rte_ring_free(cr);
	if (cmdpool)
		rte_mempool_free(cmdpool);
	if (cvq)
		virtqueue_free(cvq);
	if (dma)
		agiep_dma_free(dma, NULL, NULL);

	return -1;
}

static struct agiep_net_ctrl *virtio_net_ctrl_dup(struct agiep_net_ctrl *ctrl)
{
	struct agiep_net_ctrl *ctrl_dup;

	ctrl_dup = rte_malloc(NULL, sizeof(struct agiep_net_ctrl), 0);

	if (ctrl_dup == NULL)
		return NULL;

	rte_memcpy(ctrl_dup, ctrl, sizeof(*ctrl_dup));
	return ctrl_dup;
}

static void virtio_net_ctrl_reset(struct rte_eth_dev *dev, struct agiep_virtio_netdev *ndev)
{
	struct agiep_net_ctrl *ctrl;
	struct agiep_net_ctrl *ctrl_dup;
	struct virtqueue *cvq;

	ctrl = ndev->port.ctrl;
	if (!ctrl)
		return;
	cvq = ctrl->cvq;
	ctrl->cvq = NULL;

	agiep_ctrl_synchronize(ctrl);
	if (cvq->dma) {
		ctrl_dup = virtio_net_ctrl_dup(ctrl);
		ctrl_dup->cvq = cvq;
		agiep_dma_free(cvq->dma, virtio_ctrl_GC, ctrl_dup);
	} else {
		virtio_ctrl_release(ctrl);
	}
	if (virtio_net_ctrl_configure(dev, ndev)) {
		AGIEP_LOG_ERR("virtio net ctrl configure error");
	}
}

static __rte_always_inline void
virtio_net_init_reg(struct agiep_virtio_netdev *ndev)
{
	struct virtio_net_config *net_cfg;
	struct virtio_pci_common_cfg *common_cfg;
	struct agiep_virtio_device *vdev = ndev->vdev;
	struct rte_eth_dev *dev = ndev->fdev->eth_dev;

	assert(vdev->dev_cfg != NULL);
	assert(vdev->comm_cfg != NULL);
	common_cfg = vdev->comm_cfg;
	common_cfg->queue_select = 0;
	common_cfg->vap = 0;
	net_cfg = virtio_net_get_config_addr(vdev);
	net_cfg->status = 0;
	rte_memcpy(net_cfg->mac, dev->data->mac_addrs, sizeof(net_cfg->mac));
	net_cfg->max_virtqueue_pairs = dev->data->nb_rx_queues;
	net_cfg->mtu = 1500;
	net_cfg->speed = ETH_LINK_SPEED_10G;
	net_cfg->duplex = DUPLEX_FULL;

	dev->data->dev_link.link_speed = net_cfg->speed;
	dev->data->dev_link.link_duplex = net_cfg->duplex;
	dev->data->mtu = net_cfg->mtu + AGIEP_DMA_ALIGN;

	common_cfg->queue_size = VIRTIO_QUEUE_SIZE;
	common_cfg->queue_notify = VIRTIO_PCI_S_QUEUE_NOTIFY_INIT;
	rte_rmb();
}
static int virtio_net_configure(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_device *vdev = NULL;
	struct agiep_virtio_netdev *ndev = NULL;
	struct agiep_net_ctrl *ctrl = NULL;
	uint64_t feature;
	uint32_t ip, mask;

	if (dev->data->nb_rx_queues > MAX_QUEUE_PAIRS) {
		RTE_LOG(ERR, PMD, "agiep virtio: support %d queue pairs\n", MAX_QUEUE_PAIRS);
		return -1;
	}
	if (fdev->dev != NULL)
		return 0;
	if (agile_netdev_tab[fdev->pf][fdev->vf] != AGIEP_FREP_NUM){
		AGIEP_LOG_ERR("pf %d vf %d duplicate", fdev->pf, fdev->vf);
		return -EINVAL;
	}
	feature = VIRTIO_095_HARDWARE_FEATURES;

	if (fdev->hw_checksum)
		feature |= (1ULL << VIRTIO_NET_F_CSUM) | (1ULL << VIRTIO_NET_F_GUEST_CSUM);

	ndev = rte_calloc(NULL, 1, sizeof(struct agiep_virtio_netdev), 0);

	if (ndev == NULL)
		return -1;

	if (fdev->accel && fdev->accel->ops->features_get)
		feature |= fdev->accel->ops->features_get(fdev);

	vdev = agiep_virtio_create(fdev->pf, fdev->vf, feature,
			    dev->data->nb_rx_queues * 2 + 1,
			    dev->data->mac_addrs);
	if (vdev == NULL) {
		AGIEP_LOG_ERR("virtio create failed %d\n", rte_errno);
		goto failed;
	}
	ndev->vdev = vdev;

	vdev->dev = ndev;
	vdev->handle_pci_status = virtio_net_handle_pci_status;
	vdev->check_pfn_set_complete = virtio_net_check_pfn_set_complete;
	vdev->do_config_after_set_feature = virtio_net_do_config_after_set_feature;
	if (fdev->pf == 0 && fdev->vf == 0){
		ip = agiep_mng_get_mngip();
		mask = agiep_mng_get_netmask();
		rte_write32(ip, RTE_PTR_ADD(vdev->comm_cfg, VIRTIO_PCI_MNG_IP));
		rte_write32(mask, RTE_PTR_ADD(vdev->comm_cfg, VIRTIO_PCI_MNG_MASK));
	}

	ctrl = rte_calloc(NULL, 1, sizeof(struct agiep_net_ctrl), 0);

	if (ctrl == NULL) {
		RTE_LOG(ERR, PMD, "failed to malloc virtio_net_ctrl");
		goto failed;
	}
	ndev->port.ctrl = ctrl;
	ndev->port.fdev = fdev;

	if (virtio_net_ctrl_configure(dev, ndev)) {
		RTE_LOG(ERR, PMD, "failed to configure virito_net_ctr");
		goto failed;
	}

	ndev->fdev = fdev;
	fdev->dev = ndev;
	fdev->ep = vdev->ep;
	fdev->used_queues = dev->data->nb_rx_queues;
	// TODO: if we support modern pci, we should determine here:
	// if (!vdev->dev_feature & VIRTIO_F_VERSION_1)

	pthread_mutex_lock(&vnlist_lock);
	TAILQ_INSERT_HEAD(&virtio_netdev_list, ndev, entry);
	agile_netdev_tab[fdev->pf][fdev->vf] = AGIEP_FREP_VIRTIO;
	pthread_mutex_unlock(&vnlist_lock);

	virtio_net_init_reg(ndev);
	// TODO: RSS supported
	return 0;

failed:
	if (vdev)
		agiep_virtio_destroy(vdev);
	if (ndev)
		rte_free(ndev);
	if (ctrl)
		rte_free(ctrl);

	return -1;
}

static void virtio_net_rx_ctx_obj_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned obj_idx __rte_unused)
{
	struct virtnet_rx_ctx *ctx = obj;
	ctx->rx = opaque;
}

static void virtio_net_rx_enable_handler(void *data)
{
	struct agiep_virtio_port *port;
	struct agiep_virtio_netdev *ndev;
	struct virtnet_rx *rx;
	if (!data)
		return;
	rx = data;
	port = rx->priv;
	ndev = port->fdev->dev;
	if (ndev->vdev->dev_feature & (1 << VIRTIO_NET_F_MRG_RXBUF)) {
		rx->mergeable = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	} else {
		rx->mergeable = sizeof(struct virtio_net_hdr);
	}
	if (agiep_virtio_with_feature(ndev->vdev, VIRTIO_NET_F_PREDICT)) {
		virtqueue_set_predict_mode(rx->vq, VRING_F_RING_PREDICT);
	} else {
		virtqueue_set_predict_mode(rx->vq, 0);
	}
}

static int virtnet_rx_setup(struct agiep_virtio_netdev *ndev, struct virtnet_rx *rx, int queue_idx, uint16_t nb_desc,
		struct rte_mempool *mp) 
{
	struct virtqueue *vq = NULL;
	struct agiep_virtio_device *vdev;
	char name[RTE_MEMPOOL_NAMESIZE];
	uint64_t desc;
	struct agiep_dma *dma = NULL;
	int vq_idx;

	if (rx->vq != NULL)
		return 0;
	rx->elem_id = 0;
	rx->ctx_pool = NULL;
	rx->mergeable = 0;

	rx->mbuf_list = NULL;
	if (!nb_desc || (nb_desc & (nb_desc - 1))){
		AGIEP_LOG_ERR("nb_desc must power of 2");
		return -1;
	}
	nb_desc = VIRTIO_QUEUE_SIZE;
	rx->nb_desc = nb_desc;
	rx->nb_mbuf = 0;
	rx->id = queue_idx;
	TAILQ_INIT(&rx->ctx_list);
	vq_idx = VIRTIO_RX_INDEX(queue_idx);
	vdev = ndev->vdev;

	vq = virtqueue_create(vq_idx, nb_desc, VQ_SPLIT, 0);

	if (vq == NULL)
		goto error;

	dma = agiep_dma_create(ndev->fdev->pf, ndev->fdev->vf);
	if (dma == NULL) {
		AGIEP_LOG_ERR("DMA create error %d %d", ndev->fdev->pf, ndev->fdev->vf);
		goto error;
	}
	vq->dma = dma;
	virtqueue_set_dma(vq, vq->dma);

	vq->priv = &ndev->port;
	// TODO: support windows
	vq->msi_vector = vq_idx + 1;
	vq->notify_cb = agiep_virtio_notify;

	rx->mpool = mp;
	rx->priv = &ndev->port;
	snprintf(name, RTE_MEMPOOL_NAMESIZE, "rx_ctx_%d_%d_%lx",
		ndev->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());
	rx->ctx_pool = rte_mempool_create(name, AGIEP_DP_POOL_SIZE(nb_desc * 2),
		sizeof(struct virtnet_rx_ctx), AGIEP_DP_CACHE_SIZE(nb_desc * 2), 0,
		NULL, NULL, virtio_net_rx_ctx_obj_init, rx, 0, 0);
	if (unlikely(rx->ctx_pool == NULL)) {
		AGIEP_LOG_ERR("vf %d rx %d ctx_pool create fail %d",
			ndev->fdev->vf, queue_idx, rte_errno);
		goto error;
	}

	snprintf(name, sizeof(name), "rxring_%d_%d_%lx",
		 ndev->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());

	rx->mbuf_list = rte_calloc(NULL, nb_desc, sizeof(struct rte_mbuf *), RTE_CACHE_LINE_SIZE);
	if (rx->mbuf_list == NULL)
		goto error;

	memset(&rx->notify, 0, sizeof(rx->notify));

	rx->notify.irq_threshold = ((rte_get_tsc_hz() + US_PER_S - 1 ) / US_PER_S)
					* INTERRUPT_TSC_THRESHOLD;

	vdev->vq[vq_idx] = vq;
	rx->bvq = vq;
	rx->vq = vq;
	vq->notify = 1;

	rx->fq.qid = queue_idx;
	rx->fq.dev = ndev->fdev;

	vq->cb_data = rx;
	vq->cb = virtio_net_rx_enable_handler;
	desc = vdev->desc_addr[vq_idx];
	if (desc){
		virtqueue_set_pci_addr(vq, desc);
	}
	
	return 0;
error:
	if (vq)
		virtqueue_free(vq);
	if (dma)
		agiep_dma_free(dma, NULL, NULL);
	if (rx->ctx_pool)
		rte_mempool_free(rx->ctx_pool);

	if (rx->mbuf_list)
		rte_free(rx->mbuf_list);
	return -1;
}

static int
virtio_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
	uint16_t nb_desc, unsigned int socket __rte_unused,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool *mp)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	struct virtnet_rx *rx = NULL;

	rx = rte_calloc(NULL, 1, sizeof(struct virtnet_rx), RTE_CACHE_LINE_SIZE);
	if (rx == NULL)
		goto error;

	assert(mp != NULL);

	if (virtnet_rx_setup(ndev, rx, queue_idx, nb_desc, mp))
		goto error;

	dev->data->rx_queues[queue_idx] = rx;
	return 0;
error:
	if (rx)
		rte_free(rx);
	return -1;
}

static void virtnet_rx_release(struct virtnet_rx *rx)
{
	struct virtnet_rx_ctx *ctx;
	struct agiep_virtio_netdev *ndev;
	uint32_t i;
	uint16_t reset_num;
	virtqueue_free(rx->bvq);
	TAILQ_FOREACH(ctx, &rx->ctx_list, entry) {
		rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	}
	for (i = 0; i < rx->nb_desc; ++i) {
		rte_pktmbuf_free(rx->mbuf_list[i]);
	}
	rte_mempool_free(rx->ctx_pool);
	rte_free(rx->mbuf_list);
	ndev = rx->priv->fdev->dev;
	reset_num = __sync_add_and_fetch(&ndev->vdev->reset_num, 1);
	if (reset_num >= ndev->vdev->vq_num)
		legacy_reset_device_reg(ndev->vdev);
}

static struct virtnet_rx *virtnet_rx_dup(struct virtnet_rx *rx)
{
	struct virtnet_rx *rx_dup;

	rx_dup = rte_malloc(NULL, sizeof(struct virtnet_rx), RTE_CACHE_LINE_SIZE);

	if (rx_dup == NULL) {
		RTE_LOG(ERR, PMD, "virnet rx dump failed\n");
		return NULL;
	}
	rte_memcpy(rx_dup, rx, sizeof(*rx_dup));

	return rx_dup;
}

static void virtio_rx_queue_GC(void *data)
{
	struct virtnet_rx *rx = data;
	if (rx == NULL)
		return;
	virtnet_rx_release(rx);
	rte_free(rx);
}

static void virtio_rx_queue_release(void *rxq)
{
	struct virtnet_rx *rx = NULL;
	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;
	struct virtqueue *vq = NULL;
	struct agiep_virtio_port *port;

	if (!rxq)
		return;
	rx = rxq;

	vq = rx->vq;

	if (vq == NULL)
		return;
	port = vq->priv;

	ndev = port->fdev->dev;
	vdev = ndev->vdev;

	port->fdev->eth_dev->data->rx_queues[rx->id] = NULL;
	vdev->vq[VIRTIO_RX_INDEX(rx->id)] = NULL;

	rx->fq.dev = NULL;

	if (vq->dma) {
		agiep_dma_free_syn(vq->dma, virtio_rx_queue_GC, rx);
	} else {
		virtnet_rx_release(rx);
		rte_free(rx);
	}
}

static void virtio_rx_queue_reset(struct virtnet_rx *rx)
{
	struct agiep_virtio_port *port;
	struct virtnet_rx *rx_dup;
	struct agiep_virtio_netdev *ndev;
	uint16_t nb_desc;
	struct virtqueue *vq;
	
	vq = rx->vq;
	if (!vq)
		return;

	port = vq->priv;
	ndev = port->fdev->dev;
	nb_desc = virtqueue_desc_num(vq);

	rx->vq = NULL;
	rte_mb();
	agiep_virtio_rx_synchronize(rx);

	if (vq->dma) {
		rx_dup = virtnet_rx_dup(rx);
		agiep_dma_free(vq->dma, virtio_rx_queue_GC, rx_dup);
	} else
		 virtnet_rx_release(rx);

	if (virtnet_rx_setup(ndev, rx, rx->id, nb_desc, rx->mpool)) {
		RTE_LOG(ERR, PMD, "rx %d queue reset error\n", rx->id);
	}
}

static void virtio_net_tx_enable_handler(void *data)
{
	struct agiep_virtio_port *port;
	struct agiep_virtio_netdev *ndev;
	struct virtnet_tx *tx;
	uint16_t mode;
	if (!data)
		return;
	tx = data;
	port = tx->priv;
	ndev = port->fdev->dev;
	if (ndev->vdev->dev_feature & (1ULL << VIRTIO_NET_F_MRG_RXBUF)){
		tx->mergeable = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	} else {
		tx->mergeable = sizeof(struct virtio_net_hdr);
	}

	mode = virtqueue_get_predict_mode(tx->vq);
	if (agiep_virtio_with_feature(ndev->vdev, VIRTIO_NET_F_PREDICT)) {
		mode |= VRING_F_RING_PREDICT;
	} else {
		mode &= (~VRING_F_RING_PREDICT);
	}
	mode |= VRING_F_NO_NOTIFY;
	virtqueue_set_predict_mode(tx->vq, mode);
}

static void virtio_net_tx_ctx_obj_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned obj_idx)
{
	struct virtnet_tx_ctx *ctx = obj;
	ctx->tx = opaque;
	ctx->idx = obj_idx;
}

static int virtnet_tx_setup(struct agiep_virtio_netdev *ndev,
	struct virtnet_tx *tx, int queue_idx, uint16_t nb_desc)
{
	struct virtqueue *vq;
	struct agiep_virtio_device *vdev;
	char name[RTE_MEMPOOL_NAMESIZE];
	uint64_t desc;
	struct agiep_dma *dma = NULL;
	int vq_idx = VIRTIO_TX_INDEX(queue_idx);

	if (tx->vq != NULL)
		return 0;
	if (!nb_desc && (nb_desc & (nb_desc - 1))){
		AGIEP_LOG_ERR("nb_desc must power of 2");
		return -1;
	}

	tx->ctx_pool = NULL;
	tx->ctx_map = NULL;
	tx->mergeable = 0;
	tx->nb_desc = nb_desc;

	vdev = ndev->vdev;

	tx->id = queue_idx;
	vq = virtqueue_create(vq_idx, nb_desc, VQ_SPLIT, 0);
	if (vq == NULL)
		goto error;

	dma = agiep_dma_create(ndev->fdev->pf, ndev->fdev->vf);
	if (dma == NULL) {
		AGIEP_LOG_ERR("DMA create error %d %d", ndev->fdev->pf, ndev->fdev->vf);
		goto error_dma;
	}
	vq->dma = dma;
	virtqueue_set_dma(vq, vq->dma);

	vq->flags |= (VRING_F_CACHE_PREDICT | VRING_F_NO_NOTIFY);
	vq->notify_cb = agiep_virtio_notify;
	vq->notify = 1;
	// TODO: support windows
	vq->msi_vector = vq_idx + 1;
	vdev->vq[vq_idx] = vq;
	vq->priv = &ndev->port;

	tx->bvq = vq;
	tx->vq = vq;

	snprintf(name, sizeof(name), "txctxpl%d_%d_%lx",
			ndev->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());
	// FIXME: core migrate local cache problem
	tx->ctx_pool = rte_mempool_create(name, AGIEP_DP_POOL_SIZE(nb_desc),
			sizeof(struct virtnet_tx_ctx), AGIEP_DP_CACHE_SIZE(nb_desc),
			0, NULL, NULL, virtio_net_tx_ctx_obj_init, tx, 0, 0);

	if (tx->ctx_pool == NULL)
		goto err_ctx_pool;
	if (!tx->tx_ring){
		snprintf(name, sizeof(name), "txring_%d_%d_%lx",
			 ndev->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());
		tx->tx_ring = rte_ring_create(name, nb_desc, SOCKET_ID_ANY, 0);
		if (tx->tx_ring == NULL) {
			goto err_tx_ring;
		}
	}
	tx->ctx_map = rte_calloc(NULL, AGIEP_DP_POOL_SIZE(nb_desc), sizeof(void *), 0);
	if (tx->ctx_map == NULL)
		goto err_ctx_map;

	tx->priv = &ndev->port;
	memset(&tx->notify, 0,sizeof(tx->notify));
	tx->notify.irq_num_threshold = nb_desc / 2;
	tx->notify.irq_threshold = (rte_get_tsc_hz() + US_PER_S - 1 ) / US_PER_S * INTERRUPT_TSC_THRESHOLD;

	tx->fq.qid = queue_idx;
	tx->fq.dev = ndev->fdev;

	vq->cb_data = tx;
	vq->cb = virtio_net_tx_enable_handler;

	desc = vdev->desc_addr[vq_idx];
	if (desc){
		virtqueue_set_pci_addr(vq, desc);
	}

	return 0;
err_ctx_map:
	rte_ring_free(tx->tx_ring);
err_tx_ring:
	rte_mempool_free(tx->ctx_pool);
err_ctx_pool:
	agiep_dma_free(dma, NULL, NULL);
error_dma:
	virtqueue_free(vq);
error:
	return -rte_errno;
}

static int
virtio_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
	uint16_t nb_desc, unsigned int socket __rte_unused,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	struct virtnet_tx *tx = NULL;
	int virt_idx;
	// expand tx queue, avoid locking when sending at ovs-vswitchd
	virt_idx = queue_idx % dev->data->nb_rx_queues;
	if (dev->data->tx_queues[virt_idx]){
		dev->data->tx_queues[queue_idx] = dev->data->tx_queues[virt_idx];
		return 0;
	}

	tx = rte_calloc(NULL, 1, sizeof(struct virtnet_tx), RTE_CACHE_LINE_SIZE);
	if (tx == NULL)
		goto error;

	if (virtnet_tx_setup(ndev, tx, virt_idx, nb_desc))
		goto error;

	dev->data->tx_queues[queue_idx] = tx;
	return 0;
error:
	if (tx)
		rte_free(tx);

	return -1;
}

static struct virtnet_tx *virtnet_tx_dup(struct virtnet_tx *tx)
{
	struct virtnet_tx *tx_dup;

	tx_dup = rte_malloc(NULL, sizeof(struct virtnet_tx), RTE_CACHE_LINE_SIZE);

	if (tx_dup == NULL) {
		RTE_LOG(ERR, PMD, "virnet tx dump failed\n");
		return NULL;
	}

	rte_memcpy(tx_dup, tx, sizeof(*tx_dup));

	return tx_dup;
}

static void virtnet_tx_release(struct virtnet_tx *tx)
{
	struct virtnet_tx_ctx *ctx;
	struct agiep_virtio_netdev *ndev;
	uint i;
	uint16_t reset_num;
	virtqueue_free(tx->bvq);
	tx->bvq = NULL;
	for (i = 0; i < AGIEP_DP_POOL_SIZE(tx->nb_desc); ++i) {
		ctx = tx->ctx_map[i];
		if (likely(ctx == NULL))
			continue;
		rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	}
	rte_free(tx->ctx_map);
	rte_mempool_free(tx->ctx_pool);
	ndev = tx->priv->fdev->dev;
	reset_num = __sync_add_and_fetch(&ndev->vdev->reset_num, 1);
	if (reset_num >= ndev->vdev->vq_num)
		legacy_reset_device_reg(ndev->vdev);
}

static void virtio_tx_queue_GC(void *data)
{
	struct virtnet_tx *tx = data;
	virtnet_tx_release(tx);
	rte_free(tx);
}

static void virtio_tx_queue_release(void *txq)
{
	struct rte_mbuf *pkts[32];
	struct virtnet_tx *tx;
	struct virtqueue *vq ;
	struct agiep_virtio_port *port;
	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;
	uint avail;
	int vq_idx;
	uint32_t i;

	if (!txq)
		return;

	tx = txq;

	vq = tx->vq;
	if (vq == NULL) {
		return;
	}
	tx->vq = NULL;
	vq_idx = VIRTIO_TX_INDEX(tx->id);

	port = vq->priv;
	ndev = port->fdev->dev;
	vdev = ndev->vdev;

	port->fdev->eth_dev->data->tx_queues[tx->id] = NULL;
	for (i = 0; i < port->fdev->eth_dev->data->nb_tx_queues; ++i) {
		if (port->fdev->eth_dev->data->tx_queues[i] == tx)
			port->fdev->eth_dev->data->tx_queues[i] = NULL;
	}
	do {
		i = rte_ring_dequeue_burst(tx->tx_ring, (void **) pkts, 32, &avail);
		if (i)
			rte_pktmbuf_free_bulk(pkts, i);
	} while (avail);

	rte_ring_free(tx->tx_ring);

	vdev->vq[vq_idx] = NULL;

	tx->fq.dev = NULL;

	if (vq->dma)
		agiep_dma_free_syn(vq->dma, virtio_tx_queue_GC, tx);
	else {
		virtnet_tx_release(tx);
		rte_free(tx);
	}
}

static void virtio_tx_queue_reset(struct virtnet_tx *tx)
{
	struct rte_mbuf *pkts[32];
	struct agiep_virtio_port *port;
	struct agiep_virtio_netdev *ndev;

	struct virtnet_tx *tx_dup;
	struct virtqueue *vq;
	uint16_t nb_desc;
	uint avail;
	uint16_t i;

	if (!tx)
		return;
	vq = tx->vq;
	if (!vq)
		return;
	port = vq->priv;
	ndev = port->fdev->dev;
	nb_desc = virtqueue_desc_num(vq);

	tx->vq = NULL;
	rte_mb();
	agiep_virtio_tx_synchronize(tx);
	do {
		i = rte_ring_dequeue_burst(tx->tx_ring, (void **) pkts, 32, &avail);
		if (i)
			rte_pktmbuf_free_bulk(pkts, i);
	} while (avail);
	if (vq->dma) {
		tx_dup = virtnet_tx_dup(tx);
		agiep_dma_free(vq->dma, virtio_tx_queue_GC, tx_dup);
	} else
		 virtnet_tx_release(tx);

	if (virtnet_tx_setup(ndev, tx, tx->id, nb_desc)) {
		AGIEP_LOG_ERR("tx %d queue reset error", tx->id);
	}
}

uint16_t agiep_virtio_net_get_status(struct rte_eth_dev *dev)
{
	struct virtio_net_config *net_cfg;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	if (!ndev->vdev)
		return -1;
	net_cfg = virtio_net_get_config_addr(ndev->vdev);
	return net_cfg->status;
}

int agiep_virtio_net_set_status(struct rte_eth_dev *dev, uint16_t status)
{
	struct virtio_net_config *net_cfg;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	if (!ndev->vdev)
		return -1;
	if (!virtqueue_enabled(ndev->port.ctrl->cvq))
		return 0;
	net_cfg = virtio_net_get_config_addr(ndev->vdev);
	net_cfg->status = status;
	virtio_net_config_notify(ndev->vdev);
	return 0;
}

void virtio_set_dev_start_no_ctrl(struct agiep_virtio_device *vdev)
{
	if (NULL == vdev) {
		return;
	}

	struct virtio_net_config *net_cfg;
	net_cfg = virtio_net_get_config_addr(vdev);
	net_cfg->status |= VIRTIO_NET_S_LINK_UP;
	virtio_net_config_notify(vdev);
	return;
}

static int virtio_dev_start(struct rte_eth_dev *dev)
{
	uint16_t status;
	status = agiep_virtio_net_get_status(dev);
	status |= VIRTIO_NET_S_LINK_UP;
	return agiep_virtio_net_set_status(dev, status);
}

static int
virtio_dev_linkupdate(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct virtio_net_config *net_cfg;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;

	struct rte_eth_link link;

	ndev = fdev->dev;
	if (!ndev)
		return 0;
	vdev = ndev->vdev;
	if (!vdev)
		return 0;
	net_cfg = virtio_net_get_config_addr(vdev);

	memset(&link, 0, sizeof(link));
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_speed  = ETH_SPEED_NUM_25G;
	link.link_autoneg = ETH_LINK_FIXED;

	if ((net_cfg->status & VIRTIO_NET_S_LINK_UP)
		&& (vdev->device_status & VIRTIO_CONFIG_S_DRIVER_OK))
	{
		link.link_status = ETH_LINK_UP;
	} else {
		link.link_status = ETH_LINK_DOWN;
	}
	return rte_eth_linkstatus_set(dev, &link);
}

static void virtio_dev_stop(struct rte_eth_dev *dev)
{
	struct rte_eth_link link;
	uint16_t status;

	status = agiep_virtio_net_get_status(dev);
	status &= ~VIRTIO_NET_S_LINK_UP;
	agiep_virtio_net_set_status(dev, status);

	dev->data->dev_link.link_status = 0;

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
}

static void virtio_ctrl_release(struct agiep_net_ctrl *ctrl)
{
	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;
	struct virtqueue *cvq = ctrl->cvq;
	uint16_t reset_num;
	rte_mempool_free(ctrl->cmdpool);
	rte_ring_free(ctrl->rr);
	rte_ring_free(ctrl->cr);
	virtqueue_free(ctrl->bvq);
	ndev = ctrl->priv->fdev->dev;
	vdev = ndev->vdev;

	reset_num = __sync_add_and_fetch(&vdev->reset_num, 1);
	if (reset_num >= ndev->vdev->vq_num)
		legacy_reset_device_reg(ndev->vdev);
	/*
	 * if run as virtio_dev_close() ,ctrl->cvq not set to old cvq,
	 * we should be release "ndev" and "vdev".
	 */
	if (unlikely(cvq == NULL)){
		agiep_virtio_destroy(vdev);
		rte_free(ndev);
		rte_free(ctrl->priv->fdev);
	}
}

static void virtio_ctrl_GC(void *data)
{
	struct agiep_net_ctrl *ctrl = data;
	if (ctrl == NULL)
		return;
	virtio_ctrl_release(ctrl);
	rte_free(ctrl);
}

static void virtio_ctrl_queue_release(struct agiep_net_ctrl *ctrl)
{
	struct virtqueue *cvq;
	struct agiep_frep_device *fdev_dup;

	cvq = ctrl->cvq;
	ctrl->cvq = NULL;

	agiep_ctrl_synchronize(ctrl);
	fdev_dup = rte_calloc(NULL, 1, sizeof(struct agiep_frep_device), 0);

	*fdev_dup = *ctrl->priv->fdev;
	ctrl->priv->fdev = fdev_dup;
	agiep_dma_free_syn(cvq->dma, virtio_ctrl_GC, ctrl);
}

int virtio_vq_pairs_set(struct agiep_virtio_netdev *ndev, uint16_t cur_pairs)
{
	struct agiep_frep_device *fdev = ndev->fdev;
	fdev->used_queues = cur_pairs;
	return 0;
}

static void virtio_dev_close(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev;
	struct agiep_net_ctrl *ctrl;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;
	struct rte_eth_link link;
	int i;
	ndev = fdev->dev;
	if (!ndev)
		return;

	pthread_mutex_lock(&vnlist_lock);
	TAILQ_REMOVE(&virtio_netdev_list, ndev, entry);
	agile_netdev_tab[fdev->pf][fdev->vf] = AGIEP_FREP_NUM;
	pthread_mutex_unlock(&vnlist_lock);
	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rx = dev->data->rx_queues[i];
		virtio_rx_queue_release(rx);
	}

	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		tx = dev->data->tx_queues[i];
		if (tx == dev->data->tx_queues[0] && i)
			break;
		virtio_tx_queue_release(tx);
	}
	ctrl = ndev->port.ctrl;
	if (ctrl){
		virtio_ctrl_queue_release(ctrl);
		ndev->port.ctrl = NULL;
	}
	fdev->dev = NULL;
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
}

int virtio_net_dev_softreset(struct rte_eth_dev *dev)
{
	uint32_t i;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	struct agiep_virtio_device *vdev = ndev->vdev;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;

	if (vdev->reseted)
		return 0;
	vdev->reseted = 1;
	vdev->set_num = 0;
	vdev->started = 0;
	for (i = 0; i < dev->data->nb_rx_queues * 2 + VIRTIO_CTRL_QUEUE_SIZE; ++i) {
		vdev->desc_addr[i] = 0;
		vdev->vq[i] = NULL;
	}

	vdev->msix_enabled = 0;
	virtio_net_init_reg(ndev);

	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rx = dev->data->rx_queues[i];
		virtio_rx_queue_reset(rx);
	}

	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		tx = dev->data->tx_queues[i];
		if (tx == dev->data->tx_queues[0] && i)
			break;
		virtio_tx_queue_reset(tx);
	}

	virtio_net_ctrl_reset(dev, ndev);
	dev->data->dev_link.link_status = 0;

	agiep_virtio_legacy_expand_reset(vdev);
	AGIEP_LOG_WARN("driver notify framwork reset port %d vf %d", dev->data->port_id, fdev->vf);
	return 0;
}

static int virtio_dev_info_get(struct rte_eth_dev *dev __rte_unused,
                            struct rte_eth_dev_info *dev_info)
{
        dev_info->max_rx_queues = VIRTIO_MAX_RX_QUEUES;
        dev_info->max_tx_queues = VIRTIO_MAX_TX_QUEUES;
        dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
        dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */

        dev_info->rx_desc_lim = rx_desc_lim;
        dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->flow_type_rss_offloads = flow_type_rss_offloads;
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_CHECKSUM;
	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM; 
        return 0;
}
static int virtio_dev_promiscuous_enable(struct rte_eth_dev *dev) {
	dev->data->promiscuous = 1;
	return 0;
}

static int virtio_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu){
	struct virtio_net_config *net_cfg;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_virtio_netdev *ndev = fdev->dev;
	struct agiep_virtio_device *vdev = ndev->vdev;

	net_cfg = virtio_net_get_config_addr(vdev);
	net_cfg->mtu =  mtu - AGIEP_DMA_ALIGN;
	dev->data->mtu = mtu;
	return 0;
}

static int virtio_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	dev->data->promiscuous = 0;
	return 0;
}

static void
virtio_update_stats(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	unsigned i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const struct virtnet_tx *txvq = dev->data->tx_queues[i];
		if (txvq == NULL)
			continue;
		if (i && txvq == dev->data->tx_queues[0]) 
			break;

		stats->opackets += txvq->stats.packets;
		stats->obytes += txvq->stats.bytes;
		stats->oerrors += txvq->stats.errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = txvq->stats.packets;
			stats->q_obytes[i] = txvq->stats.bytes;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const struct virtnet_rx *rxvq = dev->data->rx_queues[i];
		if (rxvq == NULL)
			continue;

		stats->ipackets += rxvq->stats.packets;
		stats->ibytes += rxvq->stats.bytes;
		stats->ierrors += rxvq->stats.errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = rxvq->stats.packets;
			stats->q_ibytes[i] = rxvq->stats.bytes;
		}
	}

	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
}

static int
virtio_dev_stats_reset(struct rte_eth_dev *dev)
{
	unsigned i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct virtnet_tx *txvq = dev->data->tx_queues[i];
		if (txvq == NULL)
			continue;
		memset(&txvq->stats, 0, sizeof(txvq->stats));
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct virtnet_rx *rxvq = dev->data->rx_queues[i];
		if (rxvq == NULL)
			continue;
		memset(&rxvq->stats, 0, sizeof(rxvq->stats));
	}
	return 0;
}

static int virtio_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	virtio_update_stats(dev, stats);
	return 0;
}

static struct eth_dev_ops virtio_net_ops = {
	.dev_configure = virtio_net_configure,
	.rx_queue_setup = virtio_rx_queue_setup,
	.rx_queue_release = virtio_rx_queue_release,
	.tx_queue_setup = virtio_tx_queue_setup,
	.tx_queue_release = virtio_tx_queue_release,
	.dev_start = virtio_dev_start,
	.dev_stop = virtio_dev_stop,
	.dev_close = virtio_dev_close,
//	.dev_reset = virtio_dev_reset,
	.dev_infos_get = virtio_dev_info_get,
	.link_update = virtio_dev_linkupdate,
	.promiscuous_enable = virtio_dev_promiscuous_enable,
	.promiscuous_disable = virtio_dev_promiscuous_disable,
	.stats_get = virtio_dev_stats_get,
	.stats_reset = virtio_dev_stats_reset,
	.mtu_set = virtio_dev_mtu_set,
};

static struct agiep_frep virtio_net_frep = {
	.ops = &virtio_net_ops,
	.rx_pkt_burst = agiep_virtio_rx_pkt_burst,
	.tx_pkt_burst = agiep_virtio_tx_xmit,
	.type = AGIEP_FREP_VIRTIO,
};

RTE_INIT(agiep_virtio_net_init)
{
	agiep_frep_register(&virtio_net_frep);
}
