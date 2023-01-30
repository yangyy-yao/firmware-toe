#include <assert.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>

#include "agiep_vendor_port.h"
#include "agiep_vendor_ctrl.h"
#include "agiep_ctrl.h"
#include "agiep_virtio_ctrl.h"
#include "agiep_virtio_net.h"
#include "agiep_virtio_rxtx.h"
#include "agiep_reg_poller.h"
#include "agiep_pci.h"
#include "agiep_dma.h"
#include "agiep_dirty_log.h"
#include "agiep_mng.h"

#define VENDOR_FEATURES \
		(1ULL << VIRTIO_NET_F_CTRL_VQ | \
		 1ULL << VIRTIO_NET_F_MRG_RXBUF | \
		 1ULL << VIRTIO_NET_F_MQ | \
		 1ULL << VIRTIO_NET_F_MAC | \
		 1ULL << VIRTIO_NET_F_STATUS| \
		 1ULL << VIRTIO_NET_F_MTU | \
		 1ULL << VIRTIO_F_VERSION_1 | \
		 1ULL << VIRTIO_F_ANY_LAYOUT)

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = VENDOR_QUEUE_SIZE,
	.nb_min = VENDOR_QUEUE_SIZE,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = VENDOR_QUEUE_SIZE,
	.nb_min = VENDOR_QUEUE_SIZE,
	.nb_align = 8,
};

TAILQ_HEAD(vendor_port_list ,agiep_vendor_port) vendor_port_list ;
static pthread_mutex_t vnlist_lock = PTHREAD_MUTEX_INITIALIZER;

static void vendor_net_health_count(struct agiep_vendor_port *vendor_port)
{
	struct agiep_vendor_port_cfg *port_cfg;
	if (vendor_port->started) {
		port_cfg = vendor_port->cfg;
		port_cfg->health_count++;
	}
}

inline static uint16_t agiep_vendor_notify(struct virtqueue *vq)
{
	struct agiep_virtio_port *virtio_port = vq->priv;
	struct agiep_vendor_port *vendor_port = virtio_port->fdev->dev;
	struct agiep_vendor_netdev *netdev = vendor_port->netdev;
	uint16_t *notify = (uint16_t *)(RTE_PTR_ADD(netdev->notify_area_bar, AGIEP_PAGE_SIZE * vq->index));

	if (unlikely(vq->notify)){
		vq->notify = 0;
		return 1;
	}

	if (VENDOR_NOTIFY_MASK != *notify) {
		*notify = VENDOR_NOTIFY_MASK;
		return 1;
	}

	return 0;
}

void *vendor_net_ctrl_process(void *arg __rte_unused)
{
	struct agiep_vendor_port *vendor_port;
	if (TAILQ_EMPTY(&vendor_port_list))
		return NULL;
	pthread_mutex_lock(&vnlist_lock);
	TAILQ_FOREACH(vendor_port, &vendor_port_list, entry) {
		agiep_vendor_cmd_process(vendor_port);
		vendor_net_health_count(vendor_port);
	}
	pthread_mutex_unlock(&vnlist_lock);
	return NULL;
}

static void vendor_dev_close(struct rte_eth_dev *dev);

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	int *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (int)strtol(value, NULL, 10);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static void vendor_cq_queue_init(struct agiep_vendor_port *vendor_port, struct virtqueue *cvq) 
{
	struct agiep_vendor_cq_cfg *cq_cfg = vendor_port->cq_cfg;
	uint64_t desc_addr = 0;
	uint64_t avail_addr = 0;
	uint64_t used_addr = 0;

	if (cq_cfg->queue_desc_lo && cq_cfg->queue_desc_hi) {
		desc_addr = cq_cfg->queue_desc_hi;
		desc_addr = desc_addr << 32 |
			cq_cfg->queue_desc_lo;
		
		avail_addr = cq_cfg->queue_avail_hi;
		avail_addr = avail_addr << 32 |
			cq_cfg->queue_avail_lo;

		used_addr = cq_cfg->queue_used_hi;
		used_addr = used_addr << 32 |
			cq_cfg->queue_used_lo;

		virtqueue_set_addr(cvq, avail_addr, used_addr,
				desc_addr);
	}
}

static int vendor_net_ctrl_configure(struct rte_eth_dev *dev, struct agiep_vendor_port *vendor_port, uint16_t nb_desc)
{
	char ring_name[RTE_RING_NAMESIZE];
	struct agiep_net_ctrl *ctrl;
	struct virtqueue *cvq = NULL;
	struct rte_ring *rr = NULL;
	struct rte_ring *cr = NULL;
	struct rte_mempool *cmdpool = NULL;
	enum virtqueue_type vqt;
	struct agiep_dma *dma = NULL;
	struct agiep_virtio_port *virtio_port;
	struct agiep_dirty_log *dirty_log = NULL;
	int vq_idx;

	virtio_port = &(vendor_port->port);

	ctrl = virtio_port->ctrl;
	ctrl->cr = NULL;
	ctrl->rr = NULL;
	ctrl->cvq = NULL;
	ctrl->cmdpool = NULL;


	if (vendor_port->cfg->feature & (1ULL << VIRTIO_F_RING_PACKED))
		vqt = VQ_PACKED;
	else
		vqt = VQ_SPLIT;
	vq_idx = 2 * dev->data->nb_rx_queues;
	// TODO: size of cvq can be smaller.
	cvq = virtqueue_create(vq_idx, nb_desc, vqt, 0);

	if (cvq == NULL) {
		RTE_LOG(ERR, PMD, "ctrl virtqueue create fail\n");
		goto error;
	}

	vendor_port->cq_cfg->qsize = nb_desc;

	dma = agiep_dma_create(virtio_port->fdev->pf, virtio_port->fdev->vf);
	if (dma == NULL) {
		RTE_LOG(ERR, PMD, "ctrl dma create fail\n");
		goto error;
	}

	cvq->dma = dma;
	virtqueue_set_dma(cvq, cvq->dma);

	dirty_log = agiep_dirty_log_get(virtio_port->fdev->pf, virtio_port->fdev->vf);
	if (!dirty_log){
		AGIEP_LOG_ERR("dirty log get error");
		goto error;
	}
	agiep_dirty_log_init(dirty_log);
	cvq->dlog = dirty_log;
	cvq->priv = virtio_port;
	cvq->notify_cb = agiep_vendor_notify;

	snprintf(ring_name, sizeof(ring_name), "rq_ring_%d_%lx", dev->data->port_id, rte_rdtsc());
	rr = rte_ring_create(ring_name, VIRTIO_NET_CTRL_DESC_NUM, 0, 0);
	snprintf(ring_name, sizeof(ring_name), "cq_ring_%d_%lx", dev->data->port_id, rte_rdtsc());
	cr = rte_ring_create(ring_name, VIRTIO_NET_CTRL_DESC_NUM, 0, 0);

	if (!rr || !cr) {
		RTE_LOG(ERR, PMD, "ctrl ring create fail\n");
		goto error;
	}

	vendor_cq_queue_init(vendor_port, cvq);

	ctrl->rr = rr;
	ctrl->cr = cr;

	snprintf(ring_name, RTE_MEMPOOL_NAMESIZE, "ctrl_cmd_%d_%lx", dev->data->port_id, rte_rdtsc());
	cmdpool = rte_mempool_create(ring_name, /*256*/VENDOR_QUEUE_SIZE,
			sizeof(struct vendor_port_command), 0, 0, NULL, NULL, NULL,
			NULL, 0, 0);
	if (cmdpool == NULL) {
		AGIEP_LOG_ERR("ctrl cmdpool create fail: %d %s", rte_errno, rte_strerror(rte_errno));
		goto error;
	}
	ctrl->cmdpool = cmdpool;

	agiep_vendor_reset_vector(vendor_port->netdev, vendor_port->netdev->config_vector);

	ctrl->cvq = cvq;
	ctrl->bvq = cvq;

	ctrl->ctl_type = CTRL_VENDOR;
	ctrl->cvq->notify = 1;
	return 0;
error:
	RTE_LOG(ERR, PMD, "vendor_net_ctrl_configure fail\n");
	if (rr)
		rte_ring_free(rr);
	if (cr)
		rte_ring_free(cr);
	if (cvq)
		virtqueue_free(cvq);
	if (dma)
		agiep_dma_free(dma, NULL, NULL);
	return -1;
}

static void vendor_ctrl_release(struct agiep_net_ctrl *ctrl)
{
	rte_mempool_free(ctrl->cmdpool);
	rte_ring_free(ctrl->rr);
	rte_ring_free(ctrl->cr);
	virtqueue_free(ctrl->bvq);
}

static void vendor_ctrl_GC(void *data)
{
	struct agiep_net_ctrl *ctrl = data;

	if (ctrl == NULL)
		return;

	vendor_ctrl_release(ctrl);
	rte_free(ctrl);
}

static struct agiep_net_ctrl *vendor_ctrl_dup(struct agiep_net_ctrl *ctrl)
{
	struct agiep_net_ctrl *ctrl_dup;

	ctrl_dup = rte_malloc(NULL, sizeof(struct agiep_net_ctrl), 0);

	if (ctrl_dup == NULL)
		return NULL;

	*ctrl_dup = *ctrl;
	return ctrl_dup;
}

static int vendor_net_ctrl_reset(struct rte_eth_dev *dev, struct agiep_vendor_port *vendor_port, uint16_t nb_desc)
{
	struct agiep_net_ctrl *ctrl;
	struct agiep_net_ctrl *ctrl_dup;
	struct agiep_virtio_port *virtio_port;
	struct virtqueue *cvq;

	virtio_port = &(vendor_port->port);

	ctrl = virtio_port->ctrl;
	if (!ctrl)
		return -1;
	cvq = ctrl->cvq;
	ctrl->cvq = NULL;
	agiep_ctrl_synchronize(ctrl);
	if (cvq->dma) {
		ctrl_dup = vendor_ctrl_dup(ctrl);
		agiep_dma_free_syn(cvq->dma, vendor_ctrl_GC, ctrl_dup);
  	} else {
		vendor_ctrl_release(ctrl);
	}
	if (vendor_net_ctrl_configure(dev, vendor_port, nb_desc)) {
		RTE_LOG(ERR, PMD, "virtio net ctrl configure error\n");
		return -1;
	}
	return 0;
}

static int vendor_net_configure(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct rte_kvargs *kvlist = fdev->kvlist;
	struct agiep_vendor_netdev *netdev = NULL;
	struct agiep_vendor_port *vendor_port = NULL;
	struct virtqueue **rx_vq = NULL;
	struct virtqueue **tx_vq = NULL;
	struct agiep_vendor_rx_cfg **rx_cfg = NULL;
	struct agiep_vendor_tx_cfg **tx_cfg = NULL;
	struct agiep_net_ctrl *ctrl = NULL;
	int vport;
	int port_num;
	int i;
	int ret;
	int qnum;
	int mtu = RTE_PMD_AGIEP_MTU_DEFAULT;

	dev->data->nb_rx_queues = RTE_MIN(dev->data->nb_rx_queues, dev->data->nb_tx_queues);
	dev->data->nb_tx_queues = dev->data->nb_rx_queues;
	qnum = dev->data->nb_rx_queues;
	if (rte_kvargs_count(kvlist, ETH_AGIEP_VPORT) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_VPORT,
					 &open_int, &vport);
		if (ret < 0) {
			AGIEP_LOG_ERR("agiep vendor kvlist vport error");
			return ret;
		}
		if (vport < 0) {
			return -EINVAL;
		}
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_PORTNUM) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_PORTNUM,
					 &open_int, &port_num);
		if (ret < 0) {
			AGIEP_LOG_ERR("agiep vendor kvlist portnum error");
			return ret;
		}
		if (port_num < 0 || vport >= port_num){
			return -EINVAL;
		}
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_MTU) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_MTU,
			 &open_int, &mtu);
		if (ret < 0) {
			AGIEP_LOG_ERR("agiep vendor kvlist mtu error");
			return ret;
		}
		if (mtu < 0 || mtu > UINT16_MAX) {
			return -EINVAL;
		}
	}
	netdev = agiep_vendor_netdev_get(fdev->pf, fdev->vf);
	if (netdev) {
		if (strcmp(netdev->name, dev->data->name)){
			AGIEP_LOG_ERR("agiep vendor new dev %s use same pf:%d vf:%d with exiting dev %s",
					dev->data->name, fdev->pf, fdev->vf, netdev->name);
			agiep_vendor_netdev_put(netdev);
			return -EINVAL;
		}
		vendor_dev_close(dev);
	}
	if (agile_netdev_tab[fdev->pf][fdev->vf] != AGIEP_FREP_NUM &&
		agile_netdev_tab[fdev->pf][fdev->vf] != AGIEP_FREP_VENDOR){
		AGIEP_LOG_ERR("pf %d vf %d duplicate", fdev->pf, fdev->vf);
		return -EINVAL;
	}
	netdev = agiep_vendor_net_probe(fdev->pf, fdev->vf, port_num);
	if (!netdev) {
		AGIEP_LOG_ERR("agiep_vendor_net_probe error");
		return -1;
	}
	strcpy(netdev->name, dev->data->name);
	netdev->config_vector = 0;

	if (vport >= netdev->pnum) {
		AGIEP_LOG_ERR("vport >= netdev->pnum");
		return -1;
	}

	ctrl = rte_calloc(NULL, 1, sizeof(struct agiep_net_ctrl), 0); 

	if (ctrl == NULL) {
		AGIEP_LOG_ERR("agiep_net_ctrl malloc error %d", rte_errno);
		goto error_ctl;
	}

	vendor_port = &netdev->ports[vport];
	vendor_port->port.ctrl = ctrl;
	fdev->dev = vendor_port;
	fdev->ep = netdev->ep;
	vendor_port->port.fdev = fdev;
	ctrl->priv = &vendor_port->port;

	rx_vq = rte_malloc(NULL, sizeof(struct virtqueue *) * qnum * 2, 0);

	if (!rx_vq) {
		AGIEP_LOG_ERR("vq malloc error %d", rte_errno);
		goto error_ctl;
	}
	tx_vq = RTE_PTR_ADD(rx_vq, sizeof(void *) * qnum);

	vendor_port->id = vport;
	vendor_port->netdev = netdev;
	vendor_port->eth_dev = dev;
	vendor_port->rx_vq = rx_vq;
	vendor_port->tx_vq = tx_vq;
	vendor_port->dirty_log_cfg = agiep_vendor_dirty_log_cfg_get(netdev);
	vendor_port->cfg = agiep_vendor_port_cfg_get(netdev, vport, qnum);

	rte_memset(vendor_port->cfg, 0, sizeof(struct agiep_vendor_port_cfg));

	rte_memcpy(vendor_port->cfg->mac, dev->data->mac_addrs, sizeof(vendor_port->cfg->mac));
	vendor_port->cfg->qnum = qnum;
	vendor_port->port.fdev->used_queues = qnum;
	vendor_port->cfg->feature = VENDOR_FEATURES;
	vendor_port->cfg->mtu = mtu;

	if (fdev->packed)
		vendor_port->cfg->feature |= (1ULL << VIRTIO_F_RING_PACKED);

	if (fdev->hw_checksum)
		vendor_port->cfg->feature |= (1ULL << VIRTIO_NET_F_CSUM) | (1ULL << VIRTIO_NET_F_GUEST_CSUM);
	
	if (fdev->accel && fdev->accel->ops->features_get)
		vendor_port->cfg->feature |= fdev->accel->ops->features_get(fdev);

	vendor_port->cq_cfg = agiep_vendor_cq_cfg_get(netdev, vport, qnum);
	rte_memset(vendor_port->cq_cfg, 0, sizeof(struct agiep_vendor_cq_cfg));

	if (vendor_port->netdev->pf == 0 && vendor_port->netdev->vf == 0) {
		vendor_port->mng_cfg = agiep_vendor_mng_cfg_get(netdev, vport, qnum);
		vendor_port->mng_cfg->address = agiep_mng_get_mngip();
		vendor_port->mng_cfg->netmask = agiep_mng_get_netmask();
	}

	rx_cfg = rte_calloc(NULL, qnum * 2, sizeof(void *), 0);

	if (!rx_cfg) {
		AGIEP_LOG_ERR("cfg calloc error %d", rte_errno);
		goto error_vq;
	}
	tx_cfg = RTE_PTR_ADD(rx_cfg, qnum * sizeof(void *));

	vendor_port->rx_cfg = rx_cfg;
	vendor_port->tx_cfg = tx_cfg;

	for (i = 0; i < qnum; i++) {
		vendor_port->rx_cfg[i] = (struct agiep_vendor_rx_cfg *)agiep_vendor_tx_cfg_get(netdev, vport, i, qnum);//guest tx ----> vendor rx
		vendor_port->rx_cfg[i]->msi_vector = AGIEP_MSI_NO_VECTOR;
		vendor_port->rx_cfg[i]->get_last = 0;
		vendor_port->tx_cfg[i] = (struct agiep_vendor_tx_cfg *)agiep_vendor_rx_cfg_get(netdev, vport, i, qnum);//guest rx ----> vendor tx
		vendor_port->tx_cfg[i]->msi_vector = AGIEP_MSI_NO_VECTOR;
		vendor_port->tx_cfg[i]->get_last = 0;
	}

	if (vendor_net_ctrl_configure(dev, vendor_port, VENDOR_QUEUE_SIZE)) {
		AGIEP_LOG_ERR("vendor_net_ctrl_configure error");
		goto error_cfg;
	}

	if (agiep_port_addr_poller_reg(vendor_port)) {
		AGIEP_LOG_ERR("agiep_port_addr_poller_reg error");
		goto error_cfg;
	}

	pthread_mutex_lock(&vnlist_lock);
	TAILQ_INSERT_HEAD(&vendor_port_list, vendor_port, entry);
	agile_netdev_tab[fdev->pf][fdev->vf] = AGIEP_FREP_VENDOR;
	pthread_mutex_unlock(&vnlist_lock);

	vendor_port->cfg->status = VENDOR_CONFIG_S_DEVICE_INIT;
	vendor_port->vector_map = 0;
	RTE_BUILD_BUG_ON(sizeof(vendor_port->vector_map) * 8 != VENDOR_MAX_QUEUE);
	vendor_port->started = 0;
	vendor_port->enable = 0;

	return 0;
error_cfg:
	rte_free(rx_cfg);
error_vq:
	rte_free(rx_vq);
error_ctl:
	if (ctrl)
		rte_free(ctrl);
	fdev->dev = NULL;
	agiep_vendor_netdev_put(netdev);
	return -1;
}

static void vendor_net_rx_enable_handler(void *data)
{
	struct agiep_virtio_port *port;
	struct agiep_vendor_port *vendor_port;
	struct virtnet_rx *rx;
	if (!data)
		return;
	rx = data;
	port = rx->priv;

	vendor_port = port->fdev->dev;
	if (vendor_port->cfg->feature & (1<<VIRTIO_NET_F_MRG_RXBUF))
		rx->mergeable = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		rx->mergeable = sizeof(struct virtio_net_hdr);
}

static int vendor_rx_setup(struct agiep_vendor_port *vendor_port, struct virtnet_rx *rx, int queue_idx, uint16_t nb_desc,
		struct rte_mempool *mp)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct virtqueue *vq = NULL;
	struct agiep_dma *dma = NULL;
	struct agiep_virtio_port *virtio_port;
	struct agiep_dirty_log *dirty_log;
	virtio_port = &(vendor_port->port);
	enum virtqueue_type vqt;
	int vq_idx;

	if (rx->vq != NULL)
		return 0;
	rx->elem_id = 0;
	rx->ctx_pool = NULL;
	rx->mergeable = 0;

	rx->mbuf_list = NULL;
	if (!nb_desc || (nb_desc & (nb_desc - 1))) {
		AGIEP_LOG_ERR("nb_desc must power of 2");
		return -1;
	}
	rx->nb_desc = nb_desc;
	rx->nb_mbuf = 0;
	vendor_port->rx_cfg[queue_idx]->qsize = nb_desc;

	rx->id = queue_idx;
	TAILQ_INIT(&rx->ctx_list);

	vq_idx = 2 * queue_idx + 1;

	if (vendor_port->cfg->feature & (1ULL << VIRTIO_F_RING_PACKED))
		vqt = VQ_PACKED;
	else
		vqt = VQ_SPLIT;

	vq = virtqueue_create(vq_idx, nb_desc, vqt, 0);

	if (vq == NULL)
		goto error;

	dma = agiep_dma_create(virtio_port->fdev->pf, virtio_port->fdev->vf);
	if (dma == NULL) {
		AGIEP_LOG_ERR("DMA create error %d %d", virtio_port->fdev->pf, virtio_port->fdev->vf);
		goto error;
	}

	vq->dma = dma;
	virtqueue_set_dma(vq, vq->dma);

	dirty_log = agiep_dirty_log_init(agiep_dirty_log_get(virtio_port->fdev->pf, virtio_port->fdev->vf));
	vq->dlog = dirty_log;

	vq->priv = virtio_port;
	vq->msi_vector = AGIEP_MSI_NO_VECTOR;
	vq->notify_cb = agiep_vendor_notify;


	rx->mpool = mp;
	rx->priv = virtio_port;
	snprintf(name, RTE_MEMPOOL_NAMESIZE, "rx_ctx_%d_%d_%lx",
		virtio_port->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());
	rx->ctx_pool = rte_mempool_create(name, AGIEP_DP_POOL_SIZE(nb_desc * 2),
		sizeof(struct virtnet_rx_ctx), AGIEP_DP_CACHE_SIZE(nb_desc * 2), 0,
		NULL, NULL, NULL, NULL, 0, 0);
	if (rx->ctx_pool == NULL) {
		AGIEP_LOG_ERR("rte_mempool_create rx->ctx_pool failed nb_desc:%u", nb_desc);
		goto error;
	}

	snprintf(name, sizeof(name), "rx_ring_%d_%d_%lu",
		 vendor_port->eth_dev->data->port_id, queue_idx, rte_rdtsc());
	
	rx->mbuf_list = rte_calloc(NULL, nb_desc, sizeof(struct rte_mbuf *), RTE_CACHE_LINE_SIZE);
	if (rx->mbuf_list == NULL)
		goto error;

	memset(&rx->notify, 0, sizeof(rx->notify));
	rx->notify.irq_threshold = rte_get_tsc_hz();

	vendor_port->rx_vq[queue_idx] = vq;
	rx->vq = vq;
	rx->bvq = vq;
	vq->notify = 1;

	rx->fq.qid = queue_idx;
	rx->fq.dev = virtio_port->fdev;

	vq->cb_data = rx;
	vq->cb = vendor_net_rx_enable_handler;
	
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
vendor_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
	uint16_t nb_desc, unsigned int socket __rte_unused,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool *mp)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
	struct virtnet_rx *rx = NULL;

	if (queue_idx >= dev->data->nb_rx_queues) {
		return 0;
	}

	rx = rte_calloc(NULL, 1, sizeof(struct virtnet_rx), RTE_CACHE_LINE_SIZE);
	if (unlikely(rx == NULL)) {
		AGIEP_LOG_ERR("rx %d alloc failed", queue_idx);
		return -ENOMEM;
	}

	if (vendor_rx_setup(vendor_port, rx, queue_idx, nb_desc, mp)){
		AGIEP_LOG_ERR("rx %d setup failed", queue_idx);
		goto error;
	}

	dev->data->rx_queues[queue_idx] = rx;
	return 0;
error:
	rte_free(rx);
	return -1;
}

static void vendor_rx_release(struct virtnet_rx *rx)
{
	struct virtnet_rx_ctx *ctx;
	uint32_t i;

	virtqueue_free(rx->bvq);

	TAILQ_FOREACH(ctx, &rx->ctx_list, entry) {
		rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	}
	for (i = 0; i < rx->nb_desc; ++i) {
		rte_pktmbuf_free(rx->mbuf_list[i]);
	}
	rte_mempool_free(rx->ctx_pool);
	rte_free(rx->mbuf_list);
}

static struct virtnet_rx *vendor_rx_dup(struct virtnet_rx *rx)
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

static void vendor_rx_queue_GC(void *data)
{
	struct virtnet_rx *rx = data;

	if (rx == NULL)
		return;

	vendor_rx_release(rx);
	rte_free(rx);
}

static void vendor_rx_queue_release(void *rxq)
{
	struct rte_eth_dev *dev;
	struct virtnet_rx *rx = NULL;
	struct virtqueue *vq = NULL;
	struct agiep_vendor_port *vendor_port;

	if (!rxq)
		return;
	rx = rxq;

	vq = rx->vq;

	if (vq == NULL)
		return;
	rx->vq = NULL;
	agiep_virtio_rx_synchronize(rx);

	vendor_port = container_of(vq->priv, struct agiep_vendor_port, port);
	if (vendor_port == NULL) {
		return;
	}
	dev = vendor_port->eth_dev;

	dev->data->rx_queues[rx->id] = NULL;
	vendor_port->rx_vq[rx->id] = NULL;
	rx->fq.dev = NULL;

	if (vq->dma) {
		agiep_dma_free_syn(vq->dma, vendor_rx_queue_GC, rx);
	} else {
		vendor_rx_release(rx);
		rte_free(rx);
	}
}

static int vendor_rx_queue_reset(struct virtnet_rx *rx)
{
	struct agiep_virtio_port *virtio_port;
	struct agiep_frep_device *fdev;
	struct agiep_vendor_port *vendor_port;
	struct virtnet_rx *rx_dup;
	struct virtqueue *vq;
	uint16_t nb_desc;

	vq = rx->vq;
	if (!vq)
		return -1;
	virtio_port = vq->priv;
	
	fdev = virtio_port->fdev;
	vendor_port = fdev->dev;

	if (vendor_port->rx_cfg[rx->id]->qsize) 
		nb_desc = vendor_port->rx_cfg[rx->id]->qsize;
	else
		nb_desc = vq->num;

	rx->vq = NULL;
	rte_mb();
	agiep_virtio_rx_synchronize(rx);

	if (vq->dma) {
		rx_dup = vendor_rx_dup(rx);
		agiep_dma_free_syn(vq->dma, vendor_rx_queue_GC, rx_dup);
	} else
		vendor_rx_release(rx);

	if (vendor_rx_setup(vendor_port, rx, rx->id, nb_desc, rx->mpool)) {
		RTE_LOG(ERR, PMD, "rx %d queue reset error\n", rx->id);
		return -1;
	}
	return 0;
}

static void vendor_net_tx_enable_handler(void *data)
{
	struct agiep_virtio_port *port;
	struct agiep_vendor_port *vendor_port;
	struct virtnet_tx *tx;
	if (!data)
		return;
	tx = data;
	port = tx->priv;

	vendor_port = port->fdev->dev;
	if (vendor_port->cfg->feature & (1<<VIRTIO_NET_F_MRG_RXBUF)) {
		tx->mergeable = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	} else
	 	tx->mergeable = sizeof(struct virtio_net_hdr);
}

static void vendor_net_tx_ctx_obj_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned obj_idx)
{
	struct virtnet_tx_ctx *ctx = obj;
	ctx->tx = opaque;
	ctx->idx = obj_idx;
}
static int
vendor_tx_setup(struct agiep_vendor_port *vendor_port, struct virtnet_tx *tx, int queue_idx, uint16_t nb_desc)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct virtqueue *vq = NULL;
	enum virtqueue_type vqt;
	struct agiep_dma *dma = NULL;
	struct agiep_dirty_log *dirty_log = NULL;
	struct agiep_virtio_port *virtio_port;
	virtio_port = &(vendor_port->port);
	int vq_idx = 2 * queue_idx;

	if (tx->vq != NULL)
		return 0;
	if (!nb_desc && (nb_desc & (nb_desc - 1))) {
		AGIEP_LOG_ERR("nb_desc must power of 2");
		return -1;
	}
	vendor_port->tx_cfg[queue_idx]->qsize = nb_desc;

	tx->ctx_pool = NULL;
	tx->ctx_map = NULL;
	tx->mergeable = 0;
	tx->nb_desc = nb_desc;

	tx->id = queue_idx;

	if (vendor_port->cfg->feature & (1ULL << VIRTIO_F_RING_PACKED))
		vqt = VQ_PACKED;
	else
		vqt = VQ_SPLIT;

	vq = virtqueue_create(vq_idx, nb_desc, vqt, VRING_F_NO_NOTIFY);
	if (unlikely(vq == NULL)) {
		AGIEP_LOG_ERR("%d %d vq create error", virtio_port->fdev->pf, virtio_port->fdev->vf);
		goto error;
	}

	dma = agiep_dma_create(virtio_port->fdev->pf, virtio_port->fdev->vf);
	if (unlikely(dma == NULL)) {
		AGIEP_LOG_ERR("%d %d dma create error", virtio_port->fdev->pf, virtio_port->fdev->vf);
		goto error;
	}
	vq->dma = dma;
	virtqueue_set_dma(vq, vq->dma);

	dirty_log = agiep_dirty_log_init(agiep_dirty_log_get(virtio_port->fdev->pf, virtio_port->fdev->vf));
	vq->dlog = dirty_log;

	vq->flags |= (VRING_F_CACHE_PREDICT);
	vq->notify_cb = agiep_vendor_notify;

	snprintf(name, sizeof(name), "txctxpl%d_%d_%lx",
			vendor_port->eth_dev->data->port_id, queue_idx, rte_rdtsc());
	tx->ctx_pool = rte_mempool_create(name, AGIEP_DP_POOL_SIZE(nb_desc),
		sizeof(struct virtnet_tx_ctx), AGIEP_DP_CACHE_SIZE(nb_desc), 0,
		NULL, NULL, vendor_net_tx_ctx_obj_init, tx, 0, 0);

	if (tx->ctx_pool == NULL) {
		AGIEP_LOG_ERR("rte_mempool_create tx->ctx_pool failed nb_desc:%u", nb_desc);
		goto error;
	}
	if (!tx->tx_ring) {
		snprintf(name, sizeof(name), "tx_ring%d_%d_%lx",
			 virtio_port->fdev->eth_dev->data->port_id, queue_idx, rte_rdtsc());
		tx->tx_ring = rte_ring_create(name, nb_desc, SOCKET_ID_ANY, 0);
		if (tx->tx_ring == NULL) {
			goto error;
		}
	}
	tx->ctx_map = rte_calloc(NULL, AGIEP_DP_POOL_SIZE(nb_desc), sizeof(void *), 0);
	if (unlikely(tx->ctx_map == NULL)) {
		AGIEP_LOG_ERR("pf %d vf %d ctx_map create failed %d",
			virtio_port->fdev->pf, virtio_port->fdev->vf, rte_errno);
		goto error;
	}

	vq->priv = virtio_port;
	tx->priv = virtio_port;
	memset(&tx->notify, 0, sizeof(tx->notify));
	tx->notify.irq_num_threshold = nb_desc / 2;
	tx->notify.irq_threshold = (rte_get_tsc_hz() + US_PER_S - 1 ) / US_PER_S * INTERRUPT_TSC_THRESHOLD;

	vq->msi_vector = AGIEP_MSI_NO_VECTOR;

	vendor_port->tx_vq[queue_idx] = vq;
	tx->bvq = vq;
	tx->vq = vq;
	vq->notify = 1;

	tx->fq.qid = queue_idx;
	tx->fq.dev = virtio_port->fdev;

	vq->cb_data = tx;
	vq->cb = vendor_net_tx_enable_handler;
	return 0;
error:
	if (vq)
		virtqueue_free(vq);
	if (dma)
		agiep_dma_free(dma, NULL, NULL);
	if (tx->ctx_map)
		rte_free(tx->ctx_map);
	if (tx->tx_ring)
		rte_ring_free(tx->tx_ring);

	if (tx->ctx_pool)
		rte_mempool_free(tx->ctx_pool);
	return -1;
}

static int
vendor_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
	uint16_t nb_desc, unsigned int socket __rte_unused,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
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
		return -ENOMEM;

	if (vendor_tx_setup(vendor_port, tx, virt_idx, nb_desc)){
		AGIEP_LOG_ERR("tx %d setup failed", queue_idx);
		goto error;
	}
	dev->data->tx_queues[queue_idx] = tx;
	return 0;
error:
	if (tx)
		rte_free(tx);

	return -1;
}

static struct virtnet_tx *vendor_tx_dup(struct virtnet_tx *tx)
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

static void vendor_tx_release(struct virtnet_tx *tx)
{
	struct virtnet_tx_ctx *ctx;
	int i;
	if (tx == NULL)
		return;

	virtqueue_free(tx->bvq);
	for (i = 0; i < AGIEP_DP_POOL_SIZE(tx->nb_desc); ++i) {
		ctx = tx->ctx_map[i];
		if (likely(ctx == NULL))
			continue;
		rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	}
	rte_free(tx->ctx_map);
	rte_mempool_free(tx->ctx_pool);
}

static void vendor_tx_queue_GC(void *data)
{
	struct virtnet_tx *tx = data;
	if (tx == NULL)
		return;
	vendor_tx_release(tx);
	rte_free(tx);
}

static void vendor_tx_queue_release(void *txq)
{
	struct rte_mbuf *pkts[32];
	struct rte_eth_dev *dev;
	struct agiep_virtio_port *virtio_port;
	struct agiep_vendor_port *vendor_port;
	struct virtnet_tx *tx = NULL;
	struct virtqueue *vq;
	uint avail;
	uint32_t i;

	if (!txq)
		return;

	tx = txq;

	vq = tx->vq;
	if (vq == NULL) {
		return;
	}
	tx->vq = NULL;
	agiep_virtio_tx_synchronize(tx);

	virtio_port = vq->priv;
	vendor_port = container_of(virtio_port, struct agiep_vendor_port, port);
	if (vendor_port == NULL) {
		return;
	}
	dev = vendor_port->eth_dev;

	dev->data->tx_queues[tx->id] = NULL;
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		if (dev->data->tx_queues[i] == tx)
			dev->data->tx_queues[i] = NULL;
	}
	do {
		i = rte_ring_dequeue_burst(tx->tx_ring, (void **) pkts, 32, &avail);
		if (i)
			rte_pktmbuf_free_bulk(pkts, i);
	} while (avail);

	rte_ring_free(tx->tx_ring);

	vendor_port->tx_vq[tx->id] = NULL;
	tx->fq.dev = NULL;
	
	if (vq->dma) {
		agiep_dma_free_syn(vq->dma, vendor_tx_queue_GC, tx);
	} else {
		vendor_tx_release(tx);
		rte_free(tx);
	}
}

static int vendor_tx_queue_reset(struct virtnet_tx *tx)
{
	struct rte_mbuf *pkts[32];
	struct agiep_virtio_port *virtio_port;
	struct agiep_vendor_port *vendor_port;
	struct virtqueue *vq;

	struct virtnet_tx *tx_dup;
	uint i;
	uint avail;
	uint16_t nb_desc;

	if (!tx)
		return -1;
	vq = tx->vq;
	if (!vq)
		return -1;
	virtio_port = vq->priv;
	vendor_port = container_of(virtio_port, struct agiep_vendor_port, port);
	
	if (vendor_port->tx_cfg[tx->id]->qsize) 
		nb_desc = vendor_port->tx_cfg[tx->id]->qsize;
	else
		nb_desc = vq->num;

	tx->vq = NULL;
	rte_mb();
	agiep_virtio_tx_synchronize(tx);

	do {
		if (!rte_ring_count(tx->tx_ring))
			break;
		i = rte_ring_dequeue_burst(tx->tx_ring, (void **) pkts, 32, &avail);
		if (i)
			rte_pktmbuf_free_bulk(pkts, i);
	} while (avail);

	if (vq->dma) {
		tx_dup = vendor_tx_dup(tx);
		agiep_dma_free_syn(vq->dma, vendor_tx_queue_GC, tx_dup);
	} else {
		vendor_tx_release(tx);
	}

	if (vendor_tx_setup(vendor_port, tx, tx->id, nb_desc)) {
		RTE_LOG(ERR, PMD, "tx %d queue reset error\n", tx->id);
		return -1;
	}
	return 0;
}

static int
vendor_dev_linkupdate(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
	struct rte_eth_link link;

	if (!vendor_port) {
		return 0;
	}
	memset(&link, 0, sizeof(link));
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_speed  = ETH_SPEED_NUM_10G;
	link.link_autoneg = ETH_LINK_FIXED;

	if (vendor_port->started) {
		link.link_status = ETH_LINK_UP;
	} else {
		link.link_status = ETH_LINK_DOWN;
	}
	return rte_eth_linkstatus_set(dev, &link);
}

static int vendor_dev_start(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;

	vendor_port->cfg->status |= VENDOR_CONFIG_S_DEVICE_OK;
	vendor_port->started = 1;
	vendor_port->cfg->net_status |= VENDOR_NET_S_LINK_UP;
	if (vendor_port->cfg->status & VENDOR_CONFIG_S_DRIVER_OK)
		vendor_port->enable = 1;
	return 0;
}

static void vendor_dev_stop(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
	struct rte_eth_link link;


	dev->data->dev_link.link_status = ETH_LINK_DOWN;
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
	if (vendor_port) {
		vendor_port->started = 0;
		vendor_port->cfg->net_status &= (~VENDOR_NET_S_LINK_UP);
	}
}

static void vendor_ctrl_queue_release(struct agiep_net_ctrl *ctrl)
{
	struct virtqueue *cvq;

	cvq = ctrl->cvq;
	ctrl->cvq = NULL;
	if (!cvq){
		rte_free(ctrl);
		return;
	}

	agiep_ctrl_synchronize(ctrl);
	agiep_dma_free_syn(cvq->dma, vendor_ctrl_GC, ctrl);
}

void vendor_dev_failed(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
	struct rte_eth_link link;
	if (!vendor_port) {
		memset(&link, 0, sizeof(link));
		rte_eth_linkstatus_set(dev, &link);
		return;
	}
	vendor_port->cfg->status &= (~VENDOR_CONFIG_S_DEVICE_OK);
}
static void vendor_dev_close(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port = fdev->dev;
	struct agiep_vendor_netdev *ndev;
	struct agiep_virtio_port *virtio_port;
	struct agiep_net_ctrl *ctrl;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;
	struct rte_eth_link link;
	int i;
	int vector;

	if (!vendor_port) {
		return;
	}
	virtio_port = &vendor_port->port;
	ndev = vendor_port->netdev;
	vendor_port->started = 0;
	vendor_port->enable = 0;
	agiep_port_addr_poller_unreg(vendor_port);
	vendor_port->cfg->status = 0;
	vendor_port->cfg->net_status = 0;
	pthread_mutex_lock(&vnlist_lock);
	TAILQ_REMOVE(&vendor_port_list, vendor_port, entry);
	agile_netdev_tab[fdev->pf][fdev->vf] = AGIEP_FREP_NUM;
	pthread_mutex_unlock(&vnlist_lock);
	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rx = dev->data->rx_queues[i];
		if (rx == NULL) {
			continue;
		}
		vendor_rx_queue_release(rx);

	}

	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		tx = dev->data->tx_queues[i];
		if (tx == NULL) {
			continue;
		}
		if (tx == dev->data->tx_queues[0] && i)
			break;
		vendor_tx_queue_release(tx);
	}
	if (!agiep_vendor_use_msix(ndev)) {
		vector = 0;
		while (vendor_port->vector_map){
			vector = __builtin_ffs(vendor_port->vector_map);
			if (vector)
				vector -= 1;
			else
				break;
			vendor_port->vector_map &= ~(1UL << vector);
			ndev->irq_addr[vector] = NULL;
			ndev->irq_data[vector] = UINT32_MAX;
		}
		pci_ep_free_irq_addr(ndev->ep, ndev->pf,
				     ndev->vf, PCI_EP_IRQ_MSI, vector);
	}
	ctrl = virtio_port->ctrl;
	if (ctrl) {
		vendor_ctrl_queue_release(ctrl);
		virtio_port->ctrl = NULL;
	}
	rte_free(vendor_port->rx_vq);
	rte_free(vendor_port->rx_cfg);

	agiep_vendor_netdev_put(vendor_port->netdev);
	agiep_dirty_log_release(fdev->pf, fdev->vf);
	fdev->dev = NULL;
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
}

int vendor_dev_disable(struct rte_eth_dev *dev)
{
	int i;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;
	struct rte_eth_link link;
	uint16_t qnum = dev->data->nb_rx_queues;

	vendor_port = fdev->dev;
	
	vendor_port->enable = 0;
	rte_mb();
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
	for (i = 0; i < qnum; ++i) {
		rx = dev->data->rx_queues[i];
		if (rx && rx->vq) {
			agiep_virtio_rx_synchronize(rx);
			virtqueue_flush_synchronize(rx->vq);
			if (rx->vq->dma)
				agiep_dma_synchronize(rx->vq->dma);
		}
	}
	for (i = 0; i < qnum; ++i) {
		tx = dev->data->tx_queues[i];
		if (tx && tx->vq) {
			agiep_virtio_tx_synchronize(tx);
			virtqueue_flush_synchronize(tx->vq);
			if (tx->vq->dma)
				agiep_dma_synchronize(tx->vq->dma);
		} 
	}
	if (vendor_port->port.ctrl->cvq) {
		agiep_ctrl_synchronize(vendor_port->port.ctrl);
		virtqueue_flush_synchronize(vendor_port->port.ctrl->cvq);
		if (vendor_port->port.ctrl->cvq->dma)
			agiep_dma_synchronize(vendor_port->port.ctrl->cvq->dma);
	}

	vendor_port->cfg->status &= ~VENDOR_CONFIG_S_DISABLE;
	dev->data->dev_link.link_status = ETH_LINK_DOWN;
	return 0;
}

int vendor_dev_softreset(struct rte_eth_dev *dev)
{
	int i;
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vport;
	struct agiep_vendor_netdev *ndev;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;
	uint16_t nb_desc;
	uint16_t qnum;
	uint16_t vector;

	vport = fdev->dev;

	if (!vport->started) {
		goto error;
	}
	if (vport->reseted)
		goto reseted;
	ndev = vport->netdev;
	qnum = dev->data->nb_rx_queues;
	agiep_dirty_log_synchronize(agiep_dirty_log_get(fdev->pf, fdev->vf));
	vport->started = 0;
	vport->enable = 0;
	vport->cfg->qnum = qnum;
	vport->port.fdev->used_queues = qnum;
	vport->dirty_log_cfg->dlog_size = 0;

	memset(&vport->cq_cfg->queue_desc_lo, 0, sizeof(uint64_t) * 3);
	vport->cq_cfg->msi_vector = AGIEP_MSI_NO_VECTOR;
	vport->cq_cfg->doorbell = 0;
	vport->cfg->feature = VENDOR_FEATURES;
	dev->data->dev_link.link_status = ETH_LINK_DOWN;

	if (fdev->packed)
		vport->cfg->feature |= (1ULL << VIRTIO_F_RING_PACKED);

	if (fdev->hw_checksum)
		vport->cfg->feature |= (1ULL << VIRTIO_NET_F_CSUM) | (1ULL << VIRTIO_NET_F_GUEST_CSUM);
	
	for (i = 0; i < qnum; ++i) {
		rx = dev->data->rx_queues[i];
		if (vendor_rx_queue_reset(rx)) {
			AGIEP_LOG_ERR("%s vendor_rx_queue_reset failed pf %d vf %d", __FUNCTION__, fdev->pf, fdev->vf);
			goto error;
		}
	}
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		tx = dev->data->tx_queues[i];
		if (tx == dev->data->tx_queues[0] && i)
			break;
		if (vendor_tx_queue_reset(tx)) {
			AGIEP_LOG_ERR("%s vendor_tx_queue_reset failed pf %d vf %d", __FUNCTION__, fdev->pf, fdev->vf);
			goto error;
		}
	}

	for (i = 0; i < qnum; i++) {
		memset(&vport->rx_cfg[i]->queue_desc_lo, 0, sizeof(uint64_t) * 3);
		vport->rx_cfg[i]->msi_vector = AGIEP_MSI_NO_VECTOR;
		vport->rx_cfg[i]->doorbell = 0;
		vport->rx_cfg[i]->last_avail_idx = 0;
		vport->rx_cfg[i]->last_used_idx = 0;
		vport->rx_cfg[i]->get_last = 0;
	}

	for (i = 0; i < qnum; i++) {
		memset(&vport->tx_cfg[i]->queue_desc_lo, 0, sizeof(uint64_t) * 3);
		vport->tx_cfg[i]->msi_vector = AGIEP_MSI_NO_VECTOR;
		vport->tx_cfg[i]->doorbell = 0;
		vport->tx_cfg[i]->last_avail_idx = 0;
		vport->tx_cfg[i]->last_used_idx = 0;
		vport->tx_cfg[i]->get_last = 0;
	}
	if (!agiep_vendor_use_msix(ndev)) {
		vector = 0;
		while (vport->vector_map){
			vector = __builtin_ffs(vport->vector_map);
			if (vector)
				vector -= 1;
			else
				break;
			vport->vector_map &= ~(1UL << vector);
			ndev->irq_addr[vector] = NULL;
			ndev->irq_data[vector] = UINT32_MAX;
		}
		pci_ep_free_irq_addr(ndev->ep, ndev->pf,
				     ndev->vf, PCI_EP_IRQ_MSI, vector);
	}

	nb_desc = vport->port.ctrl->cvq->num;
	if (vendor_net_ctrl_reset(dev, vport, nb_desc)) {
		AGIEP_LOG_ERR("vendor_net_ctrl_reset failed pf %d vf %d", fdev->pf, fdev->vf);
		goto error;
	}
	agiep_port_addr_poller_reset(vport);
	memset(vport->doorbell, 0, sizeof(vport->doorbell));
	vport->started = 1;
	vport->reseted = 1;
reseted:
	vport->cfg->status = VENDOR_CONFIG_S_DEVICE_OK;
	AGIEP_LOG_WARN("driver notify framwork reset pf %d vf %d", fdev->pf, fdev->vf);
	return 0;
error:
	vport->cfg->status &= ~VENDOR_CONFIG_S_DEVICE_OK;
	vport->reseted = 0;
	return -1;
}

int vendor_rx_softreset(struct agiep_vendor_port *port, int id, int num)
{
	struct virtnet_rx *rx ;

	if (!port->started)
		return -1;
	port->started = 0;
	port->enable = 0;
	struct virtqueue *vq;
	vq = port->rx_vq[id];
	if (!vq)
		return -1;
	vq->num = num;

	rx = port->eth_dev->data->rx_queues[id];
	if (vendor_rx_queue_reset(rx)) {
		return -1;
	}

	port->started = 1;
	if (port->cfg->status & VENDOR_CONFIG_S_DRIVER_OK)
		port->enable = 1;
	return 0;
}

int vendor_tx_softreset(struct agiep_vendor_port *port, int id, int num)
{
	struct virtnet_tx *tx ;

	if (!port->started)
		return -1;
	port->started = 0;
	port->enable = 0;
	struct virtqueue *vq;
	vq = port->tx_vq[id];
	if (!vq)
		return -1;
	vq->num = num;

	tx = port->eth_dev->data->tx_queues[id];
	if (vendor_tx_queue_reset(tx)){
		return -1;
	}

	port->started = 1;
	if (port->cfg->status & VENDOR_CONFIG_S_DRIVER_OK)
		port->enable = 1;
	return 0;
}

int vendor_cq_softreset(struct agiep_vendor_port *port, int num)
{
	if (!port->started)
		return -1;
	port->started = 0;
	port->enable = 0;

	if (vendor_net_ctrl_reset(port->eth_dev, port, num)) {
		return -1;
	}

	port->started = 1;
	if (port->cfg->status & VENDOR_CONFIG_S_DRIVER_OK)
		port->enable = 1;
	return 0;
}

static int vendor_dev_info_get(struct rte_eth_dev *dev __rte_unused,
			struct rte_eth_dev_info *dev_info)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	dev_info->max_rx_queues = (uint16_t)fdev->queues;
	dev_info->max_tx_queues = (uint16_t)fdev->queues;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;

	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_CHECKSUM;
	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM;

	return 0;
}

static int vendor_dev_promiscuous_enable(struct rte_eth_dev *dev) 
{
	dev->data->promiscuous = 1;
	return 0;
}
static int vendor_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	dev->data->promiscuous = 0;
	return 0;
}

static void
vendor_update_stats(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
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


static int vendor_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	vendor_update_stats(dev, stats);
	return 0;
}

static int
vendor_dev_stats_reset(struct rte_eth_dev *dev)
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

static int vendor_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	dev->data->mtu = mtu;
	return 0;
}

uint64_t agiep_vendor_irq_addr(struct agiep_vendor_netdev *dev, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;
	if (agiep_vendor_use_msix(dev)) {
		irq_type = PCI_EP_IRQ_MSIX;
	}
	if (dev->irq_addr[vector] == NULL)
		dev->irq_addr[vector] = (void *)pci_ep_get_irq_addr(dev->ep,
				dev->pf, dev->vf, irq_type, vector);
	return (uint64_t)dev->irq_addr[vector];
}

uint32_t agiep_vendor_irq_data(struct agiep_vendor_netdev *dev, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;
	if (agiep_vendor_use_msix(dev)) {
		irq_type = PCI_EP_IRQ_MSIX;
	}
	if (dev->irq_data[vector] == 0xFFFFFFFF)
		dev->irq_data[vector] = pci_ep_get_irq_data(dev->ep, 
				dev->pf, dev->vf, irq_type, vector);
	return dev->irq_data[vector];
}

void agiep_vendor_irq_raise(struct agiep_vendor_netdev *dev, uint16_t vector)
{
	uint64_t addr = agiep_vendor_irq_addr(dev, vector);
	uint32_t data = agiep_vendor_irq_data(dev, vector);
	if (addr == 0)
		return;
	rte_write32(data, (void *)addr);
}

inline void agiep_vendor_reset_vector(struct agiep_vendor_netdev *dev, uint16_t vector)
{
	dev->irq_addr[vector] = NULL;
	dev->irq_data[vector] = 0xFFFFFFFF;
}

int agiep_dev_fall_to_split(struct rte_eth_dev *dev)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vport;
	struct virtnet_rx *rx;
	struct virtnet_tx *tx;
	int qidx;
	uint16_t nb_desc;

	vport = fdev->dev;
	if (!vport->started) {
		return 0;
	}

	if (!fdev->packed) {
		return 0;
	}

	if ((1ULL << VIRTIO_F_RING_PACKED) & vport->cfg->feature) {
		return 0;
	}

	vport->started = 0;
	vport->enable = 0;

	for (qidx = 0; qidx < dev->data->nb_rx_queues; ++qidx) {
		rx = dev->data->rx_queues[qidx];
		if (vendor_rx_queue_reset(rx)) {
			AGIEP_LOG_ERR("%s vendor_rx_queue_reset failed pf %d vf %d", 
				__FUNCTION__, fdev->pf, fdev->vf);
			goto error;
		}
	}

	for (qidx = 0; qidx < dev->data->nb_tx_queues; ++qidx) {
		tx = dev->data->tx_queues[qidx];
		if (tx == dev->data->tx_queues[0] && qidx) {
			break;
		}
		if (vendor_tx_queue_reset(tx)) {
			AGIEP_LOG_ERR("%s vendor_tx_queue_reset failed pf %d vf %d", 
				__FUNCTION__, fdev->pf, fdev->vf);
			goto error;
		}
	}

	nb_desc = vport->port.ctrl->cvq->num;
	if (vendor_net_ctrl_reset(dev, vport, nb_desc)) {
		AGIEP_LOG_ERR("%s vendor_net_ctrl_reset failed pf %d vf %d", 
			__FUNCTION__, fdev->pf, fdev->vf);
		goto error;
	}

	vport->started = 1;
	if (vport->cfg->status & VENDOR_CONFIG_S_DRIVER_OK) {
		vport->enable = 1;
	}

	return 0;
error:
	return -1;
}

static struct eth_dev_ops vendor_net_ops = {
	.dev_configure = vendor_net_configure,
	.rx_queue_setup = vendor_rx_queue_setup,
	.rx_queue_release = vendor_rx_queue_release,
	.tx_queue_setup = vendor_tx_queue_setup,
	.tx_queue_release = vendor_tx_queue_release,
	.dev_start = vendor_dev_start,
	.dev_stop = vendor_dev_stop,
	.dev_close = vendor_dev_close,
	.dev_infos_get = vendor_dev_info_get,
	.link_update = vendor_dev_linkupdate,
	.promiscuous_enable = vendor_dev_promiscuous_enable,
	.promiscuous_disable = vendor_dev_promiscuous_disable,
	.stats_get = vendor_dev_stats_get,
	.stats_reset = vendor_dev_stats_reset,
	.mtu_set = vendor_dev_mtu_set,
};

static struct agiep_frep vendor_net_frep = {
	.ops = &vendor_net_ops,
	.rx_pkt_burst = agiep_virtio_rx_pkt_burst,
	.tx_pkt_burst = agiep_virtio_tx_xmit,
	.type = AGIEP_FREP_VENDOR,
};

RTE_INIT(agiep_vendor_net_init)
{
	agiep_frep_register(&vendor_net_frep);
}
