#include <assert.h>
#include <rte_malloc.h>

#include "agiep_reg_poller.h"
#include "agiep_vendor_ctrl.h"
#include "agiep_ctrl.h"
#include "agiep_vendor_port.h"
#include "agiep_virtio_legacy.h"
#include "agiep_virtio_rxtx.h"
#include "agiep_vring_split_predict.h"
#include "agiep_vring_split.h"
#include "agiep_mng.h"

static int agiep_vendor_poller_regist_batch(struct agiep_poller *pollers, int poller_num)
{
	int ret;
	ret = agiep_reg_poller_send_reg_batch(pollers, poller_num);
	if (ret)
		goto error;
	return 0;
error:
	rte_free(pollers);
	return -1;
}

static void agiep_vendor_poller_unreg_batch(struct agiep_poller *pollers, int poller_num)
{
	int ret;
	ret = agiep_reg_poller_send_unreg_batch(pollers, poller_num);
	if (ret) {
		RTE_LOG(ERR, PMD, "unexpect unreg poller error\n");
		rte_free(pollers);
	}
}

static void agiep_vendor_handle_rx_addr(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	struct virtqueue *vq;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	int idx;

	if (!port->started) {
		return;
	}
	port->reseted = 0;
	idx = ((size_t)((char*)poller->addr - (char*)port->rx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);

	desc = port->rx_cfg[idx]->queue_desc_hi;
	desc = port->rx_cfg[idx]->queue_desc_lo | desc << 32;
	
	avail = port->rx_cfg[idx]->queue_avail_hi;
	avail = port->rx_cfg[idx]->queue_avail_lo | avail << 32;

	used = port->rx_cfg[idx]->queue_used_hi;
	used = port->rx_cfg[idx]->queue_used_lo | used << 32;

	vq = port->rx_vq[idx];
	if (!vq) {
		return;
	}

	if (port->cfg->feature & (1ULL << VIRTIO_F_IN_ORDER)) {
		virtqueue_set_predict_mode(port->rx_vq[idx], VRING_F_RING_PREDICT);
	}
	virtqueue_set_addr(vq, avail, used, desc);
}

static void agiep_vendor_handle_tx_addr(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	struct virtqueue *vq;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	int idx;

	if (!port->started) {
		return;
	}
	port->reseted = 0;
	idx = ((size_t)((char*)poller->addr - (char*)port->tx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);
	desc = port->tx_cfg[idx]->queue_desc_hi;
	desc = port->tx_cfg[idx]->queue_desc_lo | desc << 32;

	avail = port->tx_cfg[idx]->queue_avail_hi;
	avail = port->tx_cfg[idx]->queue_avail_lo | avail << 32;

	used = port->tx_cfg[idx]->queue_used_hi;
	used = port->tx_cfg[idx]->queue_used_lo | used << 32;
		
	vq = port->tx_vq[idx];
	if (!vq) {
		return;
	}

	if (port->cfg->feature & (1ULL << VIRTIO_F_IN_ORDER)) {
		virtqueue_set_predict_mode(port->tx_vq[idx], VRING_F_RING_PREDICT);
	}
	virtqueue_set_addr(vq, avail, used, desc);
}

static void agiep_vendor_handle_cq_addr(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	struct virtqueue *vq;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;

	if (!port->started) {
		return;
	}
	port->reseted = 0;
	desc = port->cq_cfg->queue_desc_hi;
	desc = port->cq_cfg->queue_desc_lo | desc << 32;

	avail = port->cq_cfg->queue_avail_hi;
	avail = port->cq_cfg->queue_avail_lo | avail << 32;

	used = port->cq_cfg->queue_used_hi;
	used = port->cq_cfg->queue_used_lo | used << 32;
	vq = port->port.ctrl->cvq;
	if (vq)
		virtqueue_set_addr(vq, avail, used, desc);
}

static void agiep_vendor_handle_rx_last(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->rx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);

	vq = port->rx_vq[idx];

	if (vq) {
		virtqueue_set_last_avail(vq, port->rx_cfg[idx]->last_avail_idx);
		virtqueue_set_last_used(vq, port->rx_cfg[idx]->last_used_idx);
		((struct virtnet_rx *)vq->cb_data)->elem_id = port->rx_cfg[idx]->last_used_idx % vq->num;
	}
}

static void agiep_vendor_handle_tx_last(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->tx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);

	vq = port->tx_vq[idx];

	if (vq) {
		virtqueue_set_last_avail(vq, port->tx_cfg[idx]->last_avail_idx);
		virtqueue_set_last_used(vq, port->tx_cfg[idx]->last_used_idx);
	}
}

static void agiep_vendor_handle_rx_qsize(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	int predict_mode;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	uint16_t vector;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	struct virtqueue *vq;
	if (!port->started)
		return;
	port->reseted = 0;
	idx = ((size_t)((char*)poller->addr - (char*)port->rx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);

	vq = port->rx_vq[idx];
	if (!vq) {
		return;
	}
	vector = vq->msi_vector;

	int num = 0;
	num = poller->prev;
	if (num) {
		predict_mode = virtqueue_get_predict_mode(vq);
		last_avail_idx = virtqueue_get_last_avail(vq);
		last_used_idx = virtqueue_get_last_used(vq);

		if (vendor_rx_softreset(port, idx, num)) {
			vendor_dev_failed(port->eth_dev);
			AGIEP_LOG_ERR("%s failed pf:%d vf:%d", __FUNCTION__, port->netdev->pf, port->netdev->vf);
			return;
		}

		vq = port->rx_vq[idx];
		virtqueue_set_predict_mode(vq, predict_mode);
		virtqueue_set_last_avail(vq, last_avail_idx);
		virtqueue_set_last_used(vq, last_used_idx);
		((struct virtnet_rx *)vq->cb_data)->elem_id = last_used_idx % vq->num;

		desc = port->rx_cfg[idx]->queue_desc_hi;
		desc = port->rx_cfg[idx]->queue_desc_lo | desc << 32;

		avail = port->rx_cfg[idx]->queue_desc_hi;
		avail = port->rx_cfg[idx]->queue_avail_lo | avail << 32;

		used = port->rx_cfg[idx]->queue_used_hi;
		used = port->rx_cfg[idx]->queue_used_lo | used << 32;
		vq->msi_vector = vector;
		virtqueue_set_addr(vq, avail, used, desc);
	}
}

static void agiep_vendor_handle_tx_qsize(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	int predict_mode;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	uint16_t vector;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	struct virtqueue *vq;
	if (!port->started)
		return;
	port->reseted = 0;
	idx = ((size_t)((char*)poller->addr - (char*)port->tx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);

	vq = port->tx_vq[idx];
	if (!vq){
		return;
	}
	vector = vq->msi_vector;

	int num = 0;
	num = poller->prev;
	if (num) {
		predict_mode = virtqueue_get_predict_mode(vq);
		last_avail_idx = virtqueue_get_last_avail(vq);
		last_used_idx = virtqueue_get_last_used(vq);

		if (vendor_tx_softreset(port, idx, num)) {
			vendor_dev_failed(port->eth_dev);
			AGIEP_LOG_ERR("%s failed pf:%d vf:%d", __FUNCTION__, port->netdev->pf, port->netdev->vf);
			return;
		}

		vq = port->tx_vq[idx];
		virtqueue_set_predict_mode(vq, predict_mode);
		virtqueue_set_last_avail(vq, last_avail_idx);
		virtqueue_set_last_used(vq, last_used_idx);

		desc = port->tx_cfg[idx]->queue_desc_hi;
		desc = port->tx_cfg[idx]->queue_desc_lo | desc << 32;

		avail = port->tx_cfg[idx]->queue_desc_hi;
		avail = port->tx_cfg[idx]->queue_avail_lo | avail << 32;

		used = port->tx_cfg[idx]->queue_used_hi;
		used = port->tx_cfg[idx]->queue_used_lo | used << 32;
		vq->msi_vector = vector;
		virtqueue_set_addr(vq, avail, used, desc);
	}
}

static void agiep_vendor_handle_cq_qsize(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int predict_mode;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	int num;
	struct virtqueue *cvq;
	struct agiep_net_ctrl *ctrl;

	if (!port->started) {
		return;
	}
	port->reseted = 0;
	ctrl = port->port.ctrl;

	if (!ctrl)
		return;

	cvq = ctrl->cvq;
	if (!cvq){
		return;
	}

	num = poller->prev;
	if (num) {
		predict_mode = virtqueue_get_predict_mode(cvq);
		if (vendor_cq_softreset(port, num) ) {
			vendor_dev_failed(port->eth_dev);
			AGIEP_LOG_ERR("%s failed", __FUNCTION__);
			return;
		}
		cvq = port->port.ctrl->cvq;
		virtqueue_set_predict_mode(cvq, predict_mode);

		desc = port->cq_cfg->queue_desc_hi;
		desc = port->cq_cfg->queue_desc_lo | desc << 32;

		avail = port->cq_cfg->queue_desc_hi;
		avail = port->cq_cfg->queue_avail_lo | avail << 32;

		used = port->cq_cfg->queue_used_hi;
		used = port->cq_cfg->queue_used_lo | used << 32;
		virtqueue_set_addr(cvq, avail, used, desc);
	}
}

static void agiep_vendor_handle_cq_last(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	struct virtqueue *cvq;
	if (!port->started)
		return;

	cvq = port->port.ctrl->cvq;
	assert(cvq != NULL);
}

static void agiep_vendor_handle_rxmsi(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	uint64_t addr;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->rx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);
	vq = port->rx_vq[idx];
	if (vq) {
		vq->msi_vector = port->rx_cfg[idx]->msi_vector;
		if (vq->msi_vector != AGIEP_MSI_NO_VECTOR) {
			port->vector_map |= (1UL << vq->msi_vector);
			addr = agiep_vendor_irq_addr(port->netdev, vq->msi_vector);
			agiep_vendor_irq_data(port->netdev, vq->msi_vector);
			if (addr == 0)
				AGIEP_LOG_INFO("%s agiep_vendor_irq_addr failed", __FUNCTION__);
		}
	}
}

static void agiep_vendor_handle_txmsi(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	uint64_t addr;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->tx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);
	vq = port->tx_vq[idx];
	if (vq) {
		vq->msi_vector = port->tx_cfg[idx]->msi_vector;
		if (vq->msi_vector != AGIEP_MSI_NO_VECTOR) {
			port->vector_map |= (1UL << vq->msi_vector);
			addr = agiep_vendor_irq_addr(port->netdev, vq->msi_vector);
			agiep_vendor_irq_data(port->netdev, vq->msi_vector);
			if (addr == 0)
				AGIEP_LOG_INFO("%s agiep_vendor_irq_addr failed", __FUNCTION__);
		}
	}
}

static void agiep_vendor_handle_rx_get_last(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->rx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);
	vq = port->rx_vq[idx];
	if (vq && port->rx_cfg[idx]->get_last) {
		port->rx_cfg[idx]->last_avail_idx = virtqueue_get_last_avail(vq);
		port->rx_cfg[idx]->last_used_idx = virtqueue_get_last_used(vq);
		rte_wmb();
		port->rx_cfg[idx]->get_last = 0;
	}
}

static void agiep_vendor_handle_tx_get_last(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	int idx;
	struct virtqueue *vq;
	if (!port->started)
		return;

	idx = ((size_t)((char*)poller->addr - (char*)port->tx_cfg[0])) /
		sizeof(struct agiep_vendor_queue_cfg);
	vq = port->tx_vq[idx];
	if (vq && port->tx_cfg[idx]->get_last) {
		port->tx_cfg[idx]->last_avail_idx = virtqueue_get_last_avail(vq);
		port->tx_cfg[idx]->last_used_idx = virtqueue_get_last_used(vq);
		rte_wmb();
		port->tx_cfg[idx]->get_last = 0;
	}
}

static void agiep_vendor_handle_status(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	port->cfg->status = poller->prev;
	vendor_net_handle_pci_status(port);
}

static void agiep_vendor_handle_feature(struct agiep_poller *poller)
{
	struct agiep_vendor_port *port = poller->priv;
	if (!port->started)
		return;
	port->cfg->feature = poller->prev;
	if(agiep_dev_fall_to_split(port->eth_dev)) {
		vendor_dev_failed(port->eth_dev);
		AGIEP_LOG_ERR("%s failed pf:%d vf:%d", __FUNCTION__, port->netdev->pf, port->netdev->vf);
	}
}

static void agiep_vendor_handle_qnum(struct agiep_poller *poller __rte_unused)
{
	struct agiep_vendor_port *vendor_port = poller->priv;
	if (!vendor_port->started)
		return;
	vendor_port->port.fdev->used_queues = poller->prev;
}

static void agiep_vendor_handle_dlog_size(struct agiep_poller *poller)
{
	struct agiep_vendor_port *vendor_port = poller->priv;
	uint64_t dlog_base;
	uint32_t dlog_size = poller->prev;
	if (!vendor_port->started)
		return;
	if (dlog_size > 0) {
		dlog_base = vendor_port->dirty_log_cfg->dlog_base_hi;
		dlog_base = vendor_port->dirty_log_cfg->dlog_base_lo | 
			dlog_base << 32;
		if (agiep_dirty_log_enable(vendor_port->port.fdev->pf, vendor_port->port.fdev->vf, dlog_base, dlog_size))
			AGIEP_LOG_ERR("agiep_dirty_log_enable failed");
	} else {
		agiep_dirty_log_disable(vendor_port->port.fdev->pf, vendor_port->port.fdev->vf);
		vendor_port->dirty_log_cfg->dlog_base_hi = 0;
		vendor_port->dirty_log_cfg->dlog_base_lo = 0;
	}
}

static void agiep_vendor_handle_mng_ip(struct agiep_poller *poller)
{
	struct agiep_vendor_port *vendor_port = poller->priv;
	uint32_t mng_ip;
	uint32_t netmask;
	if (!vendor_port->started)
		return;
	if (vendor_port->netdev->pf == 0 && vendor_port->netdev->vf == 0) {
		mng_ip = poller->prev;
		netmask = vendor_port->mng_cfg->netmask;
		agiep_mng_set_mng_addr(mng_ip, netmask);
	}
}
static void agiep_vendor_handle_mng_netmask(struct agiep_poller *poller)
{
	struct agiep_vendor_port *vendor_port = poller->priv;
	uint32_t mng_ip;
	uint32_t netmask;
	if (!vendor_port->started)
		return;
	if (vendor_port->netdev->pf == 0 && vendor_port->netdev->vf == 0) {
		mng_ip = vendor_port->mng_cfg->address;
		netmask = poller->prev;
		agiep_mng_set_mng_addr(mng_ip, netmask);
	}
}

struct agiep_vendor_poller_elem {
	int bits;
	size_t offset;
	poller_intr_callback intr;
};

struct agiep_vendor_poller_elem vendor_poller_rx_elems[] = {
	{32, offsetof(struct agiep_vendor_rx_cfg, queue_used_lo), agiep_vendor_handle_rx_addr},
	{16, offsetof(struct agiep_vendor_rx_cfg, msi_vector), agiep_vendor_handle_rxmsi},
	{16, offsetof(struct agiep_vendor_rx_cfg, last_used_idx), agiep_vendor_handle_rx_last},
	{32, offsetof(struct agiep_vendor_rx_cfg, qsize), agiep_vendor_handle_rx_qsize},
	{16, offsetof(struct agiep_vendor_rx_cfg, get_last), agiep_vendor_handle_rx_get_last},
};

struct agiep_vendor_poller_elem vendor_poller_tx_elems[] = {
	{32, offsetof(struct agiep_vendor_tx_cfg, queue_used_lo), agiep_vendor_handle_tx_addr},
	{16, offsetof(struct agiep_vendor_tx_cfg, msi_vector), agiep_vendor_handle_txmsi},
	{16, offsetof(struct agiep_vendor_tx_cfg, last_used_idx), agiep_vendor_handle_tx_last},
	{32, offsetof(struct agiep_vendor_tx_cfg, qsize), agiep_vendor_handle_tx_qsize},
	{16, offsetof(struct agiep_vendor_tx_cfg, get_last), agiep_vendor_handle_tx_get_last},
};

struct agiep_vendor_poller_elem vendor_poller_cq_elems[] = {
	{32, offsetof(struct agiep_vendor_cq_cfg, queue_used_lo), agiep_vendor_handle_cq_addr},
	{16, offsetof(struct agiep_vendor_cq_cfg, last_used_idx), agiep_vendor_handle_cq_last},
	{32, offsetof(struct agiep_vendor_cq_cfg, qsize), agiep_vendor_handle_cq_qsize},
};

struct agiep_vendor_poller_elem vendor_poller_port_elems[] = {
	{16, offsetof(struct agiep_vendor_port_cfg, status), agiep_vendor_handle_status},
	{64, offsetof(struct agiep_vendor_port_cfg, feature), agiep_vendor_handle_feature},
	{16, offsetof(struct agiep_vendor_port_cfg, qnum), agiep_vendor_handle_qnum},
};

struct agiep_vendor_poller_elem vendor_poller_dirtylog_elems[] = {
	{32, offsetof(struct agiep_vendor_dirty_log_cfg, dlog_size), agiep_vendor_handle_dlog_size},
};

struct agiep_vendor_poller_elem vendor_poller_mng_elems[] = {
	{32, offsetof(struct agiep_vendor_mng_cfg, address), agiep_vendor_handle_mng_ip},
	{32, offsetof(struct agiep_vendor_mng_cfg, netmask), agiep_vendor_handle_mng_netmask},
};

#define VENDOR_RX_CFG_POLLER_COUNT (sizeof(vendor_poller_rx_elems)/sizeof(struct agiep_vendor_poller_elem))
#define VENDOR_TX_CFG_POLLER_COUNT (sizeof(vendor_poller_tx_elems)/sizeof(struct agiep_vendor_poller_elem))
#define VENDOR_CQ_CFG_POLLER_COUNT (sizeof(vendor_poller_cq_elems)/sizeof(struct agiep_vendor_poller_elem))
#define VENDOR_PORT_CFG_POLLER_COUNT (sizeof(vendor_poller_port_elems)/sizeof(struct agiep_vendor_poller_elem))
#define VENDOR_DIRTY_CFG_POLLER_COUNT (sizeof(vendor_poller_dirtylog_elems)/sizeof(struct agiep_vendor_poller_elem))
#define VENDOR_MNG_CFG_POLLER_COUNT (sizeof(vendor_poller_mng_elems)/sizeof(struct agiep_vendor_poller_elem))

static void agiep_vendor_queue_poller_init(struct agiep_vendor_port *port, struct agiep_poller *pollers)
{
	int poller_index;
	uint16_t qnum;
	int queue_index;
	int elems;
	int elem_index;

	qnum = port->port.fdev->eth_dev->data->nb_rx_queues;
	elems = sizeof(vendor_poller_rx_elems)/sizeof(struct agiep_vendor_poller_elem);
	poller_index = 0;
	for (elem_index = 0; elem_index < elems; elem_index++) {
		for (queue_index = 0; queue_index < qnum; poller_index++, queue_index++) {
			pollers[poller_index].bits = vendor_poller_rx_elems[elem_index].bits;
			pollers[poller_index].addr = RTE_PTR_ADD(port->rx_cfg[queue_index], vendor_poller_rx_elems[elem_index].offset);
			pollers[poller_index].priv = port;
			pollers[poller_index].intr = vendor_poller_rx_elems[elem_index].intr;
		}
	}

	elems = sizeof(vendor_poller_tx_elems)/sizeof(struct agiep_vendor_poller_elem);
	for (elem_index = 0; elem_index < elems; elem_index++) {
		for (queue_index = 0; queue_index < qnum; poller_index++, queue_index++) {
			pollers[poller_index].bits = vendor_poller_tx_elems[elem_index].bits;
			pollers[poller_index].addr = RTE_PTR_ADD(port->tx_cfg[queue_index], vendor_poller_tx_elems[elem_index].offset);
			pollers[poller_index].priv = port;
			pollers[poller_index].intr = vendor_poller_tx_elems[elem_index].intr;
		}
	}

	elems = sizeof(vendor_poller_cq_elems)/sizeof(struct agiep_vendor_poller_elem);
	for (elem_index = 0; elem_index < elems; elem_index++, poller_index++) {
		pollers[poller_index].bits = vendor_poller_cq_elems[elem_index].bits;
		pollers[poller_index].addr = RTE_PTR_ADD(port->cq_cfg, vendor_poller_cq_elems[elem_index].offset);
		pollers[poller_index].priv = port;
		pollers[poller_index].intr = vendor_poller_cq_elems[elem_index].intr;
	}

	elems = sizeof(vendor_poller_port_elems)/sizeof(struct agiep_vendor_poller_elem);
	for (elem_index = 0; elem_index < elems; elem_index++, poller_index++) {
		pollers[poller_index].bits = vendor_poller_port_elems[elem_index].bits;
		pollers[poller_index].addr = RTE_PTR_ADD(port->cfg, vendor_poller_port_elems[elem_index].offset);
		pollers[poller_index].priv = port;
		pollers[poller_index].intr = vendor_poller_port_elems[elem_index].intr;
	}

	elems = sizeof(vendor_poller_dirtylog_elems)/sizeof(struct agiep_vendor_poller_elem);
	for (elem_index = 0; elem_index < elems; elem_index++, poller_index++) {
		pollers[poller_index].bits = vendor_poller_dirtylog_elems[elem_index].bits;
		pollers[poller_index].addr = RTE_PTR_ADD(port->dirty_log_cfg, vendor_poller_dirtylog_elems[elem_index].offset);
		pollers[poller_index].priv = port;
		pollers[poller_index].intr = vendor_poller_dirtylog_elems[elem_index].intr;
	}

	if (port->netdev->pf == 0 && port->netdev->vf == 0) {
		elems = sizeof(vendor_poller_mng_elems)/sizeof(struct agiep_vendor_poller_elem);
		for (elem_index = 0; elem_index < elems; elem_index++, poller_index++) {
			pollers[poller_index].bits = vendor_poller_mng_elems[elem_index].bits;
			pollers[poller_index].addr = RTE_PTR_ADD(port->mng_cfg, vendor_poller_mng_elems[elem_index].offset);
			pollers[poller_index].priv = port;
			pollers[poller_index].intr = vendor_poller_mng_elems[elem_index].intr;
		}
	}
}

int agiep_port_addr_poller_reg(struct agiep_vendor_port *port)
{
	int i;
	struct agiep_poller *pollers;
	int poller_num;
	uint16_t qnum = port->port.fdev->eth_dev->data->nb_rx_queues;

	// queue poller number
	poller_num = qnum * (VENDOR_RX_CFG_POLLER_COUNT + VENDOR_TX_CFG_POLLER_COUNT) + 
			(VENDOR_CQ_CFG_POLLER_COUNT + VENDOR_PORT_CFG_POLLER_COUNT + VENDOR_DIRTY_CFG_POLLER_COUNT);
	
	if (port->netdev->pf == 0 && port->netdev->vf == 0) {
		poller_num += VENDOR_MNG_CFG_POLLER_COUNT;
	}

	pollers = rte_calloc(NULL, poller_num, sizeof(struct agiep_poller), 0);

	if (pollers == NULL) {
		AGIEP_LOG_INFO("%s calloc failed", __FUNCTION__);
		return -1;
	}
	for (i = 0; i < poller_num; i++) {
		pollers[i].expand_id = -1;
	}

	agiep_vendor_queue_poller_init(port, pollers);

	port->reg_pollers = pollers;
	port->poller_num = poller_num;

	return agiep_vendor_poller_regist_batch(pollers, poller_num);
}

void agiep_port_addr_poller_unreg(struct agiep_vendor_port *port)
{
	return agiep_vendor_poller_unreg_batch(port->reg_pollers, port->poller_num);
}

void agiep_port_addr_poller_reset(struct agiep_vendor_port *port)
{
	int i;
	struct agiep_poller *poller;
	for (i = 0; i < port->poller_num; i++) {
		poller = &port->reg_pollers[i];
		switch (poller->bits) {
		case 8:
			poller->prev = *(poller->data8);
			break;
		case 16:
			poller->prev = *(poller->data16);
			break;
		case 32:
			poller->prev = *(poller->data32);
			break;
		case 64:
			poller->prev = *(poller->data64);
			break;
		}
	}
}