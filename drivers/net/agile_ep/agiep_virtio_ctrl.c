#include <rte_ring.h>
#include "agiep_virtio_ctrl.h"
#include <agiep_dma.h>
#include <agiep_vring.h>
#include "agiep_virtio_net.h"
#include <agiep_virtio.h>
#include <agiep_virtio_legacy.h>
#include "agiep_virtio_rxtx.h"

static void agiep_virtio_rq_rx_mcb(struct agiep_async_dma_group *group)
{
	struct virtio_net_command *cmd = group->priv;
	struct agiep_net_ctrl *ctrl = cmd->port->ctrl;
	if (rte_ring_enqueue(ctrl->rr, cmd) < 0) {
		AGIEP_LOG_ERR("Unexpect queue full when enqueue cmd");
	}
	rte_mempool_put(group->dma->jpool, group);
}

static void agiep_virtio_rq_rx_scb(struct agiep_async_dma_job *job)
{
	struct virtio_net_command *cmd = job->priv;
	struct agiep_net_ctrl *ctrl = cmd->port->ctrl;
	if (rte_ring_enqueue(ctrl->rr, cmd) < 0) {
		AGIEP_LOG_ERR("Unexpect queue full when enqueue cmd");
	}
	rte_mempool_put(job->dma->jpool, job);
}

void agiep_virtio_rq_process(struct agiep_virtio_port *port)
{
	struct agiep_net_ctrl *ctrl;
	struct virtqueue *vq;
	struct agiep_async_dma_job *jobs[2];
	struct agiep_async_dma_group *group;
	struct vring_queue_elem *elem;
	struct virtio_net_command *cmd;
	struct iovec *inv;
	int nb_elems;
	int nb_jobs;
	uint16_t offset;
	uint64_t data_off;
	int vq_num;

	ctrl = port->ctrl;
	if (!ctrl)
		return;
	vq = ctrl->cvq;
	if (!vq)
		return;

	if (!virtqueue_enabled(vq))
		return;
	agiep_virtio_vring_cache(vq);
	//virtqueue_flush(vq);

	vq_num = virtqueue_num(vq);

	if (!vq_num)
		return;

	for (nb_elems = 0; nb_elems < vq_num; nb_elems++) {
		elem = NULL;
		cmd = NULL;
		nb_jobs = 0;
		group = NULL;

		virtqueue_pop(vq, &elem, 1);
		if (!elem->in_num)
			goto failed;
		if (rte_mempool_get(port->ctrl->cmdpool, (void **) &cmd))
			goto failed;
		cmd->port = port;
		cmd->elem = elem;
		nb_jobs = elem->in_num;
		if (nb_jobs > 2)
			nb_jobs = 2;

		if (rte_mempool_get_bulk(vq->dma->jpool, (void **) jobs, nb_jobs)) {
			goto failed;
		}
		if (nb_jobs > 1) {
			if (rte_mempool_get(vq->dma->jpool, (void **) &group)) {
				goto failed;
			}

			group->priv = cmd;
			group->cb = agiep_virtio_rq_rx_mcb;
			data_off = rte_mem_virt2iova(cmd) +
				   offsetof(struct virtio_net_command, ctrl);

			inv = virtqueue_inv(vq, elem->id, 0);
			offset = ALIGN_DMA_CALC_OFFSET((uint64_t)inv->iov_base);
			jobs[0]->src = (uint64_t) inv->iov_base - offset;
			jobs[0]->dst = data_off - offset;
			jobs[0]->len = sizeof(struct virtio_net_ctrl_hdr) + offset;
			jobs[0]->flags = DMA_JOB_F_FROM_PCI;

			data_off = rte_mem_virt2iova(cmd) +
				offsetof(struct virtio_net_command, data);

			inv = virtqueue_inv(vq, elem->id, 1);
			offset = ALIGN_DMA_CALC_OFFSET((uint64_t)inv->iov_base);
			jobs[1]->src = (uint64_t) inv->iov_base - offset;
			jobs[1]->dst = data_off - offset;
			jobs[1]->len = inv->iov_len + offset;
			jobs[1]->flags = DMA_JOB_F_FROM_PCI;
			group->nb_jobs = nb_jobs;

			if (agiep_dma_group_enqueue(vq->dma, group, jobs, nb_jobs, DMA_JOB_F_FROM_PCI) != nb_jobs) {
				goto failed;
			}
		} else {
			jobs[0]->priv = cmd;
			jobs[0]->cb = agiep_virtio_rq_rx_scb;
			data_off = rte_mem_virt2iova(cmd) +
					offsetof(struct virtio_net_command, ctrl);

			inv = virtqueue_inv(vq, elem->id, 0);
			offset = ALIGN_DMA_CALC_OFFSET((uint64_t)inv->iov_base);
			jobs[0]->src = (uint64_t) inv->iov_base - offset;
			jobs[0]->dst = data_off - offset;
			jobs[0]->len = sizeof(struct virtio_net_ctrl_hdr) + offset;
			jobs[0]->flags = DMA_JOB_F_FROM_PCI;
			if (agiep_dma_enqueue_buffers(vq->dma, &jobs[0], 1, DMA_JOB_F_FROM_PCI) != 1)
				goto failed;
		}
	}

	return;
failed:
	if (cmd)
		rte_mempool_put(port->ctrl->cmdpool, cmd);
	if (nb_jobs)
		rte_mempool_put_bulk(vq->dma->jpool, (void *const *) jobs, nb_jobs);
	if (group)
		rte_mempool_put(vq->dma->jpool, group);
}

static void agiep_virtio_cq_rx_scb(struct agiep_async_dma_job *job)
{
	struct virtio_net_command *cmd = job->priv;
	struct agiep_virtio_port *port = cmd->port;

	virtqueue_push(port->ctrl->cvq, &cmd->elem, 1);
	rte_mempool_put(port->ctrl->cmdpool, cmd);
	rte_mempool_put(job->dma->jpool, job);
}

void agiep_virtio_cq_process(struct agiep_virtio_port *port)
{
	struct agiep_net_ctrl *ctrl;
	struct virtqueue *cvq;
	struct iovec *outv;

	struct agiep_async_dma_job *job;
	struct virtio_net_command *cmd = NULL;

	ctrl = port->ctrl;
	if (!ctrl)
		return;
	cvq = ctrl->cvq;

	if (!cvq)
		return;
	if (!virtqueue_enabled(cvq))
		return;

	//agiep_virtio_vring_cache(cvq);
	virtqueue_flush(cvq);

	while(rte_ring_count(port->ctrl->cr)) {
		if (!rte_ring_dequeue_burst(port->ctrl->cr, (void **) &cmd, 1, NULL))
			return;
		
		if (rte_mempool_get(cvq->dma->jpool, (void **) &job) < 0) {
			return;
		}
		if (!cmd->elem->out_num){
			AGIEP_LOG_ERR("cmd elem out_num %d",cmd->elem->in_num);
		}
	
		outv = virtqueue_outv(cvq, cmd->elem->id, 0);

		job->src = rte_mem_virt2iova(cmd) + 
			offsetof(struct virtio_net_command, status);

		job->dst = (uint64_t) outv->iov_base;
		job->len = sizeof(cmd->status);
		cmd->elem->len = job->len;

		job->cb = agiep_virtio_cq_rx_scb;
		job->priv = cmd;
		job->flags = DMA_JOB_F_TO_PCI;

		if (agiep_dma_enqueue_buffers(cvq->dma, &job, 1, DMA_JOB_F_TO_PCI) != 1)
			goto failed;
	}
	return;
failed:
	if (job)
		rte_mempool_put(cvq->dma->jpool, job);
}

static uint8_t virtio_net_handle_rx_mode(struct agiep_virtio_netdev *ndev, struct virtio_net_command *cmd)
{
	uint16_t status;
	if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_PROMISC) {
		ndev->promisc = 1;
	} else if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_ALLMULTI) {
		ndev->allmulti = 1;
	} else if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_ALLUNI) {
		ndev->alluni = 1;
	} else if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_NOMULTI) {
		ndev->nomulti = 1;
	} else if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_NOUNI) {
		ndev->nouni = 1;
	} else if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_RX_NOBCAST) {
		ndev->nobcast = 1;
	} else {
		return VIRTIO_NET_ERR;
	}
	status = agiep_virtio_net_get_status(ndev->fdev->eth_dev);
	status |= VIRTIO_NET_S_LINK_UP;
	agiep_virtio_net_set_status(ndev->fdev->eth_dev, status);

	return VIRTIO_NET_OK;
}

static uint8_t virtio_net_handle_mq(struct agiep_virtio_netdev *ndev,
	struct virtio_net_command *cmd)
{
	uint16_t queues;
	int ret;
	if (cmd->ctrl.cmd == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET) {
		queues = (uint16_t)cmd->data[0];
		if (queues > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
		    queues < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN)
			return VIRTIO_NET_ERR;
		ret = virtio_vq_pairs_set(ndev, queues);
		if (ret)
			return VIRTIO_NET_ERR;
	}

	return VIRTIO_NET_OK;
}

void agiep_virtio_cmd_process(struct agiep_virtio_netdev *ndev)
{
	struct agiep_virtio_port *port;
	static struct virtio_net_command *cmd = NULL;
	struct virtio_net_ctrl_hdr *ctrl;
	struct agiep_net_ctrl *dev_ctrl;
	uint8_t status = 0;
	port = &ndev->port;

	dev_ctrl = port->ctrl;
	if (unlikely(!dev_ctrl))
		return;
	dev_ctrl->cmd_seq++;

	if (!dev_ctrl->cvq)
		goto out;
	
	if (!rte_ring_count(port->ctrl->rr))
		goto out;


	while (rte_ring_dequeue(dev_ctrl->rr, (void **) &cmd) >= 0) {
		ctrl = &cmd->ctrl;
		switch(ctrl->class) {
			case VIRTIO_NET_CTRL_RX:
				status = virtio_net_handle_rx_mode(ndev, cmd);
				break;
			case VIRTIO_NET_CTRL_MQ:
				status = virtio_net_handle_mq(ndev, cmd);
				break;
			case VIRTIO_NET_CTRL_ANNOUNCE:
			case VIRTIO_NET_CTRL_MAC:
				status = VIRTIO_NET_OK;
				break;
			case VIRTIO_NET_CTRL_VLAN:
			case VIRTIO_NET_CTRL_GUEST_OFFLOADS:
				break;
			default:

				status = VIRTIO_NET_ERR; break;
		}
		AGIEP_LOG_DEBUG("agiep: virtio_net: pf %d vf %d get ctrl data: class: %d cmd: %d",port->fdev->pf, port->fdev->vf, ctrl->class, ctrl->cmd);
		cmd->status = status;
		if (rte_ring_enqueue(dev_ctrl->cr, cmd)) {
			AGIEP_LOG_ERR("virtio-net: ctrl cq full");
			goto out;
		}
	}
out:
	dev_ctrl->cmd_seq++;
}
