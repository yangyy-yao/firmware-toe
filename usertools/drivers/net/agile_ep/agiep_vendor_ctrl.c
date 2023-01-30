#include <rte_ring.h>

#include "agiep_vendor_ctrl.h"
#include "agiep_ctrl.h"
#include "agiep_reg_poller.h"
#include "agiep_dma.h"
#include "agiep_vring.h"
#include "agiep_virtio_rxtx.h"

static uint8_t vendor_net_handle_rx_mode(struct rte_eth_dev *dev, struct vendor_port_command *cmd)
{
	if (cmd->ctrl.cmd == VENDOR_NET_CTRL_RX_PROMISC) {
		dev->data->promiscuous = 1;
	} else if (cmd->ctrl.cmd == VENDOR_NET_CTRL_RX_ALLMULTI) {
		dev->data->all_multicast = 1;
	}else {
		return VENDOR_PORT_STATUS_ERR;
	}
	return VENDOR_PORT_STATUS_OK;
}

static uint8_t vendor_net_handle_mq(struct rte_eth_dev *dev, struct vendor_port_command *cmd)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	struct agiep_vendor_port *vendor_port;

	vendor_port = fdev->dev;

	if (cmd->ctrl.cmd == VENDOR_NET_CTRL_MQ_VQ_PAIRS_SET) {
		vendor_port->port.fdev->used_queues = *(uint16_t*)cmd->data;
	} 
	return VENDOR_PORT_STATUS_OK;
}

int vendor_net_handle_pci_status(struct agiep_vendor_port *vendor_port)
{
	int ret = 0;
	uint16_t device_status = vendor_port->cfg->status;
	if (device_status & VENDOR_CONFIG_S_RESET) {
		ret = vendor_dev_softreset(vendor_port->eth_dev);
		if (ret) {
			vendor_dev_failed(vendor_port->eth_dev);
			AGIEP_LOG_ERR("vendor_dev_softreset fail: %d", ret);
		}
	} else if (device_status & VENDOR_CONFIG_S_DISABLE) {
		vendor_dev_disable(vendor_port->eth_dev);
	} else if (device_status & VENDOR_CONFIG_S_DRIVER_OK) {
		if (vendor_port->started
			&& (device_status & VENDOR_CONFIG_S_DEVICE_OK)) {
			vendor_port->enable = 1;
		}
		vendor_port->eth_dev->dev_ops->link_update(vendor_port->eth_dev, 0);
	}
	return ret;
}

void agiep_vendor_cmd_process(struct agiep_vendor_port *vendor_port)
{
	struct agiep_virtio_port *port;
	static struct vendor_port_command *cmd = NULL;
	uint32_t status = 0;
	struct agiep_net_ctrl *dev_ctrl;

	port = &vendor_port->port;
	dev_ctrl = port->ctrl;
	if (!dev_ctrl)
		return;
	dev_ctrl->cmd_seq++;
	if (!dev_ctrl->cvq)
		goto out;

	if (!rte_ring_count(dev_ctrl->rr))
		goto out;

	while (rte_ring_dequeue(dev_ctrl->rr, (void **) &cmd)>=0) {
		switch(cmd->ctrl.class) {
			case VENDOR_NET_CTRL_RX:
				vendor_net_handle_rx_mode(port->fdev->eth_dev, cmd);
				break;
			case VENDOR_NET_CTRL_MQ:
				vendor_net_handle_mq(port->fdev->eth_dev, cmd);
				break;
			default:
				status = VENDOR_PORT_STATUS_404;
		}
		AGIEP_LOG_DEBUG("pf %d vf %d: get ctrl data: class: %d cmd: %d\n",
				port->fdev->pf, port->fdev->vf, cmd->ctrl.class, cmd->ctrl.cmd);
		status = 0;
		cmd->status = status;
		if (rte_ring_enqueue(dev_ctrl->cr, cmd)) {
			RTE_LOG(ERR, PMD, "vendor-net: ctrl cq full");
			goto out;
		}
	}
out:
	dev_ctrl->cmd_seq++;
}
