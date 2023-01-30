#include <pthread.h>
#include <stdlib.h>
#include <rte_malloc.h>

#include "agiep_vendor_net.h"
#include "agiep_pci.h"

static pthread_mutex_t vendor_netdev_tab_lock = PTHREAD_MUTEX_INITIALIZER;
static struct agiep_vendor_netdev *vendor_netdev_tab[MAX_PF][MAX_VF];

static void agiep_vendor_base_cfg_init(struct agiep_vendor_netdev *netdev, int pnum) 
{
	char *major = NULL;
	char *minor = NULL;
	long majorfv;	//firmware version from env vars.
	long minorfv;
	netdev->base_cfg->major = AGIEP_VENDOR_FIRMWARE_MAJOR;
	netdev->base_cfg->minor = AGIEP_VENDOR_FIRMWARE_MINOR;
	netdev->base_cfg->pnum = pnum;
	netdev->base_cfg->priv_flags = 0;
	if (netdev->vf) {
		netdev->base_cfg->priv_flags |= (1 << VENDOR_PRIV_FLAGS_MSIX);
	}
	major = getenv("AGIEP_VENDOR_FIRMWARE_MAJOR");
	minor = getenv("AGIEP_VENDOR_FIRMWARE_MINOR");
	if (major && minor) {
		majorfv = strtol(major, NULL, 10);
		minorfv = strtol(minor, NULL, 10);
		if (majorfv >= 0 && majorfv <= UINT16_MAX) {
			netdev->base_cfg->major = (uint16_t)majorfv;
		}
		if (minorfv >= 0 && minorfv <= UINT16_MAX) {
			netdev->base_cfg->minor = (uint16_t)minorfv;
		}
	}
}

struct agiep_vendor_netdev *agiep_vendor_net_probe(int pf, int vf, int num)
{
	struct agiep_vendor_netdev *netdev = NULL;
	struct agiep_vendor_port *ports = NULL;
	void *bar2;
	void *notify_area_bar;

	netdev = rte_malloc(NULL, sizeof(struct agiep_vendor_netdev), 0);

	if (!netdev) {
		AGIEP_LOG_ERR("agiep_vendor_netdev malloc error %d", rte_errno);
		return NULL;
	}

	ports = rte_malloc(NULL, sizeof(struct agiep_vendor_port) * num, 0);

	if (!ports) {
		AGIEP_LOG_ERR("agiep_vendor_port malloc error %d", rte_errno);
		goto error;
	}

	rte_memset(ports, 0, sizeof(struct agiep_vendor_port) * num);

	netdev->ports = ports;
	netdev->pf = pf;
	netdev->vf = vf;
	netdev->ep = agiep_get_ep();

	memset(netdev->irq_data, 0xFF, sizeof(netdev->irq_data));
	
	bar2 = agiep_pci_bar(pf, vf, 2);
	if (!bar2) {
		AGIEP_LOG_ERR("agiep_pci_bar error");
		goto error;
	}
	notify_area_bar = agiep_pci_bar(pf, vf, 4);
	if (!notify_area_bar) {
		AGIEP_LOG_ERR("agiep_pci_bar error 4.");
		goto error;
	}

	netdev->bar = bar2;
	netdev->notify_area_bar = notify_area_bar;
	netdev->pnum = num;
	netdev->base_cfg = bar2;
	agiep_vendor_base_cfg_init(netdev, num);
	netdev->cmd_cfg = (struct agiep_vendor_cmd_cfg *)((uint8_t *)bar2 + AGIEP_VENDOR_CMD_CFG_OFFSET);
	pthread_mutex_lock(&vendor_netdev_tab_lock);
	vendor_netdev_tab[pf][vf] = netdev;
	netdev->ref++;
	pthread_mutex_unlock(&vendor_netdev_tab_lock);
	return netdev;
error:

	if (ports)
		rte_free(ports);
	rte_free(netdev);
	return NULL;
}

struct agiep_vendor_dirty_log_cfg *agiep_vendor_dirty_log_cfg_get(struct agiep_vendor_netdev *netdev)
{
	return (struct agiep_vendor_dirty_log_cfg *)((uint8_t *)netdev->bar + AGIEP_VENDOR_DLOG_CFG_OFFSET);
}

struct agiep_vendor_port_cfg *agiep_vendor_port_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum)
{
	int offset = AGIEP_VENDOR_PORT_CFG_OFFSET;

	offset += (sizeof(struct agiep_vendor_port_cfg) + qnum * sizeof(struct agiep_vendor_rx_cfg) +
				qnum * sizeof(struct agiep_vendor_tx_cfg) + sizeof(struct agiep_vendor_cq_cfg)) * portid;

	return (struct agiep_vendor_port_cfg *)((uint8_t *)netdev->bar + offset);
}

struct agiep_vendor_rx_cfg *agiep_vendor_rx_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int rxid, int qnum)
{
	struct agiep_vendor_port_cfg *port_cfg;
	struct agiep_vendor_queue_cfg *queue_cfg;

	port_cfg = agiep_vendor_port_cfg_get(netdev, portid, qnum);
	queue_cfg = (struct agiep_vendor_queue_cfg *)(port_cfg + 1);
	return &(queue_cfg[rxid].rx_cfg);

}

struct agiep_vendor_tx_cfg *agiep_vendor_tx_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int txid, int qnum)
{
	struct agiep_vendor_port_cfg *port_cfg;
	struct agiep_vendor_queue_cfg *queue_cfg;
	port_cfg = agiep_vendor_port_cfg_get(netdev, portid, qnum);
	queue_cfg = (struct agiep_vendor_queue_cfg *)(port_cfg + 1);
	return &(queue_cfg[txid].tx_cfg);
}

struct agiep_vendor_cq_cfg *agiep_vendor_cq_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum)
{
	struct agiep_vendor_port_cfg *port_cfg;
	struct agiep_vendor_queue_cfg *queue_cfg;
	struct agiep_vendor_cq_cfg *cq_cfg;

	port_cfg = agiep_vendor_port_cfg_get(netdev, portid, qnum);
	queue_cfg = (struct agiep_vendor_queue_cfg *)(port_cfg + 1);
	cq_cfg = (struct agiep_vendor_cq_cfg *)(queue_cfg + qnum);
	return cq_cfg;
}

struct agiep_vendor_mng_cfg *agiep_vendor_mng_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum)
{
	struct agiep_vendor_cq_cfg *cq_cfg;
	struct agiep_vendor_mng_cfg *mng_cfg;

	cq_cfg = agiep_vendor_cq_cfg_get(netdev, portid, qnum);
	mng_cfg = (struct agiep_vendor_mng_cfg *)(cq_cfg + 1);
	return mng_cfg;
}

struct agiep_vendor_netdev *agiep_vendor_netdev_get(int pf, int vf)
{
	struct agiep_vendor_netdev *netdev;
	pthread_mutex_lock(&vendor_netdev_tab_lock);
	netdev = vendor_netdev_tab[pf][vf];
	if (netdev) {
		netdev->ref++;
	}
	pthread_mutex_unlock(&vendor_netdev_tab_lock);

	return netdev;
}

void agiep_vendor_netdev_put(struct agiep_vendor_netdev *netdev)
{
	pthread_mutex_lock(&vendor_netdev_tab_lock);
	netdev->ref--;
	if (!netdev->ref) {
		vendor_netdev_tab[netdev->pf][netdev->vf] = NULL;
		rte_free(netdev->ports);
		rte_free(netdev);
	}
	pthread_mutex_unlock(&vendor_netdev_tab_lock);
}

__rte_always_inline int agiep_vendor_use_msix(struct agiep_vendor_netdev *netdev)
{
	return netdev->base_cfg->priv_flags & (1 << VENDOR_PRIV_FLAGS_MSIX);
}