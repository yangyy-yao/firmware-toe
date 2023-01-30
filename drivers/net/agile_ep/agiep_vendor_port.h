#ifndef RTE_AGIEP_VENDOR_PORT_H__
#define RTE_AGIEP_VENDOR_PORT_H__

#include "agiep_virtio_port.h"
#include "agiep_virtio_legacy.h"

#define AGIEP_MSI_NO_VECTOR	0xffff
#define AGIEP_MSI_GET_LAST	0xfffe
#define VIRTIO_NET_CTRL_DESC_NUM 256
#define VENDOR_QUEUE_SIZE	(1024 * 4)
#define VENDOR_CTX_MP_CACHE_SIZE 16

#define AGIEP_VENDOR_F_SPLIT 1
#define AGIEP_VENDOR_F_PACKED 2
#define AGIEP_VENDOR_F_DIRTYLOG 4

#define AGIEP_VENDOR_FIRMWARE_MAJOR 1
#define AGIEP_VENDOR_FIRMWARE_MINOR 2

#define VENDOR_MAX_QUEUE 32
#define VENDOR_NOTIFY_MASK 0xffff

#define VENDOR_NET_S_LINK_UP          0x1
/* driver status*/
/* the driver talls the board that there is a matching driver on the host */
#define VENDOR_CONFIG_S_DRIVER		0x02
/* the driver written to the board card, to indicate that the driver is
 * ready and has been register_netdev */
#define VENDOR_CONFIG_S_DRIVER_OK	0x04
/* write by virtio_net */
#define VENDOR_CONFIG_S_FEATURES_OK	0x08
/* device status */
#define VENDOR_CONFIG_S_DEVICE_OK	0x10
/* pci driver status */
#define VENDOR_CONFIG_S_DEVICE_INIT	0x20
/* Status byte for guest to report reset */
#define VENDOR_CONFIG_S_RESET		0x40
#define VENDOR_CONFIG_S_DISABLE		0x80

#define VENDOR_PORT_STATUS_OK  0
#define VENDOR_PORT_STATUS_ERR 1
#define VENDOR_PORT_STATUS_404 2

#define VENDOR_PRIV_FLAGS_MSIX 0

#define rte_memset memset

#define VQ_IDX2ID(idx) ((idx) / 2)


struct agiep_vendor_base_cfg {
	uint16_t major;
	uint16_t minor;
	uint16_t pnum;
	uint16_t priv_flags;
};

struct agiep_vendor_cmd_cfg {
	uint16_t major;
	uint16_t minor;
	uint32_t feature;
};

struct agiep_vendor_dirty_log_cfg {
	uint32_t dlog_base_lo;
	uint32_t dlog_base_hi;
	uint32_t dlog_size;
};

#define AGIEP_VENDOR_BASE_OFFSET 0
#define AGIEP_VENDOR_CMD_CFG_OFFSET (AGIEP_VENDOR_BASE_OFFSET + \
		sizeof(struct agiep_vendor_base_cfg))
#define AGIEP_VENDOR_DLOG_CFG_OFFSET (AGIEP_VENDOR_CMD_CFG_OFFSET + \
		sizeof(struct agiep_vendor_cmd_cfg))
#define AGIEP_VENDOR_PORT_CFG_OFFSET (AGIEP_VENDOR_DLOG_CFG_OFFSET + \
		sizeof(struct agiep_vendor_dirty_log_cfg))

#define AGIEP_VENDOR_QUEUE_CFG_SIZE (sizeof(struct agiep_vendor_rx_cfg))

struct agiep_vendor_netdev {
	int pf;
	int vf;
	int pnum;
	int ref;
	void *bar;
	void *notify_area_bar;
	struct pci_ep *ep;
	uint16_t config_vector;
	void *irq_addr[VENDOR_MAX_QUEUE];
	uint32_t irq_data[VENDOR_MAX_QUEUE];
	struct agiep_vendor_base_cfg *base_cfg;
	struct agiep_vendor_cmd_cfg *cmd_cfg;
	struct agiep_vendor_port *ports;
	char name[RTE_ETH_NAME_MAX_LEN];
};

struct agiep_vendor_port_cfg {
	uint16_t qnum;
	uint16_t qlen;
	uint64_t feature;
	uint16_t status;
	uint16_t net_status;
	uint32_t health_count;
	uint8_t mac[ETH_ALEN];
	uint16_t mtu;
} __rte_packed;

struct agiep_vendor_rx_cfg {
	uint32_t qsize;
	uint16_t msi_vector;
	uint16_t doorbell;
	uint32_t queue_desc_lo;
	uint32_t queue_desc_hi;
	uint32_t queue_avail_lo;
	uint32_t queue_avail_hi;
	uint32_t queue_used_lo;
	uint32_t queue_used_hi;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t get_last;
	uint16_t reserved;
} __rte_packed;

struct agiep_vendor_tx_cfg {
	uint32_t qsize;
	uint16_t msi_vector;
	uint16_t doorbell;
	uint32_t queue_desc_lo;
	uint32_t queue_desc_hi;
	uint32_t queue_avail_lo;
	uint32_t queue_avail_hi;
	uint32_t queue_used_lo;
	uint32_t queue_used_hi;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t get_last;
	uint16_t reserved;
} __rte_packed;

struct agiep_vendor_queue_cfg {
	struct agiep_vendor_rx_cfg rx_cfg;
	struct agiep_vendor_tx_cfg tx_cfg;
};

struct agiep_vendor_cq_cfg {
	uint32_t qsize;
	uint16_t msi_vector;
	uint16_t doorbell;
	uint32_t queue_desc_lo;
	uint32_t queue_desc_hi;
	uint32_t queue_avail_lo;
	uint32_t queue_avail_hi;
	uint32_t queue_used_lo;
	uint32_t queue_used_hi;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t get_last;
	uint16_t reserved;
} __rte_packed;

struct agiep_vendor_mng_cfg {
	uint32_t address;
	uint32_t netmask;
} __rte_packed;

struct agiep_vendor_port {
	int id;
	uint8_t started;
	uint8_t enable;
	uint16_t reseted;
	struct agiep_vendor_port_cfg *cfg;
	struct agiep_vendor_dirty_log_cfg *dirty_log_cfg;
	struct agiep_vendor_rx_cfg **rx_cfg;
	struct agiep_vendor_tx_cfg **tx_cfg;
	struct agiep_vendor_cq_cfg *cq_cfg;
	struct agiep_vendor_mng_cfg *mng_cfg;
	struct virtqueue **rx_vq;
	struct virtqueue **tx_vq;
	struct agiep_virtio_port port;
	struct agiep_vendor_netdev *netdev;
	struct agiep_poller *reg_pollers;
	int poller_num;
	uint32_t vector_map;
	struct rte_eth_dev *eth_dev;
	uint16_t doorbell[VENDOR_MAX_QUEUE];
	TAILQ_ENTRY(agiep_vendor_port) entry;
};

int vendor_dev_disable(struct rte_eth_dev *dev);
int vendor_dev_softreset(struct rte_eth_dev *dev);
int vendor_rx_softreset(struct agiep_vendor_port *port, int id, int num);
int vendor_tx_softreset(struct agiep_vendor_port *port, int id, int num);
int vendor_cq_softreset(struct agiep_vendor_port *port, int num);

void agiep_vendor_cmd_process(struct agiep_vendor_port *vendor_port);
void agiep_vendor_ctrl_process(struct agiep_vendor_port *vendor_port);

struct agiep_vendor_netdev *agiep_vendor_net_probe(int pf, int vf, int num);
struct agiep_vendor_dirty_log_cfg *agiep_vendor_dirty_log_cfg_get(struct agiep_vendor_netdev *netdev);
struct agiep_vendor_port_cfg *agiep_vendor_port_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum);
struct agiep_vendor_rx_cfg *agiep_vendor_rx_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int rxid, int qnum);
struct agiep_vendor_tx_cfg *agiep_vendor_tx_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int txid, int qnum);
struct agiep_vendor_cq_cfg *agiep_vendor_cq_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum);
struct agiep_vendor_mng_cfg *agiep_vendor_mng_cfg_get(struct agiep_vendor_netdev *netdev, int portid, int qnum);
struct agiep_vendor_netdev *agiep_vendor_netdev_get(int pf, int vf);
void agiep_vendor_netdev_put(struct agiep_vendor_netdev *netdev);
int agiep_vendor_use_msix(struct agiep_vendor_netdev *netdev);
uint64_t agiep_vendor_irq_addr(struct agiep_vendor_netdev *dev, uint16_t vector);
uint32_t agiep_vendor_irq_data(struct agiep_vendor_netdev *dev, uint16_t vector);
void agiep_vendor_irq_raise(struct agiep_vendor_netdev *dev, uint16_t vector);
void agiep_vendor_reset_vector(struct agiep_vendor_netdev *dev, uint16_t vector);
void *vendor_net_ctrl_process(void *arg __rte_unused);
void vendor_dev_failed(struct rte_eth_dev *dev);
int agiep_dev_fall_to_split(struct rte_eth_dev *dev);
#endif
