#ifndef RTE_AGIEP_VENDOR_CTRL_H_
#define RTE_AGIEP_VENDOR_CTRL_H_
#include "agiep_virtio_port.h"
#include "agiep_vendor_port.h"

#define VENDOR_MAX_CTRL_DATA 2048

/*
 * Control the RX mode, ie. promisucous, allmulti, etc...
 * All commands require an "out" sg entry containing a 1 byte
 * state value, zero = disable, non-zero = enable.  Commands
 * 0 and 1 are supported with the VIRTIO_NET_F_CTRL_RX feature.
 * Commands 2-5 are added with VIRTIO_NET_F_CTRL_RX_EXTRA.
 */
#define VENDOR_NET_CTRL_RX    0
 #define VENDOR_NET_CTRL_RX_PROMISC      0
 #define VENDOR_NET_CTRL_RX_ALLMULTI     1
 #define VENDOR_NET_CTRL_RX_ALLUNI       2
 #define VENDOR_NET_CTRL_RX_NOMULTI      3
 #define VENDOR_NET_CTRL_RX_NOUNI        4
 #define VENDOR_NET_CTRL_RX_NOBCAST      5

 /*
 * Control the MAC
 *
 * The MAC filter table is managed by the hypervisor, the guest should
 * assume the size is infinite.  Filtering should be considered
 * non-perfect, ie. based on hypervisor resources, the guest may
 * received packets from sources not specified in the filter list.
 *
 * In addition to the class/cmd header, the TABLE_SET command requires
 * two out scatterlists.  Each contains a 4 byte count of entries followed
 * by a concatenated byte stream of the ETH_ALEN MAC addresses.  The
 * first sg list contains unicast addresses, the second is for multicast.
 * This functionality is present if the VIRTIO_NET_F_CTRL_RX feature
 * is available.
 *
 * The ADDR_SET command requests one out scatterlist, it contains a
 * 6 bytes MAC address. This functionality is present if the
 * VIRTIO_NET_F_CTRL_MAC_ADDR feature is available.
 */
struct vendor_net_ctrl_mac {
	uint32_t entries;
	uint8_t macs[][ETH_ALEN];
} __rte_packed;

#define VENDOR_NET_CTRL_MAC    1
 #define VENDOR_NET_CTRL_MAC_TABLE_SET        0
 #define VENDOR_NET_CTRL_MAC_ADDR_SET         1

/*
 * Control VLAN filtering
 *
 * The VLAN filter table is controlled via a simple ADD/DEL interface.
 * VLAN IDs not added may be filterd by the hypervisor.  Del is the
 * opposite of add.  Both commands expect an out entry containing a 2
 * byte VLAN ID.  VLAN filterting is available with the
 * VIRTIO_NET_F_CTRL_VLAN feature bit.
 */
#define VENDOR_NET_CTRL_VLAN       2
 #define VENDOR_NET_CTRL_VLAN_ADD             0
 #define VENDOR_NET_CTRL_VLAN_DEL             1

/*
 * Control link announce acknowledgement
 *
 * The command VIRTIO_NET_CTRL_ANNOUNCE_ACK is used to indicate that
 * driver has recevied the notification; device would clear the
 * VIRTIO_NET_S_ANNOUNCE bit in the status field after it receives
 * this command.
 */
#define VENDOR_NET_CTRL_ANNOUNCE       3
 #define VENDOR_NET_CTRL_ANNOUNCE_ACK         0

/*
 * Control Receive Flow Steering
 */
#define VENDOR_NET_CTRL_MQ   4
/*
 * The command VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
 * enables Receive Flow Steering, specifying the number of the transmit and
 * receive queues that will be used. After the command is consumed and acked by
 * the device, the device will not steer new packets on receive virtqueues
 * other than specified nor read from transmit virtqueues other than specified.
 * Accordingly, driver should not transmit new packets  on virtqueues other than
 * specified.
 */
struct vendor_net_ctrl_mq {
	uint16_t virtqueue_pairs;
};

 #define VENDOR_NET_CTRL_MQ_VQ_PAIRS_SET        0
 #define VENDOR_NET_CTRL_MQ_VQ_PAIRS_MIN        1
 #define VENDOR_NET_CTRL_MQ_VQ_PAIRS_MAX        0x8000

/*
 * The command VIRTIO_NET_CTRL_MQ_RSS_CONFIG has the same effect as
 * VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET does and additionally configures
 * the receive steering to use a hash calculated for incoming packet
 * to decide on receive virtqueue to place the packet. The command
 * also provides parameters to calculate a hash and receive virtqueue.
 */
struct vendor_net_rss_config {
	uint32_t hash_types;
	uint16_t indirection_table_mask;
	uint16_t unclassified_queue;
	uint16_t indirection_table[1/* + indirection_table_mask */];
	uint16_t max_tx_vq;
	uint8_t hash_key_length;
	uint8_t hash_key_data[/* hash_key_length */];
};

 #define VENDOR_NET_CTRL_MQ_RSS_CONFIG          1

/*
 * The command VIRTIO_NET_CTRL_MQ_HASH_CONFIG requests the device
 * to include in the virtio header of the packet the value of the
 * calculated hash and the report type of hash. It also provides
 * parameters for hash calculation. The command requires feature
 * VIRTIO_NET_F_HASH_REPORT to be negotiated to extend the
 * layout of virtio header as defined in virtio_net_hdr_v1_hash.
 */
struct vendor_net_hash_config {
	uint32_t hash_types;
	/* for compatibility with virtio_net_rss_config */
	uint16_t reserved[4];
	uint8_t hash_key_length;
	uint8_t hash_key_data[/* hash_key_length */];
};

 #define VENDOR_NET_CTRL_MQ_HASH_CONFIG         2

/*
 * Control network offloads
 *
 * Reconfigures the network offloads that Guest can handle.
 *
 * Available with the VIRTIO_NET_F_CTRL_GUEST_OFFLOADS feature bit.
 *
 * Command data format matches the feature bit mask exactly.
 *
 * See VIRTIO_NET_F_GUEST_* for the list of offloads
 * that can be enabled/disabled.
 */
#define VENDOR_NET_CTRL_GUEST_OFFLOADS   5
#define VENDOR_NET_CTRL_GUEST_OFFLOADS_SET        0

#define VENDOR_NET_CTRL_PCI_STATUS	6

struct vendor_net_ctrl_hdr {
	uint8_t class;
	uint8_t cmd;
} __rte_packed;

struct vendor_port_command {
	uint8_t pending_ctrl[64]; // TODO: dynamic alloc
	struct vendor_net_ctrl_hdr ctrl;
	uint8_t pending_data[64];
	uint8_t data[VENDOR_MAX_CTRL_DATA];
	uint8_t pending_status[64];
	uint8_t status;
	struct agiep_virtio_port *port;
	struct vring_queue_elem *elem;
};

int agiep_port_addr_poller_reg(struct agiep_vendor_port *port);
void agiep_port_addr_poller_unreg(struct agiep_vendor_port *port);
void agiep_port_addr_poller_reset(struct agiep_vendor_port *port);

int vendor_net_handle_pci_status(struct agiep_vendor_port *vendor_port);
#endif
