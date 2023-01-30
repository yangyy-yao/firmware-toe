#ifndef AGIEP_VIRTIO_H_
#define AGIEP_VIRTIO_H_

/* The feature bitmap for virtio net */
#include <linux/virtio_types.h>
#include "agiep_virtio_rxtx.h"
#include "agiep_virtio_ctrl.h"
#include "agiep_lib.h"

#define VIRTIO_NET_F_CSUM       0       /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM 1       /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MTU        3       /* Initial MTU advice. */
#define VIRTIO_NET_F_MAC        5       /* Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4 7       /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6 8       /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN  9       /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO  10      /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4  11      /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6  12      /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN   13      /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO   14      /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF  15      /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS     16      /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ    17      /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX    18      /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN  19      /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20   /* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21  /* Guest can announce device on the
       				         * network */
#define VIRTIO_NET_F_MQ         22      /* Device supports Receive Flow
       				         * Steering */
#define VIRTIO_F_ANY_LAYOUT     27
#define VIRTIO_NET_F_CTRL_MAC_ADDR 23   /* Set MAC address */
#define VIRTIO_NET_F_PREDICT	31	/* VIRTIO_F_IN_ORDER for legacy */

#define VIRTIO_NET_F_HASH_REPORT  57    /* Supports hash report */
#define VIRTIO_NET_F_RSS          60    /* Supports RSS RX steering */
#define VIRTIO_NET_F_RSC_EXT      61    /* extended coalescing info */
#define VIRTIO_NET_F_STANDBY      62    /* Act as standby for another device
                                         * with the same MAC.
                                         */
#define VIRTIO_NET_F_SPEED_DUPLEX 63    /* Device set linkspeed and duplex */

#define VIRTIO_NET_F_GSO        6       /* Host handles pkts w/ any GSO type */

#define VIRTIO_NET_S_LINK_UP    1       /* Link is up */
#define VIRTIO_NET_S_ANNOUNCE   2       /* Announcement is needed */

struct virtio_pci_common_cfg {
	uint32_t host_feature;
	uint32_t guest_feature;
	uint32_t vap; 			/* Virtqueue Address PFN */
	uint16_t queue_size;
	uint16_t queue_select;
	uint16_t queue_notify;
	uint8_t device_status;
	uint8_t isr_status;
	uint16_t msix_config;
	uint16_t queue_msix_vector;
};

struct virtio_net_config {
        /* The config defining mac address (if VIRTIO_NET_F_MAC) */
        uint8_t mac[ETH_ALEN];
        /* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
        uint16_t status;
        /* Maximum number of each of transmit and receive queues;
         * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
         * Legal values are between 1 and 0x8000
         */
        uint16_t max_virtqueue_pairs;
        /* Default maximum transmit unit advice */
        uint16_t mtu;
        /*
         * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
         * Any other value stands for unknown.
         */
        uint32_t speed;
        /*
         * 0x00 - half duplex
         * 0x01 - full duplex
         * Any other value stands for unknown.
         */
        uint8_t duplex;
        /* maximum size of RSS key */
        uint8_t rss_max_key_size;
        /* maximum number of indirection table entries */
        uint16_t rss_max_indirection_table_length;
        /* bitmask of supported VIRTIO_NET_RSS_HASH_ types */
        uint32_t supported_hash_types;
} __rte_packed;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1       /* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID     2       /* Csum is valid */
#define VIRTIO_NET_HDR_F_RSC_INFO       4       /* rsc info in csum_ fields */

#define AGIEP_DMA_MAX_FAIL 128
#define VIRTIO_QUEUE_SIZE (1024 * 4)
#define VIRTIO_COMMAND_DESC_NUM 32
#define MEMPOOL_CACHE_SIZE 32
#define VIRTIO_CTX_MP_CACHE_SIZE 16
#define VIRTIO_PKT_MP_CACHE_SIZE 16

#define AGIEP_DP_MIN_POOL_SIZE (1024)
#define AGIEP_DP_MAX_CACHE_SIZE (64)
#define AGIEP_DP_POOL_SIZE(nb) RTE_MAX(AGIEP_DP_MIN_POOL_SIZE, (nb))
#define AGIEP_DP_CACHE_SIZE(nb) RTE_MIN(AGIEP_DP_MAX_CACHE_SIZE, AGIEP_GET_CACHE_SIZE(nb))

/* This header comes first in the scatter-gather list.
 * For legacy virtio, if VIRTIO_F_ANY_LAYOUT is not negotiated, it must
 * be the first element of the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header. */
struct virtio_net_hdr {
        /* See VIRTIO_NET_HDR_F_* */
        uint8_t flags;
        /* See VIRTIO_NET_HDR_GSO_* */
        uint8_t gso_type;
        uint16_t hdr_len;             /* Ethernet + IP + tcp/udp hdrs */
        uint16_t gso_size;            /* Bytes to append to hdr_len per frame */
        uint16_t csum_start;  /* Position to start checksumming from */
        uint16_t csum_offset; /* Offset after that to place checksum */
};

/* This is the version of the header to use when the MRG_RXBUF
 * feature has been negotiated. */
struct virtio_net_hdr_mrg_rxbuf {
        struct virtio_net_hdr hdr;
        uint16_t num_buffers; /* Number of merged rx buffers */
};

#define NETDEV_MAX_BURST 32

/**
 *   tx rx tx rx    ctrl
 *   0  1  2  3 ... last
 */
#define VIRTIO_TX_INDEX(id)	(((id) * 2))
#define VIRTIO_RX_INDEX(id)	(((id) * 2) + 1)
#define VIRTIO_CTRL_INDEX(dev)	( \
		(dev)->data->nb_rx_queues + (dev)->data->nb_tx_queues)
#define VIRTIO_MAX_RX_QUEUES (3)
#define VIRTIO_MAX_TX_QUEUES (12) /* expand tx queue */

struct agiep_virtio_netdev {
	struct agiep_virtio_device *vdev;
	struct agiep_frep_device *fdev;
	struct agiep_virtio_port port;
	TAILQ_ENTRY(agiep_virtio_netdev) entry;

	uint8_t promisc;
	uint8_t allmulti;
	uint8_t alluni;
	uint8_t nomulti;
	uint8_t nouni;
	uint8_t nobcast;
};
void agiep_virtio_cmd_process(struct agiep_virtio_netdev *ndev);
int virtio_net_dev_softreset(struct rte_eth_dev *dev);
int agiep_virtio_net_set_status(struct rte_eth_dev *dev, uint16_t status);
uint16_t agiep_virtio_net_get_status(struct rte_eth_dev *dev);
void virtio_net_config_notify(struct agiep_virtio_device *vdev);
int virtio_tx_pktmpool_create(struct virtnet_tx *tx);
void virtio_net_ctrl_process(void * arg __rte_unused);
int virtio_vq_pairs_set(struct agiep_virtio_netdev *ndev, uint16_t cur_pairs);
void virtio_set_dev_start_no_ctrl(struct agiep_virtio_device *vdev);

#endif
