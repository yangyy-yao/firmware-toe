#ifndef RTE_PMD_AGI_FREP_H_
#define RTE_PMD_AGI_FREP_H_
// agile endpoint frontend representor

#include <rte_mbuf.h>
#include <rte_ethdev_driver.h>
#include <agiep_vring.h>
#include <stdbool.h>
#include "agiep_accel_engine.h"

#ifndef ETH_ALEN
#define ETH_ALEN                6
#endif

#define RTE_PMD_AGIEP_TX_MAX_BURST (32 * 2)
#define RTE_PMD_AGIEP_RX_MAX_BURST 32

#define RTE_PMD_AGIEP_MAX_SEGS 32
#define RTE_PMD_AGIEP_MAX_QUEUES 16
#define RTE_PMD_AGIEP_MTU_DEFAULT 1500

#define AGIEP_E_REG_EXPAND "AGIEP_VIRTIO_REGEXPAND_COREMASK"

#define ETH_AGIEP_FREP "frep"
#define ETH_AGIEP_PF "pf"
#define ETH_AGIEP_VF "vf"
#define ETH_AGIEP_QUEUES "queues"
#define ETH_AGIEP_MAC "vmac"
#define ETH_AGIEP_ACCEL "accel"
#define ETH_AGIEP_PCIEP "pciep"
#define ETH_AGIEP_VPORT "vport"
#define ETH_AGIEP_PACKED "packed"
#define ETH_AGIEP_MTU "mtu"

#define ETH_AGIEP_PORTNUM "portnum"
#define ETH_AGIEP_HW_CHECKSUM "hw_checksum"


enum agiep_frep_t {
	AGIEP_FREP_VIRTIO,
	AGIEP_FREP_VENDOR,
	AGIEP_FREP_LOOPBACK,
	AGIEP_FREP_TASK,
	AGIEP_FREP_NUM,
};

enum agiep_frep_ev_t {
	REP_EVENT_CONFIG_FLOW,
	REP_EVENT_CONFIG_RSS,
	REP_EVENT_CONFIG_PORT,
};

struct agiep_frep_ev {
	enum agiep_frep_ev_t type;
	void *data;
};

struct agiep_frep {
	struct eth_dev_ops *ops;
	eth_rx_burst_t rx_pkt_burst;
	eth_tx_burst_t tx_pkt_burst;
	enum agiep_frep_t type;
};

struct agiep_frep_queue {
	struct agiep_frep_device *dev;
	int qid;
};

struct agiep_frep_device {
	struct rte_eth_dev *eth_dev;
	struct agiep_frep *frep;
	struct rte_ring *ev_ring;
	struct rte_ether_addr *addr;
	struct rte_kvargs *kvlist;
	void *extra;
	int pf;
	int vf;
	int queues;
	int used_queues;
	int packed;
	int hw_checksum;
	struct pci_ep *ep;
	void *dev;
	struct agiep_accel *accel;
};

int agiep_frep_register(struct agiep_frep *frep);
struct agiep_frep *agiep_frep_get(enum agiep_frep_t type);

extern enum agiep_frep_t agile_netdev_tab[MAX_PF][MAX_VF];

/* 
 * For now we direct agiep config operation from front endpoint 
 * to accelerator. So we juest rename the configartion function
 * from accelerator module to agiep module.
 */
#define agiep_vlan_filter_set accel_vlan_filter_set
#define agiep_vlan_tpid_set accel_vlan_tpid_set
#define agiep_vlan_offload_set accel_vlan_offload_set
#define agiep_vlan_pvid_set accel_vlan_pvid_set
#define agiep_vlan_strip_queue_set accel_vlan_strip_queue_set
#define agiep_filter_ctrl accel_filter_ctrl
#define agiep_reta_update accel_reta_update
#define agiep_reta_query accel_reta_query
#define agiep_rss_hash_update accel_rss_hash_update
#define agiep_rss_hash_conf_get accel_rss_hash_conf_get
#define agiep_flow_ctrl_get accel_flow_ctrl_get
#define agiep_flow_ctrl_set accel_flow_ctrl_set

#endif
