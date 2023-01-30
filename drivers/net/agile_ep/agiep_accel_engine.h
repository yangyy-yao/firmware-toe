#ifndef RTE_PMD_ACCEL_ENG_H_
#define RTE_PMD_ACCEL_ENG_H_

#include <rte_ethdev_driver.h>
#include "agiep_accel_net.h"
#include "agiep_frep.h"


#define MAX_BURST_NUMBER 32

struct agiep_accel_device {
	void *priv;
	struct eth_dev_ops frep_ops;
	struct agiep_accel_ops *ops;
	struct agiep_frep_device *dev;
	int tx_compensate_enable;
};

struct agiep_accel {
	const char *name;
	TAILQ_ENTRY(agiep_accel) next;
	struct agiep_accel_ops *ops;
	int (*agiep_accel_module_init)(struct agiep_accel_device *accel_dev);
};

typedef int (*accel_configure_t)(struct agiep_accel_device *dev);
typedef int (*accel_start_t)(struct agiep_accel_device *dev);
typedef int (*accel_stop_t)(struct agiep_accel_device *dev);
typedef int (*accel_close_t)(struct agiep_accel_device *dev);
typedef int (*accel_infos_get_t)(struct rte_eth_dev_info *dev_info);

typedef int (*accel_rx_queue_setup_t)(struct agiep_accel_device *dev,
				    uint16_t rx_queue_id,
				    uint16_t nb_rx_desc,
				    struct rte_mempool *mb_pool);

typedef int (*accel_tx_queue_setup_t)(struct agiep_accel_device *dev,
				    uint16_t tx_queue_id,
				    uint16_t nb_tx_desc);

typedef void (*accel_queue_release_t)(void *queue);


typedef int (*accel_vlan_filter_set_t)(struct agiep_accel_device *dev,
		uint16_t vlan_id,
		int on);
typedef int (*accel_vlan_tpid_set_t)(struct agiep_accel_device *dev,
		enum rte_vlan_type type, uint16_t tpid);
typedef int (*accel_vlan_offload_set_t)(struct agiep_accel_device *dev, int mask);
typedef int (*accel_vlan_pvid_set_t)(struct agiep_accel_device *dev,
		uint16_t vlan_id,
		int on);
typedef void (*accel_vlan_strip_queue_set_t)(struct agiep_accel_device *dev,
		uint16_t rx_queue_id,
		int on);

typedef int (*accel_reta_update_t)(struct agiep_accel_device *dev,
		struct rte_eth_rss_reta_entry64 *reta_conf,
		uint16_t reta_size);
typedef int (*accel_reta_query_t)(struct agiep_accel_device *dev,
		struct rte_eth_rss_reta_entry64 *reta_conf,
		uint16_t reta_size);
typedef int (*accel_rss_hash_update_t)(struct agiep_accel_device *dev,
		struct rte_eth_rss_conf *rss_conf);
typedef int (*accel_rss_hash_conf_get_t)(struct agiep_accel_device *dev,
		struct rte_eth_rss_conf *rss_conf);

typedef int (*accel_flow_ctrl_get_t)(struct agiep_accel_device *dev,
		struct rte_eth_fc_conf *fc_conf);
typedef int (*accel_flow_ctrl_set_t)(struct agiep_accel_device *dev,
		struct rte_eth_fc_conf *fc_conf);


typedef int (*accel_filter_ctrl_t)(struct agiep_accel_device *dev,
		enum rte_filter_type filter_type,
		enum rte_filter_op filter_op,
		void *arg);

typedef uint64_t (*accel_features_get_t)(struct agiep_frep_device *frep_dev);

typedef void (*accel_features_set_t)(struct agiep_frep_device *frep_dev, uint64_t features);

#define TO_ACCEL_OPS_START(TYP, NAME, TYPES...) \
	TYP accel_ ## NAME  (struct agiep_accel_device *dev, ##TYPES) { \
		struct agiep_frep_device *frep_dev = NULL; \
		struct agiep_accel_device *accel_dev = NULL; \
		frep_dev = dev->dev; \
		assert(frep_dev != NULL); \
		accel_dev = frep_dev->extra;
#define TO_ACCEL_OPS_END(NAME, ARGS...) \
		return accel_dev->ops-> NAME (accel_dev, ARGS) ; \
	}

struct agiep_accel_ops {
	eth_rx_burst_t submit_rx_burst;
	eth_rx_burst_t back_rx_burst;
	eth_tx_burst_t submit_tx_burst;
	eth_tx_burst_t back_tx_burst;

	accel_configure_t configure;
	accel_start_t start;
	accel_stop_t stop;
	accel_close_t close;
	accel_infos_get_t infos_get;
	
	accel_rx_queue_setup_t rx_queue_setup_t;
	accel_tx_queue_setup_t tx_queue_setup_t;
	accel_queue_release_t  rx_queue_release_t;
	accel_queue_release_t  tx_queue_release_t;

	accel_vlan_filter_set_t vlan_filter_set; /**< Filter VLAN Setup. */
	accel_vlan_tpid_set_t vlan_tpid_set; /**< Outer/Inner VLAN TPID Setup. */
	accel_vlan_strip_queue_set_t vlan_strip_queue_set; /**< VLAN Stripping on queue. */
	accel_vlan_offload_set_t vlan_offload_set; /**< Set VLAN Offload. */
	accel_vlan_pvid_set_t vlan_pvid_set; /**< Set port based TX VLAN insertion. */

	accel_rss_hash_update_t rss_hash_update; /** Configure RSS hash protocols. */
	accel_rss_hash_conf_get_t rss_hash_conf_get; /** Get current RSS hash configuration. */
	accel_reta_update_t reta_update;   /** Update redirection table. */
	accel_reta_query_t reta_query;    /** Query redirection table. */

	accel_flow_ctrl_get_t flow_ctrl_get; /**< Get flow control. */
	accel_flow_ctrl_set_t flow_ctrl_set; /**< Setup flow control. */

	accel_filter_ctrl_t filter_ctrl; /**< common filter control. */
	accel_features_get_t features_get;
	accel_features_set_t features_set;
};


int agiep_accel_engine_register(struct agiep_accel *accel);

int accel_vlan_filter_set(struct agiep_accel_device *dev, uint16_t vlan_id, int on);
int accel_vlan_tpid_set(struct agiep_accel_device *dev, enum rte_vlan_type type, uint16_t tpid);
int accel_vlan_offload_set(struct agiep_accel_device *dev, int mask);
int accel_vlan_pvid_set(struct agiep_accel_device *dev, uint16_t vlan_id, int on);
void accel_vlan_strip_queue_set(struct agiep_accel_device *dev, uint16_t rx_queue_id, int on);
int accel_filter_ctrl(struct agiep_accel_device *dev, enum rte_filter_type filter_type, 
		enum rte_filter_op filter_op, void *arg);
int accel_reta_update(struct agiep_accel_device *dev, struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size);
int accel_reta_query(struct agiep_accel_device *dev, struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size);
int accel_rss_hash_update(struct agiep_accel_device *dev, struct rte_eth_rss_conf *rss_conf);
int accel_rss_hash_conf_get(struct agiep_accel_device *dev, struct rte_eth_rss_conf *rss_conf);
int accel_flow_ctrl_get(struct agiep_accel_device *dev, struct rte_eth_fc_conf *fc_conf);
int accel_flow_ctrl_set(struct agiep_accel_device *dev, struct rte_eth_fc_conf *fc_conf);
int agiep_accel_device_init(struct agiep_frep_device *frep_dev, struct agiep_accel *accel, struct eth_dev_ops *eth_ops);
struct agiep_accel *agiep_accel_engine_find(char *name);

#endif
