#include "agiep_frep.h"
#include "agiep_frep_task.h"

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = AGIEP_FREP_TASK_QUEUE_SIZE,
	.nb_min = AGIEP_FREP_TASK_QUEUE_SIZE,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = AGIEP_FREP_TASK_QUEUE_SIZE,
	.nb_min = AGIEP_FREP_TASK_QUEUE_SIZE,
	.nb_align = 8,
};

static uint16_t agiep_task_tx_pkt_burst(void *tx_queue __rte_unused, struct rte_mbuf **tx_pkts __rte_unused, uint16_t nb_pkts __rte_unused)
{
	return 0;
}

static uint16_t agiep_task_rx_pkt_burst(void *rx_queue __rte_unused, struct rte_mbuf **rx_pkts __rte_unused, uint16_t nb_pkts __rte_unused)
{
	return 0;
}

static int agiep_task_config(struct rte_eth_dev *eth_dev)
{
	if (eth_dev->data->nb_rx_queues != rte_lcore_count()) {
		RTE_LOG(ERR, PMD, "%s-%d: The number of rx queues must be equal to the number of cores:%d\n", __func__, __LINE__, rte_lcore_count());
		return -1;
	}
	return 0;
}

static int agiep_task_rx_queue_setup(struct rte_eth_dev *dev __rte_unused,
					uint16_t rx_queue_id __rte_unused,
					uint16_t nb_rx_desc __rte_unused,
					unsigned int socket_id __rte_unused,
					const struct rte_eth_rxconf *rx_conf __rte_unused,
					struct rte_mempool *mb_pool __rte_unused)
{
	return 0;
}

static void agiep_task_rx_queue_release(void *rxq __rte_unused)
{
	return;
}

static int agiep_task_tx_queue_setup(struct rte_eth_dev *dev __rte_unused,
					uint16_t tx_queue_id __rte_unused,
					uint16_t nb_tx_desc __rte_unused,
					unsigned int socket_id __rte_unused,
					const struct rte_eth_txconf *tx_conf __rte_unused)
{
	return 0;
}

static void agiep_task_tx_queue_release(void *txq __rte_unused)
{
	return;
}

static int agiep_task_dev_start(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static void agiep_task_dev_stop(struct rte_eth_dev *dev __rte_unused)
{
	return;
}

static void agiep_task_eth_dev_close(struct rte_eth_dev *eth_dev __rte_unused)
{
	return;
}

static int agiep_task_dev_info_get(__rte_unused struct rte_eth_dev *dev,
                            struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = (uint16_t)RTE_MAX_LCORE;
	dev_info->max_tx_queues = (uint16_t)RTE_MAX_LCORE;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->flow_type_rss_offloads = ETH_RSS_IP;
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_CHECKSUM;
	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM;
	return 0;
}

static int agiep_task_dev_linkupdate(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;

	link.link_status = ETH_LINK_UP;
	return rte_eth_linkstatus_set(dev, &link);
}

static int agiep_task_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused) 
{
	return 0;
}
static int agiep_task_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int agiep_task_dev_stats_get(struct rte_eth_dev *dev __rte_unused, struct rte_eth_stats *stats)
{
	memset(stats, 0, sizeof(struct rte_eth_stats));
	return 0;
}

static int agiep_task_dev_stats_reset(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static struct eth_dev_ops task_net_ops = {
	.dev_configure = agiep_task_config,
	.rx_queue_setup = agiep_task_rx_queue_setup,
	.rx_queue_release = agiep_task_rx_queue_release,
	.tx_queue_setup = agiep_task_tx_queue_setup,
	.tx_queue_release = agiep_task_tx_queue_release,
	.dev_start = agiep_task_dev_start,
	.dev_stop = agiep_task_dev_stop,
	.dev_close = agiep_task_eth_dev_close,
	.dev_infos_get = agiep_task_dev_info_get,
	.link_update = agiep_task_dev_linkupdate,
	.promiscuous_enable = agiep_task_dev_promiscuous_enable,
	.promiscuous_disable = agiep_task_dev_promiscuous_disable,
	.stats_get = agiep_task_dev_stats_get,
	.stats_reset = agiep_task_dev_stats_reset,
	.mtu_set = NULL,
};

static struct agiep_frep task_net_frep = {
	.ops = &task_net_ops,
	.rx_pkt_burst = agiep_task_rx_pkt_burst,
	.tx_pkt_burst = agiep_task_tx_pkt_burst,
	.type = AGIEP_FREP_TASK,
};

RTE_INIT(agiep_frep_task_net_init)
{
	agiep_frep_register(&task_net_frep);
}

