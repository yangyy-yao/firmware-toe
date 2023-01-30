#include <assert.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include "agiep_frep.h"
#include "agiep_frep_loopback_net.h"

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = AGIEP_FREP_LO_QUEUE_SIZE,
	.nb_min = AGIEP_FREP_LO_QUEUE_SIZE,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = AGIEP_FREP_LO_QUEUE_SIZE,
	.nb_min = AGIEP_FREP_LO_QUEUE_SIZE,
	.nb_align = 8,
};

static int loopback_config(struct rte_eth_dev *eth_dev)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_frep_loopback_device *lo_dev = NULL;
	char name[25] = {0};
	uint16_t q_num = 0;
	int i;
	
	frep_dev = eth_dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep dev already not exist! \n", __func__, __LINE__);
		goto failed;
	}
	
	lo_dev = rte_calloc(NULL, 1, sizeof(struct agiep_frep_loopback_device), 0);
	if (!lo_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:,frep pf%dvf%d loopback dev malloc failed!\n", __func__, __LINE__, frep_dev->pf, frep_dev->vf);
		goto failed;
	}
	
	q_num = frep_dev->queues;
	lo_dev->lo_q = rte_calloc(NULL, q_num, sizeof(struct frep_loopback_queue *), 0);
	if (!lo_dev->lo_q) {
		RTE_LOG(ERR, PMD, "%s-%d:,frep lo_q malloc failed! queue num:%d\n", __func__, __LINE__, q_num);
		goto failed;
	}

	for (i = 0; i < q_num; i ++) {
		lo_dev->lo_q[i] = rte_calloc(NULL, 1, sizeof(struct frep_loopback_queue), 0);
		if (!lo_dev->lo_q[i]) {
			RTE_LOG(ERR, PMD, "%s-%d:,frep lo_q[%d] malloc failed!\n", __func__, __LINE__, i);
			goto failed;
		}
		
		snprintf(name, sizeof(name), "frep_pf%dvf%d_lo_ring%d", frep_dev->pf, frep_dev->vf, i);
		lo_dev->lo_q[i]->lo_ring = rte_ring_create(name, AGIEP_FREP_LO_QUEUE_SIZE, SOCKET_ID_ANY, RTE_CACHE_LINE_SIZE);
		if (!lo_dev->lo_q[i]->lo_ring) {
			RTE_LOG(ERR, PMD, "%s-%d:,frep loopback queue[%d] malloc failed!\n", __func__, __LINE__, i);
			goto failed;
		}
		
		lo_dev->lo_q[i]->fq.dev = NULL;
		lo_dev->lo_q[i]->fq.qid = -1;
	}

	lo_dev->queue_num = q_num;
	frep_dev->dev = lo_dev;
	return 0;

failed:
	
	if (lo_dev->lo_q) {
		for (i = 0; i < q_num; i ++) {
			if (!lo_dev->lo_q[i])
				continue;
			
			if (lo_dev->lo_q[i]->lo_ring) {
				rte_ring_free(lo_dev->lo_q[i]->lo_ring);
				lo_dev->lo_q[i]->lo_ring = NULL;
			}
			rte_free(lo_dev->lo_q[i]);
			lo_dev->lo_q[i] = NULL;
		}
		rte_free(lo_dev->lo_q);
	}
	
	if (lo_dev)
		rte_free(lo_dev);
	
	return -1;
}

static int loopback_rx_queue_setup(struct rte_eth_dev *dev,
					uint16_t rx_queue_id,
					uint16_t nb_rx_desc __rte_unused,
					unsigned int socket_id __rte_unused,
					const struct rte_eth_rxconf *rx_conf __rte_unused,
					struct rte_mempool *mb_pool __rte_unused)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_frep_loopback_device *lo_dev = NULL;

	frep_dev = (struct agiep_frep_device *)dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	lo_dev = (struct agiep_frep_loopback_device *)frep_dev->dev;
	if (!lo_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:loopback dev already not exist! \n", __func__, __LINE__);
		return -1;
	}

	lo_dev->lo_q[rx_queue_id]->fq.qid = rx_queue_id;
	lo_dev->lo_q[rx_queue_id]->fq.dev = frep_dev;
	dev->data->rx_queues[rx_queue_id] = lo_dev->lo_q[rx_queue_id];
	
	return 0;
}

static void loopback_rx_queue_release(void *rxq)
{
	struct frep_loopback_queue *q = rxq;

	if (!q) {
		RTE_LOG(ERR, PMD, "%s-%d:frep loopback rx queue already not exist! \n", __func__, __LINE__);
		return;
	}
	
	q->fq.dev = NULL;
	q->fq.qid = -1;
	return;
}

static int loopback_tx_queue_setup(struct rte_eth_dev *dev,
					uint16_t tx_queue_id,
					uint16_t nb_tx_desc __rte_unused,
					unsigned int socket_id __rte_unused,
					const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_frep_loopback_device *lo_dev = NULL;

	frep_dev = dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
		
	lo_dev = (struct agiep_frep_loopback_device *)frep_dev->dev;
	if (!lo_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:loopback dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	lo_dev->lo_q[tx_queue_id]->fq.qid = tx_queue_id;
	lo_dev->lo_q[tx_queue_id]->fq.dev = frep_dev;
	dev->data->tx_queues[tx_queue_id] = lo_dev->lo_q[tx_queue_id];
	
	return 0;
}

static void loopback_tx_queue_release(void *txq)
{
	struct frep_loopback_queue *q = txq;

	if (!q) {
		RTE_LOG(ERR, PMD, "%s-%d:frep loopback tx queue already not exist! \n", __func__, __LINE__);
		return;
	}
	
	q->fq.dev = NULL;
	q->fq.qid = -1;
	return;
}

static int loopback_dev_start(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static void loopback_dev_stop(struct rte_eth_dev *dev __rte_unused)
{
	return;
}

static void loopback_eth_dev_close(struct rte_eth_dev *eth_dev)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_frep_loopback_device *lo_dev = NULL;	
	int i;

	frep_dev = eth_dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep dev already not exist! \n", __func__, __LINE__);
		return;
	}

	lo_dev = frep_dev->dev;
	if (!lo_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:loopback dev already not exist! \n", __func__, __LINE__);
		return;
	}

	frep_dev->dev = NULL;
	
	if (lo_dev->lo_q) {
		for (i = 0; i < lo_dev->queue_num; i ++) {
			if (!lo_dev->lo_q[i])
				continue;
			
			if (lo_dev->lo_q[i]->lo_ring) {
				rte_ring_free(lo_dev->lo_q[i]->lo_ring);
				lo_dev->lo_q[i]->lo_ring = NULL;
			}
			rte_free(lo_dev->lo_q[i]);
			lo_dev->lo_q[i] = NULL;
		}
		rte_free(lo_dev->lo_q);
	}

	rte_free(lo_dev);
	return;
}

static int loopback_dev_info_get(struct rte_eth_dev *dev,
                            struct rte_eth_dev_info *dev_info)
{
	struct agiep_frep_device *fdev = dev->data->dev_private;
	dev_info->max_rx_queues = (uint16_t)fdev->queues;
	dev_info->max_tx_queues = (uint16_t)fdev->queues;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->flow_type_rss_offloads = ETH_RSS_IP;
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_CHECKSUM;
	return 0;
}

static int loopback_dev_linkupdate(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_speed  = ETH_SPEED_NUM_10G;
	link.link_autoneg = ETH_LINK_FIXED;

	return rte_eth_linkstatus_set(dev, &link);
}

static int loopback_dev_promiscuous_enable(struct rte_eth_dev *dev) 
{
	dev->data->promiscuous = 1;
	return 0;
}
static int loopback_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	dev->data->promiscuous = 0;
	return 0;
}

static int loopback_dev_stats_get(struct rte_eth_dev *dev __rte_unused, struct rte_eth_stats *stats)
{
	memset(stats, 0, sizeof(struct rte_eth_stats));
	return 0;
}

static int loopback_dev_stats_reset(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static struct eth_dev_ops loopback_net_ops = {
	.dev_configure = loopback_config,
	.rx_queue_setup = loopback_rx_queue_setup,
	.rx_queue_release = loopback_rx_queue_release,
	.tx_queue_setup = loopback_tx_queue_setup,
	.tx_queue_release = loopback_tx_queue_release,
	.dev_start = loopback_dev_start,
	.dev_stop = loopback_dev_stop,
	.dev_close = loopback_eth_dev_close,
	.dev_infos_get = loopback_dev_info_get,
	.link_update = loopback_dev_linkupdate,
	.promiscuous_enable = loopback_dev_promiscuous_enable,
	.promiscuous_disable = loopback_dev_promiscuous_disable,
	.stats_get = loopback_dev_stats_get,
	.stats_reset = loopback_dev_stats_reset,
	.mtu_set = NULL,
};

static struct agiep_frep loopback_net_frep = {
	.ops = &loopback_net_ops,
	.rx_pkt_burst = agiep_frep_loopback_rx_pkt_burst,
	.tx_pkt_burst = agiep_frep_loopback_tx_pkt_burst,
	.type = AGIEP_FREP_LOOPBACK,
};

RTE_INIT(agiep_frep_loopback_net_init)
{
	agiep_frep_register(&loopback_net_frep);
}

