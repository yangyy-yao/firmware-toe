#include <assert.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <sys/mman.h>
#include "agiep_accel_engine.h"
#include "agiep_frep.h"

TAILQ_HEAD(agiep_accel_head, agiep_accel);
static struct agiep_accel_head agiep_accel_list =
	TAILQ_HEAD_INITIALIZER(agiep_accel_list);

static void accel_eth_back_tx_compensate(struct agiep_frep_queue *q, struct agiep_frep_device *frep_dev)
{
	struct agiep_frep *frep = frep_dev->frep;
	struct agiep_accel_device *dev = frep_dev->extra;
	struct rte_mbuf *tx_pkts[MAX_BURST_NUMBER] = {0};
	int tx_nb_backs, tx_nb_xmit, tx_nb_diff;
	struct rte_eth_dev_data *eth_data = q->dev->eth_dev->data;
	int i, n, qid;
	
	if (q->qid + 1 > eth_data->nb_tx_queues)
		return;

	n = eth_data->nb_tx_queues / eth_data->nb_rx_queues;

	for(i = 0; i <= n; i++) {
		qid = q->qid + eth_data->nb_rx_queues * i;

		if (qid + 1 > eth_data->nb_tx_queues)
			break;
		
		tx_nb_backs = dev->ops->back_tx_burst(eth_data->tx_queues[qid], tx_pkts, MAX_BURST_NUMBER);
		if (!tx_nb_backs)
			continue;
		
		tx_nb_xmit = frep->tx_pkt_burst(eth_data->tx_queues[qid], tx_pkts, tx_nb_backs);
		tx_nb_diff = tx_nb_backs - tx_nb_xmit;
		if (tx_nb_diff > 0)
			rte_pktmbuf_free_bulk(&tx_pkts[tx_nb_xmit], tx_nb_diff);
	}

	return;
}

static uint16_t accel_eth_rx(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = rxq;
	struct agiep_frep_device *frep_dev = NULL;
	struct agiep_accel_device *dev = NULL;
	struct agiep_frep *frep = NULL;
	struct rte_mbuf *pkts[MAX_BURST_NUMBER];
	int nb_backs, nb_recv, nb_accel;
	uint16_t nb_rx_pkts;

	if (NULL == q)
		return 0;
		
	frep_dev = q->dev;
	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}

	dev = frep_dev->extra;
	if (!dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep eth dev!\n", __func__, __LINE__);
		return 0;
	}
	
	frep = frep_dev->frep;

	nb_rx_pkts = RTE_MIN(nb_pkts, MAX_BURST_NUMBER);
	nb_recv = frep->rx_pkt_burst(rxq, pkts, nb_rx_pkts);
	if (nb_recv > 0) {
		nb_accel = dev->ops->submit_rx_burst(q, pkts, nb_recv);
		if (nb_accel < nb_recv)
			rte_pktmbuf_free_bulk(&pkts[nb_accel], nb_recv - nb_accel);
	}

	nb_backs = dev->ops->back_rx_burst(q, rx_pkts, nb_pkts);

	if (dev->tx_compensate_enable == 1)
		accel_eth_back_tx_compensate(q, frep_dev);
	
	return nb_backs;
}

static uint16_t accel_eth_tx(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = txq;
	struct agiep_frep_device *frep_dev = NULL;
	struct agiep_accel_device *dev = NULL;
	struct agiep_frep *frep = NULL;
	struct rte_mbuf *pkts[MAX_BURST_NUMBER];
	int nb_backs, nb_accel = 0;
	uint16_t nb_xmit, nb_tx_pkts;

	if (NULL == q)
		return 0;
		
	frep_dev = q->dev;
	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}

	dev = frep_dev->extra;
	if (!dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep eth dev!\n", __func__, __LINE__);
		return 0;
	}

	frep = frep_dev->frep;

	do {
		nb_tx_pkts = RTE_MIN(nb_pkts, MAX_BURST_NUMBER);
		nb_pkts = (nb_pkts > MAX_BURST_NUMBER) ? (nb_pkts - MAX_BURST_NUMBER) : 0;
		
		nb_accel += dev->ops->submit_tx_burst(q, &tx_pkts[nb_accel], nb_tx_pkts);
		nb_backs = dev->ops->back_tx_burst(q, pkts, MAX_BURST_NUMBER);
		if (!nb_backs)
			continue;
		
		nb_xmit = frep->tx_pkt_burst(txq, pkts, nb_backs);
		if (nb_xmit < nb_backs)
			rte_pktmbuf_free_bulk(&pkts[nb_xmit], nb_backs - nb_xmit);

	} while (nb_pkts > 0);
	
	return nb_accel;
}

static int agiep_accel_eth_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = eth_dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	if (accel_dev->ops->configure) {
		ret = accel_dev->ops->configure(accel_dev);
		if (ret) {
			RTE_LOG(ERR, PMD, "%s-%d:accel configure failed! \n", __func__, __LINE__);
			return ret;
		}
	}
	
	return accel_dev->frep_ops.dev_configure(eth_dev);
}

static int agiep_accel_eth_dev_start(struct rte_eth_dev *eth_dev)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = eth_dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return -1;
	}

	if (accel_dev->ops->start) {
		ret = accel_dev->ops->start(accel_dev);
		if (ret) {
			RTE_LOG(ERR, PMD, "%s-%d:accel dev start failed! \n", __func__, __LINE__);
			return ret;
		}
	}
	return accel_dev->frep_ops.dev_start(eth_dev);
}

static void agiep_accel_eth_dev_close(struct rte_eth_dev *eth_dev)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = eth_dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return;
	}
		
	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return;
	}
	
	if (accel_dev->ops->close) {
		ret = accel_dev->ops->close(accel_dev);
		assert(ret == 0);
	}
	accel_dev->frep_ops.dev_close(eth_dev);

	frep_dev->extra = NULL;
	rte_free(accel_dev);
	return;
}

static int agiep_accel_eth_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return -1;
	}

	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return -1;
	}

	if (accel_dev->ops->infos_get) {
		ret = accel_dev->ops->infos_get(dev_info);
		if (ret) {
			RTE_LOG(ERR, PMD, "%s-%d:accel dev infos get failed! \n", __func__, __LINE__);
			return ret;
		}
	}
	return accel_dev->frep_ops.dev_infos_get(dev, dev_info);
}

static int agiep_accel_eth_dev_rx_queue_setup(struct rte_eth_dev *dev,
						uint16_t rx_queue_id,
						uint16_t nb_rx_desc,
						unsigned int socket_id,
						const struct rte_eth_rxconf *rx_conf,
						struct rte_mempool *mb_pool)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return -1;
	}

	if (accel_dev->ops->rx_queue_setup_t) {
	   	ret = accel_dev->ops->rx_queue_setup_t(accel_dev, rx_queue_id, nb_rx_desc, mb_pool);
		if (ret) {
			RTE_LOG(ERR, PMD, "%s-%d:accel rx queue setup failed! \n", __func__, __LINE__);
			return ret;
		}
	}
 	return accel_dev->frep_ops.rx_queue_setup(dev, rx_queue_id, nb_rx_desc, socket_id, rx_conf, mb_pool);
}

static int agiep_accel_eth_dev_tx_queue_setup(struct rte_eth_dev *dev,
						uint16_t tx_queue_id,
						uint16_t nb_tx_desc,
						unsigned int socket_id,
						const struct rte_eth_txconf *tx_conf)
{
	struct agiep_frep_device *frep_dev = NULL; 
	struct agiep_accel_device *accel_dev = NULL;
	int ret;

	frep_dev = dev->data->dev_private;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
		
	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return -1;
	}
	
	if (accel_dev->ops->tx_queue_setup_t) {
	   	ret = accel_dev->ops->tx_queue_setup_t(accel_dev, tx_queue_id, nb_tx_desc);
		if (ret) {
			RTE_LOG(ERR, PMD, "%s-%d:accel tx queue setup failed! \n", __func__, __LINE__);
			return ret;
		}
	}
 	return accel_dev->frep_ops.tx_queue_setup(dev, tx_queue_id, nb_tx_desc, socket_id, tx_conf);
}

static void agiep_accel_eth_dev_rx_queue_release(void *rxq)
{
	struct agiep_frep_queue *q = rxq;
	struct agiep_frep_device *frep_dev = NULL;
	struct agiep_accel_device *accel_dev = NULL;

	if (q == NULL)
		return;
	
	frep_dev = q->dev;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return;
	}

	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return;
	}

	if (accel_dev->ops->rx_queue_release_t)
   		accel_dev->ops->rx_queue_release_t(q);

	accel_dev->frep_ops.rx_queue_release(rxq);
	return;
}

static void agiep_accel_eth_dev_tx_queue_release(void *txq)
{
	struct agiep_frep_queue *q = txq;
	struct agiep_frep_device *frep_dev = NULL;
	struct agiep_accel_device *accel_dev = NULL;

	if (q == NULL)
		return;

	frep_dev = q->dev;
	if (!frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:frep_dev already not exist! \n", __func__, __LINE__);
		return;
	}

	accel_dev = frep_dev->extra;
	if (!accel_dev) {
		RTE_LOG(ERR, PMD, "%s-%d:accel dev already not exist! \n", __func__, __LINE__);
		return;
	}

	if (accel_dev->ops->tx_queue_release_t)
   		accel_dev->ops->tx_queue_release_t(q);

	accel_dev->frep_ops.tx_queue_release(txq);
	return;
}

int agiep_accel_device_init(struct agiep_frep_device *frep_dev, struct agiep_accel *accel, struct eth_dev_ops *eth_ops)
{
	struct agiep_accel_device *accel_dev = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	
	accel_dev = rte_zmalloc("AGIEP_ACCEL_ENGINE", sizeof(*accel_dev), 0);

	if (accel_dev == NULL)
		return -1;

	if (accel->agiep_accel_module_init) {
		if (0 != accel->agiep_accel_module_init(accel_dev)) {
			RTE_LOG(ERR, PMD, "%s-%d: agiep_accel_module_init failed!\n", __func__, __LINE__);
			goto failed;
		}
	}

	accel_dev->dev = frep_dev;
	frep_dev->extra = accel_dev;
	accel_dev->ops = accel->ops;
	accel_dev->frep_ops = *frep_dev->frep->ops;

	eth_dev = frep_dev->eth_dev;
	eth_dev->rx_pkt_burst = accel_eth_rx;
	eth_dev->tx_pkt_burst = accel_eth_tx;
	eth_dev->data->lro = 0;

	eth_ops->dev_configure = agiep_accel_eth_dev_configure;
	eth_ops->dev_start = agiep_accel_eth_dev_start;
	eth_ops->dev_close = agiep_accel_eth_dev_close;
	eth_ops->dev_infos_get = agiep_accel_eth_dev_infos_get;
	eth_ops->rx_queue_setup = agiep_accel_eth_dev_rx_queue_setup;
	eth_ops->tx_queue_setup = agiep_accel_eth_dev_tx_queue_setup;
	eth_ops->rx_queue_release = agiep_accel_eth_dev_rx_queue_release;
	eth_ops->tx_queue_release = agiep_accel_eth_dev_tx_queue_release;

	return 0;
failed:
	if (accel_dev)
		rte_free(accel_dev);
	
	return -1;
}
/*
TO_ACCEL_OPS_START(int, vlan_filter_set, uint16_t vlan_id, int on)
TO_ACCEL_OPS_END(vlan_filter_set, vlan_id, on)
TO_ACCEL_OPS_START(int, vlan_tpid_set, enum rte_vlan_type type, uint16_t tpid)
TO_ACCEL_OPS_END(vlan_tpid_set,type, tpid)

TO_ACCEL_OPS_START(int, vlan_offload_set, int mask)
TO_ACCEL_OPS_END(vlan_offload_set, mask)

TO_ACCEL_OPS_START(int, vlan_pvid_set, uint16_t vlan_id, int on)
TO_ACCEL_OPS_END(vlan_pvid_set, vlan_id, on)

TO_ACCEL_OPS_START(void, vlan_strip_queue_set, uint16_t rx_queue_id, int on)
TO_ACCEL_OPS_END(vlan_strip_queue_set, rx_queue_id, on)

TO_ACCEL_OPS_START(int, filter_ctrl, enum rte_filter_type filter_type,
		enum rte_filter_op filter_op, void *arg)
TO_ACCEL_OPS_END(filter_ctrl, filter_type, filter_op, arg)

TO_ACCEL_OPS_START(int, reta_update, struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
TO_ACCEL_OPS_END(reta_update, reta_conf, reta_size)
TO_ACCEL_OPS_START(int, reta_query, struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
TO_ACCEL_OPS_END(reta_query, reta_conf, reta_size)
TO_ACCEL_OPS_START(int, rss_hash_update, struct rte_eth_rss_conf *rss_conf)
TO_ACCEL_OPS_END(rss_hash_update, rss_conf)
TO_ACCEL_OPS_START(int, rss_hash_conf_get, struct rte_eth_rss_conf *rss_conf)
TO_ACCEL_OPS_END(rss_hash_conf_get, rss_conf)
TO_ACCEL_OPS_START(int, flow_ctrl_get, struct rte_eth_fc_conf *fc_conf)
TO_ACCEL_OPS_END(flow_ctrl_get, fc_conf)
TO_ACCEL_OPS_START(int, flow_ctrl_set, struct rte_eth_fc_conf *fc_conf)
TO_ACCEL_OPS_END(flow_ctrl_set, fc_conf)
*/

int agiep_accel_engine_register(struct agiep_accel *accel)
{
	TAILQ_INSERT_TAIL(&agiep_accel_list, accel, next);
	return 0;
}

struct agiep_accel *agiep_accel_engine_find(char *name)
{
	struct agiep_accel *accel;
	TAILQ_FOREACH(accel, &agiep_accel_list, next) {
		if (!strcmp(accel->name, name))
			return accel;
	}
	return NULL;
}

