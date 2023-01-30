#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include <rte_cycles.h>
#include <agiep_pci.h>

#include <toe_dev.h>
//#include "toe_engine.h"
#include <toe_pcie.h>
//#include "toe_dma.h"


static const char *valid_arguments[] = {
	ETH_TOE_PF,
	ETH_TOE_VF,
	ETH_TOE_QUEUES,
	ETH_TOE_CTRL_QUEUES,
	ETH_TOE_MAC,
	FREP_QUEUES,
	NULL
};
struct toe_device *toe_net_dev = NULL;

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = TOE_MAX_RQ_SIZE,
	.nb_min = TOE_MAX_RQ_SIZE,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = TOE_MAX_RQ_SIZE,
	.nb_min = TOE_MAX_RQ_SIZE,
	.nb_align = 8,
};
/*
static int toe_ctl_pkt_mempool_create(struct toe_device *toe_dev)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	uint32_t elt_size;

	snprintf(name, sizeof(name),
			"toe_ctl_%d_%lx", toe_dev->eth_dev->data->port_id, rte_rdtsc());

	elt_size = sizeof(struct toe_ctl_pkt_msg);

	// 目前只有一个NUMA: 0
	mp = rte_mempool_create(name, CTRL_PKT_MAX_DESC,
			elt_size,
			CTRL_PKT_CACHE_DESC, 0, NULL, NULL, NULL,
			NULL, SOCKET_ID_ANY, 0);

	if (mp == NULL) {
		RTE_LOG(ERR, PMD,
				"mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	toe_dev->ctlpkt_pool = mp;	
	
	return 0;
}
*/
static int toe_net_configure(struct rte_eth_dev *eth_dev)
{
	struct toe_device *toe_dev;
	struct toe_rx_queue **p_data_rxq = NULL;
//	struct toe_rx_queue **p_ctl_rxq = NULL;
//	struct toe_tx_ctl_queue **p_ctl_txq = NULL;
	
	toe_dev = eth_dev->data->dev_private;

	if (eth_dev->data->nb_rx_queues > toe_dev->queues
		|| eth_dev->data->nb_tx_queues > toe_dev->queues) {
		//printf("%s-%d: eth_dev rx/tx queues more than toe queues\n", __func__, __LINE__);
		goto fail;
	}
	//printf("~~ %s-%d:eth_dev->data->nb_rx_queues:%d, toe_dev->ctrl_queues:%d\n",__func__,__LINE__,eth_dev->data->nb_rx_queues,toe_dev->ctrl_queues);
	p_data_rxq = rte_calloc(NULL, toe_dev->data_queues, sizeof(struct toe_rx_queue *), RTE_CACHE_LINE_SIZE);
	if (p_data_rxq == NULL)
		goto fail;
	
#if 0
	p_ctl_rxq = rte_calloc(NULL, toe_dev->ctrl_queues, sizeof(struct toe_rx_queue *), RTE_CACHE_LINE_SIZE);
	if (p_ctl_rxq == NULL)
		goto fail;

	p_ctl_txq = rte_calloc(NULL, toe_dev->queues, sizeof(struct toe_tx_ctl_queue *), RTE_CACHE_LINE_SIZE);
	if (p_ctl_txq == NULL)
		goto fail;
#endif
//	toe_dev->ctl_rxq = p_ctl_rxq;
//	toe_dev->ctl_txq = p_ctl_txq;

	toe_dev->data_rxq = p_data_rxq;
	

	if (toe_engine_init(toe_dev))
		goto fail;
/*
	if (toe_ctl_pkt_mempool_create(toe_dev))
		goto fail;
	*/
	return 0;

fail:
	if(p_data_rxq) {
		rte_free(p_data_rxq);
	}
#if 0
	if (p_ctl_rxq)
		rte_free(p_ctl_rxq);
	
	if (p_ctl_txq)
		rte_free(p_ctl_txq);
#endif
	return -1;
}

static int toe_rx_queue_setup(struct rte_eth_dev *dev,
						uint16_t rx_queue_id,
						uint16_t nb_rx_desc,
						__rte_unused unsigned int socket_id,
						__rte_unused const struct rte_eth_rxconf *rx_conf,
						struct rte_mempool *mb_pool)
{
	struct toe_device *toe_dev = dev->data->dev_private;
	char ring_name[RTE_RING_NAMESIZE];
	int data_qid;

	//printf("%s-%d:rx_queue_id:%d \n",__func__,__LINE__,rx_queue_id);

		data_qid = rx_queue_id;
		toe_dev->data_rxq[data_qid] = rte_calloc(NULL, 1, sizeof(struct toe_rx_queue), RTE_CACHE_LINE_SIZE);
		if (toe_dev->data_rxq[data_qid] == NULL)
			goto fail;

		snprintf(ring_name, sizeof(ring_name), "toe_rxq_%d_%d", dev->data->port_id, data_qid);
		toe_dev->data_rxq[data_qid]->rxq = rte_ring_create(ring_name, nb_rx_desc, SOCKET_ID_ANY, 0);
		if (!toe_dev->data_rxq[data_qid]->rxq)
			goto fail;

		toe_dev->data_rxq[data_qid]->idx = data_qid;
		toe_dev->data_rxq[data_qid]->nb_rx_desc = nb_rx_desc;
		toe_dev->data_rxq[data_qid]->toe_eg = toe_dev->toe_eg;
		toe_dev->data_rxq[data_qid]->pkt_pool = mb_pool;
		
		//printf("%s-%d:toe_dev->data_rxq[rx_queue_id]:%p,toe_dev->data_rxq[rx_queue_id]->toe_eg:%p\n",__func__,__LINE__,toe_dev->data_rxq[data_qid],toe_dev->data_rxq[data_qid]->toe_eg);

		dev->data->rx_queues[rx_queue_id] = toe_dev->data_rxq[data_qid];
		dev->data->tx_queues[rx_queue_id] = toe_dev->data_rxq[data_qid];
		
		return 0;
#if 0
/****************ctl****************/
	if (rx_queue_id + 1 > toe_dev->ctrl_queues)
		return 0;
	
	toe_dev->ctl_rxq[rx_queue_id] = rte_calloc(NULL, 1, sizeof(struct toe_rx_queue), RTE_CACHE_LINE_SIZE);
	if (toe_dev->ctl_rxq[rx_queue_id] == NULL)
		goto fail;

	snprintf(ring_name, sizeof(ring_name), "toe_crxq_%d_%d", dev->data->port_id, rx_queue_id);
	//toe_dev->ctl_rxq[rx_queue_id]->rxq = rte_ring_create(ring_name, nb_rx_desc, SOCKET_ID_ANY, 0);
	toe_dev->ctl_rxq[rx_queue_id]->rxq = toe_dev->data_rxq[rx_queue_id]->rxq;
	if (!toe_dev->ctl_rxq[rx_queue_id]->rxq)
		goto fail;

	toe_dev->ctl_rxq[rx_queue_id]->real_idx = rx_queue_id;
	toe_dev->ctl_rxq[rx_queue_id]->idx = rx_queue_id;
	toe_dev->ctl_rxq[rx_queue_id]->nb_rx_desc = nb_rx_desc;
	toe_dev->ctl_rxq[rx_queue_id]->toe_eg = toe_dev->toe_eg;
	toe_dev->ctl_rxq[rx_queue_id]->pkt_pool = mb_pool;

	//dev->data->rx_queues[rx_queue_id] = toe_dev->ctl_rxq[rx_queue_id];
	printf("%s-%d:toe_dev->ctl_rxq[rx_queue_id]:%p,toe_dev->ctl_rxq[rx_queue_id]->toe_eg:%p \n",__func__,__LINE__,toe_dev->ctl_rxq[rx_queue_id],toe_dev->ctl_rxq[rx_queue_id]->toe_eg);


	//dev->data->rx_queues[rx_queue_id] = toe_dev;


	return 0;
#endif
fail:
	if (toe_dev->data_rxq[rx_queue_id]) {
		if (toe_dev->data_rxq[rx_queue_id]->rxq)
			rte_ring_free(toe_dev->data_rxq[rx_queue_id]->rxq);
		rte_free(toe_dev->data_rxq[rx_queue_id]);
		toe_dev->data_rxq[rx_queue_id] = NULL;
	}
	return -1;

#if 0
/****************ctl************/
	if (toe_dev->ctl_rxq[rx_queue_id]) {
		//if (toe_dev->ctl_rxq[rx_queue_id]->rxq)
			//rte_ring_free(toe_dev->ctl_rxq[rx_queue_id]->rxq);
		rte_free(toe_dev->ctl_rxq[rx_queue_id]);
		toe_dev->ctl_rxq[rx_queue_id] = NULL;
	}

	return -1;
#endif 
}

static void toe_rx_queue_release(void *rxq)
{
	struct toe_rx_queue *t_rxq = rxq;

	int idx = t_rxq->idx;
	//struct toe_device *toe_dev = rxq;
	//struct toe_engine *toe_eg = toe_dev->toe_eg;
	struct toe_engine *toe_eg = t_rxq->toe_eg;
	struct toe_device *toe_dev = toe_eg->t_dev;

#if 0
	if (idx + 1 <= toe_dev->ctrl_queues) {
		
		printf("$### %s-%d: t_rxq->idx:%d\n",__func__,__LINE__,idx); 
		
		if (toe_dev->ctl_rxq[idx]) {
			if (toe_dev->ctl_rxq[idx]->rxq)
				rte_ring_free(toe_dev->ctl_rxq[idx]->rxq);
			rte_free(toe_dev->ctl_rxq[idx]);
		}
		toe_dev->ctl_rxq[idx] = NULL;
	}
#endif	
	//printf("$### %s-%d: data t_rxq->idx:%d\n",__func__,__LINE__,idx);	

	if (toe_dev->data_rxq[idx]) {
		if (toe_dev->data_rxq[idx]->rxq)
			rte_ring_free(toe_dev->data_rxq[idx]->rxq);
		rte_free(toe_dev->data_rxq[idx]);
	}
	toe_dev->data_rxq[idx] = NULL;

	//printf("$###22 %s-%d: release done\n",__func__,__LINE__);
	return;
}

static int toe_tx_queue_setup(__rte_unused struct rte_eth_dev *dev,
						__rte_unused uint16_t tx_queue_id,
						__rte_unused uint16_t nb_tx_desc,
						__rte_unused unsigned int socket_id,
						__rte_unused const struct rte_eth_txconf *tx_conf)
{
#if 0
	struct toe_device *toe_dev = dev->data->dev_private;
	char ring_name[RTE_RING_NAMESIZE];

	//if (tx_queue_id >= toe_dev->ctrl_queues)
		//return 0;
	
	toe_dev->ctl_txq[tx_queue_id] = rte_calloc(NULL, 1, sizeof(struct toe_tx_ctl_queue), RTE_CACHE_LINE_SIZE);
	if (toe_dev->ctl_txq[tx_queue_id] == NULL)
		goto fail;

	snprintf(ring_name, sizeof(ring_name), "toe_txq_%d_%d", dev->data->port_id, tx_queue_id);
	toe_dev->ctl_txq[tx_queue_id]->txq = rte_ring_create(ring_name, nb_tx_desc, SOCKET_ID_ANY, 0);
	if (!toe_dev->ctl_txq[tx_queue_id]->txq)
		goto fail;

	toe_dev->ctl_txq[tx_queue_id]->idx = tx_queue_id;
	toe_dev->ctl_txq[tx_queue_id]->data_idx = -1;
	toe_dev->ctl_txq[tx_queue_id]->nb_tx_desc = nb_tx_desc;
	toe_dev->ctl_txq[tx_queue_id]->toe_eg = toe_dev->toe_eg;
	if (tx_queue_id >= toe_dev->ctrl_queues)
		toe_dev->ctl_txq[tx_queue_id]->data_idx = tx_queue_id - toe_dev->ctrl_queues;

	dev->data->tx_queues[tx_queue_id] = toe_dev->ctl_txq[tx_queue_id];

	return 0;
fail:

/****************ctl************/
	if (toe_dev->ctl_txq[tx_queue_id]) {
		if (toe_dev->ctl_txq[tx_queue_id]->txq)
			rte_ring_free(toe_dev->ctl_txq[tx_queue_id]->txq);
		rte_free(toe_dev->ctl_txq[tx_queue_id]);
		toe_dev->ctl_txq[tx_queue_id] = NULL;
	}

	return -1;
	#endif
    return 0;
}

static int toe_dev_start(struct rte_eth_dev *dev)
{
	struct toe_device *toe_dev = dev->data->dev_private;
	struct toe_bar_base_cfg *base_cfg;
	uint16_t lcore_id;
	struct mtcp_manager *mtcp;
	int idx = 0;

	base_cfg = toe_base_bar_get((uint8_t *)toe_dev->toe_eg->bar);

	base_cfg->msg_queue_num = toe_dev->ctrl_queues;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		
			mtcp = g_mtcp[lcore_id];

			mtcp->ctx->io_private_context = toe_dev->data_rxq[idx];
		//printf("%s-%d:lcore_id:%d, mtcp:%p,idx:%d,mtcp->ctx->io_private_context:%p\n",__func__,__LINE__,lcore_id, mtcp,idx,mtcp->ctx->io_private_context);
			idx ++;
			if (idx == toe_dev->queues)
				break;
	}
	toe_dev->enable = 1;
	return 0;
}

static void toe_dev_stop(struct rte_eth_dev *dev)
{
	struct toe_device *toe_dev = dev->data->dev_private;

	toe_dev->enable = 0;
	return;
}

static void toe_dev_close(struct rte_eth_dev *dev)
{
	struct toe_device *toe_dev = dev->data->dev_private;
	toe_dev->enable = 0;

    //printf("**&&&  %s-%d: close engine free start\n",__func__,__LINE__);
	toe_engine_free(toe_dev);
	rte_free(toe_dev->data_rxq);
	rte_free(toe_dev->ctl_rxq);
//	rte_free(toe_dev->ctl_txq);
	   //printf("**&&&222  %s-%d: close done\n",__func__,__LINE__);
	return;
}

static int toe_dev_info_get(__rte_unused struct rte_eth_dev *dev,
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

static int toe_dev_linkupdate(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;

	link.link_status = ETH_LINK_UP;
	return rte_eth_linkstatus_set(dev, &link);
}

static struct eth_dev_ops toe_net_ops = {
	.dev_configure = toe_net_configure,
	.rx_queue_setup = toe_rx_queue_setup,
	.rx_queue_release = toe_rx_queue_release,
	.tx_queue_setup = toe_tx_queue_setup,
	//.tx_queue_release = toe_tx_queue_release,
	.dev_start = toe_dev_start,
	.dev_stop = toe_dev_stop,
	.dev_close = toe_dev_close,
	.dev_infos_get = toe_dev_info_get,
	.link_update = toe_dev_linkupdate,
};
	

static int
eth_dev_toe_create(struct rte_vdev_device *dev, int pf, int vf, int queues, int ctrl_queues, int f_queues, struct rte_ether_addr *mac, struct rte_kvargs *kvlist)
{
	struct toe_device *toe_dev = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct rte_ether_addr *eth_addr = NULL;

	struct rte_eth_dev_data *data = NULL;

	eth_dev = rte_eth_vdev_allocate(dev, sizeof(*toe_dev));
	if (eth_dev == NULL)
		goto error;

	eth_addr = rte_zmalloc_socket(rte_vdev_device_name(dev), sizeof(*eth_addr),
							   0, rte_socket_id());
	if (eth_addr == NULL)
		goto error;
	*eth_addr = *mac;
	data = eth_dev->data;
	data->mac_addrs = eth_addr;
	
	eth_dev->dev_ops = &toe_net_ops;

	eth_dev->rx_pkt_burst = toe_rx_pkt_burst;
	eth_dev->tx_pkt_burst = toe_tx_pkt_burst;

	toe_dev = eth_dev->data->dev_private;
	toe_dev->eth_dev = eth_dev;
	toe_dev->addr = eth_addr;
	toe_dev->pf = pf;
	toe_dev->vf = vf;
	toe_dev->queues = queues;
	toe_dev->ctrl_queues = ctrl_queues;
	toe_dev->data_queues = queues;
	toe_dev->f_queues = f_queues;
	toe_dev->kvlist = kvlist;

	toe_net_dev = toe_dev;

	return eth_dev->data->port_id;
error:
	
	if (eth_addr)
		rte_free(eth_addr);
	rte_eth_dev_release_port(eth_dev);
	return -1;
}

static inline int
toe_open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	int *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (int)strtol(value, NULL, 10);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static int toe_parse_mac_addr_kvarg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	if (value == NULL || extra_args == NULL)
		return -1;

	/* Parse MAC */
	return rte_ether_unformat_addr(value, extra_args);
}

static int rte_pmd_toe_probe(struct rte_vdev_device *vdev)
{
	struct rte_kvargs *kvlist = NULL;
	int ret;
//	int i, j;
	int pf, vf, queues, f_queues, ctrl_queues;
	struct rte_ether_addr mac;
	
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		printf("%s-%d: not primary\n",__func__,__LINE__);
		return 0;
	}

	kvlist = rte_kvargs_parse(rte_vdev_device_args(vdev), valid_arguments);
	if (kvlist == NULL)
		return -1;

	if (rte_kvargs_count(kvlist, ETH_TOE_PF) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_TOE_PF,
				&toe_open_int, &pf);
		if (ret < 0)
			goto out_free;
		if (pf < 0 || pf >= MAX_PF){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -2;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_TOE_VF) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_TOE_QUEUES,
				&toe_open_int, &vf);
		if (ret < 0)
			goto out_free;
		if (vf < 0 || vf >= MAX_VF){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -3;
		goto out_free;
	}


	if (rte_kvargs_count(kvlist, ETH_TOE_QUEUES) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_TOE_QUEUES,
				&toe_open_int, &queues);
		if (ret < 0)
			goto out_free;
		if (queues < 0 || queues > RTE_PMD_TOE_MAX_QUEUES){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -4;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_TOE_CTRL_QUEUES) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_TOE_CTRL_QUEUES,
				&toe_open_int, &ctrl_queues);
		if (ret < 0)
			goto out_free;
		if (ctrl_queues < 0 || ctrl_queues > RTE_PMD_TOE_MAX_QUEUES){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -5;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_TOE_MAC) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_TOE_MAC,
				&toe_parse_mac_addr_kvarg, &mac);
		if (ret < 0)
			goto out_free;
	} else {
		ret = -6;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, FREP_QUEUES) == 1) {
		ret = rte_kvargs_process(kvlist, FREP_QUEUES,
				&toe_open_int, &f_queues);
		if (ret < 0)
			goto out_free;
		if (f_queues < 0) {
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -7;
		goto out_free;
	}

	ret = eth_dev_toe_create(vdev, pf, vf, queues, ctrl_queues, f_queues, &mac, kvlist);
	if (ret < 0)
		goto out_free;
	rte_eth_dev_probing_finish(&rte_eth_devices[ret]);
	return 0;
out_free:
	if (ret < 1)
		printf("probe toe failed:queues=%d ret=%d",queues, ret);
	rte_kvargs_free(kvlist);
	return ret;
}

static int rte_pmd_toe_remove(struct rte_vdev_device *dev)
{
	const char *name;
	struct rte_eth_dev *eth_dev = NULL;
	struct toe_device *toe_dev = NULL;
	struct eth_dev_ops *ops = NULL;

	name = rte_vdev_device_name(dev);
   //printf("*^^ toe remove  %s-%d: start\n",__func__,__LINE__);
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return 0;
	toe_dev = eth_dev->data->dev_private;
	rte_kvargs_free(toe_dev->kvlist);
	rte_eth_dev_close(eth_dev->data->port_id);

	memcpy(&ops, &eth_dev->dev_ops, sizeof(struct eth_dev_ops *));
	rte_free(ops);

	eth_dev->dev_ops = NULL;

   //printf("*^^22 toe remove  %s-%d: done\n",__func__,__LINE__);
	rte_eth_dev_release_port(eth_dev);
	return 0;
}

static struct rte_vdev_driver pmd_toe_drv = {
	.probe = rte_pmd_toe_probe,
	.remove = rte_pmd_toe_remove,
};

RTE_PMD_REGISTER_VDEV(net_toe, pmd_toe_drv);
RTE_PMD_REGISTER_ALIAS(net_toe, eth_toe);
RTE_PMD_REGISTER_PARAM_STRING(net_toe,
		"pf=<int> "
		"vf=<int> "
		"queues=<int> "
		"ctl_queues=<int> "
		"f_queues=<int> "
				"vmac=<mac addr> ");

