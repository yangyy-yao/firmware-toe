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
	.nb_max = TOE_MAX_DESC_LIMIT,
	.nb_min = TOE_MAX_DESC_LIMIT,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = TOE_MAX_DESC_LIMIT,
	.nb_min = TOE_MAX_DESC_LIMIT,
	.nb_align = 8,
};
	
uint8_t default_rss_key[] = {
0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

uint16_t flow_queue_id[RTE_PMD_TOE_MAX_QUEUES];

struct rte_flow *eth_flows = NULL;
struct rte_flow *ip_flows = NULL;
struct rte_flow *tcp_flows[RTE_PMD_TOE_MAX_QUEUES] = {0};

static int
port_flow_complain(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) || !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];
		printf("%s-%d:Caught error type %d (%s): %s%s: %s\n", __func__, __LINE__,
	       error->type, errstr,
	       error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ", error->cause), buf) : "",
	       error->message ? error->message : "(no stated reason)",
	       rte_strerror(err));
	return -err;
}

static void flow_destroy(int port_id, struct rte_flow *flow)
{
	struct rte_flow_error error;
	int ret;
	
	ret = rte_flow_destroy(port_id, flow, &error);
	if (ret < 0)
		port_flow_complain(&error);
	return;
}

static struct rte_flow *
eth_flow_generate(int port_id, uint8_t *mac)
{
        struct rte_flow *flow = NULL;
        struct rte_flow_error error;
        struct rte_flow_attr attr;
        struct rte_flow_item pattern[2];
        struct rte_flow_action actions[2];
        struct rte_flow_action_queue queue;
        struct rte_flow_item_eth spec;
        int i;
		
        memset(&spec, 0, sizeof(struct rte_flow_item_eth));
        for (i = 0; i < 6; i++) {
                spec.dst.addr_bytes[i] = mac[i];
        }

        memset(&attr, 0, sizeof(struct rte_flow_attr));
        attr.ingress = 1;
        attr.priority = 8;

        memset(pattern, 0, sizeof(pattern));
        pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
        pattern[0].spec = &spec;
        pattern[0].mask = &spec;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        memset(actions, 0, sizeof(actions));
        queue.index = 0;
        actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
        actions[0].conf = &queue;
        actions[1].type = RTE_FLOW_ACTION_TYPE_END;
		flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
        if (!flow)
                port_flow_complain(&error);

        return flow;
}

static struct rte_flow *
ip_flow_generate(int port_id, int max_queues)
{
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[2];
	struct rte_flow_action_rss rss;
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	int i;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	memset(pattern, 0, sizeof(pattern));
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	
	attr.ingress = 1;
	attr.priority = max_queues;

	eth_spec.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);	
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	memset(actions, 0, sizeof(actions));
	
//	rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	rss.func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
	rss.level = 1;
	rss.types = (ETH_RSS_IP | ETH_RSS_TCP);
	rss.key_len = sizeof(default_rss_key);
	rss.queue_num = max_queues;
	rss.key = default_rss_key;
	rss.queue = flow_queue_id;
	
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		port_flow_complain(&error);

	return flow;
}

struct rte_flow *
tcp_flow_generate(uint16_t port_id, uint16_t rx_q, int max_queue, uint8_t *mac, uint32_t *ip)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action action[2];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_error error;
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item tcp_item;
	uint16_t spec, mask;
	int i, res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	
//	attr.group = toe_get_flow_group_id();
	attr.ingress = 1;
	//attr.priority = 0;
	attr.priority = max_queue - rx_q - 1;

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
	
	for (i = 0; i < ETH_ALEN; i ++) {
		eth_spec.dst.addr_bytes[i] = mac[i];
	}
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_spec;

	ipv4_spec.hdr.dst_addr = *ip;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4_spec;
	pattern[1].mask = &ipv4_spec;

	//spec = TOE_MIN_PORT | specid;
	//mask = TOE_MIN_PORT | (max_queue - 1);
	spec = TOE_MIN_PORT | (rx_q * 2);
	mask = TOE_MIN_PORT | (rx_q * 2);
	tcp_spec.hdr.dst_port = htons(spec);
	tcp_mask.hdr.dst_port = htons(mask);
	
	pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[2].spec = &tcp_spec;
	pattern[2].mask = &tcp_mask;

	/* the final level must be always type end */
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

	flow = rte_flow_create(port_id, &attr, pattern, action, &error);
	if (!flow)
		port_flow_complain(&error);

	return flow;
}

void toe_rte_flow_destroy(struct toe_device *toe_dev) 
{
	uint16_t i;
	
	for (i = 0; i < toe_dev->data_queues; i++) {
		if (tcp_flows[i])
			flow_destroy(toe_dev->eth_flow_id, tcp_flows[i]);
	}

	if (ip_flows)
		flow_destroy(toe_dev->eth_flow_id, ip_flows);
	if (eth_flows)
		flow_destroy(toe_dev->eth_flow_id, eth_flows);
}

int toe_rte_flow_set(struct toe_device *toe_dev)
{
	uint16_t i;

	for (i = 0; i < toe_dev->data_queues; i++) {
		tcp_flows[i] = tcp_flow_generate(toe_dev->eth_flow_id, i, toe_dev->data_queues, toe_dev->mac, toe_dev->ip);
		if (!tcp_flows[i]) {
			RTE_LOG(ERR, PMD, "%s-%d: tcp_flow set failed! portid:%d,qid:%d, \n", __func__, __LINE__, toe_dev->eth_flow_id, i);
			return -1;
		}
	}
	
	ip_flows = ip_flow_generate(toe_dev->eth_flow_id, toe_dev->data_queues);
	if (!ip_flows) {
		RTE_LOG(ERR, PMD, "%s-%d: ip_flow set failed! portid:%d\n", __func__, __LINE__, toe_dev->eth_flow_id);
		return -1;
	}

	return 0;
}

static int toe_get_eth_portid(struct toe_device *toe_dev)
{
	uint16_t portid;
	struct rte_eth_dev_info dev_info;
	int i, ret;
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret)
			return -1;
		if (!strcmp(dev_info.driver_name, ETH_FLOW_DEVICE_NAME)) {
			toe_dev->eth_flow_id = portid;
			break;
		}
	}
/*
	for (i = 0; i < toe_dev->data_queues; i++) {
		flow_queue_id[i] = i + toe_dev->ctrl_queues;
	}
	*/
	for (i = 0; i < toe_dev->queues; i++) {
		flow_queue_id[i] = i;
	}
	
	return 0;
}

static int toe_net_configure(struct rte_eth_dev *eth_dev)
{
	struct toe_device *toe_dev;
	struct toe_rx_queue **p_data_rxq = NULL;
	
	toe_dev = eth_dev->data->dev_private;

	if (eth_dev->data->nb_rx_queues > toe_dev->queues
		|| eth_dev->data->nb_tx_queues > toe_dev->queues) {
		printf("%s-%d: eth_dev rx/tx queues more than toe queues\n", __func__, __LINE__);
		goto fail;
	}
	toe_dev->sys_ctrl_rxq = rte_calloc(NULL, toe_dev->ctrl_queues, sizeof(struct toe_sys_ctl_queue), RTE_CACHE_LINE_SIZE);
	if (toe_dev->sys_ctrl_rxq == NULL)
		goto fail;
	
	p_data_rxq = rte_calloc(NULL, toe_dev->data_queues, sizeof(struct toe_rx_queue *), RTE_CACHE_LINE_SIZE);
	if (p_data_rxq == NULL)
		goto fail;

	toe_dev->data_rxq = p_data_rxq;

	if (toe_get_eth_portid(toe_dev))
		goto fail;
	
	if (toe_engine_init(toe_dev))
		goto fail;

	return 0;
fail:
	if (toe_dev->sys_ctrl_rxq)
		rte_free(toe_dev->sys_ctrl_rxq);
	if(p_data_rxq) {
		rte_free(p_data_rxq);
	}
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

	if (rx_queue_id == 0) {
		toe_dev->sys_ctrl_rxq->idx = -1;
		toe_dev->sys_ctrl_rxq->toe_eg = toe_dev->toe_eg;
		dev->data->rx_queues[rx_queue_id] = toe_dev->sys_ctrl_rxq;
		dev->data->tx_queues[rx_queue_id] = toe_dev->sys_ctrl_rxq;
		return 0;
	}
	
	data_qid = rx_queue_id - 1;
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
	

	dev->data->rx_queues[rx_queue_id] = toe_dev->data_rxq[data_qid];
	dev->data->tx_queues[rx_queue_id] = toe_dev->data_rxq[data_qid];
	
	return 0;
fail:
	if (toe_dev->data_rxq[data_qid]) {
		if (toe_dev->data_rxq[data_qid]->rxq)
			rte_ring_free(toe_dev->data_rxq[data_qid]->rxq);
		rte_free(toe_dev->data_rxq[data_qid]);
		toe_dev->data_rxq[data_qid] = NULL;
	}
	return -1;
}

static void toe_rx_queue_release(void *rxq)
{
	struct toe_rx_queue *t_rxq = rxq;
	struct toe_engine *toe_eg;
	struct toe_device *toe_dev;
	int idx;

	if (!t_rxq)
		return;
	
	idx = t_rxq->idx;
	toe_eg = t_rxq->toe_eg;
	toe_dev = toe_eg->t_dev;


	if (toe_dev->data_rxq[idx]) {
		if (toe_dev->data_rxq[idx]->rxq)
			rte_ring_free(toe_dev->data_rxq[idx]->rxq);
		rte_free(toe_dev->data_rxq[idx]);
	}
	toe_dev->data_rxq[idx] = NULL;

	return;
}

static int toe_tx_queue_setup(__rte_unused struct rte_eth_dev *dev,
						__rte_unused uint16_t tx_queue_id,
						__rte_unused uint16_t nb_tx_desc,
						__rte_unused unsigned int socket_id,
						__rte_unused const struct rte_eth_txconf *tx_conf)
{
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

	base_cfg->msg_queue_num = toe_dev->data_queues;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			mtcp = g_mtcp[lcore_id];

			mtcp->ctx->io_private_context = toe_dev->data_rxq[idx];
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

	toe_rte_flow_destroy(toe_dev);
	toe_engine_free(toe_dev);
	rte_free(toe_dev->sys_ctrl_rxq);
	rte_free(toe_dev->data_rxq);
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
	dev_info->flow_type_rss_offloads = ETH_RSS_IP | ETH_RSS_TCP;
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

	if (queues <= ctrl_queues) {
		return -1;
	}
	
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
	toe_dev->data_queues = queues - ctrl_queues;
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
		RTE_LOG(ERR, PMD, "%s-%d: not primary\n",__func__,__LINE__);
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
		RTE_LOG(ERR, PMD, "probe toe failed:queues=%d ret=%d", queues, ret);
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
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return 0;
	toe_dev = eth_dev->data->dev_private;
	rte_kvargs_free(toe_dev->kvlist);
	rte_eth_dev_close(eth_dev->data->port_id);

	memcpy(&ops, &eth_dev->dev_ops, sizeof(struct eth_dev_ops *));
	rte_free(ops);

	eth_dev->dev_ops = NULL;

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

