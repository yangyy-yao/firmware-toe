#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <rte_ethdev.h>
#include <dpaa2_ethdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_kvargs.h>
#include "agiep_accel_net.h"
#include "agiep_accel_engine.h"
#include "agiep_virtio_net.h"

extern uint32_t dpaa2_svr_family;

struct accel_hw_device *local_accel_dev[MAX_ACCEL_NUMBER] = {NULL};
uint16_t accel_dev_num = 0;
struct accel_lo_dev_info lo_dev_info = {0};
static int s_serdes_lan_loopback[ACCEL_SERDES_MAX_NB][ACCEL_SERDES_MAX_LAN_NB];

static struct rte_eth_conf accel_port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM | DEV_RX_OFFLOAD_VLAN_STRIP,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = DEV_TX_OFFLOAD_VLAN_INSERT | (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM),
	},
};

static const char *valid_arguments[] = {
	ACCEL_LO_DEV_NUM,
	ACCEL_LO_DEV_NUM_PER_FREP,
	ACCEL_LO_DEV_NAME,
	ACCEL_LO_DEV_SERDES_LAN,
	ACCEL_LO_DEV_INIT,
	NULL
};

static uint16_t agiep_accel_back_burst(void *queue, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct accel_hw_device *hw_dev = NULL;
	struct rte_eth_dev *eth_frep = NULL;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	uint16_t fqid_tx = 0;
	uint16_t fqid_rx = 0;
	uint8_t dir_vlan = 0, accel_vlan = 0;
	uint8_t ac_point;
	int i, ret = 0;
	struct {
		struct accel_hw_device *info_hw_dev;
		struct rte_mbuf *tx_pkts[nb_pkts];
		struct rte_mbuf *rx_pkts[nb_pkts];
		uint16_t fqid_tx;
		uint16_t fqid_rx;
		uint16_t tx_pkt_num;
		uint16_t rx_pkt_num;
	} info[accel_dev_num + 1];

	ret = dpaa2_dev_prefetch_rx(queue, pkts, nb_pkts);
	if (!ret) {
		return 0;
	}
	
	memset(info, 0, sizeof(info));
	
	for (i = 0; i < ret; i++) {		

		dir_vlan = (pkts[i]->vlan_tci >> 8) & 0xf;

		accel_vlan = pkts[i]->vlan_tci & 0xff;
		
		if (accel_vlan == 0 || accel_vlan > MAX_ACCEL_NUMBER) {
			rte_pktmbuf_free(pkts[i]);
			pkts[i] = NULL;
			continue;
		}
		ac_point = accel_vlan - 1;

		hw_dev = local_accel_dev[ac_point];
		if (!hw_dev) {
			rte_pktmbuf_free(pkts[i]);
			pkts[i] = NULL;
			continue;
		}
		
		eth_frep = hw_dev->accel_dev->dev->eth_dev;
		if (!eth_frep) {
			rte_pktmbuf_free(pkts[i]);
			pkts[i] = NULL;			
			continue;
		}

		fqid_tx =(dpaa2_q->cgid % eth_frep->data->nb_tx_queues);
		fqid_rx =(dpaa2_q->cgid % eth_frep->data->nb_rx_queues);
		
		info[ac_point].info_hw_dev = hw_dev;
		info[ac_point].fqid_tx = ((struct agiep_frep_queue *)eth_frep->data->tx_queues[fqid_tx])->qid;
		info[ac_point].fqid_rx = fqid_rx;
		
		if (dir_vlan == ACCEL_DIRECTION_RX) {
			info[ac_point].rx_pkts[info[ac_point].rx_pkt_num ++] = pkts[i];
			pkts[i] = NULL;
		}
		else if (dir_vlan == ACCEL_DIRECTION_TX) {			
			info[ac_point].tx_pkts[info[ac_point].tx_pkt_num ++] = pkts[i];
			pkts[i] = NULL;
		}
		else {
			rte_pktmbuf_free(pkts[i]);
			pkts[i] = NULL;
		}
	}

	for (i = 0; i < accel_dev_num; i ++) {
		hw_dev = info[i].info_hw_dev;	

		if (info[i].rx_pkt_num > 0) {
			ret = rte_ring_mp_enqueue_burst(((struct rte_ring **)hw_dev->rx_lo_queue)[info[i].fqid_rx], 
											(void *const *) info[i].rx_pkts, info[i].rx_pkt_num, NULL);

			for (; ret < info[i].rx_pkt_num; ret ++)
				rte_pktmbuf_free(info[i].rx_pkts[ret]);
		}

		if (info[i].tx_pkt_num > 0) {
			ret = rte_ring_mp_enqueue_burst(((struct rte_ring **)hw_dev->tx_lo_queue)[info[i].fqid_tx], 
											(void *const *) info[i].tx_pkts, info[i].tx_pkt_num, NULL);

			for (; ret < info[i].tx_pkt_num; ret ++)
				rte_pktmbuf_free(info[i].tx_pkts[ret]);
		}
	}

	return 0;
}

static uint16_t agiep_accel_submit_rx_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = rx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_hw_device *hw_dev = NULL;
	struct rte_eth_dev *dpni_dev = NULL;
	uint16_t vlan_rx = ACCEL_DIRECTION_RX;
	int qid =  q->qid;
	int i, ret = 0;

	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}
	
	hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	if (NULL == hw_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no accel dev!\n", __func__, __LINE__);
		return 0;
	}

	if (qid < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: qid is invalid!\n", __func__, __LINE__);
		return 0;
	}

	dpni_dev = hw_dev->lo_eth_dev[qid % hw_dev->num_lo_dev];
	if (NULL == dpni_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no lo_dev!\n", __func__, __LINE__);
		return 0;
	}

	for (i = 0; i < nb_pkts; i++) {
		rx_pkts[i]->vlan_tci = (vlan_rx << 8) | (hw_dev->aid + 1);
	}
	
	ret = dpni_dev->tx_pkt_burst(dpni_dev->data->tx_queues[qid], rx_pkts, nb_pkts);

	return ret;
}

static uint16_t agiep_accel_back_rx_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = rx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_hw_device *hw_dev = NULL;
	int nb = 0;

	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}
	
	hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	if (NULL == hw_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no accel dev!\n", __func__, __LINE__);
		return 0;
	}
	
	if (q->qid < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: qid is invalid!\n", __func__, __LINE__);
		return 0;
	}	
	nb = rte_ring_mc_dequeue_burst(((struct rte_ring **)hw_dev->rx_lo_queue)[q->qid], (void **) rx_pkts, nb_pkts, NULL);

	return nb;
}

static uint16_t agiep_accel_submit_tx_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = tx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_hw_device *hw_dev = NULL;
	struct rte_eth_dev *dpni_dev = NULL;
	uint16_t vlan_tx = ACCEL_DIRECTION_TX;
	int qid = q->qid;
	int i;
	int ret = 0;

	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}
	
	hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	if (NULL == hw_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no accel dev!\n", __func__, __LINE__);
		return 0;
	}

	if (qid < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: qid is invalid!\n", __func__, __LINE__);
		return 0;
	}

	dpni_dev = hw_dev->lo_eth_dev[qid % hw_dev->num_lo_dev];	
	if (NULL == dpni_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no lo_dev!\n", __func__, __LINE__);
		return 0;
	}
	for (i = 0; i < nb_pkts; i++) {
		tx_pkts[i]->vlan_tci = (vlan_tx << 8) | (hw_dev->aid + 1);
	}

	ret = dpni_dev->tx_pkt_burst(dpni_dev->data->tx_queues[qid], tx_pkts, nb_pkts);
	
	return ret;
}

static uint16_t agiep_accel_back_tx_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = tx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_hw_device *hw_dev = NULL;
	int nb = 0;

	if (NULL == frep_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no frep dev!\n", __func__, __LINE__);
		return 0;
	}
	
	hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	if (NULL == hw_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: no accel dev!\n", __func__, __LINE__);
		return 0;
	}
	
	if (q->qid < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: qid is invalid!\n", __func__, __LINE__);
		return 0;
	}
	
	nb = rte_ring_mc_dequeue_burst(((struct rte_ring **)hw_dev->tx_lo_queue)[q->qid], (void **) tx_pkts, nb_pkts, NULL);

	return nb;
}

static void *agiep_accel_map_region(uint64_t addr, size_t len)
{
	int fd;
	void *tmp;
	uint64_t start;
	uint64_t offset;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, PMD, "Fail to open /dev/mem\n");
		return NULL;
	}

	start = addr & PAGE_MASK;
	offset = addr - start;
	len = len & PAGE_MASK;
	if (len < (size_t)PAGE_SIZE)
		len = PAGE_SIZE;

	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);

	close(fd);

	if (tmp != MAP_FAILED)
		return (uint8_t *)tmp + offset;
	else
		return NULL;
}

static int agiep_accel_device_set_loop(char * serdes_str)
{
	int serdes_nb, lan_nb;
	void *reg = 0;
	uint32_t data;
	void *serdes_base;

	serdes_base = agiep_accel_map_region(ACCEL_SERDES_REG_BASE, 0x20000);

	for (serdes_nb = 0; serdes_nb < ACCEL_SERDES_MAX_NB; serdes_nb++) {
		for (lan_nb = 0; lan_nb < ACCEL_SERDES_MAX_LAN_NB; lan_nb++) {
			char env_str[64];

			sprintf(env_str, "SERDES%d_LAN%d_LOOPBACK", serdes_nb + 1, lan_nb);
			if (!strcmp(env_str, serdes_str)) 
				s_serdes_lan_loopback[serdes_nb][lan_nb] = 1;


			if (s_serdes_lan_loopback[serdes_nb][lan_nb]) {
				if (dpaa2_svr_family == SVR_LX2160A) {
					reg = ((char *)serdes_base + LX_SERDES_LB_REG_OFF(serdes_nb, lan_nb));
					data = rte_read32(reg);
					rte_write32(data | ACCEL_LB_EN_BIT, reg);
				}
			}
			else {
				if (dpaa2_svr_family == SVR_LX2160A) {
					reg = ((char *)serdes_base + LX_SERDES_LB_REG_OFF(serdes_nb, lan_nb));
					data = rte_read32(reg);
					rte_write32(data & (~ACCEL_LB_EN_BIT), reg);
				}
			}
		}
	}
	return 0;
}

static int agiep_accel_lo_dev_init(uint16_t port_id)
{
	struct rte_mempool *accel_mbuf_pool = NULL;
	struct rte_eth_conf port_conf = accel_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_dev_tx_buffer *tx_buffer;
	uint16_t rx_rings = ACCEL_RX_QUEUE_NUM, tx_rings = ACCEL_TX_QUEUE_NUM;
	uint16_t nb_rxd = ACCEL_RX_RING_SIZE, nb_txd = ACCEL_TX_RING_SIZE;
	uint16_t q;
	int ret = -1;

	accel_mbuf_pool = rte_pktmbuf_pool_create("ACCEL_MBUF_POOL", ACCEL_NUM_MBUFS * 1,
		ACCEL_MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!accel_mbuf_pool) {
		RTE_LOG(ERR, PMD, "%s-%d: mbuf pool creat failed!rte_errno:%d\n", __func__, __LINE__,rte_errno);
		goto failed;
	}

	fflush(stdout);
	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		RTE_LOG(ERR, PMD, "%s-%d: rte_eth_dev_info_get failed! portid:%d\n", __func__, __LINE__, port_id);

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;


	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	if (port_conf.rx_adv_conf.rss_conf.rss_hf !=
			accel_port_conf.rx_adv_conf.rss_conf.rss_hf) {
		printf("Port %u modified RSS hash function based on hardware support,"
			"requested:%#"PRIx64" configured:%#"PRIx64"\n",
			port_id,
			accel_port_conf.rx_adv_conf.rss_conf.rss_hf,
			port_conf.rx_adv_conf.rss_conf.rss_hf);
	}
	
	ret = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
	if (ret != 0) {
		RTE_LOG(ERR, PMD, "%s-%d: rte_eth_dev_configure failed!\n", __func__, __LINE__);
		goto failed;
	}
	
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret != 0) {
		RTE_LOG(ERR, PMD, "%s-%d: rte_eth_dev_adjust_nb_rx_tx_desc failed! nb_rxd:%d, nb_txd:%d\n", __func__, __LINE__, nb_rxd, nb_txd);
		goto failed;
	}

	fflush(stdout);
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
		
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
				rte_eth_dev_socket_id(port_id), &rxq_conf, accel_mbuf_pool);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d: rte_eth_rx_queue_setup failed! nb_rxd:%d\n", __func__, __LINE__, nb_rxd);
			goto failed;
		}
	}

	fflush(stdout);
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
				rte_eth_dev_socket_id(port_id), &txq_conf);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d: rte_eth_tx_queue_setup failed! nb_txd:%d\n", __func__, __LINE__, nb_txd);
			goto failed;
		}
	}

	tx_buffer = rte_zmalloc_socket("accel_tx_buffer", RTE_ETH_TX_BUFFER_SIZE(ACCEL_MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
	if (tx_buffer == NULL) {
		RTE_LOG(ERR, PMD, "%s-%d: Cannot allocate buffer for tx on port %u\n", __func__, __LINE__, port_id);
		goto failed;
	}
	
	rte_eth_tx_buffer_init(tx_buffer, ACCEL_MAX_PKT_BURST);
	
	ret = rte_eth_tx_buffer_set_err_callback(tx_buffer, rte_eth_tx_buffer_count_callback, &port_id);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: Cannot set error callback for tx buffer on port %u\n", __func__, __LINE__, port_id);
		goto failed;
	}

	ret = rte_eth_dev_set_ptypes(port_id, RTE_PTYPE_UNKNOWN, NULL,0);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "%s-%d:Port %u, Failed to disable Ptype parsing\n", __func__,__LINE__, port_id);

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "%s-%d: rte_eth_dev_start failed!\n", __func__, __LINE__);
		goto failed;
	}

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0) {
		RTE_LOG(ERR, PMD, "%s-%d: rte_eth_promiscuous_enable failed!\n", __func__, __LINE__);
		goto failed;
	}

	return 0;
failed:
	return ret;
}

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	int *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (int)strtol(value, NULL, 10);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static int agiep_accel_string_parse(const char *key, const char *value, void *extra_args)
{
	struct accel_lo_dev_info *info = extra_args;
	const char *pDelimiter = " ";
	char *pToken = NULL;
	char *pSave = NULL;
	char value_dup[64];
	int num = 0;

	if (value == NULL)
		return -1;
	strncpy(value_dup, value, sizeof(value_dup));

	pToken = strtok_r(value_dup, pDelimiter, &pSave);
	
	while (pToken != NULL && num <= ACCEL_MAX_LO_DEV_NUM) {
		if (strcmp(key, ACCEL_LO_DEV_NAME) == 0)
			memcpy(info->dev_name[num], pToken, sizeof(info->dev_name[num]));
		
		if (strcmp(key, ACCEL_LO_DEV_SERDES_LAN) == 0)
			memcpy(info->serdes_lan[num], pToken, sizeof(info->serdes_lan[num]));

		pToken = strtok_r(NULL, pDelimiter, &pSave);
		num ++;
	}
	
	if (num == 0) {
		RTE_LOG(ERR, PMD, "%s-%d: no extra_args!\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}

static int agiep_accel_lo_dev_parse(struct accel_lo_dev_info *info)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;
	
	kvlist = rte_kvargs_parse((const char *)getenv(ACCEL_HW_NAME), valid_arguments);
	if (kvlist == NULL){
		RTE_LOG(ERR, PMD, "%s-%d:kvlist get failed!\n", __func__, __LINE__);
		return -1;
	}
	
	if (rte_kvargs_count(kvlist, ACCEL_LO_DEV_NUM) == 1) {
		ret = rte_kvargs_process(kvlist, ACCEL_LO_DEV_NUM,
				&open_int, &info->n_dev);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d:lo dev num get failed!\n", __func__, __LINE__);
			goto out_free;
		}
	} else {
		RTE_LOG(ERR, PMD, "%s-%d:no lo dev num!\n", __func__, __LINE__);
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ACCEL_LO_DEV_NUM_PER_FREP) == 1) {
		ret = rte_kvargs_process(kvlist, ACCEL_LO_DEV_NUM_PER_FREP,
				&open_int, &info->n_dev_per_frep);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d:per frep lo dev num get failed!\n", __func__, __LINE__);
			goto out_free;
		}
	}

	if (rte_kvargs_count(kvlist, ACCEL_LO_DEV_NAME) == 1) {
		ret = rte_kvargs_process(kvlist, ACCEL_LO_DEV_NAME,
				&agiep_accel_string_parse, info);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d:lo dev name get failed!\n", __func__, __LINE__);
			goto out_free;
		}
	} else {
		RTE_LOG(ERR, PMD, "%s-%d:no dev name!\n", __func__, __LINE__);
		goto out_free;
	}
	
	if (rte_kvargs_count(kvlist, ACCEL_LO_DEV_SERDES_LAN) == 1) {
		ret = rte_kvargs_process(kvlist, ACCEL_LO_DEV_SERDES_LAN,
				&agiep_accel_string_parse, info);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d:lo dev serdes_lan get failed!\n", __func__, __LINE__);
			goto out_free;
		}
	} else {
		RTE_LOG(ERR, PMD, "%s-%d:no lo dev serdes_lan!\n", __func__, __LINE__);
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ACCEL_LO_DEV_INIT) == 1) {
		ret = rte_kvargs_process(kvlist, ACCEL_LO_DEV_INIT,
				&open_int, &info->dev_init_enable);
		if (ret < 0) {
			RTE_LOG(ERR, PMD, "%s-%d:lo dev init get failed!\n", __func__, __LINE__);
			goto out_free;
		}
	}

out_free:
	if (ret < 0)
		RTE_LOG(ERR, PMD, "%s-%d: parse failed! ret=%d\n", __func__, __LINE__, ret);
	rte_kvargs_free(kvlist);
	return ret;
}

static void agiep_accel_lo_dev_info_reset(struct accel_lo_dev_info *info)
{
	info->initialized = 1;
	info->n_dev = 0;
	info->n_dev_per_frep = 1;
	info->dev_init_enable = 0;
}

static int agiep_accel_hw_init(struct agiep_accel_device *accel_dev)
{
	int i, n;
	struct rte_eth_dev *lo_eth_dev = NULL;
	struct accel_hw_device *hw_dev = NULL;

	hw_dev = rte_calloc(NULL, 1, sizeof(struct accel_hw_device *), 0);
	if (!hw_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: accel hw dev malloc failed!\n", __func__, __LINE__);
		goto done;
	}
	
	for (i = 0; i < accel_dev_num; i ++) {
		if (NULL == local_accel_dev[i]) {
			local_accel_dev[i] = hw_dev;
			hw_dev->aid = i;
			break;
		}
	}

	if (i == accel_dev_num) {
		if (accel_dev_num >= MAX_ACCEL_NUMBER) {
			RTE_LOG(ERR, PMD, "%s-%d: accel dev num:%d more than the max number !\n", __func__, __LINE__, accel_dev_num);
			goto done;
		}
		
		hw_dev->aid = accel_dev_num;
		local_accel_dev[accel_dev_num ++] = hw_dev;
	}

	if (!lo_dev_info.initialized) {
		agiep_accel_lo_dev_info_reset(&lo_dev_info);
		if (0 != agiep_accel_lo_dev_parse(&lo_dev_info)) {
			RTE_LOG(ERR, PMD, "%s-%d: agiep_accel_lo_dev_parse failed !\n", __func__, __LINE__);
			goto done;
		}

		if (lo_dev_info.n_dev < 0 || lo_dev_info.n_dev > ACCEL_MAX_LO_DEV_NUM) {
			RTE_LOG(ERR, PMD, "%s-%d: lo_dev_info.n_dev:%d more than max num!\n", __func__, __LINE__, lo_dev_info.n_dev);
			goto done;
		}

		if (lo_dev_info.n_dev_per_frep < 0 || lo_dev_info.n_dev_per_frep > lo_dev_info.n_dev) {
			RTE_LOG(ERR, PMD, "%s-%d: lo_dev_info.n_dev_per_frep:%d more than lo_dev_info.n_dev:%d!\n", __func__, __LINE__, lo_dev_info.n_dev_per_frep, lo_dev_info.n_dev);
			goto done;
		}
				
		for (i = 0; i < lo_dev_info.n_dev; i ++) {
			lo_eth_dev = rte_eth_dev_allocated((const char *)lo_dev_info.dev_name[i]);
			if (NULL == lo_eth_dev) {
				RTE_LOG(ERR, PMD, "%s-%d: lo_eth_dev is NULL!\n", __func__, __LINE__);
				goto done;
			}
			
			if (!lo_eth_dev->data->dev_started && lo_dev_info.dev_init_enable) {
				if (0 != agiep_accel_lo_dev_init(lo_eth_dev->data->port_id)) {
					RTE_LOG(ERR, PMD, "%s-%d: agiep_accel_lo_dev_init failed!\n", __func__, __LINE__);
					goto done;
				}
			}
			agiep_accel_device_set_loop(lo_dev_info.serdes_lan[i]);
			
			lo_eth_dev->rx_pkt_burst = agiep_accel_back_burst;
		}
	}

	hw_dev->num_lo_dev = lo_dev_info.n_dev_per_frep;
	hw_dev->lo_eth_dev = rte_calloc(NULL, hw_dev->num_lo_dev, sizeof(struct rte_eth_dev *), 0);
	if (!hw_dev->lo_eth_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: hw_dev->lo_eth_dev malloc failed!\n", __func__, __LINE__);
		goto done;
	}

	for (i = 0; i < hw_dev->num_lo_dev; i ++) {
		n = ((hw_dev->aid * hw_dev->num_lo_dev) + i) % lo_dev_info.n_dev;
		hw_dev->lo_eth_dev[i] = rte_eth_dev_allocated((const char *)lo_dev_info.dev_name[n]);
		if (NULL == hw_dev->lo_eth_dev[i]) {
			RTE_LOG(ERR, PMD, "%s-%d: hw_dev->lo_eth_dev[%d] is NULL!\n", __func__, __LINE__, i);
			goto done;
		}
	}

	hw_dev->accel_dev = accel_dev;
	accel_dev->priv = (void *)hw_dev;
	accel_dev->tx_compensate_enable = 1;
	return 0;
done:
	if (hw_dev) {
		if (hw_dev->lo_eth_dev) {
			rte_free(hw_dev->lo_eth_dev);
			hw_dev->lo_eth_dev = NULL;
		}
		rte_free(hw_dev);
	}
	
	return -1;
}

static int agiep_accel_configure(struct agiep_accel_device * accel_dev)
{
	struct agiep_frep_device *frep_dev = accel_dev->dev;
	struct accel_hw_device *hw_dev = accel_dev->priv;
	struct rte_eth_dev_info dev_info = {0};

	if (*frep_dev->eth_dev->dev_ops->dev_infos_get
		&& 0 != (*frep_dev->eth_dev->dev_ops->dev_infos_get)(frep_dev->eth_dev, &dev_info)) {
		RTE_LOG(ERR, PMD, "%s-%d:,eth_dev->dev_ops->dev_infos_get failed!\n", __func__, __LINE__);
		goto failed;
	}

	hw_dev->rx_lo_queue = rte_calloc(NULL, dev_info.max_rx_queues, sizeof(struct rte_ring *), 0);
	if (!hw_dev->rx_lo_queue) {
		RTE_LOG(ERR, PMD, "%s-%d:hw_dev rx_lo_queue calloc failed! dev_info.max_rx_queues:%d\n", __func__, __LINE__, dev_info.max_rx_queues);
		goto failed;
	}

	hw_dev->tx_lo_queue = rte_calloc(NULL, dev_info.max_tx_queues, sizeof(struct rte_ring *), 0);
	if (!hw_dev->tx_lo_queue) {
		RTE_LOG(ERR, PMD, "%s-%d:hw_dev tx_lo_queue calloc failed! dev_info.max_tx_queues:%d\n", __func__, __LINE__, dev_info.max_tx_queues);
		goto failed;
	}

	return 0;

failed:

	if (hw_dev->rx_lo_queue) {
		rte_free(hw_dev->rx_lo_queue);
		hw_dev->rx_lo_queue = NULL;
	}

	if (hw_dev->tx_lo_queue) {
		rte_free(hw_dev->tx_lo_queue);
		hw_dev->tx_lo_queue = NULL;
	}

	return -1;
}

static int agiep_accel_dev_start(struct agiep_accel_device * accel_dev __rte_unused)
{
	return 0;
}

static int agiep_accel_dev_close(struct agiep_accel_device * accel_dev)
{
	struct agiep_frep_device *frep_dev = accel_dev->dev;
	struct accel_hw_device *hw_dev = accel_dev->priv;
	struct rte_eth_dev_info dev_info = {0};
	int i;

	accel_dev->priv = NULL;
	local_accel_dev[hw_dev->aid] = NULL;

	if (*frep_dev->eth_dev->dev_ops->dev_infos_get
		&& 0 != (*frep_dev->eth_dev->dev_ops->dev_infos_get)(frep_dev->eth_dev, &dev_info)) {
		RTE_LOG(ERR, PMD, "%s-%d:,eth_dev->dev_ops->dev_infos_get failed!\n", __func__, __LINE__);
		return -1;
	}

	for (i = 0; i < dev_info.max_rx_queues; i ++) {
		if (!hw_dev->rx_lo_queue[i])
			continue;
		
		rte_ring_free(hw_dev->rx_lo_queue[i]);
		hw_dev->rx_lo_queue[i] = NULL;
	}

	for (i = 0; i < dev_info.max_tx_queues; i ++) {
		if (!hw_dev->tx_lo_queue[i])
			continue;
		
		rte_ring_free(hw_dev->tx_lo_queue[i]);
		hw_dev->tx_lo_queue[i] = NULL;
	}
		
	rte_free(hw_dev->rx_lo_queue);
	rte_free(hw_dev->tx_lo_queue);

	for (i = 0; i < hw_dev->num_lo_dev; i ++)
		hw_dev->lo_eth_dev[i] = NULL;

	rte_free(hw_dev->lo_eth_dev);

	rte_free(hw_dev);
	return 0;
}

static int agiep_accel_dev_infos_get(struct rte_eth_dev_info *dev_info)
{
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_CHECKSUM;
	return 0;
}

static int agiep_accel_rx_queue_setup(struct agiep_accel_device *accel_dev,
					uint16_t rx_queue_id,
					uint16_t nb_rx_desc,
					struct rte_mempool *mb_pool __rte_unused)
{
	struct accel_hw_device *hw_dev = accel_dev->priv;
	struct rte_ring **rx_lo_queue = (struct rte_ring **)hw_dev->rx_lo_queue;
	char name[ACCEL_LO_RING_NAME_LEN];
	
	snprintf(name, ACCEL_LO_RING_NAME_LEN, "accel_hw%d_rx_ring_%d", hw_dev->aid, rx_queue_id);

	rx_lo_queue[rx_queue_id] = rte_ring_create((const char *)name, nb_rx_desc, rte_socket_id(), 0);
	if (NULL == rx_lo_queue[rx_queue_id]) {
		RTE_LOG(ERR, PMD, "%s-%d:rx_lo_queue[%d] create failed! nb_rx_desc:%d, rte_errno:%d\n",
				__func__, __LINE__, rx_queue_id, nb_rx_desc, rte_errno);
		return -1;
	}

	return 0;
}

static int agiep_accel_tx_queue_setup(struct agiep_accel_device *accel_dev,
					uint16_t tx_queue_id,
					uint16_t nb_tx_desc)
{
	struct accel_hw_device *hw_dev = accel_dev->priv;
	struct rte_ring **tx_lo_queue = (struct rte_ring **)hw_dev->tx_lo_queue;
	char name[ACCEL_LO_RING_NAME_LEN];

	snprintf(name, ACCEL_LO_RING_NAME_LEN, "accel_hw%d_lo_tx_ring_%d", hw_dev->aid, tx_queue_id);

	tx_lo_queue[tx_queue_id] = rte_ring_create((const char *)name, nb_tx_desc, SOCKET_ID_ANY, 0);
	if (NULL == tx_lo_queue[tx_queue_id]) {
		RTE_LOG(ERR, PMD, "%s-%d: tx_lo_queue[%d] create failed!\n", __func__, __LINE__, tx_queue_id);
		return -1;
	}
	
	return 0;
}

static void agiep_accel_rx_queue_release(void *rxq)
{
	struct agiep_frep_queue *rx = rxq;
	struct agiep_frep_device *frep_dev = rx->dev;
	struct accel_hw_device *hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;

	rte_ring_free(hw_dev->rx_lo_queue[rx->qid]);
	hw_dev->rx_lo_queue[rx->qid] = NULL;
	return;
}

static void agiep_accel_tx_queue_release(void *txq)
{
	struct agiep_frep_queue *tx = txq;
	struct agiep_frep_device *frep_dev = tx->dev;
	struct accel_hw_device *hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	
	rte_ring_free(hw_dev->tx_lo_queue[tx->qid]);
	hw_dev->tx_lo_queue[tx->qid] = NULL;
	return;
}

static uint64_t agiep_accel_features_get(struct agiep_frep_device *frep_dev)
{
	struct accel_hw_device *hw_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	struct rte_eth_conf *port_conf = NULL;
	uint64_t req_features = 0;

	if (hw_dev && hw_dev->lo_eth_dev[0])
		port_conf = &hw_dev->lo_eth_dev[0]->data->dev_conf;

	if (port_conf->txmode.offloads & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM))
		req_features |= (1 << VIRTIO_NET_F_CSUM);
	
	if (port_conf->rxmode.offloads & DEV_RX_OFFLOAD_CHECKSUM)
		req_features |= (1 << VIRTIO_NET_F_GUEST_CSUM);

	if (port_conf->rxmode.mq_mode & ETH_MQ_RX_RSS)
		req_features |= (1ULL << VIRTIO_NET_F_RSS);

	return req_features;
}

static void agiep_accel_features_set(struct agiep_frep_device *frep_dev __rte_unused, uint64_t req_features __rte_unused)
{
	return;
}

static struct agiep_accel_ops agiep_accel_engine_ops = {
	.submit_rx_burst = agiep_accel_submit_rx_burst,
	.back_rx_burst = agiep_accel_back_rx_burst,
	.submit_tx_burst = agiep_accel_submit_tx_burst,
	.back_tx_burst = agiep_accel_back_tx_burst,

	.configure = agiep_accel_configure,
	.start = agiep_accel_dev_start,
	.stop = NULL,
	.close = agiep_accel_dev_close,
	.infos_get = agiep_accel_dev_infos_get,
	.rx_queue_setup_t = agiep_accel_rx_queue_setup,
	.tx_queue_setup_t = agiep_accel_tx_queue_setup,
	.rx_queue_release_t = agiep_accel_rx_queue_release,
	.tx_queue_release_t = agiep_accel_tx_queue_release,

	.vlan_filter_set = NULL,
	.vlan_tpid_set = NULL,
	.vlan_strip_queue_set = NULL,
	.vlan_offload_set = NULL,
	.vlan_pvid_set = NULL,

	.rss_hash_update = NULL,
	.rss_hash_conf_get = NULL,
	.reta_update = NULL,
	.reta_query = NULL,

	.flow_ctrl_get = NULL,
	.flow_ctrl_set = NULL,

	.filter_ctrl = NULL,
	.features_get = agiep_accel_features_get,
	.features_set = agiep_accel_features_set,
};

static struct agiep_accel dpaa2_accel = {
	.name = ACCEL_HW_NAME,
	.ops = &agiep_accel_engine_ops,
	.agiep_accel_module_init = &agiep_accel_hw_init,
};

RTE_INIT(agiep_accel_hw_net_init)
{
	agiep_accel_engine_register(&dpaa2_accel);
}


