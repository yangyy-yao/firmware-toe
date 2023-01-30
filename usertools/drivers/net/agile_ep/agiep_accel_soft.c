#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_malloc.h>
#include "agiep_accel_engine.h"
#include "agiep_virtio_net.h"
#include "agiep_accel_soft.h"

#define accel_default_features \
	((1 << VIRTIO_NET_F_CSUM)	|  \
	(1 << VIRTIO_NET_F_GUEST_CSUM))

static int agiep_accel_soft_init(struct agiep_accel_device *accel_dev)
{
	struct accel_soft_device *soft_dev = NULL;

	soft_dev = rte_calloc(NULL, 1, sizeof(struct accel_soft_device), 0);
	if (!soft_dev) {
		RTE_LOG(ERR, PMD, "%s-%d: accel soft dev malloc failed!\n", __func__, __LINE__);
		return -1;
	}

	soft_dev->feature = accel_default_features;
	accel_dev->priv = (void *)soft_dev;
	return 0;
}

static uint64_t agiep_accel_soft_features_get(struct agiep_frep_device *frep_dev)
{
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;

	return soft_dev->feature;
}

static void agiep_accel_soft_features_set(struct agiep_frep_device *frep_dev, uint64_t req_features)
{
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;

	soft_dev->feature |= req_features;
	return;
}

static void agiep_accel_pkt_parse(struct rte_mbuf *m)
{
	struct rte_net_hdr_lens hdr_lens;

	memset(&hdr_lens, 0, sizeof(hdr_lens));
	m->packet_type = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK);

	m->l2_len = hdr_lens.l2_len;
	m->l3_len = hdr_lens.l3_len;
	m->l4_len = hdr_lens.l4_len;
	return;
}

static void agiep_accel_v4_checksum_calculate(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_udp_hdr *udphdr = NULL;
	struct rte_tcp_hdr *tcphdr = NULL;

	ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, m->l2_len);

	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP
		&& (m->ol_flags & PKT_TX_UDP_CKSUM) != 0) {
		udphdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, m->l2_len + m->l3_len);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udphdr);
		m->ol_flags &= ~PKT_TX_UDP_CKSUM;
	}

	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP
		&& (m->ol_flags & PKT_TX_TCP_CKSUM) != 0) {
		tcphdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, m->l2_len + m->l3_len);
		tcphdr->cksum = 0;
		tcphdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcphdr);
		m->ol_flags &= ~PKT_TX_TCP_CKSUM;
	}

	if ((m->ol_flags & PKT_TX_IP_CKSUM) != 0) {
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);		
		m->ol_flags &= ~PKT_TX_IP_CKSUM;
	}
	
	return;
}

static void agiep_accel_v6_checksum_calculate(struct rte_mbuf *m)
{
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	struct rte_udp_hdr *udphdr = NULL;
	struct rte_tcp_hdr *tcphdr = NULL;

	ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, m->l2_len);
		
	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP
		&& (m->ol_flags & PKT_TX_UDP_CKSUM) != 0) {
		udphdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, m->l2_len + m->l3_len);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udphdr);
		m->ol_flags &= ~PKT_TX_UDP_CKSUM;
	}
	
	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP
		&& (m->ol_flags & PKT_TX_TCP_CKSUM) != 0) {
		tcphdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, m->l2_len + m->l3_len);
		tcphdr->cksum = 0;
		tcphdr->cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, tcphdr);
		m->ol_flags &= ~PKT_TX_TCP_CKSUM;
	}

	return;
}

static void agiep_accel_checksum_calculate(struct rte_mbuf *m)
{
	if (m->packet_type & RTE_PTYPE_L3_IPV4)
		agiep_accel_v4_checksum_calculate(m);

	if (m->packet_type & RTE_PTYPE_L3_IPV6)
		agiep_accel_v6_checksum_calculate(m);

	return;
}

static uint16_t agiep_accel_soft_submit_rx_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = rx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	int i;

	if (nb_pkts > MAX_BURST_NUMBER)
		nb_pkts = MAX_BURST_NUMBER;
	
	for (i = 0; i < nb_pkts; i++) {
		agiep_accel_pkt_parse(rx_pkts[i]);
		agiep_accel_checksum_calculate(rx_pkts[i]);
		soft_dev->rx_ring[q->qid].pkts[i] = rx_pkts[i];
	}
	
	soft_dev->rx_ring[q->qid].nb_pkts = nb_pkts;
	return nb_pkts;
}

static uint16_t agiep_accel_soft_back_rx_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts __rte_unused)
{
	struct agiep_frep_queue *q = rx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	uint16_t nb_back_pkts = soft_dev->rx_ring[q->qid].nb_pkts;
	int i;

	for (i = 0; i < nb_back_pkts; i++) {
		rx_pkts[i] = soft_dev->rx_ring[q->qid].pkts[i];
		soft_dev->rx_ring[q->qid].pkts[i] = NULL;
	}
	
	soft_dev->rx_ring[q->qid].nb_pkts = 0;
	return nb_back_pkts;
}

static void agiep_accel_v4_checksum(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_udp_hdr *udphdr = NULL;
	struct rte_tcp_hdr *tcphdr = NULL;
	uint16_t csum = 0;

	ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, m->l2_len);

	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP
		&& (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
		udphdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, m->l2_len + m->l3_len);
		if (udphdr->dgram_cksum != 0) {
			csum = ~(rte_ipv4_udptcp_cksum(ipv4_hdr, udphdr));
			m->ol_flags |= !csum ? PKT_RX_L4_CKSUM_GOOD : PKT_RX_L4_CKSUM_BAD;
		}
	}

	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP
		&& (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
		tcphdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, m->l2_len + m->l3_len);
		csum = ~(rte_ipv4_udptcp_cksum(ipv4_hdr, tcphdr));
		m->ol_flags |= !csum ? PKT_RX_L4_CKSUM_GOOD : PKT_RX_L4_CKSUM_BAD;
	}

	if ((m->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_UNKNOWN) {
		csum = ~(rte_ipv4_cksum(ipv4_hdr));
		m->ol_flags |= !csum ? PKT_RX_IP_CKSUM_GOOD : PKT_RX_IP_CKSUM_BAD;
	}
	return;
}

static void agiep_accel_v6_checksum(struct rte_mbuf *m)
{
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	struct rte_udp_hdr *udphdr = NULL;
	struct rte_tcp_hdr *tcphdr = NULL;
	uint16_t csum = 0;

	ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, m->l2_len);
		
	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP
		&& (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
		udphdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, m->l2_len + m->l3_len);
		csum = ~(rte_ipv6_udptcp_cksum(ipv6_hdr, udphdr));		
		m->ol_flags |= !csum ? PKT_RX_L4_CKSUM_GOOD : PKT_RX_L4_CKSUM_BAD;
	}
	
	if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP
		&& (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
		tcphdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, m->l2_len + m->l3_len);
		csum = ~(rte_ipv6_udptcp_cksum(ipv6_hdr, tcphdr));
		m->ol_flags |= !csum ? PKT_RX_L4_CKSUM_GOOD : PKT_RX_L4_CKSUM_BAD;
	}

	return;
}

static void agiep_accel_pkt_checksum(struct rte_mbuf *m)
{
	if (m->packet_type & RTE_PTYPE_L3_IPV4)
		agiep_accel_v4_checksum(m);

	if (m->packet_type & RTE_PTYPE_L3_IPV6)
		agiep_accel_v6_checksum(m);
	
	return;
}

static uint16_t agiep_accel_soft_submit_tx_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct agiep_frep_queue *q = tx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	int lcore_idx = rte_lcore_index(rte_lcore_id());
	int i;
	
	
	if (nb_pkts > MAX_BURST_NUMBER)
		nb_pkts = MAX_BURST_NUMBER;
	
	for (i = 0; i < nb_pkts; i++) {
		agiep_accel_pkt_parse(tx_pkts[i]);
		agiep_accel_pkt_checksum(tx_pkts[i]);
		soft_dev->tx_ring[lcore_idx][q->qid].pkts[i] = tx_pkts[i];
	}
	
	soft_dev->tx_ring[lcore_idx][q->qid].nb_pkts = nb_pkts;
	return nb_pkts;
}

static uint16_t agiep_accel_soft_back_tx_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts __rte_unused)
{
	struct agiep_frep_queue *q = tx_queue;
	struct agiep_frep_device *frep_dev = q->dev;
	struct accel_soft_device *soft_dev = ((struct agiep_accel_device *)frep_dev->extra)->priv;
	int lcore_idx = rte_lcore_index(rte_lcore_id());
	int i;
	uint16_t nb_back_pkts = soft_dev->tx_ring[lcore_idx][q->qid].nb_pkts;
	

	for (i = 0; i < nb_back_pkts; i++) {
		tx_pkts[i] = soft_dev->tx_ring[lcore_idx][q->qid].pkts[i];
		soft_dev->tx_ring[lcore_idx][q->qid].pkts[i] = NULL;
	}
	
	soft_dev->tx_ring[lcore_idx][q->qid].nb_pkts = 0;
	return nb_back_pkts;
}

static int agiep_accel_soft_configure(struct agiep_accel_device * accel_dev)
{
	struct agiep_frep_device *frep_dev = accel_dev->dev;
	struct accel_soft_device *soft_dev = accel_dev->priv;
	struct rte_eth_dev_info dev_info = {0};
	int i;
	int lcore_num = rte_lcore_count();
	
	if (*frep_dev->eth_dev->dev_ops->dev_infos_get
		&& 0 != (*frep_dev->eth_dev->dev_ops->dev_infos_get)(frep_dev->eth_dev, &dev_info)) {
		RTE_LOG(ERR, PMD, "%s-%d:,eth_dev->dev_ops->dev_infos_get failed!\n", __func__, __LINE__);
		goto failed;
	}

	soft_dev->rx_ring = rte_calloc(NULL, dev_info.max_rx_queues, sizeof(struct accel_soft_ring), 0);
	if (!soft_dev->rx_ring) {
		RTE_LOG(ERR, PMD, "%s-%d:soft_dev rx_ring calloc failed! dev_info.max_rx_queues:%d\n", __func__, __LINE__, dev_info.max_rx_queues);
		goto failed;
	}


	soft_dev->tx_ring = rte_calloc(NULL, lcore_num, sizeof(struct accel_soft_ring *), 0);
	if (!soft_dev->tx_ring) {
		RTE_LOG(ERR, PMD, "%s-%d:soft_dev tx_ring calloc failed! rte_lcore_count():%d\n", __func__, __LINE__, lcore_num);
		goto failed;
	}

	for (i = 0; i < lcore_num; i++) {
		soft_dev->tx_ring[i] = rte_calloc(NULL, dev_info.max_tx_queues, sizeof(struct accel_soft_ring), 0);
		if (!soft_dev->tx_ring[i]) {
			RTE_LOG(ERR, PMD, "%s-%d:soft_dev tx_ring[%d] calloc failed! dev_info.max_tx_queues:%d\n", __func__, __LINE__, i, dev_info.max_tx_queues);
			goto failed;
		}
	}
	return 0;

failed:

	if (soft_dev->rx_ring) {
		rte_free(soft_dev->rx_ring);
		soft_dev->rx_ring = NULL;
	}

	if (soft_dev->tx_ring) {
		for (i = 0; i < lcore_num; i++)
			if (soft_dev->tx_ring[i]) {
				rte_free(soft_dev->tx_ring[i]);
				soft_dev->tx_ring[i] = NULL;
			}
			
		rte_free(soft_dev->tx_ring);
		soft_dev->tx_ring = NULL;
	}

	return -1;
}

static int agiep_accel_soft_dev_close(struct agiep_accel_device * accel_dev)
{
	struct accel_soft_device *soft_dev = accel_dev->priv;
	int i;
	int lcore_num = rte_lcore_count();
	
	accel_dev->priv = NULL;
	
	rte_free(soft_dev->rx_ring);

	for (i = 0; i < lcore_num; i++)
		if (soft_dev->tx_ring[i]) {
			rte_free(soft_dev->tx_ring[i]);
			soft_dev->tx_ring[i] = NULL;
		}
		
	rte_free(soft_dev->tx_ring);
	rte_free(soft_dev);
	return 0;
}

static int agiep_accel_soft_dev_infos_get(struct rte_eth_dev_info *dev_info)
{
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_CHECKSUM;
	return 0;
}

static struct agiep_accel_ops agiep_accel_engine_ops = {
	.submit_rx_burst = agiep_accel_soft_submit_rx_burst,
	.back_rx_burst = agiep_accel_soft_back_rx_burst,
	.submit_tx_burst = agiep_accel_soft_submit_tx_burst,
	.back_tx_burst = agiep_accel_soft_back_tx_burst,

	.configure = agiep_accel_soft_configure,
	.start = NULL,
	.stop = NULL,
	.close = agiep_accel_soft_dev_close,
	.infos_get = agiep_accel_soft_dev_infos_get,
	
	.rx_queue_setup_t = NULL,
	.tx_queue_setup_t = NULL,
	.rx_queue_release_t = NULL,
	.tx_queue_release_t = NULL,

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
	.features_get = agiep_accel_soft_features_get,
	.features_set = agiep_accel_soft_features_set,
};


static struct agiep_accel soft_accel = {
	.name = "accel_soft",
	.ops = &agiep_accel_engine_ops,
	.agiep_accel_module_init = &agiep_accel_soft_init,
};

RTE_INIT(agiep_accel_soft_deal_init)
{
	agiep_accel_engine_register(&soft_accel);
}

