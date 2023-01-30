/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_eventdev.h>
#include <rte_gro.h>

#include "l3fwd.h"

#define INVALID_EVENDEV_ID 0xFF
/* 100 ms*/
#define EVENT_DQ_TIMEOUT_NS (100*1000*1000)

#define HZ                      1000
#define TIME_TICK               (1000000/HZ)        // in us
#define TIMEVAL_TO_TS(t)        (uint32_t)((t)->tv_sec * HZ + \
                                ((t)->tv_usec / TIME_TICK))


#define GRO_MAX_FLUSH_CYCLES    1

void* toe_gro_ctx[RTE_MAX_LCORE];
struct gro_ctx {
	/* GRO types to perform */
	uint64_t gro_types;
	/* reassembly tables */
	void *tbls[RTE_GRO_TYPE_MAX_NUM];
};

struct ipv4_l3fwd_lpm_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct ipv6_l3fwd_lpm_route {
	uint8_t ip[16];
	uint8_t  depth;
	uint8_t  if_out;
};

/* 198.18.0.0/16 are set aside for RFC2544 benchmarking (RFC5735). */
static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {
	{RTE_IPV4(198, 18, 0, 0), 24, 0},
	{RTE_IPV4(198, 18, 1, 0), 24, 1},
	{RTE_IPV4(198, 18, 2, 0), 24, 2},
	{RTE_IPV4(198, 18, 3, 0), 24, 3},
	{RTE_IPV4(198, 18, 4, 0), 24, 4},
	{RTE_IPV4(198, 18, 5, 0), 24, 5},
	{RTE_IPV4(198, 18, 6, 0), 24, 6},
	{RTE_IPV4(198, 18, 7, 0), 24, 7},
};

/* 2001:0200::/48 is IANA reserved range for IPv6 benchmarking (RFC5180) */
static struct ipv6_l3fwd_lpm_route ipv6_l3fwd_lpm_route_array[] = {
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 48, 0},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 48, 1},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0}, 48, 2},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0}, 48, 3},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0}, 48, 4},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0}, 48, 5},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0}, 48, 6},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0}, 48, 7},
};

#define IPV4_L3FWD_LPM_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_lpm_route_array) / sizeof(ipv4_l3fwd_lpm_route_array[0]))
#define IPV6_L3FWD_LPM_NUM_ROUTES \
	(sizeof(ipv6_l3fwd_lpm_route_array) / sizeof(ipv6_l3fwd_lpm_route_array[0]))

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];
static inline void toe_parse_ptype(struct rte_mbuf *m);

static inline uint16_t
lpm_get_ipv4_dst_port(void *ipv4_hdr, uint16_t portid, void *lookup_struct)
{
	uint32_t next_hop;
	struct rte_lpm *ipv4_l3fwd_lookup_struct =
		(struct rte_lpm *)lookup_struct;

	return (uint16_t) ((rte_lpm_lookup(ipv4_l3fwd_lookup_struct,
		rte_be_to_cpu_32(((struct rte_ipv4_hdr *)ipv4_hdr)->dst_addr),
		&next_hop) == 0) ? next_hop : portid);
}

static inline uint16_t
lpm_get_ipv6_dst_port(void *ipv6_hdr, uint16_t portid, void *lookup_struct)
{
	uint32_t next_hop;
	struct rte_lpm6 *ipv6_l3fwd_lookup_struct =
		(struct rte_lpm6 *)lookup_struct;

	return (uint16_t) ((rte_lpm6_lookup(ipv6_l3fwd_lookup_struct,
			((struct rte_ipv6_hdr *)ipv6_hdr)->dst_addr,
			&next_hop) == 0) ?  next_hop : portid);
}

static __rte_always_inline uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint16_t portid)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		return lpm_get_ipv4_dst_port(ipv4_hdr, portid,
					     qconf->ipv4_lookup_struct);
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					     qconf->ipv6_lookup_struct);
	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static __rte_always_inline uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint16_t portid)
{
	uint32_t next_hop;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct,
						   dst_ipv4, &next_hop) == 0)
				   ? next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop) == 0)
				? next_hop : portid);

	}

	return portid;
}

#if defined(RTE_ARCH_X86)
#include "l3fwd_lpm_sse.h"
#elif defined RTE_MACHINE_CPUFLAG_NEON
#include "l3fwd_lpm_neon.h"
#elif defined(RTE_ARCH_PPC_64)
#include "l3fwd_lpm_altivec.h"
#else
#include "l3fwd_lpm.h"
#endif

/* main processing loop for eventdev*/
int
lpm_eventdev_main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_event ev[MAX_PKT_BURST];
	struct rte_event_port_conf event_port_conf;
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint16_t portid, dequeue_len;
	uint8_t event_port_id = INVALID_EVENDEV_ID;
	uint8_t queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;
	uint64_t timeout_tick;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &l3_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	for (i = 0; i < link_config.nb_links; i++) {
		if (link_config.links[i].lcore_id == lcore_id)
			event_port_id = link_config.links[i].event_portid;
	}

	rte_event_port_default_conf_get(event_devices[0].dev_id, event_port_id,
					&event_port_conf);
	dequeue_len = event_port_conf.dequeue_depth;

	rte_event_dequeue_timeout_ticks(event_devices[0].dev_id,
					EVENT_DQ_TIMEOUT_NS, &timeout_tick);

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from event ports
		 */
		nb_rx = rte_event_dequeue_burst(event_devices[0].dev_id,
						event_port_id,
						ev, dequeue_len,
						timeout_tick);
		if (nb_rx == 0)
			continue;

		for (i = 0; i < nb_rx; i++) {
			pkts_burst[0] = ev[i].mbuf;
			portid = ev[i].flow_id;
#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON \
			 || defined RTE_ARCH_PPC_64
			l3fwd_lpm_send_packets(1, pkts_burst, portid,
					       qconf);
#else
			l3fwd_lpm_no_opt_send_packets(1, pkts_burst,
						      portid, qconf);
#endif /* X86 */
		}
	}

	return 0;
}

/* main processing loop */
#define PORT_TYPE_DPNI 0
#define PORT_TYPE_FREP_TASK 1
#define PORT_TYPE_FREP_PF0 2
#define PORT_TYPE_TOE 3


inline void* toe_gro_get_ctx()
{
    return toe_gro_ctx[rte_lcore_id()];
}

static void toe_mbuf_tcp4_gro(struct gro_ctx *gro_ctx,struct rte_mbuf **unprocess_pkts, struct rte_mbuf *m, uint64_t current_time, uint16_t *unprocess_num)
{
	void *tcp_tbl;

	tcp_tbl = gro_ctx->tbls[RTE_GRO_TCP_IPV4_INDEX];

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type) && ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)) {
		if (gro_tcp4_reassemble(m, tcp_tbl, current_time) < 0)
			unprocess_pkts[(*unprocess_num) ++] = m;
	} else {
		unprocess_pkts[(*unprocess_num) ++] = m;
	}

}

static void toe_rcv_pkt_process(int portid, int nb_rx, struct rte_mbuf **pkts_burst, struct lcore_conf *qconf, uint64_t current_time)
{
	int dst_portid;
	int j;
	struct rte_mbuf *unprocess_pkts[nb_rx];
	//uint64_t current_time = rte_rdtsc();
	uint16_t unprocess_num = 0;
	uint8_t toe_gro_times = 0;
	uint16_t nb_gro_pkts = 0;
	struct gro_ctx *gro_ctx = toe_gro_get_ctx();
	
	for (j = 0; j < nb_rx; j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void*));
		toe_parse_ptype(pkts_burst[j]);
	//printf("%s-%d: portid:%d\n",__func__,__LINE__,portid);	
		switch (portid) {
			case PORT_TYPE_DPNI:
				if ((pkts_burst[j]->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
					dst_portid = PORT_TYPE_TOE;
				else 
					dst_portid = PORT_TYPE_FREP_PF0;
				break;
			case PORT_TYPE_FREP_TASK:
				dst_portid = PORT_TYPE_DPNI;
				break;
			 case PORT_TYPE_FREP_PF0:
				dst_portid = PORT_TYPE_DPNI;
				break;
			case PORT_TYPE_TOE:
				dst_portid = PORT_TYPE_DPNI;
				break;
			default:
				dst_portid = portid;
				break;
		};
		toe_mbuf_tcp4_gro(gro_ctx, unprocess_pkts, pkts_burst[j], current_time, &unprocess_num);
	}

	//printf("%s-%d:unprocess_num:%d \n",__func__,__LINE__,unprocess_num);
	if (unprocess_num > 0) {
			memcpy(pkts_burst, unprocess_pkts, sizeof(struct rte_mbuf *) *
					unprocess_num);
	}

	if (GRO_MAX_FLUSH_CYCLES <= ++toe_gro_times) {
		toe_gro_times = 0;
		nb_gro_pkts = rte_gro_get_pkt_count(gro_ctx);
					
		if (nb_gro_pkts > (MAX_PKT_BURST - unprocess_num))
			nb_gro_pkts = MAX_PKT_BURST - unprocess_num;

		unprocess_num += rte_gro_timeout_flush(gro_ctx, 0, RTE_GRO_TCP_IPV4, &pkts_burst[unprocess_num], nb_gro_pkts);
	}
	//printf("%s-%d: nb_gro_pkts:%d,unprocess_num:%d \n",__func__,__LINE__,nb_gro_pkts,unprocess_num);
	for (j = 0; j < unprocess_num; j++) {
		send_single_packet(qconf, pkts_burst[j], dst_portid);
	}

}

int
toe_main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, j,nb_rx;
	uint16_t portid, dst_portid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	struct timeval cur_ts = {0};
	uint32_t ts;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &l3_lcore_conf[lcore_id];
		//return lpm_eventdev_main_loop(dummy);

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

//		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
//		diff_tsc = cur_tsc - prev_tsc;
//		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
                
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

//			prev_tsc = cur_tsc;
//		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				max_rx_burst);
			if (nb_rx == 0)
				continue;
			if (portid == PORT_TYPE_DPNI) {
				printf("%s-%d: nb_rx:%d\n",__func__,__LINE__,nb_rx);
			}
	//		gettimeofday(&cur_ts, NULL);
	//		ts = TIMEVAL_TO_TS(&cur_ts);

#ifdef toe_gro
			toe_rcv_pkt_process(portid, nb_rx, pkts_burst, qconf, cur_tsc);
#else
			for (j = 0; j < nb_rx; j++) {
				switch (portid) {
					case PORT_TYPE_DPNI:
						rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void*));
						toe_parse_ptype(pkts_burst[j]);
						
						if ((pkts_burst[j]->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
							dst_portid = PORT_TYPE_TOE;
						else 
							dst_portid = PORT_TYPE_FREP_PF0;
						break;
					case PORT_TYPE_FREP_TASK:
						dst_portid = PORT_TYPE_DPNI;
						break;
					 case PORT_TYPE_FREP_PF0:
						dst_portid = PORT_TYPE_DPNI;
						break;
					case PORT_TYPE_TOE:
						dst_portid = PORT_TYPE_DPNI;
						break;
					default:
						dst_portid = portid;
						break;
				};
				//pkts_burst[j]->timestamp = (rte_rdtsc()*1000)/rte_get_tsc_hz(); //ms
            //RTE_LOG(INFO, L3FWD, "Receive %u Pkts From Port.%u[Q.%u]  Forwarding To Port.%u\n", nb_rx, portid, queueid, dst_portid);
	//			pkts_burst[j]->timestamp = ts; //ms
				send_single_packet(qconf, pkts_burst[j], dst_portid); 
			}
#endif
#if 0
#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON \
			 || defined RTE_ARCH_PPC_64
			l3fwd_lpm_send_packets(nb_rx, pkts_burst,
						portid, qconf);
#else
			l3fwd_lpm_no_opt_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#endif /* X86 */
#endif

		}
	}

	return 0;
}

void
setup_lpm(const int socketid)
{
	struct rte_lpm6_config config;
	struct rte_lpm_config config_ipv4;
	unsigned i;
	int ret;
	char s[64];
	char abuf[INET6_ADDRSTRLEN];

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {
		struct in_addr in;

		/* skip unused ports */
		if ((1 << ipv4_l3fwd_lpm_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
			ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		in.s_addr = htonl(ipv4_l3fwd_lpm_route_array[i].ip);
		printf("LPM: Adding route %s / %d (%d)\n",
		       inet_ntop(AF_INET, &in, abuf, sizeof(abuf)),
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
	}

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_l3fwd_lpm_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
				&config);
	if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < IPV6_L3FWD_LPM_NUM_ROUTES; i++) {

		/* skip unused ports */
		if ((1 << ipv6_l3fwd_lpm_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
			ipv6_l3fwd_lpm_route_array[i].ip,
			ipv6_l3fwd_lpm_route_array[i].depth,
			ipv6_l3fwd_lpm_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route %s / %d (%d)\n",
		       inet_ntop(AF_INET6, ipv6_l3fwd_lpm_route_array[i].ip,
				 abuf, sizeof(abuf)),
		       ipv6_l3fwd_lpm_route_array[i].depth,
		       ipv6_l3fwd_lpm_route_array[i].if_out);
	}
}

int
lpm_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (ptype_l3_ipv4 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

	if (ptype_l3_ipv6 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

	if (ptype_l3_ipv4 && ptype_l3_ipv6)
		return 1;

	return 0;

}

static inline void
toe_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint16_t ether_type;
	struct rte_net_hdr_lens hdr_lens;
	uint32_t packet_type = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_L2_MASK|RTE_PTYPE_L3_MASK|RTE_PTYPE_L4_MASK);

  
	m->l2_len = hdr_lens.l2_len;
  	m->l3_len = hdr_lens.l3_len;
  	m->l4_len = hdr_lens.l4_len;
	m->packet_type = packet_type;
  /*
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
*/
}

uint16_t
toe_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		   struct rte_mbuf *pkts[], uint16_t nb_pkts,
		   uint16_t max_pkts __rte_unused,
		   void *user_param __rte_unused)
{
	unsigned int i;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int) (nb_pkts - 1); ++i) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1],
			struct ether_hdr *));
		toe_parse_ptype(pkts[i]);
	}
	toe_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* Return ipv4/ipv6 lpm fwd lookup struct. */
void *
lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lpm_lookup_struct[socketid];
}

void *
lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_lpm_lookup_struct[socketid];
}

//void *
//lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
//{
//	return ipv6_l3fwd_lpm_lookup_struct[socketid];
//}
