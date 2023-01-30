#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "debug.h"
#include "tcp_in.h"
#include "logger.h"


void thread_printf(const char* _Format, ...) 
{
    uint32_t lcore_id = rte_lcore_id();
    va_list argptr;
    va_start(argptr, _Format);

    struct mtcp_manager* mtcp = g_mtcp[lcore_id];

    if (!mtcp || !mtcp->log_fp)
        return;
    
    rte_spinlock_lock(&mtcp->logger->mutex);
    vfprintf(mtcp->log_fp, _Format, argptr);
    rte_spinlock_unlock(&mtcp->logger->mutex);

    va_end(argptr);
}
/*----------------------------------------------------------------------------*/
void DumpPacket(mtcp_manager_t mtcp, char *buf, int len, char *step, int ifindex)
{
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    uint8_t *t;

    if (ifindex >= 0)
        thread_printf("%s %d %u", step, ifindex, mtcp->cur_ts);
    else
        thread_printf("%s ? %u", step, mtcp->cur_ts);

    ethh = (struct ethhdr *)buf;
    if (ntohs(ethh->h_proto) != ETH_P_IP) {
        thread_printf("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
                ethh->h_source[0],
                ethh->h_source[1],
                ethh->h_source[2],
                ethh->h_source[3],
                ethh->h_source[4],
                ethh->h_source[5],
                ethh->h_dest[0],
                ethh->h_dest[1],
                ethh->h_dest[2],
                ethh->h_dest[3],
                ethh->h_dest[4],
                ethh->h_dest[5]);

        thread_printf("protocol %04hx  ", ntohs(ethh->h_proto));
        goto done;
    }

    thread_printf(" ");

    iph = (struct iphdr *)(ethh + 1);
    udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
    tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);

    t = (uint8_t *)&iph->saddr;
    thread_printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        thread_printf("(%d)", ntohs(udph->source));

    thread_printf(" -> ");

    t = (uint8_t *)&iph->daddr;
    thread_printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        thread_printf("(%d)", ntohs(udph->dest));

    thread_printf(" IP_ID=%d", ntohs(iph->id));
    thread_printf(" TTL=%d ", iph->ttl);

    if (ip_fast_csum(iph, iph->ihl)) {
        __sum16 org_csum, correct_csum;
        
        org_csum = iph->check;
        iph->check = 0;
        correct_csum = ip_fast_csum(iph, iph->ihl);
        thread_printf("(bad checksum %04x should be %04x) ",
                ntohs(org_csum), ntohs(correct_csum));
        iph->check = org_csum;
    }

    switch (iph->protocol) {
    case IPPROTO_TCP:
        thread_printf("TCP ");
        
        if (tcph->syn)
            thread_printf("S ");
        if (tcph->fin)
            thread_printf("F ");
        if (tcph->ack)
            thread_printf("A ");
        if (tcph->rst)
            thread_printf("R ");

        thread_printf("seq %u ", ntohl(tcph->seq));
        if (tcph->ack)
            thread_printf("ack %u ", ntohl(tcph->ack_seq));
        thread_printf("WDW=%u ", ntohs(tcph->window));
        break;
    default:
        thread_printf("protocol %d ", iph->protocol);
        goto done;
    }
done:
    thread_printf("len=%d\n", len);
}
/*----------------------------------------------------------------------------*/
void
DumpIPPacket(mtcp_manager_t mtcp, const struct iphdr *iph, int len)
{
    struct udphdr *udph;
    struct tcphdr *tcph;
    uint8_t *t;

    udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
    tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);

    t = (uint8_t *)&iph->saddr;
    thread_printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        thread_printf("(%d)", ntohs(udph->source));

    thread_printf(" -> ");

    t = (uint8_t *)&iph->daddr;
    thread_printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        thread_printf("(%d)", ntohs(udph->dest));

    thread_printf(" IP_ID=%d", ntohs(iph->id));
    thread_printf(" TTL=%d ", iph->ttl);

    if (ip_fast_csum(iph, iph->ihl)) {
        thread_printf("(bad checksum) ");
    }

    switch (iph->protocol) {
    case IPPROTO_TCP:
        thread_printf("TCP ");
        
        if (tcph->syn)
            thread_printf("S ");
        if (tcph->fin)
            thread_printf("F ");
        if (tcph->ack)
            thread_printf("A ");
        if (tcph->rst)
            thread_printf("R ");

        thread_printf("seq %u ", ntohl(tcph->seq));
        if (tcph->ack)
            thread_printf("ack %u ", ntohl(tcph->ack_seq));
        thread_printf("WDW=%u ", ntohs(tcph->window));
        break;
    default:
        thread_printf("protocol %d ", iph->protocol);
        goto done;
    }
done:
    thread_printf("len=%d\n", len);
}

