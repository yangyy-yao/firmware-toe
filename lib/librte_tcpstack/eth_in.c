#include "ps.h"
#include "ip_in.h"
#include "eth_in.h"
//#include "arp.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
int ProcessPacket(void* ctx, const int ifidx, uint32_t cur_ts, unsigned char *pkt_data, int len)
{
    struct ethhdr *ethh = (struct ethhdr *)pkt_data;
    u_short ip_proto = ntohs(ethh->h_proto);
    int ret;
    mtcp_manager_t mtcp = (mtcp_manager_t)ctx;

#ifdef PKTDUMP
    DumpPacket(mtcp, (char *)pkt_data, len, "IN", ifidx);
#endif

#ifdef NETSTAT
    mtcp->nstat.rx_packets[ifidx]++;
    mtcp->nstat.rx_bytes[ifidx] += len + 24;
#endif /* NETSTAT */

    if (ip_proto == ETH_P_IP) {
        /* process ipv4 packet */
        ret = ProcessIPv4Packet(mtcp, cur_ts, ifidx, pkt_data, len);

//    } else if (ip_proto == ETH_P_ARP) {
//        ProcessARPPacket(mtcp, cur_ts, ifidx, pkt_data, len);
//        return TRUE;
//
    } else {
        //DumpPacket(mtcp, (char *)pkt_data, len, "??", ifidx);
        //mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
        return FALSE;
    }

#ifdef NETSTAT
    if (ret < 0) {
        mtcp->nstat.rx_errors[ifidx]++;
    }
#endif

    return ret;
}
