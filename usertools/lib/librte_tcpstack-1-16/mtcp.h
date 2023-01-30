#ifndef MTCP_H
#define MTCP_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>
#include <gmp.h>

#include "memory_mgt.h"
#include "tcp_ring_buffer.h"
#include "tcp_send_buffer.h"
#include "socket.h"
#include "rte_tcpstack.h"
#include "eventpoll.h"
#include "addr_pool.h"
#include "ps.h"
#include "logger.h"
#include "stat.h"
//#include "io_module.h"
#include <rte_spinlock.h>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define ETHERNET_HEADER_LEN             14  // sizeof(struct ethhdr)
#define IP_HEADER_LEN                   20  // sizeof(struct iphdr)
#define TCP_HEADER_LEN                  20  // sizeof(struct tcphdr)
#define TOTAL_TCP_HEADER_LEN            54  // total header length

/* configurations */
#define BACKLOG_SIZE                    (10*1024)
#define MAX_PKT_SIZE                    (2*1024)
#define ETH_NUM                         MAX_DEVICES

#define TCP_OPT_TIMESTAMP_ENABLED       TRUE   // enabled for rtt measure
#define TCP_OPT_SACK_ENABLED            TRUE   // only recv-side implemented

/* Only use rate limiting if using CCP */
//#ifdef ENABLE_CCP
#undef  RATE_LIMIT_ENABLED
#define RATE_LIMIT_ENABLED              TRUE
#define PACING_ENABLED                  FALSE
// The following two logs are for debugging / experiments only, should be turned
// off for production use
// #define DBGCCP                                 // ccp debug messages
// #define PROBECCP                               // print all cwnd changes, similar to tcpprobe output
#define CC_NAME             20
//#else
//#undef  RATE_LIMIT_ENABLED
//#define RATE_LIMIT_ENABLED              FALSE
//#define PACING_ENABLED                  FALSE
//#endif

#define LOCK_STREAM_QUEUE               FALSE
#define INTR_SLEEPING_MTCP              TRUE
#define PROMISCUOUS_MODE                TRUE

#include "tcp_stream_queue.h"

#ifndef MAX_CPUS
#define MAX_CPUS                        16
#endif
/*----------------------------------------------------------------------------*/
/* Statistics */
#ifdef NETSTAT
#define NETSTAT_PERTHREAD       TRUE
#define NETSTAT_TOTAL           TRUE
#endif /* NETSTAT */
#define RTM_STAT            FALSE
/*----------------------------------------------------------------------------*/
/* Lock definitions for socket buffer */
#define SBUF_LOCK_INIT(lock, errmsg, action) rte_spinlock_init(lock)
#define SBUF_LOCK(lock)                      rte_spinlock_lock(lock)
#define SBUF_UNLOCK(lock)                    rte_spinlock_unlock(lock)

/* add macro if it is not defined in /usr/include/sys/queue.h */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                      \
    for ((var) = TAILQ_FIRST((head));                               \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1);       \
         (var) = (tvar))
#endif
/*----------------------------------------------------------------------------*/
struct eth_table
{
    char dev_name[128];
    int ifindex;
    int stat_print;
    unsigned char haddr[ETH_ALEN];
    uint32_t netmask;
//  unsigned char dst_haddr[ETH_ALEN];
    uint32_t ip_addr;
};
/*----------------------------------------------------------------------------*/
struct route_table
{
    uint32_t daddr;
    uint32_t mask;
    uint32_t masked;
    int prefix;
    int nif;
};
/*----------------------------------------------------------------------------*/
struct arp_entry
{
    uint32_t ip;
    int8_t prefix;
    uint32_t ip_mask;
    uint32_t ip_masked;
    unsigned char haddr[ETH_ALEN];
};
/*----------------------------------------------------------------------------*/
struct arp_table
{
    struct arp_entry *entry;
    struct arp_entry *gateway;
    int entries;
};
/*----------------------------------------------------------------------------*/
struct mtcp_config
{
    /* network interface config */
    struct eth_table *eths;
    int *nif_to_eidx; // mapping physic port indexes to that of the configured port-list
    int eths_num;

    /* route config */
    struct route_table *rtable;     // routing table
    struct route_table *gateway;    
    int routes;                     // # of entries

    /* arp config */
    struct arp_table arp;

    int num_cores;
    int num_mem_ch;
    int max_concurrency;
    mpz_t _cpumask;

    int max_num_buffers;
    uint32_t rcvbuf_size;
    uint32_t sndbuf_size;
    
    int tcp_timewait;
    int tcp_timeout;

    /* adding multi-process support */
    uint8_t multi_process;
    uint8_t multi_process_is_master;

//#ifdef ENABLE_CCP
    char     cc[CC_NAME];
//#endif
};
/*----------------------------------------------------------------------------*/
struct mtcp_context
{
    int cpu;
};
/*----------------------------------------------------------------------------*/
struct mtcp_sender
{
    int ifidx;

    /* TCP layer send queues */
    TAILQ_HEAD (control_head, tcp_stream) control_list;
    TAILQ_HEAD (send_head, tcp_stream) send_list;
    TAILQ_HEAD (ack_head, tcp_stream) ack_list;

    int control_list_cnt;
    int send_list_cnt;
    int ack_list_cnt;
};
/*----------------------------------------------------------------------------*/
struct mtcp_manager
{
    mem_pool_t flow_pool;       /* memory pool for tcp_stream */
    mem_pool_t rv_pool;         /* memory pool for recv variables */
    mem_pool_t sv_pool;         /* memory pool for send variables */
    mem_pool_t mv_pool;         /* memory pool for monitor variables */
    mem_pool_t rvbuf_pool;
    mem_pool_t hostbuf_pool;
    //mem_pool_t socket_pool;
    sb_manager_t rbm_snd;
    rb_manager_t rbm_rcv;
    struct hashtable *tcp_flow_table;
//#ifdef ENABLE_CCP
    struct hashtable *tcp_sid_table;
//#endif

    uint32_t s_index:24;        /* stream index */
    socket_map_t smap;
    TAILQ_HEAD (, socket_map) free_smap;

    addr_pool_t ap;         /* address pool */

    uint32_t g_id;          /* id space in a thread */
    uint32_t flow_cnt;      /* number of concurrent flows */

    struct mtcp_thread_context* ctx;
    
    /* variables related to logger */
    int sp_fd;
    log_thread_context* logger;
    //log_buff* w_buffer;
    FILE *log_fp;

    /* variables related to event */
    struct mtcp_epoll *ep;
    uint32_t ts_last_event;

    struct hashtable *listeners;

    stream_queue_t connectq;                /* streams need to connect */
    stream_queue_t sendq;               /* streams need to send data */
    stream_queue_t ackq;                    /* streams need to send ack */

    stream_queue_t closeq;              /* streams need to close */
    stream_queue_int *closeq_int;       /* internally maintained closeq */
    stream_queue_t resetq;              /* streams need to reset */
    stream_queue_int *resetq_int;       /* internally maintained resetq */
    
    stream_queue_t destroyq;                /* streams need to be destroyed */

    struct mtcp_sender *g_sender;
    struct mtcp_sender *n_sender[ETH_NUM];

    /* lists related to timeout */
    struct rto_hashstore* rto_store;
    TAILQ_HEAD (timewait_head, tcp_stream) timewait_list;
    TAILQ_HEAD (timeout_head, tcp_stream) timeout_list;

    int rto_list_cnt;
    int timewait_list_cnt;
    int timeout_list_cnt;

    uint32_t cur_ts;

    int wakeup_flag;
    int is_sleeping;

    /* statistics */
    struct bcast_stat bstat;
    struct timeout_stat tstat;
#ifdef NETSTAT
    struct net_stat nstat;
    struct net_stat p_nstat;
    uint32_t p_nstat_ts;

    struct run_stat runstat;
    struct run_stat p_runstat;

    struct time_stat rtstat;
#endif /* NETSTAT */
    struct io_module_func *iom;

//#ifdef ENABLE_CCP
    int from_ccp;
    int to_ccp;
//#endif
};
/*----------------------------------------------------------------------------*/
typedef struct mtcp_manager* mtcp_manager_t;
/*----------------------------------------------------------------------------*/
//mtcp_manager_t 
//GetMTCPManager(mctx_t mctx);
/*----------------------------------------------------------------------------*/
struct mtcp_thread_context
{
    int cpu;
    pthread_t thread;
    uint8_t done:1, 
            exit:1, 
            interrupt:1;

    struct mtcp_manager* mtcp_manager;

    void *io_private_context;
    rte_spinlock_t smap_lock;
    rte_spinlock_t flow_pool_lock;
    rte_spinlock_t socket_pool_lock;
    rte_spinlock_t connect_lock;
    rte_spinlock_t close_lock;
    rte_spinlock_t reset_lock;
    rte_spinlock_t sendq_lock;
    rte_spinlock_t ackq_lock;
    rte_spinlock_t destroyq_lock;
};
/*----------------------------------------------------------------------------*/
typedef struct mtcp_thread_context* mtcp_thread_context_t;
/*----------------------------------------------------------------------------*/
extern struct mtcp_manager *g_mtcp[MAX_CPUS];
extern struct mtcp_config CONFIG;
extern addr_pool_t ap[ETH_NUM];
/*----------------------------------------------------------------------------*/

#endif /* MTCP_H */
