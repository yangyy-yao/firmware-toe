#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#include "mtcp.h"
#include "config.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "debug.h"
#include "timer.h"
/* for setting up io modules */
//#include "io_module.h"
/* for if_nametoindex */
#include <net/if.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#define MAX_ROUTE_ENTRY             64
#define MAX_OPTLINE_LEN             1024
#define ALL_STRING              "all"

static const char *route_file =         "config/route.conf";
static const char *arp_file =           "config/arp.conf";
struct mtcp_manager *g_mtcp[MAX_CPUS] =     {NULL};
/* handlers for threads */
struct mtcp_thread_context *g_pctx[MAX_CPUS] = {0};
struct log_thread_context *g_logctx[MAX_CPUS] = {0};
struct mtcp_config CONFIG = {
    /* set default configuration */
    .max_concurrency  =         10000,
    .max_num_buffers  =         10000,
    .rcvbuf_size      =         65535,//8192,
    .sndbuf_size      =         131328,
    .tcp_timeout      =         TCP_TIMEOUT,
    .tcp_timewait     =         TCP_TIMEWAIT,
    .num_mem_ch   =         0,
#ifdef ENABLE_CCP
    .cc               =                 "reno\n",
#endif
};
addr_pool_t ap[ETH_NUM] =           {NULL};
static char port_list[MAX_OPTLINE_LEN] =    "";
static char port_stat_list[MAX_OPTLINE_LEN] =   "";
/* total cpus detected in the mTCP stack*/
int num_cpus;
/* this should be equal to num_cpus */
int num_queues;
int num_devices;

int num_devices_attached;
int devices_attached[MAX_DEVICES];

inline struct mtcp_sender* CreateMTCPSender(int ifidx)
{
    struct mtcp_sender *sender;

    sender = (struct mtcp_sender *)rte_zmalloc(NULL, sizeof(struct mtcp_sender), RTE_CACHE_LINE_SIZE);
    if (!sender) {
        TRACE_DEBUG("Failed to calloc mtcp sender.\n");
        return NULL;
    }

    sender->ifidx = ifidx;

    TAILQ_INIT(&sender->control_list);
    TAILQ_INIT(&sender->send_list);
    TAILQ_INIT(&sender->ack_list);

    sender->control_list_cnt = 0;
    sender->send_list_cnt = 0;
    sender->ack_list_cnt = 0;

    return sender;
}

void* InitializeMTCPManagerPerCore(uint32_t lcore_id)
{
    mtcp_manager_t mtcp;
    struct mtcp_thread_context *ctx;
    int i;
    char log_name[64] = {0};

    ctx = (struct mtcp_thread_context*)rte_zmalloc(NULL, sizeof(struct mtcp_thread_context), RTE_CACHE_LINE_SIZE);
    
    if (!ctx) {
        printf("Core.%u ctx alloc fail\n", lcore_id);
        return NULL;
    }
    
//    ctx->thread = pthread_self();
    ctx->cpu = lcore_id;
        
    rte_spinlock_init(&ctx->smap_lock);
    rte_spinlock_init(&ctx->flow_pool_lock);
    rte_spinlock_init(&ctx->socket_pool_lock);

    /* initialize logger */
    g_logctx[lcore_id] = (struct log_thread_context*)rte_zmalloc(NULL, sizeof(struct log_thread_context), RTE_CACHE_LINE_SIZE);
    if (!g_logctx[lcore_id]) {
        rte_free(ctx);
        printf("Core.%u g_logctx alloc fail\n", lcore_id);
        return NULL;
    }
    
    rte_spinlock_init(&g_logctx[lcore_id]->mutex);

    mtcp = (mtcp_manager_t)rte_zmalloc(NULL, sizeof(struct mtcp_manager), RTE_CACHE_LINE_SIZE);
    if (!mtcp) {
        printf("Core.%u mtcp alloc fail\n", lcore_id);
        return NULL;
    }
    
    g_mtcp[ctx->cpu] = mtcp;
//    printf("%s-%d: ctx->cpu:%d, mtcp:%p\n",__func__,__LINE__,ctx->cpu,mtcp);
    mtcp->tcp_flow_table = CreateHashtable(HashFlow, EqualFlow, NUM_BINS_FLOWS);
    if (!mtcp->tcp_flow_table) {
        printf("Core.%u mtcp->tcp_flow_table alloc fail\n", lcore_id);
        return NULL;
    }

#ifdef ENABLE_CCP
    mtcp->tcp_sid_table = CreateHashtable(HashSID, EqualSID, NUM_BINS_FLOWS);
    if (!mtcp->tcp_sid_table) {
        printf("Core.%u mtcp->tcp_sid_table alloc fail\n", lcore_id);
        return NULL;
    }
#endif

    mtcp->listeners = CreateHashtable(HashListener, EqualListener, NUM_BINS_LISTENERS);
    if (!mtcp->listeners) {
        printf("Core.%u mtcp->listeners alloc fail\n", lcore_id);
        return NULL;
    }

    mtcp->ctx = ctx;

    char pool_name[RTE_MEMPOOL_NAMESIZE];
    sprintf(pool_name, "flow_pool_%d", ctx->cpu);
    mtcp->flow_pool = MPCreate(pool_name, sizeof(tcp_stream),
                   sizeof(tcp_stream) * CONFIG.max_concurrency);
    if (!mtcp->flow_pool) {
        printf("Core.%u mtcp->flow_pool alloc fail\n", lcore_id);
        return NULL;
    }
    
    sprintf(pool_name, "rv_pool_%d", ctx->cpu); 
    mtcp->rv_pool = MPCreate(pool_name, sizeof(struct tcp_recv_vars), 
            sizeof(struct tcp_recv_vars) * CONFIG.max_concurrency);
    if (!mtcp->rv_pool) {
        printf("Core.%u mtcp->rv_pool alloc fail\n", lcore_id);
        return NULL;
    }
    
    sprintf(pool_name, "sv_pool_%d", ctx->cpu);
    mtcp->sv_pool = MPCreate(pool_name, sizeof(struct tcp_send_vars), 
            sizeof(struct tcp_send_vars) * CONFIG.max_concurrency);
    if (!mtcp->sv_pool) {
        printf("Core.%u mtcp->sv_pool alloc fail\n", lcore_id);
        return NULL;
    }

    sprintf(pool_name, "rvbuf_pool_%d", ctx->cpu);
    mtcp->rvbuf_pool = MPCreate(pool_name, sizeof(struct tcp_ring_buffer),
            sizeof(struct tcp_ring_buffer) * CONFIG.max_concurrency);
    if (!mtcp->rvbuf_pool) {
        printf("Core.%u mtcp->sv_pool alloc fail\n", lcore_id);
        return NULL;
    }

    sprintf(pool_name, "host_buff_pool%d", ctx->cpu);
    mtcp->hostbuf_pool = MPCreate(pool_name, sizeof(struct tcp_prepare_read),
		sizeof(struct tcp_prepare_read) * CONFIG.max_concurrency);
    if (!mtcp->hostbuf_pool) {
	printf("Core.%u mtcp->hostbuf_pool alloc fail\n", lcore_id);
        return NULL;
    }

    mtcp->rbm_snd = SBManagerCreate(mtcp, CONFIG.sndbuf_size, CONFIG.max_num_buffers);
    if (!mtcp->rbm_snd) {
        printf("Core.%u mtcp->rbm_snd alloc fail\n", lcore_id);
        return NULL;
    }

    mtcp->rbm_rcv = RBManagerCreate(mtcp, CONFIG.rcvbuf_size, CONFIG.max_num_buffers);
    if (!mtcp->rbm_rcv) {
        printf("Core.%u mtcp->rbm_rcv alloc fail\n", lcore_id);
        return NULL;
    }

    InitializeTCPStreamManager();

    mtcp->smap = (socket_map_t)rte_zmalloc(NULL, CONFIG.max_concurrency * sizeof(struct socket_map), RTE_CACHE_LINE_SIZE);
    if (!mtcp->smap) {
        printf("Core.%u mtcp->smap alloc fail\n", lcore_id);
        return NULL;
    }
    TAILQ_INIT(&mtcp->free_smap);
    for (i = 0; i < CONFIG.max_concurrency; i++) {
        mtcp->smap[i].id = i;
        mtcp->smap[i].socktype = MTCP_SOCK_UNUSED;
        memset(&mtcp->smap[i].saddr, 0, sizeof(struct sockaddr_in));
        mtcp->smap[i].stream = NULL;
        TAILQ_INSERT_TAIL(&mtcp->free_smap, &mtcp->smap[i], free_smap_link);
    }

    mtcp->ep = NULL;

    sprintf(log_name, "/tmp/dpdk_tcp_stack.%02d.log", ctx->cpu);
    mtcp->log_fp = fopen(log_name, "w");
    if (!mtcp->log_fp) {
        mtcp->log_fp = stdout;
        printf("Core.%u mtcp->log_fp open fail\n", lcore_id);
        return NULL;
    }
    printf("Core.%u mtcp->log_fp %s created\n", lcore_id, log_name);
    
    mtcp->sp_fd = g_logctx[ctx->cpu]->pair_sp_fd;
    mtcp->logger = g_logctx[ctx->cpu];
   /* 
    mtcp->connectq = CreateStreamQueue(BACKLOG_SIZE);
    if (!mtcp->connectq) {
        TRACE_DEBUG("Failed to create connect queue.\n");
        return NULL;
    }
    mtcp->sendq = CreateStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->sendq) {
        TRACE_DEBUG("Failed to create send queue.\n");
        return NULL;
    }
    mtcp->ackq = CreateStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->ackq) {
        TRACE_DEBUG("Failed to create ack queue.\n");
        return NULL;
    }
    mtcp->closeq = CreateStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->closeq) {
        TRACE_DEBUG("Failed to create close queue.\n");
        return NULL;
    }
    mtcp->closeq_int = CreateInternalStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->closeq_int) {
        TRACE_DEBUG("Failed to create close queue.\n");
        return NULL;
    }
    mtcp->resetq = CreateStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->resetq) {
        TRACE_DEBUG("Failed to create reset queue.\n");
        return NULL;
    }
    mtcp->resetq_int = CreateInternalStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->resetq_int) {
        TRACE_DEBUG("Failed to create reset queue.\n");
        return NULL;
    }
    mtcp->destroyq = CreateStreamQueue(CONFIG.max_concurrency);
    if (!mtcp->destroyq) {
        TRACE_DEBUG("Failed to create destroy queue.\n");
        return NULL;
    }
*/
    mtcp->g_sender = CreateMTCPSender(-1);
    if (!mtcp->g_sender) {
        TRACE_DEBUG("Failed to create global sender structure.\n");
        return NULL;
    }
    for (i = 0; i < 1; i++) {
        mtcp->n_sender[i] = CreateMTCPSender(i);
        if (!mtcp->n_sender[i]) {
            TRACE_DEBUG("Failed to create per-nic sender structure.\n");
            return NULL;
        }
    }

    mtcp->rto_store = InitRTOHashstore();
    TAILQ_INIT(&mtcp->timewait_list);
    TAILQ_INIT(&mtcp->timeout_list);
    TRACE_DEBUG("InitializeMTCPManagerPerCore On Core.%u Finish.\n", lcore_id);

    return mtcp;
}



