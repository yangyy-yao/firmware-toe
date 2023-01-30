#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "debug.h"
#include "fhash.h"
#include <rte_malloc.h>
#include <rte_common.h>
#define IS_FLOW_TABLE(x)    (x == HashFlow)
#define IS_LISTEN_TABLE(x)  (x == HashListener)
#ifdef ENABLE_CCP
#define IS_SID_TABLE(x)     (x == HashSID)
#endif

/*----------------------------------------------------------------------------*/
struct hashtable* CreateHashtable(unsigned int (*hashfn)(const void*), int (*eqfn)(const void*, const void*), int bins)
{
    int i;
    struct hashtable* ht = rte_zmalloc(NULL, sizeof(struct hashtable), RTE_CACHE_LINE_SIZE);
    if (!ht){
        TRACE_DEBUG("calloc: CreateHashtable");
        return 0;
    }

    ht->hashfn = hashfn;
    ht->eqfn = eqfn;
    ht->bins = bins;

    /* creating bins */
#ifdef ENABLE_CCP
    if (IS_FLOW_TABLE(hashfn) || IS_SID_TABLE(hashfn))
#else
    if (IS_FLOW_TABLE(hashfn))
#endif
    {
        ht->ht_table = rte_zmalloc(NULL, bins * sizeof(hash_bucket_head), RTE_CACHE_LINE_SIZE);
        if (!ht->ht_table) {
            TRACE_DEBUG("calloc: CreateHashtable bins!\n");
            rte_free(ht);
            return 0;
        }
        /* init the tables */
        for (i = 0; i < bins; i++)
            TAILQ_INIT(&ht->ht_table[i]);
    } else if (IS_LISTEN_TABLE(hashfn)) {
        ht->lt_table = rte_zmalloc(NULL, bins * sizeof(list_bucket_head), RTE_CACHE_LINE_SIZE);
        if (!ht->lt_table) {
            TRACE_DEBUG("calloc: CreateHashtable bins!\n");
            rte_free(ht);
            return 0;
        }
        /* init the tables */
        for (i = 0; i < bins; i++)
            TAILQ_INIT(&ht->lt_table[i]);
    }

    return ht;
}
/*----------------------------------------------------------------------------*/
void
DestroyHashtable(struct hashtable *ht)
{
    if (IS_FLOW_TABLE(ht->hashfn))
        rte_free(ht->ht_table);
    else /* IS_LISTEN_TABLE(ht->hashfn) */
        rte_free(ht->lt_table);
    
    rte_free(ht);
}
/*----------------------------------------------------------------------------*/
int 
StreamHTInsert(struct hashtable *ht, void *it)
{
    /* create an entry*/ 
    int idx;
    tcp_stream *item = (tcp_stream *)it;

    //printf("%s:%d assert\n", __FUNCTION__, __LINE__);
    assert(ht);

    idx = ht->hashfn(item);
    //printf("%s:%d assert\n", __FUNCTION__, __LINE__);
    assert(idx >=0 && idx < NUM_BINS_FLOWS);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, rcvvar->he_link);

    item->ht_idx = TCP_AR_CNT;
    
    return 0;
}
/*----------------------------------------------------------------------------*/
void* 
StreamHTRemove(struct hashtable *ht, void *it)
{
    hash_bucket_head *head;
    tcp_stream *item = (tcp_stream *)it;
    int idx = ht->hashfn(item);

    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, rcvvar->he_link);  

    return (item);
}   
/*----------------------------------------------------------------------------*/
void * 
StreamHTSearch(struct hashtable *ht, const void *it)
{
    int idx;
    const tcp_stream *item = (const tcp_stream *)it;
    tcp_stream *walk;
    hash_bucket_head *head;

    idx = ht->hashfn(item);

    head = &ht->ht_table[ht->hashfn(item)];
    TAILQ_FOREACH(walk, head, rcvvar->he_link) {
        if (ht->eqfn(walk, item)) 
            return walk;
    }

    UNUSED(idx);
    return NULL;
}

__rte_always_inline void * 
StreamHTSearch_by_stream(const void *it)
{
	int idx;
	const tcp_stream *item = (const tcp_stream *)it;
	tcp_stream *walk;
	hash_bucket_head *head;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	struct hashtable *ht = mtcp->tcp_flow_table;

	idx = ht->hashfn(item);

	head = &ht->ht_table[ht->hashfn(item)];
	TAILQ_FOREACH(walk, head, rcvvar->he_link) {
		if (ht->eqfn(walk, item)) 
			return walk;
	}

	UNUSED(idx);
	return NULL;
}

/*----------------------------------------------------------------------------*/
unsigned int
HashListener(const void *l)
{
    struct tcp_listener *listener = (struct tcp_listener *)l;

    return listener->socket->saddr.sin_port & (NUM_BINS_LISTENERS - 1);
}
/*----------------------------------------------------------------------------*/
int
EqualListener(const void *l1, const void *l2)
{
    struct tcp_listener *listener1 = (struct tcp_listener *)l1;
    struct tcp_listener *listener2 = (struct tcp_listener *)l2;

    return (listener1->socket->saddr.sin_port == listener2->socket->saddr.sin_port);
}
/*----------------------------------------------------------------------------*/
int 
ListenerHTInsert(struct hashtable *ht, void *it)
{
    /* create an entry*/ 
    int idx;
    struct tcp_listener *item = (struct tcp_listener *)it;

    printf("%s:%d assert\n", __FUNCTION__, __LINE__);
    assert(ht);

    idx = ht->hashfn(item);
    printf("%s:%d assert\n", __FUNCTION__, __LINE__);
    assert(idx >=0 && idx < NUM_BINS_LISTENERS);

    TAILQ_INSERT_TAIL(&ht->lt_table[idx], item, he_link);
    
    return 0;
}
/*----------------------------------------------------------------------------*/
void * 
ListenerHTRemove(struct hashtable *ht, void *it)
{
    list_bucket_head *head;
    struct tcp_listener *item = (struct tcp_listener *)it;
    int idx = ht->hashfn(item);

    head = &ht->lt_table[idx];
    TAILQ_REMOVE(head, item, he_link);  

    return (item);
}   
/*----------------------------------------------------------------------------*/
void * 
ListenerHTSearch(struct hashtable *ht, const void *it)
{
    int idx;
    struct tcp_listener item;
    uint16_t port = *((uint16_t *)it);
    struct tcp_listener *walk;
    list_bucket_head *head;
    struct socket_map s;

    s.saddr.sin_port = port;
    item.socket = &s;

    idx = ht->hashfn(&item);

    head = &ht->lt_table[idx];
    TAILQ_FOREACH(walk, head, he_link) {
        if (ht->eqfn(walk, &item)) 
            return walk;
    }

    return NULL;
}
/*----------------------------------------------------------------------------*/
