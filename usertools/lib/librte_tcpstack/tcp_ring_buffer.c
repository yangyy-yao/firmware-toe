#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include "tcp_ring_buffer.h"
#include "tcp_rb_frag_queue.h"
#include "memory_mgt.h"
#include "debug.h"
#include <rte_malloc.h>
#include <rte_cycles.h>

#define MAX_RB_SIZE (16*1024*1024)
#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
#ifdef ENABLELRO
#define __MEMCPY_DATA_2_BUFFER                      \
    mtcp_manager_t mtcp = rbm->mtcp;                \
    if (mtcp->iom == &dpdk_module_func && len > TCP_DEFAULT_MSS)    \
        mtcp->iom->dev_ioctl(mtcp->ctx, 0, PKT_RX_TCP_LROSEG, buff->head + putx); \
    else                                \
        memcpy(buff->head + putx, data, len);
#endif
/*----------------------------------------------------------------------------*/
struct rb_manager
{
    size_t chunk_size;
    uint32_t cur_num;
    uint32_t cnum;

    mem_pool_t mp;
    mem_pool_t frag_mp;

    rb_frag_queue_t free_fragq;     /* free fragment queue (for app thread) */
    rb_frag_queue_t free_fragq_int; /* free fragment quuee (only for mtcp) */
#ifdef ENABLELRO
    mtcp_manager_t mtcp;
#endif
} rb_manager;
/*----------------------------------------------------------------------------*/
uint32_t
RBGetCurnum(rb_manager_t rbm)
{
    return rbm->cur_num;
}
/*-----------------------------------------------------------------------------*/
void 
RBPrintInfo(struct tcp_ring_buffer* buff)
{
    printf("buff_data %p, buff_size %d, buff_mlen %d, "
            "buff_clen %lu, buff_head %p (%d), buff_tail (%d)\n", 
            buff->data, buff->size, buff->merged_len, buff->cum_len, 
            buff->head, buff->head_offset, buff->tail_offset);
}
/*----------------------------------------------------------------------------*/
void 
RBPrintStr(struct tcp_ring_buffer* buff)
{
    RBPrintInfo(buff);
    printf("%s\n", buff->head);
}
/*----------------------------------------------------------------------------*/
void 
RBPrintHex(struct tcp_ring_buffer* buff)
{
    int i;

    RBPrintInfo(buff);

    for (i = 0; i < buff->merged_len; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%0x ", *( (unsigned char*) buff->head + i));
    }
    printf("\n");
}
/*----------------------------------------------------------------------------*/
rb_manager_t
RBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum)
{
    rb_manager_t rbm = (rb_manager_t)rte_zmalloc(NULL, sizeof(rb_manager), RTE_CACHE_LINE_SIZE);

    if (!rbm) {
        perror("rbm_create calloc");
        return NULL;
    }

    rbm->chunk_size = chunk_size;
    rbm->cnum = cnum;

    char pool_name[RTE_MEMPOOL_NAMESIZE];
/*    sprintf(pool_name, "rbm_pool_%u", mtcp->ctx->cpu);
    rbm->mp = (mem_pool_t)MPCreate(pool_name, chunk_size, (uint64_t)chunk_size * cnum); 

    if (!rbm->mp) {
        TRACE_DEBUG("Failed to allocate mp pool.\n");
        rte_free(rbm);
        return NULL;
    }
*/
    sprintf(pool_name, "frag_mp_%u", mtcp->ctx->cpu);
    rbm->frag_mp = (mem_pool_t)MPCreate(pool_name, sizeof(struct fragment_ctx), 
                        sizeof(struct fragment_ctx) * cnum);    

    if (!rbm->frag_mp) {
        TRACE_DEBUG("Failed to allocate frag_mp pool.\n");
        MPDestroy(rbm->mp);
        rte_free(rbm);
        return NULL;
    }

    rbm->free_fragq = CreateRBFragQueue(cnum);
    if (!rbm->free_fragq) {
        TRACE_DEBUG("Failed to create free fragment queue.\n");
        MPDestroy(rbm->mp);
        MPDestroy(rbm->frag_mp);
        rte_free(rbm);
        return NULL;
    }
    rbm->free_fragq_int = CreateRBFragQueue(cnum);
    if (!rbm->free_fragq_int) {
        TRACE_DEBUG("Failed to create internal free fragment queue.\n");
        MPDestroy(rbm->mp);
        MPDestroy(rbm->frag_mp);
        DestroyRBFragQueue(rbm->free_fragq);
        rte_free(rbm);
        return NULL;
    }

#ifdef ENABLELRO
    rbm->mtcp = mtcp;
#endif
    return rbm;
}
/*----------------------------------------------------------------------------*/
static inline void
FreeFragmentContextSingle(rb_manager_t rbm, struct fragment_ctx* frag)
{
    if (frag->is_calloc)
        rte_free(frag);
    else    
        MPFreeChunk(rbm->frag_mp, frag);
}
/*----------------------------------------------------------------------------*/
void
FreeFragmentContext(rb_manager_t rbm, struct fragment_ctx* fctx)
{
    struct fragment_ctx *remove;

    assert(fctx);
    if (fctx == NULL)   
        return;

    while (fctx) {
        remove = fctx;
        fctx = fctx->next;
        FreeFragmentContextSingle(rbm, remove);
    }
}
/*----------------------------------------------------------------------------*/
static struct fragment_ctx *
AllocateFragmentContext(rb_manager_t rbm)
{
    /* this function should be called only in mtcp thread */
    struct fragment_ctx *frag;

    /* first try deqeue the fragment in free fragment queue */
    frag = RBFragDequeue(rbm->free_fragq);
    if (!frag) {
        frag = RBFragDequeue(rbm->free_fragq_int);
        if (!frag) {
            /* next fall back to fetching from mempool */
            frag = MPAllocateChunk(rbm->frag_mp);
            if (!frag) {
                TRACE_DEBUG("fragments depleted, fall back to calloc\n");
                frag = (struct fragment_ctx*)rte_zmalloc(NULL, sizeof(struct fragment_ctx), RTE_CACHE_LINE_SIZE);
                if (frag == NULL) {
                    TRACE_DEBUG("calloc failed\n");
                    exit(-1);
                }
                frag->is_calloc = 1; /* mark it as allocated by calloc */
            }
        }
    }
    memset(frag, 0, sizeof(*frag));
    return frag;
}
/*----------------------------------------------------------------------------*/
struct tcp_ring_buffer* 
RBInit(rb_manager_t rbm, uint32_t init_seq)
{
    struct tcp_ring_buffer* buff = (struct tcp_ring_buffer*)rte_zmalloc(NULL, sizeof(struct tcp_ring_buffer), RTE_CACHE_LINE_SIZE);

    if (buff == NULL){
        perror("rb_init buff");
        return NULL;
    }

    buff->data = MPAllocateChunk(rbm->mp);
    if(!buff->data){
        perror("rb_init MPAllocateChunk");
        rte_free(buff);
        return NULL;
    }

    //memset(buff->data, 0, rbm->chunk_size);

    buff->size = rbm->chunk_size;
    buff->head = buff->data;
    buff->head_seq = init_seq;
    buff->init_seq = init_seq;
		
    //buff->data_buf.size = TCP_RECV_MBUF_RING_MAX_NUM;
			
    rbm->cur_num++;

    return buff;
}

struct tcp_ring_buffer* 
RBInit_no_copy(mtcp_manager_t mtcp, uint32_t init_seq)
{
    rb_manager_t rbm = mtcp->rbm_rcv;
    //struct tcp_ring_buffer* buff = (struct tcp_ring_buffer*)rte_zmalloc(NULL, sizeof(struct tcp_ring_buffer), RTE_CACHE_LINE_SIZE);
    struct tcp_ring_buffer* buff = (struct tcp_ring_buffer*)MPAllocateChunk(mtcp->rvbuf_pool);

    if (buff == NULL){
        perror("rb_init buff");
        return NULL;
    }

    buff->size = rbm->chunk_size;
    buff->head = buff->data;
    buff->head_seq = init_seq;
    buff->init_seq = init_seq;
			
    rbm->cur_num++;

    return buff;
}

/*----------------------------------------------------------------------------*/
void
RBFree(rb_manager_t rbm, struct tcp_ring_buffer* buff)
{
    assert(buff);
    if (buff->fctx) {
        FreeFragmentContext(rbm, buff->fctx);
        buff->fctx = NULL;
    }
    
    if (buff->data) {
        MPFreeChunk(rbm->mp, buff->data);
    }
    
    rbm->cur_num--;

    rte_free(buff);
}
/*----------------------------------------------------------------------------*/
#define MAXSEQ               ((uint32_t)(0xFFFFFFFF))
/*----------------------------------------------------------------------------*/
static inline uint32_t
GetMinSeq(uint32_t a, uint32_t b)
{
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? a : b;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? b : a;
}
/*----------------------------------------------------------------------------*/
static inline uint32_t
GetMaxSeq(uint32_t a, uint32_t b)
{
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? b : a;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? a : b;
}

static struct fragment_ctx * GetMinSeqCtx(const struct fragment_ctx *a, const struct fragment_ctx *b)
{
	  if (a->seq == b->seq) return NULL;
    if (a->seq < b->seq) 
        return ((b->seq - a->seq) <= MAXSEQ/2) ? a : b;
    /* b < a */
    return ((a->seq - b->seq) <= MAXSEQ/2) ? b : a;
}

static struct fragment_ctx * GetMaxSeqCtx(const struct fragment_ctx *a, const struct fragment_ctx *b)
{
    if (a->seq == b->seq) return NULL;
    if (a->seq < b->seq) 
        return ((b->seq - a->seq) <= MAXSEQ/2) ? b : a;
    /* b < a */
    return ((a->seq - b->seq) <= MAXSEQ/2) ? a : b;

}

/*----------------------------------------------------------------------------*/
static inline int
CanMerge(const struct fragment_ctx *a, const struct fragment_ctx *b)
{
    uint32_t a_end = a->seq + a->len + 1;
    uint32_t b_end = b->seq + b->len + 1;

    if (GetMinSeq(a_end, b->seq) == a_end ||
        GetMinSeq(b_end, a->seq) == b_end)
        return 0;
    return (1);
}
/*----------------------------------------------------------------------------*/
static inline void
MergeFragments(struct fragment_ctx *a, struct fragment_ctx *b)
{
    /* merge a into b */
    uint32_t min_seq, max_seq;

    min_seq = GetMinSeq(a->seq, b->seq);
    max_seq = GetMaxSeq(a->seq + a->len, b->seq + b->len);
    b->seq  = min_seq;
    b->len  = max_seq - min_seq;
}

static struct fragment_ctx * Fragments_overlap_all(struct fragment_ctx *a, struct fragment_ctx *b)
{
	uint32_t a_end = a->seq + a->len;
	uint32_t b_end = b->seq + b->len;
	
	if (a->len <= b->len && a->seq >= b->seq && a_end <= b_end)
		return a;
	if (a->len > b->len && a->seq <= b->seq && a_end >= b_end)
		return b;

	return NULL;
}

static inline void
MergeFragments_mbuf(struct fragment_ctx *a, struct fragment_ctx *b)
{
	struct fragment_ctx *front_ctx;
	struct fragment_ctx *behind_ctx;
	struct fragment_ctx *overlap_ctx;
	struct rte_mbuf *m, *next_m, *prev_m;
	uint32_t front_end;
	long long int repeat_len;
		
	overlap_ctx = Fragments_overlap_all(a, b);
	if (overlap_ctx) {
		//printf("%s-%d:overlap_ctx:%p\n",__func__,__LINE__,overlap_ctx);
		if (overlap_ctx == b) {
			b->head_mbuf = a->head_mbuf;
			b->tail_mbuf = a->tail_mbuf;
		}
		m = overlap_ctx->head_mbuf;
		while(m) {
			next_m = m->next;
			m->next = NULL;
			m->nb_segs = 1;
			rte_pktmbuf_free(m);
			m = next_m;
		}
		return;
	} 

	front_ctx = GetMinSeqCtx(a, b);
	behind_ctx = GetMaxSeqCtx(a, b);
	assert(front_ctx != NULL && behind_ctx != NULL);

	front_end = front_ctx->seq + front_ctx->len;
	repeat_len = front_end - behind_ctx->seq;
	assert(repeat_len >= 0);
	
	if (repeat_len > 0) {
		
		//printf("%s-%d:repeat_len:%d,front_ctx:%p,behind_ctx:%p\n",__func__,__LINE__,repeat_len, front_ctx, behind_ctx);
		m = behind_ctx->head_mbuf;
		while (m->data_len < repeat_len) {
			repeat_len -= m->data_len;
			rte_pktmbuf_adj(m, m->data_len);
			m = m->next;
		}
		rte_pktmbuf_adj(m, repeat_len);
	}

	prev_m = front_ctx->tail_mbuf;
	next_m = front_ctx->tail_mbuf->next;

	while (next_m) {
		prev_m = next_m;
		next_m = next_m->next;
	}
	
	prev_m->next = behind_ctx->head_mbuf;
	b->head_mbuf = front_ctx->head_mbuf;
	b->tail_mbuf = behind_ctx->tail_mbuf;
	//printf("%s-%d:front_ctx:%p,behind_ctx:%p, b:%p,b->head_mbuf:%p,b->tail_mbuf:%p\n",__func__,__LINE__,front_ctx, behind_ctx,b,b->head_mbuf,b->tail_mbuf);

	return;
}


/*----------------------------------------------------------------------------*/
int
RBPut(rb_manager_t rbm, struct tcp_ring_buffer* buff, 
       void* data, uint32_t len, uint32_t cur_seq)
{
    int putx, end_off;
    struct fragment_ctx *new_ctx;
    struct fragment_ctx* iter;
    struct fragment_ctx* prev, *pprev;
    int merged = 0;

    if (len <= 0)
        return 0;

    // if data offset is smaller than head sequence, then drop
    if (GetMinSeq(buff->head_seq, cur_seq) != buff->head_seq)
        return 0;

    putx = cur_seq - buff->head_seq;
    end_off = putx + len;
    if (buff->size < end_off) {
        return -2;
    }
    
    // if buffer is at tail, move the data to the first of head
    if (buff->size <= (buff->head_offset + end_off)) {
        memmove(buff->data, buff->head, buff->last_len);
        buff->tail_offset -= buff->head_offset;
        buff->head_offset = 0;
        buff->head = buff->data;
    }
#ifdef ENABLELRO
    // copy data to buffer
    __MEMCPY_DATA_2_BUFFER;
#else
    //copy data to buffer
    memcpy(buff->head + putx, data, len);
#endif
    if (buff->tail_offset < buff->head_offset + end_off) 
        buff->tail_offset = buff->head_offset + end_off;
    buff->last_len = buff->tail_offset - buff->head_offset;

    // create fragmentation context blocks
    new_ctx = AllocateFragmentContext(rbm);
    if (!new_ctx) {
        perror("allocating new_ctx failed");
        return 0;
    }
    new_ctx->seq  = cur_seq;
    new_ctx->len  = len;
    new_ctx->next = NULL;

    // traverse the fragment list, and merge the new fragment if possible
    for (iter = buff->fctx, prev = NULL, pprev = NULL; 
        iter != NULL;
        pprev = prev, prev = iter, iter = iter->next) {
        
        if (CanMerge(new_ctx, iter)) {
            /* merge the first fragment into the second fragment */
            MergeFragments(new_ctx, iter);

            /* remove the first fragment */
            if (prev == new_ctx) {
                if (pprev)
                    pprev->next = iter;
                else
                    buff->fctx = iter;
                prev = pprev;
            }   
            FreeFragmentContextSingle(rbm, new_ctx);
            new_ctx = iter;
            merged = 1;
        } 
        else if (merged || 
                 GetMaxSeq(cur_seq + len, iter->seq) == iter->seq) {
            /* merged at some point, but no more mergeable
               then stop it now */
            break;
        } 
    }

    if (!merged) {
        if (buff->fctx == NULL) {
            buff->fctx = new_ctx;
        } else if (GetMinSeq(cur_seq, buff->fctx->seq) == cur_seq) {
            /* if the new packet's seqnum is before the existing fragments */
            new_ctx->next = buff->fctx;
            buff->fctx = new_ctx;
        } else {
            /* if the seqnum is in-between the fragments or
               at the last */
            assert(GetMinSeq(cur_seq, prev->seq + prev->len) ==
                   prev->seq + prev->len);
            prev->next = new_ctx;
            new_ctx->next = iter;
        }
    }
    if (buff->head_seq == buff->fctx->seq) {
        buff->cum_len += buff->fctx->len - buff->merged_len;
        buff->merged_len = buff->fctx->len;
    }
    
    return len;
}

int
RBPut_no_copy(rb_manager_t rbm, struct tcp_ring_buffer* buff, 
       uint32_t len, uint32_t cur_seq, struct rte_mbuf *m)
{
    int putx, end_off;
    struct fragment_ctx *new_ctx;
    struct fragment_ctx* iter;
    struct fragment_ctx* prev, *pprev;
    int merged = 0;

    if (len <= 0)
        return -1;

    // if data offset is smaller than head sequence, then drop
    if (GetMinSeq(buff->head_seq, cur_seq) != buff->head_seq) {
    	printf("%s-%d: data offset is smaller than head sequence! buff->head_seq:%u,cur_seq:%u\n",__func__,__LINE__, buff->head_seq, cur_seq);
        return -1;
    }

    putx = cur_seq - buff->head_seq;
    end_off = putx + len;
    if (buff->size < end_off) {
    	printf("%s-%d: more than recv buffer size! buff->size:%d,end_off:%d,cur_seq:%u\n",__func__,__LINE__, buff->size, end_off,cur_seq);
        return -2;
    }
    /*
    // if buffer is at tail, move the data to the first of head
    if (buff->size <= (buff->head_offset + end_off)) {
        memmove(buff->data, buff->head, buff->last_len);
        buff->tail_offset -= buff->head_offset;
        buff->head_offset = 0;
        buff->head = buff->data;
    }
    */
#ifdef ENABLELRO
    // copy data to buffer
    __MEMCPY_DATA_2_BUFFER;
#else
    //copy data to buffer
    //memcpy(buff->head + putx, data, len);
    //if ((buff->data_buf.tail + 1) % buff->data_buf.size == buff->data_buf.head)
			//return -2;
		/*
		buff->data_buf.m_data[buff->data_buf.tail] = m;
		buff->data_buf.tail = (buff->data_buf.tail + 1) % buff->data_buf.size;
		*/
#endif
/*
    if (buff->tail_offset < buff->head_offset + end_off) 
        buff->tail_offset = buff->head_offset + end_off;
    buff->last_len = buff->tail_offset - buff->head_offset;
*/
    // create fragmentation context blocks
    new_ctx = AllocateFragmentContext(rbm);
    if (!new_ctx) {
        perror("allocating new_ctx failed");
        return -1;
    }
    new_ctx->seq  = cur_seq;
    new_ctx->len  = len;
    new_ctx->next = NULL;
    new_ctx->head_mbuf = m;
    new_ctx->tail_mbuf = m;
	
    while (new_ctx->tail_mbuf->next) {
	new_ctx->tail_mbuf = new_ctx->tail_mbuf->next;
    }

    //printf("%s-%d: new_ctx:%p, new_ctx->len:%d,new_ctx->seq:%u,m:%p\n",__func__,__LINE__,new_ctx,new_ctx->len,new_ctx->seq,m);
    //printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
    // traverse the fragment list, and merge the new fragment if possible
    for (iter = buff->fctx, prev = NULL, pprev = NULL; 
        iter != NULL;
        pprev = prev, prev = iter, iter = iter->next) {
        
   // printf("%s-%d: iter:%p, iter->next:%p,iter->len:%d,iter->seq:%u\n",__func__,__LINE__,iter,iter->next,iter->len,iter->seq);
        if (CanMerge(new_ctx, iter)) { //如果不满足条件，表示new_ctx 的数据段在iter数据段的前后，且不连续。
					//满足条件有如下几种情况
					//1、new_ctx数据段在iter数据之后且连续，说明当前new_ctx数据段没有乱序
					//2、new_ctx数据段在iter数据段之前且连续
					//3、有重叠， new_ctx这段数据所在的区间与iter 数据段有重叠， 可能重叠一部分，也可能全部重叠
    //printf("%s-%d: new_ctx:%p, new_ctx->len:%d,new_ctx->seq:%llu,iter:%p, iter->next:%p,iter->len:%d,iter->seq:%llu\n",__func__,__LINE__,new_ctx,new_ctx->len,new_ctx->seq,iter,iter->next,iter->len,iter->seq);
						MergeFragments_mbuf(new_ctx, iter);
						/* merge the first fragment into the second fragment */
            MergeFragments(new_ctx, iter);

    //printf("%s-%d: new_ctx:%p, new_ctx->len:%d,new_ctx->seq:%llu,iter:%p, iter->next:%p,iter->len:%d,iter->seq:%llu\n",__func__,__LINE__,new_ctx,new_ctx->len,new_ctx->seq,iter,iter->next,iter->len,iter->seq);
            /* remove the first fragment */
            if (prev == new_ctx) {
                if (pprev)
                    pprev->next = iter;
                else
                    buff->fctx = iter;
                prev = pprev;
            }   
            FreeFragmentContextSingle(rbm, new_ctx);
            new_ctx = iter;
            merged = 1;
        } //表示new_ctx这段数据的区间段在iter区间段之外，之前或之后。
        else if (merged || 
                 GetMaxSeq(cur_seq + len, iter->seq) == iter->seq) {
             /*满足merged==1，表示new_ctx与prev的数据区间段重叠，已合并处理 */
						 /*未满足merge==1，满足GetMaxSeq，表示 new_ctx 在iter数据区间段之前，在prev数据区间段之后的空白区域*/
            /* merged at some point, but no more mergeable
               then stop it now */
    	    //printf("%s-%d:  new_ctx->len:%d,cur_seq:%llu,len:%d,iter->seq:%llu,merged at some point, but no more mergeable then stop it now\n",__func__,__LINE__,new_ctx->len,cur_seq,len,iter->seq);
            break;
        } 
    }

    //printf("%s-%d:  new_ctx:%p,new_ctx->len:%d\n",__func__,__LINE__,new_ctx,new_ctx->len);
    //printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
    if (!merged) { 
        if (buff->fctx == NULL) {
            buff->fctx = new_ctx;
        } else if (GetMinSeq(cur_seq, buff->fctx->seq) == cur_seq) {
            /* if the new packet's seqnum is before the existing fragments */
   // printf("%s-%d:new_ctx:%p,buff->fctx:%p  if the new packet's seqnum is before the existing fragments\n",__func__,__LINE__,new_ctx,buff->fctx);
            new_ctx->next = buff->fctx; 
            buff->fctx = new_ctx;
    //	    printf("%s-%d:  if the new packet's seqnum is before the existing fragments\n",__func__,__LINE__);
        } else {
            /* if the seqnum is in-between the fragments or
               at the last */
            assert(GetMinSeq(cur_seq, prev->seq + prev->len) ==
                   prev->seq + prev->len);
    //	    printf("%s-%d:new_ctx:%p,prev:%p,iter:%p if the seqnum is in-between the fragments or at the last\n",__func__,__LINE__,new_ctx,prev,iter);
            prev->next = new_ctx;
            new_ctx->next = iter;
        }
    }
   // printf("%s-%d:buff->head_seq:%u,  buff->fctx->seq:%u,buff->cum_len:%u\n",__func__,__LINE__,buff->head_seq,buff->fctx->seq,buff->cum_len);
    if (buff->head_seq == buff->fctx->seq) {
        buff->cum_len += buff->fctx->len - buff->merged_len;
   //     printf("%s-%d:  buff->fctx->len:%d\n",__func__,__LINE__,buff->fctx->len);
        buff->merged_len = buff->fctx->len;
    }
    
    //printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
    return len;
}

/*----------------------------------------------------------------------------*/
size_t
RBRemove(rb_manager_t rbm, struct tcp_ring_buffer* buff, size_t len, int option)
{
    /* this function should be called only in application thread */

    if (buff->merged_len < len) 
        len = buff->merged_len;
    
    if (len == 0) 
        return 0;

    buff->head_offset += len;
    buff->head = buff->data + buff->head_offset;
    buff->head_seq += len;

    buff->merged_len -= len;
    buff->last_len -= len;

    // modify fragementation chunks
    if (len == buff->fctx->len) {
        struct fragment_ctx* remove = buff->fctx;
        buff->fctx = buff->fctx->next;
        if (option == AT_APP) {
            RBFragEnqueue(rbm->free_fragq, remove);
        } else if (option == AT_MTCP) {
            RBFragEnqueue(rbm->free_fragq_int, remove);
        }
    } 
    else if (len < buff->fctx->len) {
        buff->fctx->seq += len;
        buff->fctx->len -= len;
    } 
    else {
        assert(0);
    }

    return len;
}

size_t
RBRemove_no_copy(rb_manager_t rbm, struct tcp_ring_buffer* buff, size_t len, int option)
{
	/* this function should be called only in application thread */

	if (buff->merged_len < len) 
		len = buff->merged_len;
	
	if (len == 0) 
		return 0;

	buff->head_offset += len;
	buff->head = buff->data + buff->head_offset;
	buff->head_seq += len;

	buff->merged_len -= len;
	buff->last_len -= len;

	// modify fragementation chunks
	//printf("%s-%d:buff->head_seq:%u, buff->fctx:%p, buff->fctx->seq:%u,buff->fctx->len:%d,len:%d\n",__func__,__LINE__,buff->head_seq,buff->fctx,buff->fctx->seq,buff->fctx->len,len);
	if (len == buff->fctx->len)	{
		struct fragment_ctx* remove = buff->fctx;
		buff->fctx = buff->fctx->next;
		if (option == AT_APP) {
			RBFragEnqueue(rbm->free_fragq, remove);
		} else if (option == AT_MTCP) {
			RBFragEnqueue(rbm->free_fragq_int, remove);
		}
	} 
	else if (len < buff->fctx->len) {
		buff->fctx->seq += len;
		buff->fctx->len -= len;
	} 
	else {
		assert(0);
	}

	return len;
}

/*----------------------------------------------------------------------------*/
