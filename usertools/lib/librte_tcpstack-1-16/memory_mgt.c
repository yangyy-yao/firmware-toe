#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <rte_errno.h>
#include <unistd.h>
#include "debug.h"
#include "memory_mgt.h"
/*----------------------------------------------------------------------------*/
typedef struct tag_mem_chunk
{
    int mc_free_chunks;
    struct tag_mem_chunk *mc_next;
} mem_chunk;
/*----------------------------------------------------------------------------*/
typedef mem_chunk *mem_chunk_t;
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
mem_pool_t
MPCreate(char *name, int chunk_size, size_t total_size)
{
    struct rte_mempool *mp;
    size_t sz, items;

    mp = rte_mempool_lookup(name);

    if (unlikely(mp)) {
        MPDestroy(mp);
        mp = NULL;
    }
    
    items = total_size/chunk_size;
    sz = RTE_ALIGN_CEIL(chunk_size, RTE_CACHE_LINE_SIZE);
    mp = rte_mempool_create(name, items, sz, 0, 0, NULL,
                0, NULL, 0, rte_socket_id(),
                MEMPOOL_F_NO_SPREAD);

    if (mp == NULL) {
        TRACE_DEBUG("Can't allocate memory for mempool!\n");
        printf("Core.%u Can't allocate memory for mempool! total_size=%lu %s\n", rte_lcore_id(), total_size, rte_strerror(rte_errno));
        return NULL;
    }

    return mp;
}
/*----------------------------------------------------------------------------*/
void *
MPAllocateChunk(mem_pool_t mp)
{
    int rc;
    void *buf;

    rc = rte_mempool_get(mp, (void **)&buf);
    if (rc != 0)
        return NULL;

    return buf;
}
/*----------------------------------------------------------------------------*/
void
MPFreeChunk(mem_pool_t mp, void *p)
{
    rte_mempool_put(mp, p);
}
/*----------------------------------------------------------------------------*/
void
MPDestroy(mem_pool_t mp)
{
#if RTE_VERSION < RTE_VERSION_NUM(16, 7, 0, 0)
    /* do nothing.. old versions don't have a method to reclaim back mem */
#else
    rte_mempool_free(mp);
#endif
}
/*----------------------------------------------------------------------------*/
int
MPGetFreeChunks(mem_pool_t mp)
{
#if RTE_VERSION <= RTE_VERSION_NUM(16, 7, 0, 0)
    return (int)rte_mempool_free_count(mp);
#else
    return (int)rte_mempool_avail_count(mp);
#endif
}
/*----------------------------------------------------------------------------*/

