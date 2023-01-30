#ifndef TCP_SEND_BUFFER_H
#define TCP_SEND_BUFFER_H

#include <stdlib.h>
#include <stdint.h>
#include <rte_mbuf_core.h>
#include "memory_mgt.h"

#define TCP_SEND_DATA_BUFFER_MAX_NUM 1024

/*----------------------------------------------------------------------------*/
typedef struct sb_manager* sb_manager_t;
typedef struct mtcp_manager* mtcp_manager_t;
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer
{
    unsigned char *data;
    unsigned char *head;

    uint32_t head_off;
    uint32_t tail_off;
    uint32_t len;
    uint64_t cum_len;
    uint32_t size;

    uint32_t head_seq;
    uint32_t init_seq;
};

struct tcp_send_data_ring {
		uint16_t head;
		uint16_t una_head;
		uint16_t tail;
		uint16_t prev_tail;
		uint16_t free_num;
		uint16_t mbuf_data_len[TCP_SEND_DATA_BUFFER_MAX_NUM];
		struct rte_mbuf *m[TCP_SEND_DATA_BUFFER_MAX_NUM];
};

struct tcp_prepare_read {
		uint64_t host_buffer_phyaddr;
		uint64_t host_buffer_viraddr;
		uint16_t len;
		struct tcp_prepare_read *next;
};

struct tcp_prepare_read_list {
		mem_pool_t poor;
		struct tcp_prepare_read *head;
		struct tcp_prepare_read *tail;
};

/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm);
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum);
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq);

struct tcp_send_buffer *
SBInit_no_copy(sb_manager_t sbm, uint32_t init_seq);

/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf);
/*----------------------------------------------------------------------------*/
size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len);
/*----------------------------------------------------------------------------*/
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, struct tcp_send_data_ring *data_ring, size_t len);
size_t 
SBRemove_no_copy(sb_manager_t sbm, struct tcp_send_buffer *buf, struct tcp_send_data_ring *data_ring, size_t len);

/*----------------------------------------------------------------------------*/

#endif /* TCP_SEND_BUFFER_H */
