#ifndef ETH_OUT_H
#define ETH_OUT_H

#include <stdint.h>

#include "mtcp.h"
#include "tcp_stream.h"
#include "ps.h"

#define MAX_SEND_PCK_CHUNK 64

struct io_module_func {
	void	  (*load_module)(void);
	void      (*init_handle)(struct mtcp_thread_context *ctx);
	int32_t   (*link_devices)(struct mtcp_thread_context *ctx);
	void      (*release_pkt)(struct mtcp_thread_context *ctx, int ifidx, unsigned char *pkt_data, int len);
	uint8_t * (*get_wptr)(struct mtcp_thread_context *ctx, uint16_t len);
	
	uint8_t * (*get_wptr_datapkt)(struct mtcp_thread_context *ctx, uint16_t len, void *st, int data_posit);
	int32_t   (*send_pkts)(struct mtcp_thread_context *ctx, int nif);
	uint8_t * (*get_rptr)(struct mtcp_thread_context *ctx, int ifidx, int index, uint16_t *len);
	int32_t   (*recv_pkts)(struct mtcp_thread_context *ctx, int ifidx);
	int32_t	  (*select)(struct mtcp_thread_context *ctx);
	void	  (*destroy_handle)(struct mtcp_thread_context *ctx);
	int32_t	  (*dev_ioctl)(struct mtcp_thread_context *ctx, int nif, int cmd, void *argp);
} io_module_func;

uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto, 
        int nif, unsigned char* dst_haddr, uint16_t iplen, tcp_stream *stream, uint16_t payloadlen, int data_posit);

#endif /* ETH_OUT_H */
