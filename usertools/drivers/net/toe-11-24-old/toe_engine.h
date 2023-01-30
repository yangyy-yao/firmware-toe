#ifndef RTE_PMD_TOE_ENGINE_H_
#define RTE_PMD_TOE_ENGINE_H_

#include <tcp_stream.h>
#include <rte_ether.h>

//#ifndef STRUCTURE_COMPACT_MODE
//#define STRUCTURE_COMPACT_MODE      __attribute__((__packed__))
//#endif

#define TOE_MAX_RQ_SIZE 512
#define TOE_MAX_CQ_SIZE 512

#define TOE_MAX_TX_DATA_RQ_SIZE  1024
#define TOE_MAX_TX_DATA_CQ_SIZE  1024

#define TOE_HASH_SIZE 	8
//#define TOE_NH_CACHE_SIZE 	32
#define TOE_JOB_DATABUF_NUM 64
#define TOE_MAX_QUEUE 32
#define MAX_PKT_BURST 32

#define TOE_CTL_FLAG 0x01000000
#define TOE_DATA_RECV_FLAG 0x02000000
#define TOE_DATA_SEND_FLAG 0x04000000

#define TOE_RECVBUF_SEND_PER_MAX_LEN 2048
#define TOE_TX_DATA_RING_DESC 1024
#define TOE_MAX_SOCKET_NUM 1024


#define TOE_DRIVER_ACTIVE 0x04
#define TOE_CARD_RESET 0x40

#define TOE_MAX_HOST_BUF_NUM 8

#define RTE_PMD_TOE_MAX_QUEUES 16
#define TOE_RECV_BUFFER_COUNT_RESERVED      8



enum TOE_RETURN_TYPE {
	TOE_SUCCESS_RETAIN,
	TOE_SUCCESS_FREE,
	TOE_FAILED_FREE,
	TOE_CLOSE_FREE,
	
};

enum TOE_MESSAGE_OPCODE {
	TOE_MSG_OPCODE_H2D_IP_MAC_NOTIFICATION,
		
	TOE_MSG_OPCODE_H2D_ACTIVE_CONNECT_REQUEST,
	TOE_MSG_OPCODE_D2H_ACTIVE_CONNECT_ACCEPT,
	TOE_MSG_OPCODE_D2H_ACTIVE_CONNECT_REJECT,
	TOE_MSG_OPCODE_H2D_ACTIVE_CONNECT_CONFIRM,
	
	TOE_MSG_OPCODE_D2H_PASSIVE_CONNECT_REQUEST,
	TOE_MSG_OPCODE_H2D_PASSIVE_CONNECT_ACCEPT,
	TOE_MSG_OPCODE_H2D_PASSIVE_CONNECT_REJECT,
	TOE_MSG_OPCODE_D2H_PASSIVE_CONNECT_CONFIRM,
	
	TOE_MSG_OPCODE_H2D_ACTIVE_CLOSE_REQUEST,
	TOE_MSG_OPCODE_D2H_ACTIVE_CLOSE_ACCEPT,
	TOE_MSG_OPCODE_D2H_ACTIVE_CLOSE_REJECT,
	TOE_MSG_OPCODE_D2H_ACTIVE_CLOSE_CONFIRM,
	TOE_MSG_OPCODE_H2D_ACTIVE_CLOSE_COMPLETE,
	
	TOE_MSG_OPCODE_D2H_PASSIVE_CLOSE_REQUEST,
	TOE_MSG_OPCODE_H2D_PASSIVE_CLOSE_ACCEPT,
	TOE_MSG_OPCODE_H2D_PASSIVE_CLOSE_REJECT,
	TOE_MSG_OPCODE_H2D_PASSIVE_CLOSE_CONFIRM,
	TOE_MSG_OPCODE_D2H_PASSIVE_CLOSE_COMPLETE,
	
	TOE_MSG_OPCODE_D2H_ABNORMAL_CLOSE,
	
	TOE_MSG_OPCODE_H2D_SEND_DATA_REQUEST, 
	TOE_MSG_OPCODE_D2H_SEND_DATA_RESULT, 
	
	TOE_MSG_OPCODE_H2D_NEW_RECV_BUFFER, 
	TOE_MSG_OPCODE_D2H_RECV_DATA,
	TOE_MSG_OPCODE_END
};

enum toe_dma_result_type {
	TOE_DMA_SUCCESS,
    TOE_DMA_REFUSED,
	TOE_DMA_FAILED,
	TOE_DMA_TIMEOUT,
	TOE_DMA_EAGAIN,
	TOE_DMA_MAX
};


struct toe_socket_id {
    unsigned long long          host_dataptr;
    unsigned long long          card_stream_addr;
}__attribute__((__packed__));

struct toe_data_recv_buffer {
    uint64_t          		recv_buffer_phyaddr;
    uint16_t              	recv_buffer_len;
    uint64_t               	host_list_virtaddr;
}__attribute__((__packed__));


struct toe_h2d_msg_ipmac_notification_hdr {
    unsigned char               ifindex;
    unsigned int                ip;
    unsigned char               mac[RTE_ETHER_ADDR_LEN];
}__attribute__((__packed__));

struct toe_tcp_params {
    unsigned short              mss;
    unsigned short              window;
    unsigned int                sequence;
	unsigned int                acknowledge;
    unsigned char               window_scale;
}__attribute__((__packed__));

struct toe_h2d_msg_active_connect_request_hdr
{
    unsigned int                local_ip;
    unsigned int                remote_ip;
    unsigned short              local_port;
    unsigned short              remote_port;
    unsigned char               local_mac[RTE_ETHER_ADDR_LEN];
    unsigned char               remote_mac[RTE_ETHER_ADDR_LEN];
    struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_active_connect_accept_hdr
{
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_active_connect_reject_hdr
{
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_active_connect_confirm_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_passive_connect_request_hdr {
    unsigned long               host_dpuinfo_ptr;
    struct toe_tcp_params       tcp_params;
    unsigned int                saddr;
    unsigned int                daddr;
    unsigned short              sport;
    unsigned short              dport;
}__attribute__((__packed__));

struct toe_h2d_msg_passive_connect_accept_hdr {
    struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_passive_connect_reject_hdr {
    struct toe_tcp_params tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_passive_connect_confirm_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_active_close_request_hdr {
}__attribute__((__packed__));

struct toe_d2h_msg_active_close_accept_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_active_close_reject_hdr{
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_active_close_confirm_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_active_close_complete_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_passive_close_request_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_passive_close_accept_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_passive_close_reject_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_h2d_msg_passive_close_confirm_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));
struct toe_d2h_msg_passive_close_complete_hdr {
	struct toe_tcp_params       tcp_params;
}__attribute__((__packed__));

struct toe_d2h_msg_abnormal_close_hdr {
}__attribute__((__packed__));
	

struct toe_ctrl_host_to_dpu_req {
	unsigned char opcode;
	struct toe_socket_id id;
	union {
		struct toe_h2d_msg_ipmac_notification_hdr ipmac_notification;
		struct toe_h2d_msg_active_connect_request_hdr active_connect_request; 
		struct toe_h2d_msg_active_connect_confirm_hdr active_connect_confirm; 
		struct toe_h2d_msg_passive_connect_accept_hdr passive_connect_accept; 
		struct toe_h2d_msg_passive_connect_reject_hdr passive_connect_reject; 
		struct toe_h2d_msg_active_close_request_hdr active_close_request; 
		struct toe_h2d_msg_active_close_complete_hdr active_close_complete; 
		struct toe_h2d_msg_passive_close_accept_hdr passive_close_accept; 
		struct toe_h2d_msg_passive_close_reject_hdr passive_close_reject; 
		struct toe_h2d_msg_passive_close_confirm_hdr passive_close_confirm;
		};
}__attribute__((__packed__));

struct toe_ctrl_host_to_dpu_res {
	unsigned char opcode : 7;
	unsigned char compl  : 1;
    unsigned char result;
	unsigned char qid;
	unsigned short rq_head;
	struct toe_socket_id identification;
	union {
		struct toe_d2h_msg_active_connect_accept_hdr active_connect_accept; 
		struct toe_d2h_msg_active_connect_reject_hdr active_connect_reject; 
		struct toe_d2h_msg_passive_connect_request_hdr passive_connect_request; 
		struct toe_d2h_msg_passive_connect_confirm_hdr passive_connect_confirm; 
		struct toe_d2h_msg_active_close_accept_hdr active_close_accept; 
		struct toe_d2h_msg_active_close_reject_hdr active_close_reject; 
		struct toe_d2h_msg_active_close_confirm_hdr active_close_confirm; 
		struct toe_d2h_msg_passive_close_request_hdr passive_close_request; 
		struct toe_d2h_msg_passive_close_complete_hdr passive_close_complete;
		struct toe_d2h_msg_abnormal_close_hdr abnormal_close;
		};
}__attribute__((__packed__));

struct toe_data_host_to_dpu_req {  //channel 2 rq
		unsigned char opcode;
		struct toe_socket_id identification;
		unsigned long long send_buffer_addr;
		uint16_t data_len;
		uint64_t send_list_addr;
}__attribute__((__packed__));

struct toe_data_host_to_dpu_res {  //channel 2 cq
		unsigned char opcode : 7;
		unsigned char compl  : 1;
		unsigned char result;
		uint16_t rq_head;
		uint16_t sent_len;
        	uint64_t send_list_virtaddr;
		struct toe_socket_id identification;
}__attribute__((__packed__));

struct toe_data_dpu_to_host_req {  //channel 3 rq
		unsigned char opcode;
		struct toe_socket_id identification;
		unsigned char use_idx;
		struct toe_data_recv_buffer recv_buffer[TOE_RECV_BUFFER_COUNT_RESERVED];
}__attribute__((__packed__));

struct toe_data_dpu_to_host_res{  //channel 3 cq
    unsigned char        opcode : 7;
    unsigned char        complete : 1;
    unsigned char        qid;
    uint16_t       rq_head;
    uint16_t       data_len;
    struct toe_socket_id identification;
    uint64_t        recv_list_virtaddr;
}__attribute__((__packed__));



#define TOE_CTRL_RQ_MSG_SIZE sizeof(struct toe_ctrl_host_to_dpu_req)
#define TOE_CTRL_CQ_MSG_SIZE sizeof(struct toe_ctrl_host_to_dpu_res)



#define TOE_DATA_RXRQ_MSG_SIZE sizeof(struct toe_data_host_to_dpu_req)
#define TOE_DATA_RXCQ_MSG_SIZE sizeof(struct toe_data_host_to_dpu_res)

#define TOE_DATA_TXRQ_MSG_SIZE sizeof(struct toe_data_dpu_to_host_req)
#define TOE_DATA_TXCQ_MSG_SIZE sizeof(struct toe_data_dpu_to_host_res)







struct toe_ctl_rq_info {
	struct rq_bar_cfg *rbc;
	uint16_t rq_size;
	struct toe_ctrl_host_to_dpu_req *rq_local;
	uint16_t local_head;
	uint16_t pre_head;
	uint16_t head;
	rte_atomic16_t wait_head_num;
	uint8_t wait_head[TOE_MAX_RQ_SIZE];
	uint16_t tail;
};

struct toe_ctl_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_ctrl_host_to_dpu_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t head;
	uint16_t pre_tail;
	uint16_t tail;
	rte_atomic16_t wait_tail_num;
	uint8_t wait_tail[TOE_MAX_CQ_SIZE];
};

struct toe_ctl_rx_vring {
	struct toe_ctl_rq_info rq_info;
	struct toe_ctl_cq_info cq_info;
};

struct toe_data_rx_rq_info {
	struct rq_bar_cfg *rbc;
	uint16_t rq_size;
	struct toe_data_host_to_dpu_req *rq_local;
	uint16_t pre_head;
	uint16_t head;
	uint16_t real_tail;
	uint16_t tail;
};

struct toe_data_rx_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_data_host_to_dpu_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t head;
	uint16_t pre_tail;
	uint16_t tail;
};

struct toe_data_tx_rq_info {
	struct rq_bar_cfg *rbc;
	uint16_t rq_size;
	struct toe_data_dpu_to_host_req *rq_local;
	uint16_t pre_head;
	uint16_t head;
	uint16_t enq_tail;
	uint16_t real_tail;
	uint16_t tail;
//	struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
//	uint16_t jobs_num;
//	uint16_t jobs_head;
//	uint16_t jobs_tail;
};

struct toe_data_tx_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_data_dpu_to_host_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t head;
	uint16_t tail;
};

struct toe_host_buf_info {
	uint64_t data_buffer_addr;
	unsigned int data_len;
	uint64_t host_recv_buf_addr;
};

struct toe_tx_data_queue {
	TAILQ_ENTRY(toe_tx_data_queue) next;
	int fd;
	struct rte_ring *ring;
	uint16_t host_buf_num;
	uint16_t host_buf_head;
	uint16_t host_buf_tail;
	struct toe_host_buf_info host_buf[TOE_MAX_HOST_BUF_NUM];
};

struct toe_data_rx_vring {
	struct toe_device *toe_dev;
	struct toe_data_rx_rq_info rq_info;
	struct toe_data_rx_cq_info cq_info;
	int idx;
};

struct toe_data_tx_vring {
	struct toe_device *toe_dev;
	struct toe_data_tx_rq_info rq_info;
	struct toe_data_tx_cq_info cq_info;
	int idx;
};

struct toe_engine {
	void *bar;
	int pf;
	int vf;
	struct pci_ep *ep;
	uint16_t config_vector;
	void *irq_addr[TOE_MAX_QUEUE];
	uint32_t irq_data[TOE_MAX_QUEUE];
	uint32_t vector_map;
	struct toe_ctl_rx_vring **ctl_rx_vring;
	struct toe_data_rx_vring **data_rx_vring;
	struct toe_data_tx_vring **data_tx_vring;
	struct toe_device *t_dev;
	struct toe_dma_info *t_dma;
	//struct toe_close_fd_tail fd_close[TOE_MAX_SOCKET_NUM];
	uint64_t fd_save_kernel[TOE_MAX_SOCKET_NUM];
};


void toe_irq_raise(struct toe_engine *toe_eg, uint16_t vector);



uint16_t
toe_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t 
toe_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void toe_engine_free(struct toe_device *toe_dev);
int toe_ctl_recv(void *vaddr, struct toe_engine *toe_eg, int idx);
int toe_engine_init(struct toe_device *toe_dev);
int toe_tcp_datapkt_send(tcp_stream *stream, struct toe_engine *toe_eg, int idx);
int toe_sendbuf_update(tcp_stream *stream, int data_len);
#endif
