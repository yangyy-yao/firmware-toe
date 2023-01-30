#ifndef RTE_PMD_TOE_ENGINE_H_
#define RTE_PMD_TOE_ENGINE_H_

#include <tcp_stream.h>
#include <rte_ether.h>

//#ifndef STRUCTURE_COMPACT_MODE
//#define STRUCTURE_COMPACT_MODE      __attribute__((__packed__))
//#endif

enum {
	CHANNEL1_DOORBELL,
	RECV_PKT,
	CHANNEL1_IRQ,
	CHANNEL2_DOORBELL,
	CHANNEL2_IRQ,
	CHANNEL3_IRQ,
	
};

#define TOE_LOG_ON 0
#define LOG_NUM  600
#undef TOE_GRO
#define TOE_MAX_DESC_LIMIT 512

#define TOE_CHANNEL0_MAX_QUEUE_SIZE               16
#define TOE_CHANNEL1_MAX_QUEUE_SIZE               512
#define TOE_CHANNEL2_MAX_QUEUE_SIZE               512
#define TOE_CHANNEL3_MAX_QUEUE_SIZE               1024

#define TOE_HASH_SIZE 	8
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
#define TOE_RECV_BUFFER_COUNT_RESERVED      1

#define TOE_US_PER_S 1000000
#define TOE_BURST_TX_DRAIN_US 50 /* TX drain every ~100us */

#define TOE_RECOVERY_MBUF_RING_SIZE 32767

#define TOE_SEND_INCWND_TO_HOST_THRESHOLD 4096
#define TOE_CTRL_PROCESS "TOE_CTRL_COREMASK"

#define TOE_INC_WND_MAX_TAPS   4
#define TOE_INC_WND_PER_STEP   4096

enum TOE_RETURN_TYPE {
	TOE_SUCCESS_RETAIN = 1,
	TOE_SUCCESS_FREE,
	TOE_FAILED_RETAIN,
	TOE_FAILED_FREE,
	TOE_ERR_FREE,
	
};

enum TOE_MESSAGE_OPCODE {
	TOE_MSG_OPCODE_H2D_IP_MAC_NOTIFICATION,

  TOE_MESSAGE_OPCODE_H2D_CTRL_PACKET,
  TOE_MESSAGE_OPCODE_D2H_CTRL_PACKET,
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
	TOE_DMA_HOST_REFUSED,
	TOE_DMA_PENDING,
	TOE_DMA_MAX
};

enum TOE_CONNECT_STATUS {
    TOE_ESTABLISHING = 1, //$)A1;6/A4=S#,7"syn-ackJ1JU5=2"VC3I4KW4L,#,JU5=6T6KackJ1#,?(WT<:VC3IESTABLISHEDW4L,!#
    TOE_ESTABLISHED,      //$)AVw6/A4=S#,7"5ZH}4NNUJV5DackJ1JU5=2"VC3I4KW4L,
    TOE_CLOSED,			//$)AVw6/9X1U#,7"5ZKD4N;SJV5DackJ1#,JU5=4KW4L,#,I>3}1mOn
    TOE_CLOSING     //$)A1;6/9X1UJ1#,7"KM5ZH}4N;SJV5Dfin_ackJ1#,JU5=2"VC3I4KW4L,#,H;:sJU5=6T6K5DH7HOack:sI>1m
};

struct toe_socket_id {
	uint64_t host_dataptr;
	uint64_t card_stream_addr;
}__attribute__((__packed__));

struct toe_data_recv_buffer {
	uint64_t recv_buffer_phyaddr;
	uint16_t recv_buffer_len;
	uint64_t host_list_virtaddr;
}__attribute__((__packed__));


struct toe_h2d_msg_ipmac_notification_hdr {
    uint8_t               ifindex;
    uint32_t                ip;
    uint8_t               mac[RTE_ETHER_ADDR_LEN];
}__attribute__((__packed__));

struct toe_tcp_tuples {
	uint32_t							local_ip;
	uint32_t							remote_ip;
	uint16_t							local_port;
	uint16_t							remote_port;
	uint8_t 							local_mac[RTE_ETHER_ADDR_LEN];
	uint8_t 							remote_mac[RTE_ETHER_ADDR_LEN];
}__attribute__((__packed__));

struct toe_tcp_params {
		uint8_t               tcp_flags;
    uint16_t              mss;
    uint16_t              window;
    uint32_t              sequence;
    uint32_t              acknowledge;
    uint8_t               window_scale;
}__attribute__((__packed__));


struct toe_tcp_info {
	struct toe_tcp_tuples tcp_tuples;
	struct toe_tcp_params tcp_params;
}__attribute__((__packed__));

struct toe_h2d_ctrl_packet_msg {
    unsigned char               status;     // Valued From enum TOE_SOCK_STATUS
	struct toe_tcp_info         tcp_info;
}__attribute__((__packed__));

struct toe_sys_ctrl_host_to_dpu_req { //channel 0 rq
	struct toe_h2d_msg_ipmac_notification_hdr ipmac_notify;
}__attribute__((__packed__));

struct toe_sys_ctrl_dpu_to_host_res { //channel 0 cq
	unsigned char result   : 7;
  unsigned char complete : 1;
  unsigned char qid;
  unsigned short rq_head;
}__attribute__((__packed__));

struct toe_ctrl_host_to_dpu_req { //channel 1 rq
	struct toe_socket_id id;
	struct toe_h2d_ctrl_packet_msg ctrl_pkt_msg;
}__attribute__((__packed__));

struct toe_ctrl_host_to_dpu_res { //channel 1 cq
	uint8_t result : 7;
	uint8_t compl  : 1;
	uint8_t qid;
	uint16_t rq_head;
	struct toe_socket_id identification;
	struct toe_tcp_info tcp_info;
}__attribute__((__packed__));

struct toe_data_host_to_dpu_req {  //channel 2 rq
		struct toe_socket_id identification;
		uint64_t send_buffer_addr;
		uint16_t data_len;
		uint64_t send_list_addr;
}__attribute__((__packed__));

struct toe_data_host_to_dpu_res {  //channel 2 cq
		uint8_t result : 7;
		uint8_t compl  : 1;
		uint16_t rq_head;
		//uint16_t sent_len;
    	//uint64_t send_list_virtaddr;
		uint32_t increment_wnd;
		struct toe_socket_id identification;
}__attribute__((__packed__));

struct toe_data_dpu_to_host_req {  //channel 3 rq
		struct toe_socket_id identification;
		//uint8_t buffer_num;
		//uint8_t use_idx;
		//struct toe_data_recv_buffer recv_buffer[TOE_RECV_BUFFER_COUNT_RESERVED];
		struct toe_data_recv_buffer recv_buffer;
}__attribute__((__packed__));

struct toe_data_dpu_to_host_res{  //channel 3 cq
    uint8_t        qid : 7;
    uint8_t        complete : 1;
    uint16_t       rq_head;
    uint16_t       data_len;
    struct toe_socket_id identification;
    uint64_t        recv_list_virtaddr;
}__attribute__((__packed__));

#define TOE_SYS_CTRL_RQ_MSG_SIZE sizeof(struct toe_sys_ctrl_host_to_dpu_req)
#define TOE_SYS_CTRL_CQ_MSG_SIZE sizeof(struct toe_sys_ctrl_dpu_to_host_res)

#define TOE_CTRL_RQ_MSG_SIZE sizeof(struct toe_ctrl_host_to_dpu_req)
#define TOE_CTRL_CQ_MSG_SIZE sizeof(struct toe_ctrl_host_to_dpu_res)

#define TOE_DATA_RXRQ_MSG_SIZE sizeof(struct toe_data_host_to_dpu_req)
#define TOE_DATA_RXCQ_MSG_SIZE sizeof(struct toe_data_host_to_dpu_res)

#define TOE_DATA_TXRQ_MSG_SIZE sizeof(struct toe_data_dpu_to_host_req)
#define TOE_DATA_TXCQ_MSG_SIZE sizeof(struct toe_data_dpu_to_host_res)

struct toe_sys_ctl_rq_info {
	struct rq_bar_cfg *rbc;
	uint16_t rq_size;
	struct toe_sys_ctrl_host_to_dpu_req *rq_local;
	uint16_t local_head;
	uint16_t pre_head;
	uint16_t head;
	uint16_t *tail;
};

struct toe_sys_ctl_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_sys_ctrl_dpu_to_host_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t *head;
	uint16_t pre_tail;
	uint16_t tail;

};

struct toe_sys_ctl_vring {
	struct toe_sys_ctl_rq_info rq_info;
	struct toe_sys_ctl_cq_info cq_info;
};

struct toe_ctl_rq_info {
	struct rq_bar_cfg *rbc;
	uint16_t rq_size;
	struct toe_ctrl_host_to_dpu_req *rq_local;
	uint16_t local_head;
	uint16_t pre_head;
	uint16_t head;
	uint16_t *tail;
};

struct toe_ctl_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_ctrl_host_to_dpu_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t *head;
	uint16_t pre_tail;
	uint16_t tail;
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
	uint16_t *tail;
};

struct toe_data_rx_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_data_host_to_dpu_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t *head;
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
	uint16_t *tail;
};

struct toe_data_tx_cq_info {
	struct cq_bar_cfg *cbc;
	uint16_t cq_size;
	struct toe_data_dpu_to_host_res *cq_local;
	int cq_compl;
	uint16_t pre_head;
	uint16_t *head;
	uint16_t tail;
};
/*
struct toe_host_buf_info {
	uint64_t data_buffer_addr;
	uint32_t data_len;
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
*/
struct toe_mbuf_recovery {
		struct rte_mbuf *m_data[TOE_RECOVERY_MBUF_RING_SIZE];
		int head;
		int tail;
		int size;
};

struct toe_data_rx_vring {
	struct toe_device *toe_dev;
	struct toe_data_rx_rq_info rq_info;
	struct toe_data_rx_cq_info cq_info;
	int idx;
	struct rte_mempool *mbuf_save_pool;
};

struct toe_data_tx_vring {
	struct toe_device *toe_dev;
	struct toe_data_tx_rq_info rq_info;
	struct toe_data_tx_cq_info cq_info;
	int idx;
	struct rte_ring *data_ring;
	struct toe_mbuf_recovery recovery_ring;
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
	struct toe_sys_ctl_vring *sys_ctl_vring;
	struct toe_ctl_rx_vring **ctl_rx_vring;
	struct toe_data_rx_vring **data_rx_vring;
	struct toe_data_tx_vring **data_tx_vring;
	struct toe_device *t_dev;
	struct toe_dma_info *t_dma;
};

void toe_destory_stream_check(tcp_stream *tcp_s);

uint16_t
toe_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t 
toe_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void toe_engine_free(struct toe_device *toe_dev);
int toe_ctl_recv(void *vaddr, struct toe_engine *toe_eg, int idx);
int toe_engine_init(struct toe_device *toe_dev);
int toe_tcp_datapkt_send(tcp_stream *stream, struct toe_engine *toe_eg, int idx);
int toe_sendbuf_create(tcp_stream *stream);
void toe_sendbuf_update(tcp_stream *stream, int data_len);
#endif
