#ifndef RTE_PMD_TOE_PCIE_H_
#define RTE_PMD_TOE_PCIE_H_

//#include "toe_engine.h"

//#ifndef STRUCTURE_COMPACT_MODE
//#define STRUCTURE_COMPACT_MODE      __attribute__((__packed__))
//#endif
/*
#define TOE_CONFIG_H_ACTIVE    0x1
#define TOE_CONFIG_C_ACTIVE    0x2
#define TOE_CONFIG_C_NEEDS_RESET     0x4
#define TOE_CONFIG_C_RESET_OK    0x8
*/
struct toe_bar_base_cfg {
	uint8_t status;
	uint8_t msg_queue_num;
	uint8_t vendor_queue_num;
	uint16_t fd_reserve_num;
}__attribute__((__packed__));

struct rq_bar_cfg {
	uint16_t qsize;
	uint16_t doorbell;
	uint32_t queue_desc_lo;
	uint32_t queue_desc_h;
}__attribute__((__packed__));

struct cq_bar_cfg {
	uint16_t qsize;
	uint16_t doorbell;
	uint16_t msi_vector;
	uint32_t queue_desc_lo;
	uint32_t queue_desc_h;

}__attribute__((__packed__));

struct toe_bar_queue_cfg {
	struct rq_bar_cfg rq_cfg;   //12
	struct cq_bar_cfg cq_cfg;   //14
}__attribute__((__packed__));

struct toe_bar_cfg {
	struct toe_bar_base_cfg base_cfg; 	 	//8
	struct toe_bar_queue_cfg sys_ctrl_cfg; //26
	struct toe_bar_queue_cfg ctrl_rx_cfg; //26
//	struct toe_bar_queue_cfg ctrl_tx_cfg; //26
	struct toe_bar_queue_cfg data_rx_cfg; //26
	struct toe_bar_queue_cfg data_tx_cfg; //26
}__attribute__((__packed__));

#define TOE_BAR_BASE_OFFSET 0
#define TOE_BAR_NUM 0


#define TOE_RQ_BAR_BASE_OFFSET (TOE_BAR_BASE_OFFSET + sizeof(struct toe_bar_base_cfg))
#define TOE_CQ_BAR_BASE_OFFSET (TOE_RQ_BAR_BASE_OFFSET + sizeof(struct rq_bar_cfg))

#define TOE_RQ_CQ_BAR_SIZE (sizeof(struct rq_bar_cfg) + sizeof(struct cq_bar_cfg))

void *toe_pcie_bar_get(int pf, int vf);
struct toe_bar_base_cfg *toe_base_bar_get(uint8_t *bar);
struct rq_bar_cfg *toe_rq_bar_get(uint8_t *bar, int offset);
struct cq_bar_cfg *toe_cq_bar_get(uint8_t *bar, int offset);


#endif

