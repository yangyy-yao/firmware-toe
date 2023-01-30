#ifndef RTE_AGIEP_ACCEL_NET_H_
#define RTE_AGIEP_ACCEL_NET_H_

#include "agiep_accel_engine.h"

#define ACCEL_HW_NAME                     "accel_hw"
#define MAX_ACCEL_NUMBER                  32

#define ACCEL_LO_RING_NAME_LEN            23
#define ACCEL_LO_DEV_NUM                  "num"
#define ACCEL_LO_DEV_NUM_PER_FREP         "per_frep_num"
#define ACCEL_LO_DEV_NAME                 "name"
#define ACCEL_LO_DEV_SERDES_LAN           "serdes_lan"
#define ACCEL_LO_DEV_INIT                 "init"

#define ACCEL_NUM_MBUFS                   (8191)
#define ACCEL_MBUF_CACHE_SIZE             256
#define ACCEL_RX_QUEUE_NUM                8
#define ACCEL_TX_QUEUE_NUM                8
#define ACCEL_RX_RING_SIZE                1024
#define ACCEL_TX_RING_SIZE                1024
#define ACCEL_MAX_PKT_BURST               32

#define ACCEL_DIRECTION_TX                2
#define ACCEL_DIRECTION_RX                3

#define ACCEL_MAX_LO_DEV_NUM              8

#define ACCEL_SERDES_MAX_NB 3
#define ACCEL_SERDES_MAX_LAN_NB 8
#define ACCEL_LB_EN_BIT 0x10000000
#define ACCEL_SERDES_REG_BASE 0x1ea0000

#define LX_SERDES_LB_REG_OFF(serdes_id, lan_id)\
	(0x8a0 + (ACCEL_SERDES_MAX_LAN_NB - lan_id - 1) * 0x100 + serdes_id * 0x4)
	
#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

struct accel_lo_dev_info {
	int initialized;
	int n_dev;
	int n_dev_per_frep;
	char dev_name[ACCEL_MAX_LO_DEV_NUM][10];
	char serdes_lan[ACCEL_MAX_LO_DEV_NUM][22];
	int dev_init_enable;
};

struct accel_hw_device {
	struct agiep_accel_device *accel_dev;
	int aid;
	int num_lo_dev;
	struct rte_eth_dev **lo_eth_dev;
	void **rx_lo_queue;
	void **tx_lo_queue;
};

#endif
