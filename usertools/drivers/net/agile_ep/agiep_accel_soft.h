#ifndef RTE_AGIEP_ACCEL_SOFT_H_
#define RTE_AGIEP_ACCEL_SOFT_H_

#include "agiep_accel_engine.h"

struct accel_soft_ring {
	struct rte_mbuf *pkts[MAX_BURST_NUMBER];
	uint16_t nb_pkts;
};

struct accel_soft_device {
	struct accel_soft_ring **tx_ring;
	struct accel_soft_ring *rx_ring;
	uint64_t feature;
};

#endif
