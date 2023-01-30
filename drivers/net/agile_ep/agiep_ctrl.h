#ifndef AGIEP_CONFIG_H_
#define AGIEP_CONFIG_H_
#include <stdint.h>

#include "agiep_lib.h"
#include "agiep_virtio_port.h"

enum net_ctrl_type {
	CTRL_VIRTIO,
	CTRL_VENDOR,
};

struct agiep_net_ctrl {
	volatile uint64_t cmd_seq;
	volatile uint64_t seq;
	struct virtqueue *cvq;
	struct virtqueue *bvq;
	struct rte_mempool *cmdpool;
	struct rte_ring *rr; // request ring
	struct rte_ring *cr; // complete ring
	struct agiep_virtio_port *priv;
	enum net_ctrl_type ctl_type;
};

void agiep_rq_process(struct agiep_virtio_port *port);
void agiep_cq_process(struct agiep_virtio_port *port);
void agiep_ctrl_synchronize(struct agiep_net_ctrl *ctrl);
int agiep_ctrl_init(void);
#endif