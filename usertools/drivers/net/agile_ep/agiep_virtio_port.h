#ifndef AGIEP_VIRTIO_PORT_H__
#define AGIEP_VIRTIO_PORT_H__

#include "agiep_frep.h"
#include "agiep_vring.h"

#define PORT_MAX_QUEUE 32

#define DB_NOR 0
#define DB_POS 1

struct agiep_virtio_port {
	struct agiep_frep_device *fdev;
	struct agiep_net_ctrl *ctrl;
};

void agiep_virtio_port_msix_raise(struct agiep_virtio_port *port, int vector);
uint16_t agiep_virtio_port_enabled(struct agiep_virtio_port *port);

#endif
