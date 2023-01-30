#include <agiep_virtio.h>
#include "agiep_frep.h"
#include "agiep_virtio_port.h"
#include "agiep_virtio_net.h"

#include "agiep_vendor_port.h"

void agiep_virtio_port_msix_raise(struct agiep_virtio_port *port, int vector)
{
	struct agiep_frep_device *fdev;
	enum agiep_frep_t ftype;

	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;

	struct agiep_vendor_port *vendor_port;
	struct agiep_vendor_netdev *vendor_netdev;

	fdev = port->fdev;
	ftype = fdev->frep->type;

	switch(ftype) {
	case AGIEP_FREP_VIRTIO:
		ndev = fdev->dev;
		vdev = ndev->vdev;
		return agiep_virtio_msix_raise(vdev, vector);
	case AGIEP_FREP_VENDOR:
		vendor_port = fdev->dev;
		vendor_netdev = vendor_port->netdev;
		return agiep_vendor_irq_raise(vendor_netdev, vector);
	default:
		return;
	}

}


uint16_t agiep_virtio_port_enabled(struct agiep_virtio_port *port)
{
	struct agiep_frep_device *fdev;
	enum agiep_frep_t ftype;
	struct agiep_virtio_netdev *ndev;
	struct agiep_virtio_device *vdev;
	struct agiep_vendor_port *vendor_port;

	fdev = port->fdev;
	ftype = fdev->frep->type;
	switch(ftype) {
	case AGIEP_FREP_VIRTIO:
		ndev = fdev->dev;
		vdev = ndev->vdev;
		return vdev->started;
	case AGIEP_FREP_VENDOR:
		vendor_port = fdev->dev;
		return vendor_port->enable;
	default:
		break;
	}
	return 0;
}