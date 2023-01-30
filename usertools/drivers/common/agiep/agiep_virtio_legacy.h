#ifndef AGIEP_VIRTIO_LEGACY_H_
#define AGIEP_VIRTIO_LEGACY_H_

#include "agiep_virtio.h"

#define VIRTIO_PCI_CONFIG_OFF(dev) ((dev)->msix_enabled ? 24 : 20)
#define VIRTIO_MSI_NO_VECTOR 0xffff
#define VIRTIO_NET_CTRL_PCI_STATUS	6
#define VIRTIO_NET_CTRL_PFN_SET		7
#define VIRTIO_NET_CTRL_PFN_RESET	8
#define VIRTIO_NET_CTRL_NOTIFY		9

int agiep_virtio_legacy_probe(struct agiep_virtio_device *dev, void *bar0,
	uint64_t feature, uint16_t num, void *init_data);
void agiep_virtio_legacy_expand_reset(struct agiep_virtio_device *dev);
void agiep_virtio_legacy_remove(struct agiep_virtio_device *dev);
void legacy_queue_set_pfn(struct agiep_virtio_device *dev, uint16_t queue_select, uint64_t pfn);
void legacy_queue_set_notify(struct agiep_virtio_device *dev, uint16_t queue_select);
void legacy_reset_device_reg(struct agiep_virtio_device *dev);
void legacy_set_device_status(struct agiep_virtio_device *dev, uint16_t status);

#define  legacy_get_ioaddr(dev) (dev->comm_cfg)

#endif
