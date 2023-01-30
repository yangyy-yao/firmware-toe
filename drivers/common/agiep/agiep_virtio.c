#include <rte_malloc.h>
#include <rte_io.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <assert.h>

#include "agiep_virtio.h"
#include "agiep_virtio_legacy.h"
#include "agiep_pci.h"

struct agiep_virtio_device *agiep_virtio_create(int pf, int vf, uint64_t feature, uint16_t num, void *init_data)
{
	void *bar0 = NULL;
	struct agiep_virtio_device *dev = NULL;
	struct virtqueue **vq = NULL;
	uint64_t *desc_addr = NULL;
	int ret;

	dev = rte_calloc(NULL, 1, sizeof(struct agiep_virtio_device), 0);

	if (dev == NULL)
		return NULL;

	vq = rte_calloc(NULL, num, sizeof(struct virtqueue *), 0);

	if (vq == NULL)
		goto error;
	desc_addr = rte_calloc(NULL, num + VIRTIO_CTRL_QUEUE_SIZE, sizeof(uint64_t), 0);
	if (desc_addr == NULL)
		goto error;

	bar0 = agiep_pci_bar(pf, vf, 0);

	if (bar0 == NULL)
		goto error;
	memset(bar0, 0, agiep_pci_bar_size(pf, vf, 0));
	dev->BAR[BAR_0] = bar0;
	dev->dev_feature = feature;
	dev->vq = vq;
	dev->vq_num = num;
	dev->pf = pf;
	dev->vf = vf;
	dev->desc_addr = desc_addr;
	dev->ep = agiep_get_ep();
	memset(dev->irq_data, 0xFF, sizeof(dev->irq_data));
	// TODO: Support virtio1.0 (modern pci)
	ret = agiep_virtio_legacy_probe(dev, bar0, feature, num, init_data);

	if (ret){
		AGIEP_LOG_ERR("virito legacy probe fail %d", ret);
		goto error;
	}
	return dev;
error:
	if (desc_addr)
		rte_free(desc_addr);
	if (vq)
		rte_free(vq);
	if (dev)
		rte_free(dev);
	return NULL;
}

static inline uint64_t agiep_virtio_msi_irq_addr(struct agiep_virtio_device *dev, uint16_t vector)
{
	if (dev->irq_addr[vector] == NULL)
		dev->irq_addr[vector] = (void *)pci_ep_get_irq_addr(dev->ep,
				dev->pf, dev->vf, PCI_EP_IRQ_MSI, vector);
	return (uint64_t)dev->irq_addr[vector];
}

static inline uint32_t agiep_virtio_msi_irq_data(struct agiep_virtio_device *dev, uint16_t vector)
{
	if (dev->irq_data[vector] == 0xFFFFFFFF)
		dev->irq_data[vector] = pci_ep_get_irq_data(dev->ep,
				dev->pf, dev->vf, PCI_EP_IRQ_MSI, vector);
	return dev->irq_data[vector];
}

static inline uint64_t agiep_virtio_msix_irq_addr(struct agiep_virtio_device *dev, uint16_t vector)
{
	if (dev->irq_addr[vector] == NULL)
		dev->irq_addr[vector] = (void *)pci_ep_get_irq_addr(dev->ep,
				dev->pf, dev->vf, PCI_EP_IRQ_MSIX, vector);
	return (uint64_t)dev->irq_addr[vector];
}

static inline uint32_t agiep_virtio_msix_irq_data(struct agiep_virtio_device *dev, uint16_t vector)
{
	if (dev->irq_data[vector] == 0xFFFFFFFF)
		dev->irq_data[vector] = pci_ep_get_irq_data(dev->ep, 
				dev->pf, dev->vf, PCI_EP_IRQ_MSIX, vector);
	return dev->irq_data[vector];
}

void agiep_virtio_msi_raise(struct agiep_virtio_device *dev, uint16_t vector)
{
	uint64_t addr = agiep_virtio_msi_irq_addr(dev, vector);
	uint32_t data = agiep_virtio_msi_irq_data(dev, vector);
	if (addr == 0)
		return;
	rte_write32(data, (void *)addr);
}

void agiep_virtio_msix_raise(struct agiep_virtio_device *dev, uint16_t vector)
{
	uint64_t addr = agiep_virtio_msix_irq_addr(dev, vector);
	uint32_t data = agiep_virtio_msix_irq_data(dev, vector);
	if (addr == 0)
		return;
	rte_write32(data, (void *)addr);
}

void agiep_virtio_destroy(struct agiep_virtio_device *dev)
{
	if (!dev)
		return;
	rte_free(dev->desc_addr);
	rte_free(dev->vq);
	agiep_virtio_legacy_remove(dev);
}
void agiep_virtio_reset_vector(struct agiep_virtio_device *dev, uint16_t vector)
{
	dev->irq_addr[vector] = NULL;
	dev->irq_data[vector] = 0xFFFFFFFF;
}

inline int
agiep_virtio_with_feature(struct agiep_virtio_device *dev, uint64_t bit)
{
	return (dev->dev_feature & (1ULL << bit)) != 0;
}
