#ifndef RTE_AGIEP_VIRTIO_H_
#define RTE_AGIEP_VIRTIO_H_

#include "agiep_vring.h"
#include "agiep_pci.h"

/* Status byte for guest to report reset */
#define VIRTIO_CONFIG_S_RESET    0
/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE     1
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_S_DRIVER          2
/* Driver has used its parts of the config, and is happy */
#define VIRTIO_CONFIG_S_DRIVER_OK       4
/* Driver has finished configuring features */
#define VIRTIO_CONFIG_S_FEATURES_OK     8

/* Device entered invalid state, driver must reset it */
#define VIRTIO_CONFIG_S_NEEDS_RESET     0x40
/* We've given up on this device. */
#define VIRTIO_CONFIG_S_FAILED          0x80

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES        0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES       4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN            8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM            12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL            14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY         16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS               18

/* An 8-bit r/o interrupt status register.  Reading the value will return the
 *   * current contents of the ISR and will also clear it.  This is effectively
 *     * a read-and-acknowledge. */
#define VIRTIO_PCI_ISR                  19

/* MSI-X registers: only enabled if MSI-X is enabled. */
/* A 16-bit vector for configuration changes. */
#define VIRTIO_MSI_CONFIG_VECTOR        20
/* A 16-bit vector for selected queue notifications. */
#define VIRTIO_MSI_QUEUE_VECTOR         22

/* How many bits to shift physical queue address written to QUEUE_PFN.
 * 12 is historical, and due to x86 page size. */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT     12U

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY        24

/* Can the device handle any descriptor layout? */
#define VIRTIO_F_ANY_LAYOUT             27

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC     28

#define VIRTIO_F_VERSION_1              32
#define VIRTIO_F_IOMMU_PLATFORM 33
#define VIRTIO_F_RING_PACKED            34

/*
 * Some VirtIO feature bits (currently bits 28 through 31) are
 * reserved for the transport being used (eg. virtio_ring), the
 * rest are per-device feature bits.
 */
#define VIRTIO_TRANSPORT_F_START 28
#define VIRTIO_TRANSPORT_F_END   34

/*
 * Inorder feature indicates that all buffers are used by the device
 * in the same order in which they have been made available.
 */
#define VIRTIO_F_IN_ORDER 35

/*
 * This feature indicates that memory accesses by the driver and the device
 * are ordered in a way described by the platform.
 */
#define VIRTIO_F_ORDER_PLATFORM 36

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX         29

/* When Host destroy Guest, host quick write this register
 * Work with kernel patch. this not standard
 * */
#define VIRTIO_PCI_HOST_STATUS       64
#define VIRTIO_PCI_HOST_S_INIT       0xEFEF
#define VIRTIO_PCI_HOST_S_RESET      0
#define VIRTIO_PCI_HOST_S_ACK        0xFEFE

#define VIRTIO_PCI_DEVICE_STATUS     66
#define VIRTIO_PCI_DEVICE_S_OK       0
#define VIRTIO_PCI_DEVICE_S_RESETED  1


#define VIRTIO_MAX_QUEUE 32

#define VIRTIO_CTRL_QUEUE_SIZE		1U
#define VIRTIO_F_ACCESS_PLATFORM        33

#define VIRTIO_PCI_S_QUEUE_NOTIFY_INIT  65535
#define MAX_NB_MBUF          		(8192)

#define VIRTIO_PCI_INVALID_OFFSET 		64

#define VIRTIO_PCI_MNG_IP		128
#define VIRTIO_PCI_MNG_MASK		132

struct agiep_virtio_device;
typedef void (*virtio_handle_pci_status)(struct agiep_virtio_device *vdev, uint8_t device_status);
typedef uint8_t (*virtio_check_pfn_set_complete)(struct agiep_virtio_device *vdev);
typedef void (*virtio_do_config_after_set_feature)(struct agiep_virtio_device *vdev);

struct agiep_virtio_device {
	uint8_t started;
	uint8_t vq_num;
	uint8_t reseted;
	uint8_t set_num;
	uint16_t reset_num;
	uint16_t poller_num;
	struct pci_ep *ep;
	void *BAR[PCI_STD_NUM_BARS];
	uint64_t host_feature;
	uint64_t dev_feature;
	uint16_t config_vector;
	uint8_t device_status;
	uint8_t msix_enabled;
	int pf;
	int vf;
	struct virtqueue **vq;
	struct agiep_poller *poller;
	void *comm_cfg; /* alias from BAR0  */
	void *dev_cfg;
	void *irq_addr[VIRTIO_MAX_QUEUE];
	uint32_t irq_data[VIRTIO_MAX_QUEUE];
	uint64_t *desc_addr;
	void *dev;
	virtio_handle_pci_status handle_pci_status;
	uint32_t mng_ip;
	uint32_t netmask;
	int16_t pfn_expand_id;
	int16_t notify_expand_id;
	int16_t queue_vec_expand_id;
	int16_t config_expand_id;
	virtio_check_pfn_set_complete check_pfn_set_complete;
	virtio_do_config_after_set_feature do_config_after_set_feature;
};

struct agiep_virtio_device *
agiep_virtio_create(int pf, int vf, uint64_t feature, uint16_t num, void *init_data);
void agiep_virtio_destroy(struct agiep_virtio_device *dev);
void agiep_virtio_reset_vector(struct agiep_virtio_device *dev, uint16_t vector);
void agiep_virtio_msi_raise(struct agiep_virtio_device *dev, uint16_t vector);
void agiep_virtio_msix_raise(struct agiep_virtio_device *dev, uint16_t vector);
int agiep_virtio_with_feature(struct agiep_virtio_device *dev, uint64_t bit);
#endif
