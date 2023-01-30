#include <stdlib.h>
#include <sys/mman.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>

#include "agiep_logs.h"
#include "agiep_virtio.h"
#include "agiep_virtio_legacy.h"
#include "agiep_reg_poller.h"
#include "agiep_reg_expand.h"
#include "agiep_lib.h"
#include "agiep_mng.h"

// force zero for need
static uint16_t zero = 0;

static void legacy_handle_feature(struct agiep_poller *poller);
static void legacy_handle_pfn(struct agiep_poller *poller);
static void legacy_handle_notify(struct agiep_poller *poller);

static void legacy_handle_device_status(struct agiep_poller *poller);

static int agiep_virtio_pfn_poller_init(struct agiep_poller *pollers, void *addr, void *select_addr, int num);
static int agiep_virtio_notify_poller_init(struct agiep_poller *pollers, void *addr, int num);

static void legacy_handle_config_vector(struct agiep_poller *poller __rte_unused);
static void legacy_handle_queue_vector(struct agiep_poller *poller __rte_unused);

static void legacy_handle_mng_ip(struct agiep_poller *poller __rte_unused);
static void legacy_handle_mng_mask(struct agiep_poller *poller __rte_unused);

static int agiep_virtio_config_vector_poller_init(struct agiep_poller *pollers,
	void *addr, uint16_t init);
static int agiep_virtio_queue_vector_poller_init(struct agiep_poller *pollers,
	void *addr, void *select_addr, int num, uint16_t init);
static void legacy_handle_driver_status(struct agiep_poller *poller);
void legacy_bit_device_status_set(struct agiep_virtio_device *dev, uint8_t bit);
void legacy_bit_device_status_clear(struct agiep_virtio_device *dev, uint8_t bit);

static struct agiep_poller poller_insts[] = {
	{
		.bits = 32,
		.addr = (void *)VIRTIO_PCI_GUEST_FEATURES,
		.intr = legacy_handle_feature,
		.act  = ACT_NO,
	},
	{
		.bits = 8,
		.addr = (void *) VIRTIO_PCI_STATUS,
		.intr = legacy_handle_device_status,
		.act  = ACT_NO,
	},
	{
		.bits = 16,
		.addr = (void *) VIRTIO_PCI_HOST_STATUS,
		.intr = legacy_handle_driver_status,
		.act = ACT_INIT,
		.init = VIRTIO_PCI_HOST_S_INIT,
	},
	{
		.bits = 32,
		.addr = (void *) VIRTIO_PCI_MNG_IP,
		.intr = legacy_handle_mng_ip,
		.act = ACT_NO,
	},
	{
		.bits = 32,
		.addr = (void *) VIRTIO_PCI_MNG_MASK,
		.intr = legacy_handle_mng_mask,
		.act = ACT_NO,
	}
};

int agiep_virtio_legacy_probe(struct agiep_virtio_device *dev, void *bar0,
	uint64_t feature, uint16_t num, void *init_data)
{
	struct agiep_poller *pollers = NULL;
	int num_pollers;
	int const_pnum;
	int config_num = 1; /**  config vector num */
	int j;
	int i;
	int ret;
	uint16_t add_dup[3];

	const_pnum = sizeof(poller_insts)/sizeof(poller_insts[0]);
	if (dev->pf != 0 || dev->vf != 0)
		const_pnum -= 2;	// ignore mng pollers as vf
	num_pollers = num * 3 + config_num + const_pnum ;

	*(uint32_t *)(((uint8_t *)bar0 + VIRTIO_PCI_HOST_FEATURES)) = feature;

	pollers = rte_calloc(NULL, num_pollers, sizeof(struct agiep_poller), 0);

	if (pollers == NULL) {
		return -1;
	}

	rte_memcpy(pollers, poller_insts, sizeof(poller_insts[0]) * const_pnum);

	for (j = 0; j < num_pollers; j++) {
		pollers[j].expand_id = -1;
	}

	dev->pfn_expand_id = agiep_virtio_pfn_poller_init(&pollers[const_pnum],
			RTE_PTR_ADD(bar0, VIRTIO_PCI_QUEUE_PFN),
			RTE_PTR_ADD(bar0, VIRTIO_PCI_QUEUE_SEL), num);
	if (dev->pfn_expand_id < 0)
		goto free_poller;
	dev->notify_expand_id = agiep_virtio_notify_poller_init(&pollers[const_pnum + num],
			RTE_PTR_ADD(bar0, VIRTIO_PCI_QUEUE_NOTIFY), num);
	if (dev->notify_expand_id < 0)
		goto failed;
	/**
	 * mac设置原因: driver reset 后VIRTIO_MSI_QUEUE_VECTOR
	 * 与VIRTIO_MSI_CONFIG_VECTOR 被设置为0xFFFF, 在连续rmmod-insmod过程中,
	 * regpoller 来不及将mac位复位为mac, 这里使用reg_expand来初始化mac保证速度。
	 */
	// mac addr transform uint16
	rte_memcpy(add_dup, init_data, sizeof(add_dup));

	dev->queue_vec_expand_id = agiep_virtio_queue_vector_poller_init(&pollers[const_pnum + num * 2],
			RTE_PTR_ADD(bar0, VIRTIO_MSI_QUEUE_VECTOR),
			RTE_PTR_ADD(bar0, VIRTIO_PCI_QUEUE_SEL),
			num, add_dup[1]);
	if (dev->queue_vec_expand_id < 0)
		goto failed;

	dev->config_expand_id = agiep_virtio_config_vector_poller_init(&pollers[const_pnum + num * 3],
			RTE_PTR_ADD(bar0, VIRTIO_MSI_CONFIG_VECTOR), add_dup[0]);
	if (dev->config_expand_id < 0)
		goto q_failed;

	dev->poller = pollers;
	dev->poller_num = num_pollers;

	for (i = 0; i < num_pollers; i++) {
		pollers[i].addr = RTE_PTR_ADD(bar0, (uint64_t)pollers[i].addr);
		pollers[i].priv = dev;
		ret = agiep_reg_poller_send_reg(&pollers[i]);
		if (ret) {
			goto error;
		}
	}
	dev->comm_cfg = bar0;
	dev->dev_cfg = RTE_PTR_ADD(bar0, VIRTIO_PCI_CONFIG_OFF(dev));
	dev->config_vector = 0;
	return 0;
error:
	j = i;
	for (j = j - 1; j >= 0; j--) {
		ret = agiep_reg_poller_send_unreg(&pollers[i]);
		if (ret) {
			AGIEP_LOG_ERR("unexpect unreg poller error");
			break;
		}
	}

	agiep_reg_expand_unregister(dev->config_expand_id, 16);
q_failed:
	agiep_reg_expand_unregister(dev->queue_vec_expand_id, 16);
failed:
	agiep_reg_expand_unregister(dev->pfn_expand_id, 32);
free_poller:
	if (pollers)
		rte_free(pollers);
	return -1;
}


void agiep_virtio_legacy_expand_reset(struct agiep_virtio_device *dev)
{
	if (NULL == dev) {
		return;
	}

	agiep_reg_expand_reset(dev->pfn_expand_id, 32, NULL);       /*register in agiep_virtio_pfn_poller_init()*/
	agiep_reg_expand_reset(dev->notify_expand_id, 16, NULL);    /*register in agiep_virtio_notify_poller_init()*/
	agiep_reg_expand_reset(dev->queue_vec_expand_id, 16, NULL); /*register in agiep_virtio_queue_vector_poller_init()*/
	agiep_reg_expand_reset(dev->config_expand_id, 16, NULL);    /*register in agiep_virtio_config_vector_poller_init()*/

	return ;
}

static int agiep_virtio_pfn_poller_init(struct agiep_poller *pollers, void *addr, void *select_addr, int num)
{
	int i;
	int expand_id;
	struct agiep_poller *poller;
	struct agiep_reg_expand expand;

	expand.addr = addr;
	expand.init = 0;
	expand.select16 = select_addr;
	expand.max_num = num;

	expand_id = agiep_reg_expand_register(&expand, 32);
	if (expand_id == -1) {
		return -1;
	}

	for (i = 0; i < num; i++) {
		poller = &pollers[i];
		poller->expand_id = expand_id;
		poller->select_id = i;
		poller->select_num = num;
		poller->bits = 32;
		poller->intr = legacy_handle_pfn;
		poller->act  = ACT_INIT;
		poller->init = 0;
	}
	return expand_id;
}

static int agiep_virtio_notify_poller_init(struct agiep_poller *pollers, void *addr, int num)
{
	int i;
	int expand_id;
	struct agiep_poller *poller;
	struct agiep_reg_expand expand;

	expand.addr = addr;
	expand.init = VIRTIO_PCI_S_QUEUE_NOTIFY_INIT;
	expand.select16 = addr;

	expand_id = agiep_reg_expand_register(&expand, 16);
	if (expand_id == -1) {
		return -1;
	}

	for (i = 0; i < num; i++) {
		poller = &pollers[i];
		poller->expand_id = expand_id;
		poller->select_id = i;
		poller->select_num = num;
		poller->bits = 16;
		poller->intr = legacy_handle_notify;
		poller->act = ACT_INIT;
		poller->init = VIRTIO_PCI_S_QUEUE_NOTIFY_INIT;
	}
	return expand_id;
}

static int agiep_virtio_config_vector_poller_init(struct agiep_poller *pollers,
	void *addr, uint16_t init)
{
	int expand_id;
	struct agiep_poller *poller;
	struct agiep_reg_expand expand;

	expand.addr = addr;
	expand.init = init;
	expand.max_num = 0;
	// not need select
	expand.select16 = &zero;

	expand_id = agiep_reg_expand_register(&expand, 16);
	if (expand_id == -1) {
		return -1;
	}
	poller = pollers;
	poller->expand_id = expand_id;
	poller->select_id = 0;
	poller->select_num = 1;
	poller->bits = 16;
	poller->intr = legacy_handle_config_vector;
	poller->act = ACT_INIT;
	poller->init = init;
	return expand_id;
}

static int agiep_virtio_queue_vector_poller_init(struct agiep_poller *pollers,
	void *addr, void *select_addr, int num, uint16_t init)
{
	int i;
	int expand_id;
	struct agiep_poller *poller;
	struct agiep_reg_expand expand;

	expand.addr = addr;
	expand.init = init;
	expand.max_num = 0;
	expand.select16 = select_addr;

	expand_id = agiep_reg_expand_register(&expand, 16);
	if (expand_id == -1) {
		return -1;
	}

	for (i = 0; i < num; i++) {
		poller = &pollers[i];
		poller->expand_id = expand_id;
		poller->select_id = i;
		poller->select_num = num;
		poller->bits = 16;
		poller->intr = legacy_handle_queue_vector;
		poller->act = ACT_INIT;
		poller->init = init;
	}
	return expand_id;
}

void agiep_virtio_legacy_remove(struct agiep_virtio_device *dev)
{
	int i;
	int ret;
	struct agiep_poller *pollers = dev->poller;
	for (i = 0; i < dev->poller_num; i++) {
		ret = agiep_reg_poller_send_unreg(&pollers[i]);
		if (ret) {
			RTE_LOG(ERR, PMD, "unexpect unreg poller error\n");
			goto error;
		}
	}
error:
	rte_free(pollers);
}

static void legacy_handle_feature(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	dev->dev_feature = *poller->data32;

	/* All operations that depend on dev_feature need to be done in feature Settings */
	if (dev->do_config_after_set_feature != NULL) {
		dev->do_config_after_set_feature(dev);
	}

	/*If reseted not cleared, the configuration execution order may be out of order, and need to try to start the device here*/
	if (dev->reseted) {
		if (dev->check_pfn_set_complete == NULL) {
			return;
		}

		if (!dev->check_pfn_set_complete(dev)) {
			return;
		}

		dev->started = 1;
		dev->reseted = 0;
		legacy_bit_device_status_clear(dev, VIRTIO_PCI_DEVICE_S_RESETED);
	}
}

static void legacy_handle_pfn(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	uint16_t queue_select;
	uint64_t pfn;

	queue_select = poller->select_id;
	pfn = poller->prev;

	if (!dev->reseted){
		if (dev->handle_pci_status != NULL)
			dev->handle_pci_status(dev, VIRTIO_CONFIG_S_RESET);
	}

	legacy_queue_set_pfn(dev, queue_select, pfn);
	if (dev->reseted) {
		dev->set_num++;
		if (dev->check_pfn_set_complete == NULL) {
			return;
		}

		if (!dev->check_pfn_set_complete(dev)) {
			return;
		}

		dev->started = 1;
		dev->reseted = 0;
		legacy_bit_device_status_clear(dev, VIRTIO_PCI_DEVICE_S_RESETED);
	}
}

static void legacy_handle_notify(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	uint16_t notify;

	notify = poller->prev;
	if (notify != VIRTIO_PCI_S_QUEUE_NOTIFY_INIT)
		legacy_queue_set_notify(dev, poller->select_id);
}
static void legacy_handle_config_vector(struct agiep_poller *poller __rte_unused)
{
}
static void legacy_handle_queue_vector(struct agiep_poller *poller __rte_unused)
{
}
static void legacy_handle_driver_status(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	if (poller->prev == VIRTIO_PCI_HOST_S_INIT)
		return;
	if (poller->prev == VIRTIO_PCI_HOST_S_RESET)
		if (dev->handle_pci_status != NULL)
			dev->handle_pci_status(dev, VIRTIO_CONFIG_S_RESET);
	AGIEP_LOG_WARN("get host pci set status vf %d %lx", dev->vf, poller->prev);
}
static void legacy_handle_device_status(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;

	dev->device_status = poller->prev;
	if (dev->handle_pci_status != NULL)
		dev->handle_pci_status(dev, dev->device_status);
}

static void legacy_handle_mng_ip(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	uint32_t mng_ip;

	if (dev->pf == 0 && dev->vf == 0) {
		mng_ip = poller->prev;
		dev->mng_ip = mng_ip;
		agiep_mng_set_mng_addr(mng_ip, dev->netmask);
	}
}

static void legacy_handle_mng_mask(struct agiep_poller *poller)
{
	struct agiep_virtio_device *dev = poller->priv;
	uint32_t netmask;

	if (dev->pf == 0 && dev->vf == 0) {
		netmask = poller->prev;
		dev->netmask = netmask;
		agiep_mng_set_mng_addr(dev->mng_ip, netmask);
	}
}

void legacy_queue_set_notify(struct agiep_virtio_device *dev, uint16_t queue_select)
{
	if (dev->vq[queue_select])
		dev->vq[queue_select]->notify = 1;
}
__rte_always_inline void
legacy_queue_set_pfn(struct agiep_virtio_device *dev, uint16_t queue_select, uint64_t pfn)
{
	uint64_t desc;
	struct virtqueue *vq;

	dev->msix_enabled = 1;
	vq = dev->vq[queue_select];

	desc = (pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT);
	if (!vq){
		dev->desc_addr[queue_select] = desc;
		return;
	}
	virtqueue_set_pci_addr(dev->vq[queue_select], desc);

	dev->desc_addr[queue_select] = desc;
}
__rte_always_inline void
legacy_set_device_status(struct agiep_virtio_device *dev, uint16_t status)
{
	rte_write16(status,
		    RTE_PTR_ADD(dev->comm_cfg, VIRTIO_PCI_DEVICE_STATUS));
}
__rte_always_inline void
legacy_bit_device_status_set(struct agiep_virtio_device *dev, uint8_t bit)
{
	void *addr = RTE_PTR_ADD(dev->comm_cfg, VIRTIO_PCI_DEVICE_STATUS);
	rte_write16(rte_read16(addr) | (1U << bit), addr);
}
__rte_always_inline void
legacy_bit_device_status_clear(struct agiep_virtio_device *dev, uint8_t bit)
{
	void *addr = RTE_PTR_ADD(dev->comm_cfg, VIRTIO_PCI_DEVICE_STATUS);
	rte_write16(rte_read16(addr) & ~(1U << bit), addr);
}

inline void legacy_reset_device_reg(struct agiep_virtio_device *dev)
{
	legacy_bit_device_status_set(dev, VIRTIO_PCI_DEVICE_S_RESETED);
	dev->reset_num = 0;
}
