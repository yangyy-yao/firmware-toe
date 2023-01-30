#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include "agiep_accel_engine.h"
#include <agiep_pci.h>
#include <agiep_reg_poller.h>
#include <agiep_reg_expand.h>
#include "agiep_task.h"
#include "agiep_frep.h"
#include "agiep_ctrl.h"
#include "agiep_dirty_log.h"
#include "agiep_mng.h"

static const char *valid_arguments[] = {
	ETH_AGIEP_FREP,
	ETH_AGIEP_PF,
	ETH_AGIEP_VF,
	ETH_AGIEP_QUEUES,
	ETH_AGIEP_MAC,
	ETH_AGIEP_ACCEL,
	ETH_AGIEP_PCIEP,
	ETH_AGIEP_VPORT,
	ETH_AGIEP_PORTNUM,
	ETH_AGIEP_PACKED,
	ETH_AGIEP_MTU,
	ETH_AGIEP_HW_CHECKSUM,
	NULL
};

struct agiep_frep *freps[AGIEP_FREP_NUM];

static bool agiep_pci_ep_inited = false;
int parse_mac_addr_kvarg(const char *key __rte_unused,
	const char *value, void *extra_args);

int agiep_frep_register(struct agiep_frep *frep)
{
	if (freps[frep->type] != NULL)
		return -1;
	freps[frep->type] = frep;
	return 0;
}

struct agiep_frep *agiep_frep_get(enum agiep_frep_t type)
{
	return freps[type];
}

_Noreturn static void * agiep_reg_expand_loop(void * reg __rte_unused)
{
	while (true)
		agiep_reg_expand_run();
}

static int agiep_frep_regexpand_configure(void)
{
	int ret;
	pthread_t regexpand_thread;
	cpu_set_t mask;
	uint16_t lcoreid = 0;
	int cpu_cores ;
	char *core_id = NULL;
	char thread_name[16];
	cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
	core_id = getenv(AGIEP_E_REG_EXPAND);
	if (core_id == NULL){
		AGIEP_LOG_WARN(AGIEP_E_REG_EXPAND " not set");
		lcoreid = 0;
	} else{
		lcoreid = strtol(core_id, NULL, 10);
		if (lcoreid > cpu_cores){
			RTE_LOG(ERR, PMD, AGIEP_E_REG_EXPAND " %d is vaild\n", lcoreid);
			return -1;
		}
	}

	ret = pthread_create(&regexpand_thread, NULL, agiep_reg_expand_loop, NULL);
	if (ret){
		RTE_LOG(ERR, PMD, "agiep: reg expand thread create error\n");
		return -1;
	}
	snprintf(thread_name, sizeof(thread_name), "reg_expand-c%02d", lcoreid);
	ret = pthread_setname_np(regexpand_thread, thread_name);
	if (ret)
		return ret;
	CPU_ZERO(&mask);
	CPU_SET(lcoreid, &mask);
	ret = pthread_setaffinity_np(regexpand_thread, sizeof(mask), &mask);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "agiep: set reg expand thread cpu id fail: %d\n", ret);
	return ret;
}
static int
eth_dev_agiep_create(struct rte_vdev_device *dev, enum agiep_frep_t type,
		int pf, int vf, int queues, struct rte_ether_addr *mac,
		char *accel_name, int packed, int hw_checksum, struct rte_kvargs *kvlist )
{
	struct agiep_frep_device *frep_dev = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct rte_ether_addr *eth_addr = NULL;
	struct agiep_frep *frep = NULL;
	struct agiep_accel *accel = NULL;
	struct rte_eth_dev_data *data = NULL;
	struct eth_dev_ops *ops = NULL;
	int ret = 0;

	frep = agiep_frep_get(type);
	if (frep == NULL)
		return -1;
	if (accel_name != NULL) {
		accel = agiep_accel_engine_find(accel_name);
		if (accel == NULL)
			return -1;
	}
	eth_dev = rte_eth_vdev_allocate(dev, sizeof(*frep_dev));
	if (eth_dev == NULL)
		goto error;

	eth_addr = rte_zmalloc_socket(rte_vdev_device_name(dev), sizeof(*eth_addr),
							   0, rte_socket_id());
	if (eth_addr == NULL)
		goto error;
	*eth_addr = *mac;
	data = eth_dev->data;
	data->mac_addrs = eth_addr;

	ops = (struct eth_dev_ops *)rte_zmalloc("FREP_DEV_OPS", sizeof(struct eth_dev_ops), 0);
	if (NULL == ops) {
		RTE_LOG(ERR, PMD, "%s-%d:dev ops malloc failed! \n",__func__, __LINE__);
		goto error;
	}

	rte_memcpy(ops, frep->ops, sizeof(struct eth_dev_ops));
	
	eth_dev->dev_ops = ops;

	eth_dev->rx_pkt_burst = frep->rx_pkt_burst;
	eth_dev->tx_pkt_burst = frep->tx_pkt_burst;

	frep_dev = eth_dev->data->dev_private;
	frep_dev->eth_dev = eth_dev;
	frep_dev->addr = eth_addr;
	frep_dev->pf = pf;
	frep_dev->vf = vf;
	frep_dev->queues = queues;
	frep_dev->kvlist = kvlist;
	frep_dev->frep = frep;
	frep_dev->accel = accel;
	frep_dev->packed = packed;
	frep_dev->hw_checksum = hw_checksum;
	
	if (accel == NULL)
		return eth_dev->data->port_id;
	ret = agiep_accel_device_init(frep_dev, accel, ops);
	if (ret)
		goto error;

	return eth_dev->data->port_id;
error:

	if (ops) {
		eth_dev->dev_ops = NULL;
		rte_free(ops);
	}
	
	if (eth_addr)
		rte_free(eth_addr);
	rte_eth_dev_release_port(eth_dev);
	return -1;
}

static inline int
frep_type(const char *key __rte_unused, const char *value, void *extra_args)
{
	enum agiep_frep_t *frep = extra_args;
	if (value == NULL || extra_args == NULL)
		return -1;
	if (!strcmp(value, "virtio"))
		*frep = AGIEP_FREP_VIRTIO;
	else if (!strcmp(value, "vendor"))
		*frep = AGIEP_FREP_VENDOR;
	else if (!strcmp(value, "loopback"))
		*frep = AGIEP_FREP_LOOPBACK;
	else if (!strcmp(value, "task"))
		*frep = AGIEP_FREP_TASK;
	else
		return -1;
	return 0;
}

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	int *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (int)strtol(value, NULL, 10);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static inline int
open_string(const char *key __rte_unused, const char *value, void *extra_args)
{
	const char **name = extra_args;

	if (value == NULL)
		return -1;

	*name = value;
	return 0;
}

int parse_mac_addr_kvarg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	if (value == NULL || extra_args == NULL)
		return -1;

	/* Parse MAC */
	return rte_ether_unformat_addr(value, extra_args);
}

static int agiep_single_init(void)
{
	int ret = 0;
	char task_name[32] = "agiep_dma";

	ret = agiep_task_init();
	if (ret) {
		RTE_LOG(ERR, PMD, "agiep: common task init failed: %d\n",ret);
		return ret;
	}
	ret = agiep_reg_poller_init();
	if (ret){
		RTE_LOG(ERR, PMD, "agiep: reg poller init failed: %d\n",ret);
	}
	ret = agiep_pci_init();
	if (ret) {
		RTE_LOG(ERR, PMD, "agiep: ep init failed: %d\n",ret);
		return ret;
	}

	assert(agiep_get_portid() != -1);
	ret = agiep_dma_init();
	if (ret){
		RTE_LOG(ERR, PMD, "agiep: dma init failed: %d\n",ret);
		agiep_pci_ep_inited = true;
		return ret;
	}

	agiep_task_register(agiep_dma_dequeue_process, NULL, task_name);

	ret = agiep_frep_regexpand_configure();
	if (ret < 0 ){
		RTE_LOG(ERR, PMD, "regexpand configure failed: %d \n", ret);

		return ret;
	}
	agiep_ctrl_init();
	agiep_mng_init();
	return 0;
}
static __rte_always_inline void agiep_single_fini(void)
{
	agiep_dma_fini();
}
static int rte_pmd_agiep_probe(struct rte_vdev_device *vdev)
{
	struct rte_kvargs *kvlist = NULL;
	enum agiep_frep_t frep;
	int ret;
	int pf = -1;
	int vf = -1;
	int i, j;
	int queues;
	int packed = 0;
	int hw_checksum = 0;
	char *packed_input = NULL;
	char *accel_name = NULL;
	char *hw_checksum_input = NULL;
	struct rte_ether_addr mac;

	if (!agiep_pci_ep_inited){
		ret = agiep_single_init();
		if (ret)
			return ret;
		for (i = 0; i < MAX_PF; ++i) {
			for (j = 0; j < MAX_VF; ++j)
				agile_netdev_tab[i][j] = AGIEP_FREP_NUM;
		}
	}
	agiep_pci_ep_inited = true;

	kvlist = rte_kvargs_parse(rte_vdev_device_args(vdev), valid_arguments);
	if (kvlist == NULL)
		return -1;

	if (rte_kvargs_count(kvlist, ETH_AGIEP_FREP) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_FREP,
				&frep_type, &frep);
		if (ret < 0)
			goto out_free;
	} else {
		ret = -2;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_PF) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_PF,
				&open_int, &pf);
		if (ret < 0)
			goto out_free;
		if (pf >= MAX_PF || pf < 0){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -3;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_VF) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_VF,
				&open_int, &vf);
		if (ret < 0)
			goto out_free;
		if (vf >= MAX_VF || vf < 0){
			ret = -EINVAL;
			goto out_free;
		}
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_QUEUES) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_QUEUES,
				&open_int, &queues);
		if (ret < 0)
			goto out_free;
		if (queues <= 0 || queues > RTE_PMD_AGIEP_MAX_QUEUES){
			ret = -EINVAL;
			goto out_free;
		}
	} else {
		ret = -4;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_MAC) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_MAC,
				&parse_mac_addr_kvarg, &mac);
		if (ret < 0)
			goto out_free;
	} else {
		ret = -5;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_PACKED) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_PACKED,
				&open_string, &packed_input);
		if (ret < 0)
			goto out_free;
	} 

	if (rte_kvargs_count(kvlist, ETH_AGIEP_ACCEL) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_ACCEL,
				&open_string, &accel_name);
		if (ret < 0)
			goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_AGIEP_HW_CHECKSUM) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_AGIEP_HW_CHECKSUM,
				&open_string, &hw_checksum_input);
		if (ret < 0)
			goto out_free;
	} 

	if (packed_input && !strcmp(packed_input,"on"))
		packed = 1;

	if (hw_checksum_input && !strcmp(hw_checksum_input, "on"))
		hw_checksum = 1;
		
	ret = eth_dev_agiep_create(vdev, frep, pf, vf, queues, &mac, accel_name, packed, hw_checksum, kvlist);
	if (ret < 0)
		goto out_free;
	rte_eth_dev_probing_finish(&rte_eth_devices[ret]);
	return 0;
out_free:
	if (ret < 1)
		AGIEP_LOG_ERR("probe agiep failed: %u pf=%d vf=%d queues=%d ret=%d",frep, pf, vf, queues, ret);
	rte_kvargs_free(kvlist);
	return ret;
}

static int rte_pmd_agiep_remove(struct rte_vdev_device *dev)
{
	const char *name;
	struct rte_eth_dev *eth_dev = NULL;
	struct agiep_frep_device *frep_dev = NULL;
	struct eth_dev_ops *ops = NULL;

	name = rte_vdev_device_name(dev);

	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return 0;
	frep_dev = eth_dev->data->dev_private;
	rte_kvargs_free(frep_dev->kvlist);
	rte_eth_dev_close(eth_dev->data->port_id);

	memcpy(&ops, &eth_dev->dev_ops, sizeof(struct eth_dev_ops *));
	rte_free(ops);

	eth_dev->dev_ops = NULL;

	rte_eth_dev_release_port(eth_dev);
	return 0;
}

static struct rte_vdev_driver pmd_agiep_drv = {
	.probe = rte_pmd_agiep_probe,
	.remove = rte_pmd_agiep_remove,
};

RTE_PMD_REGISTER_VDEV(net_agiep, pmd_agiep_drv);
RTE_PMD_REGISTER_ALIAS(net_agiep, eth_agiep);
RTE_PMD_REGISTER_PARAM_STRING(net_agiep,
		"frep=<string> "
		"pf=<int> "
		"vf=<int> "
		"queues=<int> "
		"vmac=<mac addr> "
		"accel=<string> "
		"packed=<string> "
  		"vport=<int> "
		"portnum=<int> "
		"mtu=<int>");

