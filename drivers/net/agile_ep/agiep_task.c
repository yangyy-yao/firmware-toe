#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev_driver.h>
#include "agiep_task.h"
#include "agiep_frep.h"

static int eth_dev_cb_registered = 0;
static pthread_t eth_dev_cb_register_id;
static pthread_t task_thread;

struct agiep_task_group agiep_task_group;

void *agiep_task_dev_callback_setup(void *arg __rte_unused);
void *agiep_task_dev_callback_remove(void *arg __rte_unused);

static uint16_t agiep_task_dev_rx_callback_process(uint16_t port_id __rte_unused,
		uint16_t queue __rte_unused, struct rte_mbuf *pkts[] __rte_unused,
		uint16_t nb_pkts, uint16_t max_pkts __rte_unused,
		void *user_param __rte_unused)
{
	struct agiep_task *item;
	agiep_task_func func;
	void *param;
	int i;
	for (i = 0; i < agiep_task_group.cnt; i++) {
		item = &agiep_task_group.items[i];
		func = item->func;
		param = item->param;
		if (func)
			func(param);
	}
	
	return nb_pkts;
}

int agiep_task_register(agiep_task_func func, void *param, char *task_name)
{
	struct agiep_task *item;

	if (agiep_task_group.cnt >= MAX_FUNC_NUM) {
		RTE_LOG(ERR, PMD, "agiep task is over max number");
		return -1;
	}

	item = &agiep_task_group.items[agiep_task_group.cnt];

	memcpy(item->task_name, task_name, strlen(task_name));
	item->func  = func;
	item->param = param;

	rte_wmb();
	agiep_task_group.cnt++;

	return 0;
}

int agiep_task_unregister(char *task_name)
{
	struct agiep_task *item;
	int i;
	for (i = 0; i < agiep_task_group.cnt; i++) {
		item = &agiep_task_group.items[i];
		if (!strcmp(item->task_name, task_name)) {
			item->func  = NULL;
			item->param = NULL;

			item->task_name[0] = '\0';
			return 0;
		}
	}

	return -1;

}

void *agiep_task_dev_callback_setup(void *arg __rte_unused)
{   
	int i; 
	struct rte_eth_dev *bind_dev = NULL;
	char *rx_core_count_env;
	uint16_t rx_core_count;
	uint16_t portid = 0;
	const char *name_mask = "net_agiep";
	char dev_name[RTE_DEV_NAME_MAX_LEN];
	struct agiep_frep_device *frep_dev = NULL;
	
	while (!eth_dev_cb_registered) {
		AGIEP_ETH_FOREACH_VALID_DEV(portid) {
			rte_eth_dev_get_name_by_port(portid, dev_name);
			if (!strncmp(name_mask, dev_name, strlen(name_mask))) {
				frep_dev = rte_eth_devices[portid].data->dev_private;
				if (!frep_dev)
					continue;
				
				if (frep_dev->frep->type == AGIEP_FREP_TASK) {
					bind_dev = frep_dev->eth_dev;
					break;
				}
			}
		}
		
		if (!bind_dev) {
			RTE_LOG(WARNING, PMD, "frep_task port not find or "
						"agiep task dev callnack setup before frep_task port\n");
			goto next;
		}
		
		rx_core_count_env = getenv("RX_CORE_COUNT");
		if (!rx_core_count_env) {
			RTE_LOG(WARNING, PMD,
					"DO NOT SET RX_CORE_COUNT, Used lcore count %d", rte_lcore_count());
			rx_core_count = rte_lcore_count(); 
		} else {
			rx_core_count = strtol(rx_core_count_env, NULL, 10);
		}	   

		if (bind_dev->data->nb_rx_queues < rx_core_count) {
			if (bind_dev->data->nb_rx_queues != 0){
				RTE_LOG(ERR, PMD, "eth dev %s need at lease %d rx queues", bind_dev->data->name, rx_core_count);
				goto next;
			} else {
				RTE_LOG(WARNING, PMD, "port %s queue num is 0 or "
						"task initialized before frep_task port\n", bind_dev->data->name);
				RTE_LOG(WARNING, PMD, "If some pmd core removed,"
						" there may be problems\n");
				goto next;		  
			}	   
		}	   
		for (i = 0; i < bind_dev->data->nb_rx_queues; i++) {
			if (!rte_eth_add_rx_callback(bind_dev->data->port_id, i, agiep_task_dev_rx_callback_process, NULL)) {
				RTE_LOG(ERR, PMD, "Bind task to %s rx queue[%d] failed\n", bind_dev->data->name, i);
				goto next; 
			}	   
		}	   
		RTE_LOG(INFO, PMD, "agiep eth dev callback registered %d", bind_dev->data->port_id);
		eth_dev_cb_registered = 1;
next:
		portid = 0;
		bind_dev = NULL;
		usleep(100000);
	}
	return (void*)0x01;
}

void *agiep_task_dev_callback_remove(void *arg __rte_unused)
{   
	int i; 
	struct rte_eth_dev *bind_dev = NULL;
	char *rx_core_count_env;
	uint16_t rx_core_count;
	uint16_t portid = 0;
	const char *name_mask = "net_agiep";
	char dev_name[RTE_DEV_NAME_MAX_LEN];
	struct agiep_frep_device *frep_dev = NULL;

	AGIEP_ETH_FOREACH_VALID_DEV(portid) {
		rte_eth_dev_get_name_by_port(portid, dev_name);
		if (!strncmp(name_mask, dev_name, strlen(name_mask))) {
			frep_dev = rte_eth_devices[portid].data->dev_private;
			if (!frep_dev)
				continue;
			
			if (frep_dev->frep->type == AGIEP_FREP_TASK) {
				bind_dev = frep_dev->eth_dev;
				break;
			}
		}
	}
	
	if (!bind_dev) {
		RTE_LOG(WARNING, PMD, "%s-%d:frep_task port not find \n", __func__, __LINE__);
		return NULL;
	}

	rx_core_count_env = getenv("RX_CORE_COUNT");
	if (!rx_core_count_env) {
		RTE_LOG(WARNING, PMD,
				"DO NOT SET RX_CORE_COUNT, Used lcore count %d", rte_lcore_count());
		rx_core_count = rte_lcore_count(); 
	} else {
		rx_core_count = strtol(rx_core_count_env, NULL, 10);
	}	   

	if (bind_dev->data->nb_rx_queues < rx_core_count) {
		if (bind_dev->data->nb_rx_queues != 0){
			RTE_LOG(ERR, PMD, "frep_task need at lease %d rx queues", rx_core_count);
			return NULL;
		} else {
			RTE_LOG(WARNING, PMD, "frep_task port not detected or "
					"net_agiep initialized before frep_task port\n");
			RTE_LOG(WARNING, PMD, "If some pmd core removed,"
					" there may be problems\n");
			return NULL;		  
		}	   
	}
	for (i = 0; i < bind_dev->data->nb_rx_queues; i++) {
		if (!rte_eth_remove_rx_callback(bind_dev->data->port_id, i, bind_dev->post_rx_burst_cbs[i])) {
			RTE_LOG(ERR, PMD, "Remove task to %s rx queue[%d] failed\n", bind_dev->data->name, i);
			return NULL; 
		}	   
	}	   
	RTE_LOG(INFO,PMD, "agiep frep_task callback registered %d", bind_dev->data->port_id);
	return NULL;
}


static void *agiep_task(void *arg __rte_unused)
{
	int ret;
	ret = rte_ctrl_thread_create(&eth_dev_cb_register_id, "register_frep_task_cb",
				NULL, agiep_task_dev_callback_setup, NULL);
	if (ret)
		AGIEP_LOG_ERR("callback thread create fail %d", ret);

	while (!eth_dev_cb_registered){
		sleep(1);
	}

	return NULL;
}

int agiep_task_init(void)
{
	int ret;

	memset(&agiep_task_group, 0, sizeof(struct agiep_task));

	const char *thread_name = "agiep_task";

	assert(task_thread == 0);

	ret = pthread_create(&task_thread, NULL, agiep_task, NULL);

	if (ret) {
		RTE_LOG(ERR, PMD, "AGIEP: task thread create failed\n");
		return -1;
	}
	ret = pthread_setname_np(task_thread, thread_name);
	if (ret)
		return ret;

	return 0;
}

void agiep_task_free(void)
{

	agiep_task_dev_callback_remove(NULL);
}
