#ifndef RTE_AGIEP_COMMON_TASK_H_
#define RTE_AGIEP_COMMON_TASK_H_
#include <stdint.h>
#include <rte_ethdev.h>

typedef void (*agiep_task_func)(void *param);
#define MAX_FUNC_NUM 32
#define TASK_NAME_LEN 32

#define AGIEP_ETH_FOREACH_VALID_DEV(port_id) \
	for (port_id = rte_eth_find_next(0); \
	     port_id < RTE_MAX_ETHPORTS; \
	     port_id = rte_eth_find_next(port_id + 1))

struct agiep_task {
    char task_name[TASK_NAME_LEN];

    agiep_task_func func;
    void *param;
};

struct agiep_task_group {
    int cnt;
    struct agiep_task items[MAX_FUNC_NUM];
};

int agiep_task_register(agiep_task_func func, void *param, char *task_name);
int agiep_task_unregister(char *task_name);
void *agiep_task_dev_callback_setup(void *arg __rte_unused);
int agiep_task_init(void);
void agiep_task_free(void);

#endif
