#include <rte_ring.h>
#include <stdbool.h>

#include "agiep_ctrl.h"
#include "agiep_virtio_ctrl.h"
#include "agiep_vendor_ctrl.h"
#include "agiep_virtio_rxtx.h"
#include "agiep_reg_poller.h"
#include "agiep_virtio_net.h"
#include "agiep_vendor_port.h"
#include "agiep_dma.h"
#include "agiep_vring.h"

static pthread_t ctrl_thread = 0;

void agiep_rq_process(struct agiep_virtio_port *port)
{
	struct agiep_net_ctrl *ctrl;
	ctrl = port->ctrl;
	if (!ctrl)
		return;
	agiep_virtio_rq_process(port);
}

void agiep_cq_process(struct agiep_virtio_port *port)
{
	struct agiep_net_ctrl *ctrl;
	ctrl = port->ctrl;
	if (!ctrl)
		return;
	agiep_virtio_cq_process(port);
}

__rte_always_inline void
agiep_ctrl_synchronize(struct agiep_net_ctrl *ctrl)
{
	while (ctrl->cmd_seq & 1) {
		cpu_relax();
	}
	while (ctrl->seq & 1) {
		cpu_relax();
	}
}
_Noreturn static void * agiep_ctrl_process(void * reg __rte_unused){
	while (true) {
		agiep_reg_poller_process(NULL);
		virtio_net_ctrl_process(NULL);
		vendor_net_ctrl_process(NULL);
	}
}

static int agiep_ctrl_create_thread(void)
{
	int ret;
	cpu_set_t mask;
	int16_t lcoreid = -1;
	int cpu_cores ;
	char *core_id = NULL;
	char thread_name[16];
	cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
#define AGIEP_E_CTRL_PROCESS "AGIEP_CTRL_COREMASK"
	core_id = getenv(AGIEP_E_CTRL_PROCESS);
	if (core_id != NULL){
		lcoreid = strtol(core_id, NULL, 10);
		if (lcoreid > cpu_cores){
			RTE_LOG(ERR, PMD, AGIEP_E_CTRL_PROCESS " %d is vaild\n",lcoreid);
			return -1;
		}
	}

	ret = pthread_create(&ctrl_thread, NULL, agiep_ctrl_process, NULL);
	if (ret){
		RTE_LOG(ERR, PMD, "agiep: ctrl thread create error\n");
		return -1;
	}
	if (lcoreid < 0)
		return ret;
	snprintf(thread_name, sizeof(thread_name), "agiep_ctrl-c%02d", lcoreid);
	CPU_ZERO(&mask);
	CPU_SET(lcoreid, &mask);
	ret = pthread_setaffinity_np(ctrl_thread, sizeof(mask), &mask);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "agiep: set ctrl thread cpu id fail: %d\n", ret);
	ret = pthread_setname_np(ctrl_thread, thread_name);
	if (ret)
		return ret;
	return 0;
}

int agiep_ctrl_init(void)
{
	return agiep_ctrl_create_thread();
}