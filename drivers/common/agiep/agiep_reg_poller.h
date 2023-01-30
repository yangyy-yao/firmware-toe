#ifndef RTE_AGIEP_POLLER_H_
#define RTE_AGIEP_POLLER_H_

#include <sys/queue.h>
#include <stdint.h>
#include <rte_common.h>
enum action_t {
	ACT_NO,
	ACT_INIT,
};
enum poller_status {
	POLLER_REGISTERED,
	POLLER_DELETED,
	POLLER_SENDED,
};
struct agiep_poller;

typedef void (*poller_intr_callback) (struct agiep_poller *poller);

struct agiep_poller {
	int bits;
	int expand_id;
	int select_id;
	int select_num;
	union {
		void *addr;
		uint8_t *data8;
		uint16_t *data16;
		uint32_t *data32;
		uint64_t *data64;
	};
	uint64_t prev;
	uint64_t init;
	uint64_t status;
	void *priv;
	// 这里回调不允许执行耗时的操作
	poller_intr_callback intr;
	enum action_t act;
	LIST_ENTRY(agiep_poller) next;
};

enum poller_op_t {
	OP_REG,
	OP_UNREG,
};

struct agiep_poller_op {
	enum poller_op_t op;	
	struct agiep_poller *poller;
	int count;
};
int agiep_reg_poller_send_reg(struct agiep_poller *poller);
int agiep_reg_poller_send_reg_batch(struct agiep_poller *poller, int count);
int agiep_reg_poller_send_unreg(struct agiep_poller *poller);
int agiep_reg_poller_send_unreg_batch(struct agiep_poller *poller, int count);
struct agiep_poller *
agiep_reg_poller_create(void *data, uint64_t init, enum action_t act, int expand);
void * agiep_reg_poller_process(void * reg __rte_unused);
int agiep_reg_poller_init(void);
#endif
