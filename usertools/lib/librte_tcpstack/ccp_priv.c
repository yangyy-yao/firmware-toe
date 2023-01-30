#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy,memset
#else
#include <stdlib.h>
#include <string.h>
#endif
#include <rte_malloc.h>

extern struct ccp_datapath *datapath;

int init_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state;
    conn->state = rte_zmalloc(NULL, sizeof(struct ccp_priv_state), RTE_CACHE_LINE_SIZE);
    state = (struct ccp_priv_state*) conn->state;

    state->sent_create = false;
    state->implicit_time_zero = datapath->time_zero;
    state->program_index = 0;
    state->staged_program_index = -1;
    return 0;
}

void free_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    rte_free(state);
}

inline struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*)conn->state;
}
