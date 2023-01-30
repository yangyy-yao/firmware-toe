#include <agiep_pci.h>

#include "toe_pcie.h"

void *toe_pcie_bar_get(int pf, int vf)
{
	
	return agiep_pci_bar(pf, vf, TOE_BAR_NUM);
}

struct toe_bar_base_cfg *toe_base_bar_get(uint8_t *bar)
{
	return (struct toe_bar_base_cfg *) (bar + TOE_BAR_BASE_OFFSET);
}

struct rq_bar_cfg *toe_rq_bar_get(uint8_t *bar, int offset)
{
	return (struct rq_bar_cfg *) (bar + TOE_RQ_BAR_BASE_OFFSET + offset * TOE_RQ_CQ_BAR_SIZE);
}

struct cq_bar_cfg *toe_cq_bar_get(uint8_t *bar, int offset)
{
	return (struct cq_bar_cfg *) (bar + TOE_CQ_BAR_BASE_OFFSET + offset * TOE_RQ_CQ_BAR_SIZE);
}


