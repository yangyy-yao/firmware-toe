#ifndef AGIEP_PCI_H_
#define AGIEP_PCI_H_
#include <stdint.h>
#include <rte_cfgfile.h>
#include <pci-ep.h>
#define PAGE_SIZE_ALIGN 4096
#define MAX_PF 2
#define MAX_VF 64
#define PCI_STD_NUM_BARS 6
struct agiep_pci_funcfg {
	int pf;
	int vf_num;
	uint32_t bar_size[PCI_STD_NUM_BARS];
	uint32_t vbar_size[PCI_STD_NUM_BARS];
};

#define MAX_PCI_FUNC 8
#define MAX_FUNC_NAME_LEN 32
struct agiep_pci_funcfg_group {
	int num;
	char name[MAX_FUNC_NAME_LEN];
	struct agiep_pci_funcfg items[MAX_PCI_FUNC];
};

struct agiep_pci_func {
	int pf;
	int vf_num;
	const struct rte_memzone *mz[PCI_STD_NUM_BARS];
	void *bar[PCI_STD_NUM_BARS];
	const struct rte_memzone *vmz[PCI_STD_NUM_BARS];
	void *vbar[PCI_STD_NUM_BARS];
	uint32_t bar_size[PCI_STD_NUM_BARS];
	uint32_t vbar_size[PCI_STD_NUM_BARS];
};

struct agiep_pci {
	struct pci_ep *ep;
	struct agiep_pci_func *funcs[MAX_PF];
};

#define MAX_ENTRIES_LEN 64
struct param_map {
	char str[MAX_ENTRIES_LEN];
	int param;
};

enum bar_param {
	PF = 0,
	VF_NUM,
	BAR0,
	BAR1,
	BAR2,
	BAR3,
	BAR4,
	BAR5,
	VBAR0,
	VBAR1,
	VBAR2,
	VBAR3,
	VBAR4,
	VBAR5
};

#define BAR_BASE BAR0
#define VBAR_BASE VBAR0 

enum mode_type {
	VENDOR = 0,
	VIRTIO
};

int agiep_pci_func_configure(struct agiep_pci_funcfg *cfg);
void *agiep_pci_bar(int pf, int vf, int barno);
uint32_t agiep_pci_bar_size(int pf, int vf, int barno);
int agiep_get_portid(void);
struct pci_ep *agiep_get_ep(void);
int agiep_pci_init(void);
int agiep_pci_get_pf(int *pf, int *vf_num);
int agiep_parse_enum(struct param_map *map, int len, char *str);
int agiep_load_cfg(const char *path, struct agiep_pci_funcfg_group* cfg_group, const char *mode);
int agiep_cfg_set(struct rte_cfgfile_entry *entries, int entries_num, struct agiep_pci_funcfg* cfg);
int cfg_size_parse(enum bar_param param, struct agiep_pci_funcfg *cfg, char *value);
#endif
