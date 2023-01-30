#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <assert.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_cfgfile.h>
#include <rte_errno.h>
#include <pci-ep.h>
#include "agiep_pci.h"
#include "agiep_logs.h"

struct agiep_pci_funcfg_group cfg_group;
struct agiep_pci pci;

int agiep_pci_func_configure(struct agiep_pci_funcfg *cfg)
{
	const struct rte_memzone *mz;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct agiep_pci_func *pcif;
	struct pci_ep_bar bar;
	int i;

	pcif = rte_calloc(NULL, 1, sizeof(struct agiep_pci_func), 0);

	if (pcif == NULL)
		return -1;

	pcif->pf = cfg->pf;

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (cfg->bar_size[i] == 0)
			continue;
		bzero(mz_name, sizeof(*mz_name));
		snprintf(mz_name, sizeof(mz_name) - 1, "BAR_%d_%d_%d",
				cfg->pf, 0, i);
		mz = rte_memzone_reserve_aligned(mz_name, cfg->bar_size[i],
				0, RTE_MEMZONE_IOVA_CONTIG, cfg->bar_size[i]);
		if (!mz) {
			AGIEP_LOG_ERR( "Unable to allocate DMA memory "
					"of size %u bytes", cfg->bar_size[i]);
			goto error;
		}

		bar.phy_addr = mz->iova;
		bar.addr = mz->addr;
		bar.barno = i;

		if (pci_ep_set_bar(pci.ep, cfg->pf, 0, &bar)) {
			AGIEP_LOG_ERR( "set bar error %d %d", cfg->pf, i);
			rte_memzone_free(mz);
			goto error;
		}

		pcif->mz[i] = mz;
		pcif->bar[i] = mz->addr;
		pcif->bar_size[i] = cfg->bar_size[i];
	}

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (cfg->vbar_size[i] == 0)
			continue;
		bzero(mz_name, sizeof(*mz_name));
		snprintf(mz_name, sizeof(mz_name) - 1, "vBAR_%d_%d_%d",
				cfg->pf, 1, i);
		mz = rte_memzone_reserve_aligned(mz_name, cfg->vbar_size[i] * cfg->vf_num,
				0, RTE_MEMZONE_IOVA_CONTIG,
				cfg->vbar_size[i] *  cfg->vf_num);
		if (!mz) {
			AGIEP_LOG_ERR( "Unable to allocate DMA memory "
					"of size %u bytes, errno: %d", cfg->bar_size[i], rte_errno);
			goto error;
		}

		bar.phy_addr = mz->iova;
		bar.addr = mz->addr;
		bar.barno = i;

		if (pci_ep_set_bar(pci.ep, cfg->pf, 1, &bar)) {
			AGIEP_LOG_ERR( "set vf bar error %d %d", cfg->pf, i);
			rte_memzone_free(mz);
			goto error;
		}

		pcif->vmz[i] = mz;
		pcif->vbar[i] = mz->addr;
		pcif->vbar_size[i] = cfg->vbar_size[i];
	}

	pci.funcs[cfg->pf] = pcif;
	return 0;
error:
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (pcif->bar[i]) {
			bar.barno = i;
			pci_ep_unmap_addr(pci.ep, cfg->pf, 0, bar.phy_addr);
		}

		if (pcif->vbar[i]) {
			bar.barno = i;
			pci_ep_unmap_addr(pci.ep, cfg->pf, 1, bar.phy_addr);
		}

		if (pcif->mz[i])
			rte_memzone_free(pcif->mz[i]);
		if (pcif->vmz[i])
			rte_memzone_free(pcif->vmz[i]);
	}
	rte_free(pcif);
	return -1;
}

void *agiep_pci_bar(int pf, int vf, int barno)
{
	struct agiep_pci_func *pcif;

	pcif = pci.funcs[pf];

	if (pcif == NULL)
		return NULL;

	if (vf == 0) {
		return pcif->bar[barno];
	}

	return (void *)((uint8_t *)pcif->vbar[barno] + pcif->vbar_size[barno] * (vf - 1)) ;
}

uint32_t agiep_pci_bar_size(int pf, int vf, int barno)
{
	struct agiep_pci_func *pcif;

	pcif = pci.funcs[pf];

	if (pcif == NULL)
		return 0;

	if (vf == 0) {
		return pcif->bar_size[barno];
	}

	return pcif->vbar_size[barno];
}

int agiep_get_portid(void)
{
	return ((uint64_t)(pci.ep->ctr->ctr_cfg->reg) - 0x3400000) / 0x100000;
}

inline struct pci_ep *agiep_get_ep(void)
{
	return pci.ep;
}

int agiep_pci_get_pf(int *pf, int *vf_num)
{
	int i, pf_num = 0;
	for (i = 0; i < cfg_group.num; i++) {
		pf[i]     = cfg_group.items[i].pf;
		vf_num[i] = cfg_group.items[i].vf_num;
		pf_num++;
	}
	
	return pf_num;
}


int agiep_parse_enum(struct param_map *map, int len, char *str)
{
    int i; 
    for(i = 0; i < len; i++) { 
        if(!strcmp(map[i].str, str)) {
            return map[i].param;
        }
    }
    
    return -1;
}

int cfg_size_parse(enum bar_param param, struct agiep_pci_funcfg *cfg, char *value)
{   
    switch(param)
    {   
        case BAR0:
        case BAR1:
        case BAR2:
        case BAR3:
        case BAR4:
        case BAR5:
            cfg->bar_size[param - BAR_BASE] = strtoul(value, NULL, 10);
        break;
        
        case VBAR0:
        case VBAR1:
        case VBAR2:
        case VBAR3:
        case VBAR4:
        case VBAR5:
            cfg->vbar_size[param - VBAR_BASE] = strtoul(value, NULL, 10);
        break;

        case VF_NUM:
            cfg->vf_num = strtol(value, NULL, 10);
        break;

        case PF:
            cfg->pf = strtol(value, NULL, 10);
        break;

        default:
            assert(0);
            return -1;
        break;
    }

    return 0;
}

int agiep_cfg_set(struct rte_cfgfile_entry *entries, int entries_num, struct agiep_pci_funcfg* cfg)
{
	int param;
	int i;
	int ret;

	struct param_map cfg_map[] = {
		{"pf", PF},
		{"vf_num", VF_NUM},
		{"bar0_size", BAR0},
		{"bar1_size", BAR1},
		{"bar2_size", BAR2},
		{"bar3_size", BAR3},
		{"bar4_size", BAR4},
		{"bar5_size", BAR5},
		{"vbar0_size", VBAR0},
		{"vbar1_size", VBAR1},
		{"vbar2_size", VBAR2},
		{"vbar3_size", VBAR3},
		{"vbar4_size", VBAR4},
		{"vbar5_size", VBAR5}
	};  

	for (i = 0; i < entries_num; i++) {
		param = agiep_parse_enum(cfg_map, sizeof(cfg_map)/sizeof(cfg_map[0]), entries[i].name);
		if (param == -1) {
			RTE_LOG(ERR, PMD, "not find entries:%s fail int cfg file.\n", entries[i].name);
			return -1;
		}
		
		ret = cfg_size_parse(param, cfg, entries[i].value);
		if (ret == -1) {
			RTE_LOG(ERR, PMD, "parse entries error.\n");
			return -1;
		}
	}
	return 0;
}

#define MAX_ENTRIES_NUM 20
int  agiep_load_cfg(const char *path, struct agiep_pci_funcfg_group* cfg_group, const char *mode)
{
	int ret;
	int index;
	int entry_num;
	char sectionname[CFG_NAME_LEN];
	struct rte_cfgfile_entry entries[MAX_ENTRIES_NUM];
	struct rte_cfgfile_parameters cfg_param;
	struct rte_cfgfile* cfgfile;

	cfg_param.comment_character = '#';

	cfgfile = rte_cfgfile_load_with_params(path, 0, &cfg_param);
	if (cfgfile == NULL) {
		AGIEP_LOG_ERR( "load cfg file:%s fail.", path);
		return -1;
	}

	index = 0;
	ret = -1;
	while(1) {
		entry_num = rte_cfgfile_section_entries_by_index(cfgfile, index++, sectionname, entries, MAX_ENTRIES_NUM);
		if (entry_num == -1) {
			//section is NULL
			break;
		}
		
		if (strcmp(sectionname, mode)) 
			continue;

		ret = agiep_cfg_set(entries, entry_num, &cfg_group->items[cfg_group->num++]);
		if (ret == -1)
			return -1;
	}
		
	return ret;
}

#define PCI_BAR_CONFIG_FILENAME "/etc/pcie-func.conf"
int  agiep_pci_init(void)
{
	char *mode;
	char *endpoint;
	struct pci_ep *ep;
	int ret;
	int i;	
	struct agiep_pci_funcfg *item;
	char *ep_mode_list[MAX_EP_MODE_NUM];

	if (!getenv("AGIEP_PCI_INIT"))
		return 0;

	memset(ep_mode_list, 0, sizeof(ep_mode_list));

	endpoint = getenv("AGIEP_NIC_EPF_ENDPOINT");
	assert(endpoint != NULL);
	ep_mode_list[0] = endpoint; //now app only support one ep_mode
	assert(pci_ep_init(NULL, ep_mode_list) == 0);
	ep = pci_ep_get(endpoint);

	assert(ep != NULL);

	pci.ep = ep;

	mode = getenv("AGIEP_MODE");

	memset(&cfg_group, 0, sizeof(struct agiep_pci_funcfg_group));

	memcpy(cfg_group.name, mode, strlen(mode));
	if (agiep_load_cfg(PCI_BAR_CONFIG_FILENAME, &cfg_group, mode) != 0) {
		//load cfg file fail. 
		RTE_LOG(ERR, PMD, "Parse cfg file fail, plese check cfg file.\n");
		return -1;
	}

	for (i = 0; i < cfg_group.num; i++) {
		item = &cfg_group.items[i];
		ret = agiep_pci_func_configure(item);
		if (ret) {
			RTE_LOG(ERR, PMD, "agiep pcie func configure error\n");
			return -1;
		}
	}

	return 0;
}
