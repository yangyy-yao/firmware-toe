#include <rte_common.h>
#include <string.h>
#include <stdlib.h>

#include "agiep_mng.h"
#include "agiep_logs.h"
#include "agiep_lib.h"

struct rte_cfgfile* mng_cfg_file;

void agiep_mng_init(void)
{
	struct rte_cfgfile_parameters cfg_param;
	cfg_param.comment_character = '#';
	mng_cfg_file = rte_cfgfile_load_with_params(AGIEP_MNG_CONFIG_FILENAME, 0, &cfg_param);
	if (mng_cfg_file == NULL) {
		mng_cfg_file = rte_cfgfile_create(0);
		if (mng_cfg_file == NULL) {
			AGIEP_LOG_ERR("mng_cfg_file create failed");
		} else {
			rte_cfgfile_save(mng_cfg_file, AGIEP_MNG_CONFIG_FILENAME);
		}
	}
}

void agiep_mng_set_mng_addr(uint32_t ip, uint32_t netmask)
{
	char address_str[20];
	char *ip_str;
	ip_str = inet_ntoa(*(struct in_addr*)&ip);
	sprintf(address_str, "%s/%d", ip_str, netmask);
	if (!rte_cfgfile_has_section(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION)) {
		rte_cfgfile_add_section(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION);
	}
	if (rte_cfgfile_has_entry(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION, AGIEP_MNG_CONFIG_ADDRESS)) {
		rte_cfgfile_set_entry(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION, AGIEP_MNG_CONFIG_ADDRESS, address_str);
	} else {
		rte_cfgfile_add_entry(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION, AGIEP_MNG_CONFIG_ADDRESS, address_str);
	}
	rte_cfgfile_save(mng_cfg_file, AGIEP_MNG_CONFIG_FILENAME);
}

uint32_t agiep_mng_get_mngip(void)
{
	const char *config_address_str;
	char address_str[20];
	const char *mng_ip_str;
	struct sockaddr_in mng_ip;
	*(uint32_t*)&mng_ip.sin_addr = 0;
	config_address_str = rte_cfgfile_get_entry(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION, AGIEP_MNG_CONFIG_ADDRESS);
	if (config_address_str) {
		memcpy(address_str, config_address_str, 20);
		mng_ip_str = strtok(address_str, "/");
		inet_aton(mng_ip_str, &mng_ip.sin_addr);
	}
	return *(uint32_t*)&mng_ip.sin_addr;
}

uint32_t agiep_mng_get_netmask(void)
{
	const char *config_address_str;
	char address_str[20];
	char *netmask_str;
	uint32_t netmask = 0;
	config_address_str = rte_cfgfile_get_entry(mng_cfg_file, AGIEP_MNG_CONFIG_SECTION, AGIEP_MNG_CONFIG_ADDRESS);
	if (config_address_str) {
		memcpy(address_str, config_address_str, 20);
		strtok(address_str, "/");
		netmask_str = strtok(NULL, "/");
		netmask = atoi(netmask_str);
	}
	return netmask;
}