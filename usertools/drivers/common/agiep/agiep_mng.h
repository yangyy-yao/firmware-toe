#ifndef RTE_AGIEP_MNG_H_
#define RTE_AGIEP_MNG_H_

#include <rte_cfgfile.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
/*
/etc/management_ip.conf:

[AGIEP_MNG]
address=192.168.2.22/24
*/
#define AGIEP_MNG_CONFIG_FILENAME "/etc/management_ip.conf"
#define AGIEP_MNG_CONFIG_SECTION "AGIEP_MNG"
#define AGIEP_MNG_CONFIG_ADDRESS "address"
#define AGIEP_MNG_CONFIG_NETMASK "netmask"
extern struct rte_cfgfile* mng_cfg_file;

void agiep_mng_init(void);
void agiep_mng_set_mng_addr(uint32_t ip, uint32_t netmask);
uint32_t agiep_mng_get_mngip(void);
uint32_t agiep_mng_get_netmask(void);
#endif
