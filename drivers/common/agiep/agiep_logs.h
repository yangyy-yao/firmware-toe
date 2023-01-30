#ifndef DPDK_COMMON_AGIEP_LOGS_H
#define DPDK_COMMON_AGIEP_LOGS_H

extern int agiep_logtype_common;
#include <rte_log.h>

#define AGIEP_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, agiep_logtype_common,\
			"agiep: " fmt "\n", ## args)

// default disable debug log
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
#define AGIEP_LOG_DEBUG(fmt, ...)  AGIEP_LOG(DEBUG, fmt, ##__VA_ARGS__)
#else
#define AGIEP_LOG_DEBUG(fmt, ...) do {} while(0)
#endif

#define AGIEP_LOG_INFO(fmt, ...) AGIEP_LOG(INFO, fmt, ##__VA_ARGS__)
#define AGIEP_LOG_ERR(fmt, ...)  AGIEP_LOG(ERR, fmt, ##__VA_ARGS__)
#define AGIEP_LOG_WARN(fmt, ...)  AGIEP_LOG(WARNING, fmt, ##__VA_ARGS__)

#endif //DPDK_COMMON_AGIEP_LOGS_H
