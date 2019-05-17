/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MULTIAP_CONTROLLER_UTILS_H
#define MULTIAP_CONTROLLER_UTILS_H
#include "multiap_controller.h"
#include "map_data_model.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include <syslog.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/stat.h>

//###############################################################
//Timer deadline defines for the event loops in the multiap Agent
//###############################################################
//1905 message reading interval 
#define TIMER_1905_READ     500
//Timer interval used for monitoring the 802.11 event changes
#define TIMER_80211_EVENTS  2000
//Timer interval for gathering the data periodically to be buffered
#define TIMER_DATA_GATHER   3000

#define SOCK_NAME_LEN_MAX   20

#define MAX_BSS 12

/* Flags for MultiAp extension subelement  */
#define MAP_TEAR_DOWN	0x10	/* Bit 4 */
#define MAP_FRONTHAUL_BSS	0x20	/* Bit 5 */
#define MAP_BACKHAUL_BSS	0x40	/* Bit 6 */
#define MAP_BACKHAUL_STA	0x80	/* Bit 7 */


#define ARRAY_LEN(data_struct, struct_definition) (sizeof(data_struct)/sizeof(struct_definition))

// ONLY FOR DEBUGGING
#define CRASH_POINT(num) {platform_log(LOG_ERR, "%s : %d : %d \n", __FUNCTION__, __LINE__, num);}

int platform_init(plfrm_config* config);

// All the contoller config should be read using this API
map_cfg* get_controller_config();

int parse_update_client_capability(map_sta_info_t  *sta, uint16_t assoc_frame_len, uint8_t* assoc_frame);

/** @brief This function will update the receiving interface of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param pointer to a string of interface name
 *  @return None
 */
static inline void map_update_ale_recving_iface (map_ale_info_t *ale, char* iface_name) {
	strncpy(ale->iface_name, iface_name, MAX_IFACE_NAME_LEN);
}

/** @brief This function will update the interface type of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param interface type
 *  @return status
 */
int8_t map_update_ale_upstream_iface_type (map_ale_info_t *ale, uint16_t iface_type);

/** @brief This function will update the upstream remote MAC of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param pointer to a string of interface MAC
 *  @return status
 */
int8_t map_update_ale_upstream_remote_mac (map_ale_info_t *ale, uint8_t* iface_mac);

/** @brief This function will update the upstream local MAC of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param pointer to a string of interface MAC
 *  @return status
 */
int8_t map_update_ale_upstream_local_mac (map_ale_info_t *ale, uint8_t* iface_mac);

#endif

#ifdef __cplusplus
}
#endif
