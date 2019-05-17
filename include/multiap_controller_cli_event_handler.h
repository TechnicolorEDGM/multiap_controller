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

#ifndef MULTIAP_CONTROLLER_CLI_EVENT_HANDLER_H
#define MULTIAP_CONTROLLER_CLI_EVENT_HANDLER_H

#include "map_common_defines.h"
#include "map_events.h"

typedef struct map_clicap_args_s map_clicap_args_t;

/** @brief This api will initialize uv callback events
 * 
 *  This function will be called from controller thread on uv call back fire from monitor thread
 *
 *  @param uv loop
 *  @param returns init status
 */
int init_cli_event_handler(uv_loop_t *loop);

/** @brief This api will be invoked on recieving event from monitor thread 
 * 
 *  This function will be called from controller thread on uv call back fire from monitor thread
 *
 *  @param handle callback handle associated
 *  @param data pointer to dynamic memory passed by uv_callback_fire to pass on events
 */
uint8_t periodic_timer_cb (char* timer_id, void* args);

/** @brief This api will be get the Mulitcast MAC address
 * 
 *  This function will be used to get the multicast MAC address
 *
 *  @param pointer to the destination MAC storage
 *  
 */
void get_mcast_macaddr(uint8_t * dest_mac);

/** @brief Callback on receiving event from montor thread.
 *
 *  This will be assigned as event callback for event type
 *  MAP_MONITOR_WIRED_LINK_EVENT in map agent event diapatcher.
 *
 *  @param : Pointer to received event data (map_monitor_evt_t)
 *  @return: None
 */
int8_t map_handle_netlink_event(map_monitor_evt_t *event);

#endif //MULTIAP_CONTROLLER_CLI_EVENT_HANDLER_H

struct map_clicap_args_s {
    uint8_t sta_mac[ETHER_ADDR_LEN];
    uint8_t bssid[ETHER_ADDR_LEN];
};

#ifdef __cplusplus
}
#endif

