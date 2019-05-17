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

#ifndef MULTIAP_CONTROLLER_ACTION_CALLBACKS_H
#define MULTIAP_CONTROLLER_ACTION_CALLBACKS_H

#include "multiap_controller.h"
#include "multiap_controller_utils.h"
#include "map_data_model.h"

/** @brief This will be handled
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_topology_response(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_DISCOVERY in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_topology_discovery (struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_NOTIFICATION in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_topology_notification(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_AP_CAPABILITY_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_ap_caps_report (struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_AP_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_ap_metrics_response (struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_assoc_sta_link_metrics(struct CMDU *cmdu);


/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_BEACON_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_beacon_metrics_response(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_VENDOR_SPECIFIC in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_vendor_specific(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t  map_send_unassoc_sta_metrics_ack(struct CMDU *recv_cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_HIGHER_LAYER_DATA in global data structure
 *  gmap_cb_config
 *
 *  @param recv_cmdu: Pointer to recieved CMDU
 *  @return The status code 0 - success, -ve - failure
 */
int8_t map_ctrl_higher_layer_data_msg_ack(struct CMDU *recv_cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_channel_pref_report(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_channel_selec_response(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_ACK in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_ack(struct CMDU *cmdu);

/** @brief This will be handled 
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_operating_channel_report(struct CMDU *cmdu);

/** @brief This will be handled
 *
 *  This will be assigned as action_cb for msg type
 *  CMDU_TYPE_LINK_METRIC_QUERY in global data structure
 *  gmap_cb_config.
 *
 *  @param recv_cmdu: Pointer to received CMDU
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_link_metrics_query(struct CMDU *recv_cmdu);

#endif

#ifdef __cplusplus
}
#endif
