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

#ifndef MULTIAP_CONTROLLER_CALLBACKS_H
#define MULTIAP_CONTROLLER_CALLBACKS_H

#include "multiap_controller.h"
#include "multiap_controller_utils.h"
#include "map_data_model.h"

#define MAX_CMDU_PER_SEND 8

#define MCAST_1905_B0     (0x01)
#define MCAST_1905_B1     (0x80)
#define MCAST_1905_B2     (0xC2)
#define MCAST_1905_B3     (0x00)
#define MCAST_1905_B4     (0x00)
#define MCAST_1905_B5     (0x13)
#define ATTR_MAC_ADDR     (0x1020)
#define ATTR_MANUFACTURER (0x1021)

#define MCAST_1905  {MCAST_1905_B0, MCAST_1905_B1, MCAST_1905_B2, MCAST_1905_B3, MCAST_1905_B4, MCAST_1905_B5}


// TODO: Add all the Fixed TLV counts in one place common to Agent and controller.
#define MAP_AP_AUTO_CONFIGURATION_SEARCH_TLV_COUNT 5
#define MAP_WSC_M1_TLV_COUNT  2

/* Controller initiated is used to track those messages that are initiated by 
controller and are not needed to be registered in 1905*/
typedef struct map_cb_config {
        uint16_t recv_msg_type;
        uint16_t send_msg_type;
        uint8_t controller_initiated;
        uint8_t relay_indicator;
        int (*validation_cb) (uint8_t *, struct CMDU * , void *);
        void (*data_gathering) (uv_work_t *);
        int8_t (*action_cb) (struct CMDU *recv_cmdu);
} map_cb_config_t;

// Initialize the agent initiated callbacks 
int init_map_controller_callback();

// Event dispatcher
void uvpoll_1905read_cb (uv_poll_t* handle, int status, int events);

// 1905 connect
int ipc_1905_connect();

// Error callback
int error_callback(char *message, int code);

// Multiap controller initialisation
int multiap_controller_init();

// Uv poll read message callback
void uvpoll_1905read_cb (uv_poll_t* handle, int status, int events);

// Map read mssage callback triggered from uv callback
int map_read_cb (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

// Apply message filter to 1905
int map_apply_msg_filter (handle_1905_t handle);

/***************************************************************************/
//---------------------------- Validation callbacks  -----------------------/
/***************************************************************************/

/** @brief This will be validation callback for AP Capability Report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_DISCOVERY in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_discovery_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for AP Capability Report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_autoconfig_search_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);


/** @brief This will be validation callback for AP Capability Report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_AP_AUTOCONFIGURATION_WSC M1 in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_wsc_m1_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for AP Capability Report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_AP_CAPABILITY_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_ap_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for Client Capability Report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_CLIENT_CAPABILITY_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_client_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology query.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_QUERY in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology response.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int8_t map_action_autoconfig_search (struct CMDU *cmdu);

/** @brief This will be validation callback for topology response.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology notification.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_NOTIFICATION in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_notification_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for channel preference report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */

int map_ap_channel_pref_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);


/** @brief This will be validation callback for associated link metrics reponse
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_associated_sta_link_metrics_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for AP metrics reponse
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_AP_METRICS_RESPONSE in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_ap_metrics_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for operating channel report
 * 
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */   
int map_operating_channel_report_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for client steering btm report
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CLIENT_STEERING_BTM_REPORT in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_client_steering_btm_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for client steering completed msg
 *
 *  This will be assigned as validation cb for msg type
 *  CMDU_TYPE_MAP_STEERING_COMPLETED in global data structure
 *  gMultiap_data_structure.
 *  @param src_mac_adddr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0 -sucess, -ve for failure
 */
int map_client_steering_completd_msg_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for the beacon metrics response
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_callback_beacon_metrics_response(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for 1905 ACK
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_ACK in global data structure
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_ack_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for un associated sta link metrics
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE in global data structure
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_unassoc_sta_link_metrics_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be balidation callback for higher layer data message
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_HIGHER_LAYER_DATA in global data structure
 *
 *  @param src_mac_addr: received payloads source mac address
 *  @param cmdu: received payload structure
 *  @param context: context to be used for lib1905 reference purpose
 *  @return:  The status code 0 - success, -ve - failure
 */
int map_ctrl_higher_layer_data_msg_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for link metrics response
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_LINK_METRIC_RESPONSE in global data structure
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_link_metrics_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for the vendor specific message
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_VENDOR_SPECIFIC in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */

int map_vendor_specific_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for the beacon metrics response
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_callback_channel_pref_report_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for the channel selection response
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_callback_channel_selec_response_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for the Link metrics query
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_LINK_METRIC_QUERY in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_link_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

#endif

#ifdef __cplusplus
}
#endif

