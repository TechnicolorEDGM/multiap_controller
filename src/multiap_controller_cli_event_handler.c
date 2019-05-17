/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef MAC_SIMULATOR_ENABLED
#include "multiap_controller.h"
#include "multiap_controller_callbacks.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_tlv_parser.h"
#include "map_events.h"
#include "map_ipc_event_handler.h"
#include "map_data_model.h"
#include "map_data_model_dumper.h"
#include "map_topology_tree.h"
#include "map_timer_handler.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "monitor_task.h"
#include "mon_platform.h"
#include "1905_platform.h"
#include "platform_lib_capi.h"
#include "platform_commands.h"
#include "platform_multiap_get_info.h"

extern plfrm_config pltfrm_config;

static map_monitor_cmd_t g_event_monitor_register[] = {
    {
        .cmd    = MAP_MONITOR_REGISTER_EVENTS_CMD,
        .subcmd = MAP_MONITOR_CREDENTIAL_EVENTS_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_REGISTER_EVENTS_CMD,
        .subcmd = MAP_MONITOR_NETWORK_LINK_EVENTS_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_STATION_STEER_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_SEND_POLICY_CONFIG_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_AP_CAPABILITY_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_CLIENT_CAPABILITY_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_CHANNEL_PREFERENCE_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_CHANNEL_SELECTION_REQUEST_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_DUMP_CONTROLLER_INFO_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_CLIENT_ACL_REQUEST_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_ASSOC_STA_METRIC_QUERY_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_UNASSOC_STA_METRIC_QUERY_SUBCMD,
    },
    {
    	.cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
    	.subcmd = MAP_MONITOR_TOPOLOGY_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_SEND_AUTOCONFIG_RENEW_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_BEACON_METRIC_QUERY_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_LINK_METRIC_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_SEND_HIGHERLAYER_DATA_MSG_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_SEND_STEERING_POLICY_CONFIG_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_AP_METRIC_QUERY_METHOD_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_CHANNEL_SELECTION_REQUEST_DETAIL_SUBCMD,
    },
    {
        .cmd    = MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_COMBINED_INFRA_METRIC_QUERY_METHOD_SUBCMD,        	
    },
    {
        .cmd	= MAP_MONITOR_PUBLISH_SERVICES_CMD,
        .subcmd = MAP_MONITOR_GET_TOPO_TREE_METHOD_SUBCMD,
    },
};

static map_event_dispatcher_t map_controller_ipc_event_dispatcher[] = {
    { MAP_MONITOR_WIRED_LINK_EVENT ,        map_handle_netlink_event },
};


static int register_events_publish_services();
static int map_cli_send_channel_selection_request(map_handle_t *handle, uint8_t *al_mac, uint8_t * radio_id);
static int map_cli_send_policy_config(map_handle_t *handle, map_policy_config_cmd_t *policy_info, uint8_t *dst_mac);
static int map_cli_send_steering_policy_config(map_handle_t *handle, map_steering_policy_config_cmd_t *policy_info, uint8_t *dst_mac);
static int client_capability_query_cb (map_handle_t *handle, client_info_t *client_info);
static void map_send_aysnc_repsonse(map_handle_t *handle, int8_t status, uint16_t msg_type);
static void map_send_async_data(void *data);

int init_cli_event_handler(uv_loop_t *loop) {
    int status = 0;
    do
    {
        // Register the monitor queue check timer
        const char* monitor_evt_timer = "monitor_event_check_timer";
        if( map_timer_register_callback(TIMER_FREQUENCY_ONE_SEC, monitor_evt_timer , NULL , periodic_timer_cb) < 0) {
            ERROR_EXIT(status)
        }

        if(map_monitor_thread_init(&pltfrm_config.map_config.monitor_q_hdle, MAP_MONITOR_CONTROLLER) < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "map_monitor_thread_init failed.\n");
            ERROR_EXIT(status)
        }

        if(register_events_publish_services() < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "register_events_publish_services failed.\n");
            ERROR_EXIT(status)
        }
        uint8_t event_count = ARRAY_LEN(map_controller_ipc_event_dispatcher, map_event_dispatcher_t);
        if(init_map_ipc_handler(loop, map_controller_ipc_event_dispatcher, event_count) < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Failed to initialize map ipc event handler.\n");
            ERROR_EXIT(status)
        }

    } while (0);
    return status;
}

int8_t map_handle_netlink_event(map_monitor_evt_t *event) {
    map_network_link_evt_data *link_event = NULL;
    uint8_t lib1905_if_event = 0x00;

    if(NULL == event) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Received empty event\n", __FUNCTION__);
        return -1;
    }
    platform_log(MAP_CONTROLLER,LOG_INFO, "Received MAP_MONITOR_WIRED_LINK_EVENT");

    link_event = (map_network_link_evt_data *)event->evt_data;
    if (NULL == link_event) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : link_event is empty\n", __FUNCTION__);
        return -1;
    }

    platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s link event, i/f %s, state %s\n", __FUNCTION__, link_event->if_name, \
                 link_event->status);

    if (0 == strcmp(link_event->status, "up")) {
        lib1905_if_event = LIB_1905_IF_UP_EVENT;
    } else if(0 == strcmp(link_event->status, "new")) {
        lib1905_if_event = LIB_1905_NEW_IF_CREATED_EVENT;
    } else if(0 == strcmp(link_event->status, "down")) {
        lib1905_if_event = LIB_1905_IF_DOWN_EVENT;
    } else {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : unknown link_event: %s for interface: %s \n", __FUNCTION__, link_event->if_name, link_event->status);
        return -1;
    }

    if(0 != lib1905_notify_event(handle_1905, link_event->if_name, lib1905_if_event)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s i/f %s event %s , 1905 notification failed\n", __FUNCTION__, link_event->if_name, link_event->status);
        return -1;
    }

    return 0;
}
static int register_events_publish_services()
{
    int status = 0,ret=0;

    uint8_t max_index = ARRAY_LEN(g_event_monitor_register, map_monitor_cmd_t);

    for ( uint8_t index = 0; index < max_index; index++, ret = 0) {
        ret = map_monitor_send_cmd(g_event_monitor_register[index]);
        if(0 != ret) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
        }
        // acumulate the status
        status |= ret;
    }
    return status;
}

uint8_t periodic_timer_cb (char* timer_id, void* args) {

    char  *q_obj         = NULL;
    map_monitor_evt_t *event_info;
    array_list_t *monitor_queue        = NULL;
    monitor_q_handle_t *monitor_q_hdle = NULL;
    map_handle_t map_handle;
    uint16_t msg_type = 0;
    int8_t status = 0;

    monitor_q_hdle = &pltfrm_config.map_config.monitor_q_hdle;
    monitor_queue  = monitor_q_hdle->list_handle;
    if(monitor_queue != NULL) {
        while((q_obj = pop_object(monitor_queue)) != NULL) {

            // Cleanup the handle on every request
            memset(&map_handle , 0 , sizeof(map_handle_t));
            status = 0;

            event_info = (map_monitor_evt_t*)q_obj;
            /* First byte of q_obj represents the type of the object */
            switch((uint8_t)*q_obj) {
                case MAP_MONITOR_CREDENTIAL_EVT:
                {
                    msg_type = CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW;

                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_CREDENTIAL_EVT \n", __FUNCTION__);
                    
                    load_credential_config((void*)&pltfrm_config);
                    // Irrespective of the frequency band, Agent has to send M1 for all the radios
                    // as per section 7.1 in the Multiap specification.

                    uint8_t freq_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;

                    get_mcast_macaddr(map_handle.dest_addr);
                    map_handle.recv_cmdu   = NULL;

                    if(map_send_autoconfig_renew(&map_handle,freq_band)){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_autoconfig_renew failed\n", __FUNCTION__);
                    }

                    break;
                }
                case MAP_MONITOR_STEER_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST;
                    struct sta_steer_params* psteer = NULL;
                    psteer = (struct sta_steer_params*)event_info->evt_data;
                    if(NULL != psteer) {
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------Steering Request info Start--------\n");
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------AL MAC : %x:%x:%x:%x:%x:%x--------\n",psteer->dst_mac[5],
                            psteer->dst_mac[4],psteer->dst_mac[3],psteer->dst_mac[2],psteer->dst_mac[1],psteer->dst_mac[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------STA MAC : %x:%x:%x:%x:%x:%x--------\n",psteer->sta_info[0].sta_mac[5],
                            psteer->sta_info[0].sta_mac[4],psteer->sta_info[0].sta_mac[3],psteer->sta_info[0].sta_mac[2],psteer->sta_info[0].sta_mac[1],
                            psteer->sta_info[0].sta_mac[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------CURRENT BSSID : %x:%x:%x:%x:%x:%x--------\n",psteer->source_bssid[5],
                            psteer->source_bssid[4],psteer->source_bssid[3],psteer->source_bssid[2],psteer->source_bssid[1],psteer->source_bssid[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------TARGET BSSID : %x:%x:%x:%x:%x:%x--------\n",psteer->sta_info[0].bssid[5],
                            psteer->sta_info[0].bssid[4],psteer->sta_info[0].bssid[3],psteer->sta_info[0].bssid[2],
                            psteer->sta_info[0].bssid[1],psteer->sta_info[0].bssid[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------TARGET CHANNEL : %d--------\n",psteer->sta_info[0].channel);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------Steering Request info End--------\n");
                        
                        if(0 != map_send_steering_request(&map_handle, psteer, psteer->dst_mac)) {
                            status = -1;
                            platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_steering_request failed\n", __FUNCTION__);
                        }
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d invalid data pointer recieved\n", __FUNCTION__, __LINE__);
                    }
                    break;
                }
                case MAP_MONITOR_SEND_POLICY_CONFIG_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST;
                    map_policy_config_cmd_t *policy_config = NULL;
                    policy_config = (map_policy_config_cmd_t*)event_info->evt_data;
                    if(NULL != policy_config) {
                        if(0 != map_cli_send_policy_config(&map_handle, policy_config, policy_config->dst_mac)) {
                            status = -1;
                            platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d map_cli_send_policy_config failed\n", __FUNCTION__, __LINE__);
                        }
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d invalid data pointer recieved\n", __FUNCTION__, __LINE__);
                    }
                    break;
                }
                case MAP_MONITOR_SEND_STEER_POLICY_CONFIG_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST;
                    map_steering_policy_config_cmd_t *policy_config = NULL;
                    policy_config = (map_steering_policy_config_cmd_t*)event_info->evt_data;
                    if(NULL != policy_config) {
                        if(0 != map_cli_send_steering_policy_config(&map_handle, policy_config, policy_config->al_mac)) {
                            status = -1;
                            platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d map_cli_send_steering_policy_config failed\n", __FUNCTION__, __LINE__);
                        }
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d invalid data pointer recieved\n", __FUNCTION__, __LINE__);
                    }
                    break;
                }
                case MAP_MONITOR_SEND_AP_CAPABILITY_QUERY:
                {
                    msg_type = CMDU_TYPE_MAP_AP_CAPABILITY_QUERY;
                    uint8_t *mac = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_AP_CAPABILITY_QUERY \n", __FUNCTION__);

                    mac = (uint8_t *)event_info->evt_data;
                    if (NULL == mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s : MAC is empty \n", __FUNCTION__);
                        break;
                    }

                    map_ale_info_t *ale = get_ale(mac);
                    if(ale == NULL) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR,"Unable to find agent node with mac: %s\n",mac);
                    }
                    else if(map_send_ap_capability_query(&map_handle, ale)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_ap_capability_query failed\n", __FUNCTION__);
                    }
                    break;
                }

                case MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY:
                {
                    msg_type = CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY;
                    client_info_t *client_data = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY \n", __FUNCTION__);

                    client_data = (client_info_t *)event_info->evt_data;
                    if (NULL == client_data) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : STA mac is empty \n", __FUNCTION__);
                        break;
                    }

                    if(0 != client_capability_query_cb(&map_handle, client_data)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s client_capability_query_cb failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_LINK_METRIC_QUERY:
                {
                    msg_type = CMDU_TYPE_LINK_METRIC_QUERY;
                    link_metric_query_t *lm_query = NULL;
                    lm_query = (link_metric_query_t *)event_info->evt_data;
                    if (NULL == lm_query) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Insufficient data to trigger link metrics query via ubus cli \n", __FUNCTION__);
                        break;
                    }

                    if(map_send_link_metric_query(&map_handle, lm_query) < 0){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_link_metric_query failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_AP_METRIC_QUERY:
                {
                    msg_type = CMDU_TYPE_MAP_AP_METRICS_QUERY;
                    ap_metric_query_t *ap_query = NULL;
                    ap_query = (ap_metric_query_t *)event_info->evt_data;
                    if (NULL == ap_query) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Insufficient data to trigger ap metrics query via ubus cli \n", __FUNCTION__);
                        break;
                    }

                    if(map_send_ap_metric_query(&map_handle, ap_query) < 0) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_ap_metric_query failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_CLIENT_ACL_REQUEST:
                {
                    msg_type = CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST;
                    client_acl_data_t *acl_data = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_CLIENT_ACL_REQUEST \n", __FUNCTION__);

                    acl_data = (client_acl_data_t *)event_info->evt_data;
                    if (NULL == acl_data) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : ACL data is empty \n", __FUNCTION__);
                        break;
                    }

                    if(map_send_client_acl_request(&map_handle, acl_data) < 0){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_client_acl_request failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_HIGHLAYER_DATA_EVENT:
                {
                    msg_type = CMDU_TYPE_MAP_HIGHER_LAYER_DATA;
                    higherlayer_info_t *higherlayer_data = NULL;
                    higherlayer_data = (higherlayer_info_t *)event_info->evt_data;
                    if (NULL == higherlayer_data) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : No valid data for high layer query\n",__FUNCTION__);
                        break;
                    }

                    if(map_send_higher_layer_data_msg(&map_handle, higherlayer_data) < 0){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s: Higher layer data msg parse failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_ASSOC_STA_METRIC_QUERY:
                {
                    msg_type = CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY;
                    uint8_t *mac = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_ASSOC_STA_METRIC_QUERY \n", __FUNCTION__);

                    mac = (uint8_t *)event_info->evt_data;
                    if (NULL == mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : MAC is empty \n", __FUNCTION__);
                        break;
                    }

                    if(-1 == map_send_associated_sta_link_metrics_query( &map_handle ,mac)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_associated_sta_link_metrics_query failed\n", __FUNCTION__);
                    }
                    break;
                }

                case MAP_MONITOR_BEACON_QUERY_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_BEACON_METRICS_QUERY;
                    beacon_metrics_query_t* beacon_query = NULL;
                    beacon_query = (beacon_metrics_query_t *)event_info->evt_data;
                    if(NULL != beacon_query) {
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------ Beacon Query info Start--------\n");
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------AL MAC : %x:%x:%x:%x:%x:%x--------\n",beacon_query->dst_mac[5],
                            beacon_query->dst_mac[4],beacon_query->dst_mac[3],beacon_query->dst_mac[2],beacon_query->dst_mac[1],beacon_query->dst_mac[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------STA MAC : %x:%x:%x:%x:%x:%x--------\n",beacon_query->sta_mac[5],
                            beacon_query->sta_mac[4],beacon_query->sta_mac[3],beacon_query->sta_mac[2],beacon_query->sta_mac[1], beacon_query->sta_mac[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------TARGET BSSID : %x:%x:%x:%x:%x:%x--------\n",beacon_query->bssid[5], beacon_query->bssid[4],beacon_query->bssid[3],beacon_query->bssid[2], beacon_query->bssid[1],beacon_query->bssid[0]);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------TARGET SSID : %s--------\n",beacon_query->ssid);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------TARGET CHANNEL : %d--------\n",beacon_query->channel);
                        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------Beacon Query info End--------\n");

                        if(map_send_beacon_metrics_query(&map_handle, beacon_query, beacon_query->dst_mac)) {
                            status = -1;
                            platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_beacon_metrics_query failed\n", __FUNCTION__);
                        }
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d invalid data pointer recieved\n", __FUNCTION__, __LINE__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_CHANNEL_PREFERENCE_QUERY_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY;
                    uint8_t *mac = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_CHANNEL_PREFERENCE_QUERY_CALL \n", __FUNCTION__);

                    mac = (uint8_t *)event_info->evt_data;
                    if (NULL == mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : MAC is empty \n", __FUNCTION__);
                        break;
                    }

                    map_ale_info_t *ale = get_ale(mac);
                    if(ale == NULL){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s Invalid ALE MAC address.\n", __FUNCTION__);
                        break;
                    }

                    map_handle.handle_1905 = handle_1905;
                    memcpy(map_handle.dest_addr, mac, MAC_ADDR_LEN);
                    if(map_send_channel_preference_query(&map_handle, ale) < 0){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_channel_preference_query failed\n", __FUNCTION__);
                    }

                    break;
                }
                case MAP_MONITOR_SEND_CHANNEL_SELECTION_REQUEST_CALL:
                {
                    msg_type = CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST;
                    uint8_t *dst_al_mac = NULL;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_CHANNEL_SELECTION_REQUEST_CALL \n", __FUNCTION__);
                    dst_al_mac = (uint8_t *)event_info->evt_data;
                    if (NULL == dst_al_mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : MAC is empty \n", __FUNCTION__);
                        break;
                    }
                    map_handle.handle_1905 = handle_1905;
                    memcpy(map_handle.dest_addr, dst_al_mac, MAC_ADDR_LEN);

                    if(map_cli_send_channel_selection_request(&map_handle, dst_al_mac, NULL) < 0){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_cli_send_channel_selection_request failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_DUMP_CONTROLLER_INFO:
                {
                    platform_log(MAP_CONTROLLER,LOG_INFO,"-------------START DUMP--------------------\n");
                    print_agent_info_tree();
                    break;
                }

                case MAP_MONITOR_DUMP_TOPO_TREE:
                {
                    void * jason_buff = NULL;
                    get_topo_tree_jason_buf(&jason_buff);                    
                    map_send_async_data(jason_buff);                    
                    break;
                }

                case MAP_MONITOR_SEND_AUTOCONFIG_RENEW:
                {
                    msg_type = CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW;
                    uint8_t *freq_band = NULL;
                    freq_band = (uint8_t *)event_info->evt_data;
                    
                    map_handle.handle_1905 = handle_1905;
                    get_mcast_macaddr(map_handle.dest_addr);

                    if(map_send_autoconfig_renew(&map_handle,*freq_band)){
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_autoconfig_renew failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_UNASSOC_STA_METRICS_QUERY:
                {
                    msg_type = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY;
                    struct unassoc_sta_dm_s *unassoc_metrics = (struct unassoc_sta_dm_s *)q_obj;
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_UNASSOC_STA_METRICS_QUERY \n", __FUNCTION__);
                    uint8_t (*sta_mac)[MAC_ADDR_LEN] = NULL;
                    for (int i = 0; i<unassoc_metrics->channel_list_cnt; i++) {
                        sta_mac = unassoc_metrics->sta_list[i].sta_mac;
                        for(int j = 0; j< unassoc_metrics->sta_list[i].sta_count; j++) {
                            uint8_t *mac = (uint8_t *)sta_mac;

                            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s %d query unassoc sta metrics for channel %d, sta_mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n",
                                                                          __func__, __LINE__, unassoc_metrics->sta_list[i].channel,
                                                                          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                            sta_mac++;
                        }
                    }

                    map_handle.handle_1905 = handle_1905;
                    memcpy(map_handle.dest_addr, unassoc_metrics->al_mac, MAC_ADDR_LEN);
                     
                    if(map_send_unassoc_sta_metrics_query (&map_handle, unassoc_metrics) < 0) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_unassoc_sta_metrics_query failed\n", __FUNCTION__);
                    }

                     if(unassoc_metrics!= NULL) {
                        for(int i = 0; i <unassoc_metrics->channel_list_cnt; i++) {
                            free(unassoc_metrics->sta_list[i].sta_mac);
                        }
                    }
                    break;
                }

                case MAP_MONITOR_WIRED_LINK_EVENT:
                {
                    map_network_link_evt_data *link_event = NULL;
                    event_info = (map_monitor_evt_t*)q_obj;
                    uint8_t lib1905_if_event = 0x00;
                    
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_NETWORK_LINK_EVENTS_SUBCMD \n", __FUNCTION__);

                    link_event = (map_network_link_evt_data *)event_info->evt_data;
                    if (NULL == link_event) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : link_event is empty\n", __FUNCTION__);
                        break;
                    }
                    platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s link event, i/f %s, state %s\n", __FUNCTION__, link_event->if_name, \
                                 link_event->status);
                    if (0 == strcmp(link_event->status, "up")) {
                        lib1905_if_event = LIB_1905_IF_UP_EVENT;
                    } else if(0 == strcmp(link_event->status, "new")) {
                        lib1905_if_event = LIB_1905_NEW_IF_CREATED_EVENT;
                    } else if(0 == strcmp(link_event->status, "down")) {
                        lib1905_if_event = LIB_1905_IF_DOWN_EVENT;
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : unknown link_event: %s for interface: %s \n", __FUNCTION__, link_event->if_name, link_event->status);
                        break;
                    }

                    if(0 != lib1905_notify_event(handle_1905, link_event->if_name, lib1905_if_event)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR,"%s i/f %s event %s , 1905 notification failed\n", __FUNCTION__, link_event->if_name, link_event->status);
                        break;
                    }   

                    break;
                }

                case MAP_MONITOR_SEND_TOPOLOGY_QUERY:
                {
                    msg_type = CMDU_TYPE_TOPOLOGY_QUERY;
                    map_monitor_evt_t *event_info;
                    uint8_t           *al_dst_mac = NULL;
                    map_ale_info_t* dst_ale       = NULL;

                    event_info = (map_monitor_evt_t*)q_obj;
   
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_TOPOLOGY_QUERY \n", __FUNCTION__);
   
                    al_dst_mac = (uint8_t *)event_info->evt_data;
                    if (NULL == al_dst_mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : dst Al mac is empty\n", __FUNCTION__);
                        break;
                    }

                    dst_ale = get_ale(al_dst_mac);
                    if(dst_ale != NULL) {
                        if(0 != map_send_topology_query(&map_handle, dst_ale)){
                            status = -1;
                            platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_topology_query failed\n", __FUNCTION__);
                        }
                    } else {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : dst Al mac is not onboarded\n", __FUNCTION__);
                    }
                    break;
                }

                case MAP_MONITOR_SEND_CHANNEL_SEL_REQ_DETAIL:
                {
                    msg_type = CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST;
                    channel_report_t  *ch_info = NULL;

                    map_ale_info_t *dst_ale =  NULL;
                    channel_preference_tlv_t channel_pref_tlv = {0};


                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_CHANNEL_SELECTION_REQUEST_DETAIL \n", __FUNCTION__);
                    ch_info = (channel_report_t *)q_obj;

                    if(ch_info == NULL || ch_info->al_mac == NULL) {
                        status = -1;
                        break;
                    }

                    dst_ale = get_ale (ch_info->al_mac);
                    if(dst_ale == NULL) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, " %s dst_ale not found ", __func__);
                        break;
                    }

                    memcpy(map_handle.dest_addr, ch_info->al_mac, MAC_ADDR_LEN);
                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s %d al_mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n", __func__, __LINE__,
                                                              map_handle.dest_addr[0],
                                                              map_handle.dest_addr[1],
                                                              map_handle.dest_addr[2],
                                                              map_handle.dest_addr[3],
                                                              map_handle.dest_addr[4],
                                                              map_handle.dest_addr[5]);
                    map_handle.handle_1905 = handle_1905;

                    /* Update Channel pref */
                    memcpy(channel_pref_tlv.radio_id, ch_info->radio_id, MAC_ADDR_LEN);
                    channel_pref_tlv.numOperating_class = ch_info->numOperating_class;
                    memcpy(channel_pref_tlv.operating_class, ch_info->operating_class, 
                    sizeof(channel_pref_operating_class_t) * ch_info->numOperating_class);

                    map_radio_info_t *radio = get_radio(ch_info->radio_id);
                    if(radio == NULL) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, radio Id for chan pref tlv is NULL\n", 
                                                                    __FUNCTION__, __LINE__);
                        break;
                    }
                    memset(radio->op_class_list, 0 , radio->op_class_count * sizeof(map_op_class_t));
                    radio->op_class_count = 0;

                    if(parse_chan_pref_tlv(&channel_pref_tlv) < 0) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, parsing chan pref tlv failed\n", __FUNCTION__, __LINE__);
                        break;
                    }

                    /* Update transmit power */
                    if(update_transmit_power(ch_info->al_mac, ch_info->radio_id, ch_info->txpower)) {
                        status = -1;
                        break;
                    }


                    if(map_cli_send_channel_selection_request(&map_handle, ch_info->al_mac, ch_info->radio_id) < 0) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_cli_send_channel_selection_request failed\n", __FUNCTION__);
                    }

                    break;
                }

                case MAP_MONITOR_SEND_COMBINED_INFRA_METRICS:
                {
                    msg_type = CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS;
                    map_monitor_evt_t *event_info;
                    uint8_t           *al_dst_mac = NULL;

                    event_info = (map_monitor_evt_t*)q_obj;

                    platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s MAP_MONITOR_SEND_COMBINED_INFRA_METRICS \n", __FUNCTION__);

                    al_dst_mac = (uint8_t *)event_info->evt_data;
                    if (NULL == al_dst_mac) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : dst Al mac is empty\n", __FUNCTION__);
                        break;
                    }
                    if(0 != map_send_combined_infra_metrics( &map_handle ,al_dst_mac)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_combined_infra_metrics failed\n", __FUNCTION__);
                    }
                    break;
                }
                case MAP_MONITOR_LINK_METRICS_REPORT:
                {
                    struct neighbour_link_met_response *link_met_resp = (struct neighbour_link_met_response *)q_obj;

                    if (NULL == link_met_resp) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "link_met_resp is empty.");
                        break;
                    }

                    if (0 != map_send_link_metrics_report(link_met_resp)) {
                        status = -1;
                        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_link_metrics_report failed.");
                    }
                    break;
                }
                default:
                {
                    platform_log(MAP_CONTROLLER,LOG_ERR, "%s invalid event \n", __FUNCTION__);
                    break;
                }
            }
            
            if(event_info && event_info->async_status_response) {
                map_send_aysnc_repsonse(&map_handle, status, msg_type);
            }

            /* free up the memory allocated in monitor thread */
            map_monitor_free_evt_mem(event_info);
        }
    }
    // Return to zero to avoid unregister from timer
    return 0;
}

static void map_send_async_data(void *data)
{
    map_monitor_cmd_t cmd = { MAP_MONITOR_SEND_UBUS_DATA_CMD, MAP_MONITOR_SEND_TOPO_TREE_DATA, data};
    if(0 != map_monitor_send_cmd(cmd)) {
        platform_log(MAP_CONTROLLER, LOG_ERR, "Failed to send command %s : %d", __func__, __LINE__);
        if(NULL != data)
            free(data);
    }
}

static void map_send_aysnc_repsonse(map_handle_t *handle, int8_t status, uint16_t msg_type) {
    map_cli_async_resp_t *ubus_resp = calloc(1,sizeof(map_cli_async_resp_t));
    if(NULL == ubus_resp){
        platform_log(MAP_CONTROLLER,LOG_ERR, "Internal error calloc failed in %s : %d", __func__, __LINE__);
        return;
    }
    const char *status_msg = "Success";
    if(-1 == status) {status_msg = "Failure";}

    strncpy(ubus_resp->status, status_msg, MAX_CLI_ASYNC_STATUS_LEN);
    ubus_resp->msg_type = msg_type;
    ubus_resp->mid      = handle->mid;
    platform_log(MAP_CONTROLLER,LOG_DEBUG, " Status Message : %s, Message type : %d, Message ID : %d ", ubus_resp->status, ubus_resp->msg_type, ubus_resp->mid);
    map_monitor_cmd_t cmd = { MAP_MONITOR_SEND_UBUS_DATA_CMD, MAP_MONITOR_RESPONSE_TO_CLI_SUBCMD, ubus_resp};
    if(0 != map_monitor_send_cmd(cmd)) {
        free(ubus_resp);
    }
}

static int map_cli_send_channel_selection_request(map_handle_t *handle, uint8_t *dst_al_mac, uint8_t *radio_id)
{
    int status = 0;

    platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s \n", __FUNCTION__);
    do
    {
        if(dst_al_mac != NULL)
        {
            map_ale_info_t *dst_ale =  NULL;
            map_radio_info_t *radio = NULL;

            dst_ale = get_ale(dst_al_mac);
            if(dst_ale == NULL) {
                platform_log(MAP_CONTROLLER,LOG_ERR, " %s dst_ale not found ", __func__);
                ERROR_EXIT(status)
            }

            if(radio_id != NULL) {
                for (int8_t radio_index = 0; radio_index < dst_ale->num_radios; ++radio_index) {
                    radio = dst_ale->radio_list[radio_index];
                    // Send request only to a configured radios
                    if (memcmp(radio->radio_id, radio_id, MAC_ADDR_LEN) == 0) {
                       break;
                    }
                    radio = NULL;
                }
            }

            map_chan_selec_pref_type_t pref_type = { .ale = dst_ale, .radio_cnt = 1, .radio = radio, .pref = GET_AGENT_PREFERENCE};
            if(-1 == map_send_channel_selection_request(handle, &pref_type)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, " %s Failed to send channel selection request", __func__);
                ERROR_EXIT(status)
            }

            // Set the status to channel selection completed
            if(dst_ale->radio_list[0])
                set_radio_state_channel_selection_sent(&dst_ale->radio_list[0]->state);
        }
        else {
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

static int map_cli_send_steering_policy_config(map_handle_t *handle, map_steering_policy_config_cmd_t *policy_info, uint8_t *dst_mac)
{
    int ret = 0;
    steering_policy_tlv_t *steering_policy_tlv = NULL;  

    if((NULL == policy_info) ||(NULL == dst_mac)){
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Invalid i/p param\n", __func__, __LINE__);
        goto Failure;
    }
    
    steering_policy_tlv = (steering_policy_tlv_t*)calloc(1, sizeof(steering_policy_tlv_t));
    if(NULL == steering_policy_tlv) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed\n", __func__, __LINE__);
        goto Failure;
    }           
    steering_policy_tlv->number_of_local_steering_disallowed = policy_info->local_disalllowed_sta_cnt;
    if(steering_policy_tlv->number_of_local_steering_disallowed > 0) {
        if(steering_policy_tlv->number_of_local_steering_disallowed < MAX_STATIONS) {
            steering_policy_tlv->local_steering_macs = (uint8_t*)calloc(steering_policy_tlv->number_of_local_steering_disallowed*MAC_ADDR_LEN, sizeof(uint8_t));
            if(NULL != steering_policy_tlv->local_steering_macs) {
                for(int i = 0; i < steering_policy_tlv->number_of_local_steering_disallowed; i++) 
                {
                    memcpy((steering_policy_tlv->local_steering_macs + i*MAC_ADDR_LEN), policy_info->local_disallowed_sta_list[i], MAC_ADDR_LEN);
                }
            }
        } else {    
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, max supported station count exceeded %d\n", __func__, __LINE__, steering_policy_tlv->number_of_local_steering_disallowed);
            goto Failure;
        }
    } 
    
    steering_policy_tlv->number_of_btm_steering_disallowed = policy_info->btm_disalllowed_sta_cnt;                
    if(steering_policy_tlv->number_of_btm_steering_disallowed > 0) {
        if(steering_policy_tlv->number_of_btm_steering_disallowed  < MAX_STATIONS) {
            steering_policy_tlv->btm_steering_macs = (uint8_t*)calloc(steering_policy_tlv->number_of_btm_steering_disallowed*MAC_ADDR_LEN, sizeof(uint8_t));
            if(NULL != steering_policy_tlv->btm_steering_macs) {
                for(int i = 0; i < steering_policy_tlv->number_of_btm_steering_disallowed; i++) 
                {
                    memcpy((steering_policy_tlv->btm_steering_macs + i*MAC_ADDR_LEN), &policy_info->btm_disalllowed_sta_list[i], MAC_ADDR_LEN);
                }
            }
        } else {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, max supported station count exceeded %d\n", __func__, __LINE__, steering_policy_tlv->number_of_btm_steering_disallowed);
            goto Failure;
        }
    }   
    steering_policy_tlv->number_of_radio = policy_info->radio_count;        
    for(int i = 0; i < steering_policy_tlv->number_of_radio; i++) {
        steering_policy_tlv->radio_policy[i].channel_utilization_threshold = policy_info->radio_list[i].chnlutil_threshold;
        steering_policy_tlv->radio_policy[i].rssi_steering_threshold = policy_info->radio_list[i].rcpi_threshold;
        steering_policy_tlv->radio_policy[i].steering_policy = policy_info->radio_list[i].steering_policy;
        memcpy(steering_policy_tlv->radio_policy[i].radioId, policy_info->radio_list[i].radio_mac, MAC_ADDR_LEN);
    }

    ret = map_send_policy_config(handle, NULL, steering_policy_tlv, dst_mac);
    if(0 != ret) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, map_send_policy_config failed\n", __func__, __LINE__);
    }
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->local_steering_macs))
        free(steering_policy_tlv->local_steering_macs);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->btm_steering_macs))
        free(steering_policy_tlv->btm_steering_macs);
    if(NULL != steering_policy_tlv)
        free(steering_policy_tlv);
    return ret;
Failure:
    platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Failure \n", __func__, __LINE__);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->local_steering_macs))
        free(steering_policy_tlv->local_steering_macs);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->btm_steering_macs))
        free(steering_policy_tlv->btm_steering_macs);
    if(NULL != steering_policy_tlv)
        free(steering_policy_tlv);
    return -1;
}

static int map_cli_send_policy_config(map_handle_t *handle, map_policy_config_cmd_t *policy_info, uint8_t *dst_mac)
{
    int ret = 0;    
    map_policy_config_t uci_steer_policy_config;
    metric_policy_tlv_t *metric_policy_tlv = NULL;
    steering_policy_tlv_t *steering_policy_tlv = NULL;  

    if((NULL == policy_info) ||(NULL == dst_mac)){
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Invalid i/p param\n", __func__, __LINE__);
        goto Failure;
    }
    /* read steering configuration using uci */
    if(0 != platform_get(MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG, NULL, (void*)&uci_steer_policy_config)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG failed\n", __func__, __LINE__);
        goto Failure;
    }
    
    metric_policy_tlv = (metric_policy_tlv_t*)calloc(1, sizeof(metric_policy_tlv_t));   
    if(NULL == metric_policy_tlv) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed\n", __func__, __LINE__);
        goto Failure;
    }
    metric_policy_tlv->metric_reporting_interval = uci_steer_policy_config.metrics_report_interval;
    metric_policy_tlv->number_of_radio = policy_info->radio_count;
    for(int i=0; i<metric_policy_tlv->number_of_radio; i++)
    {
        memcpy(metric_policy_tlv->radio_policy[i].radioId,policy_info->radio_mac[i],MAC_ADDR_LEN); 
        metric_policy_tlv->radio_policy[i].reporting_rssi_threshold= uci_steer_policy_config.sta_metrics_rssi_threshold_dbm;
        metric_policy_tlv->radio_policy[i].reporting_rssi_margin_override = uci_steer_policy_config.sta_metrics_rssi_hysteresis_margin;
        metric_policy_tlv->radio_policy[i].channel_utilization_reporting_threshold = uci_steer_policy_config.ap_metrics_channel_utilization_threshold_dbm;
        metric_policy_tlv->radio_policy[i].associated_sta_policy = uci_steer_policy_config.sta_link_sta_traffic_stats;          
    }
    
    if(policy_info->station_count > 0) {
        steering_policy_tlv = (steering_policy_tlv_t*)calloc(1, sizeof(steering_policy_tlv_t));
        if(NULL == steering_policy_tlv) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed\n", __func__, __LINE__);
            goto Failure;
        }           
        steering_policy_tlv->number_of_local_steering_disallowed = policy_info->station_count;
        if((steering_policy_tlv->number_of_local_steering_disallowed > 0) && (steering_policy_tlv->number_of_local_steering_disallowed < MAX_STATIONS)) {
            steering_policy_tlv->local_steering_macs = (uint8_t*)calloc(steering_policy_tlv->number_of_local_steering_disallowed*MAC_ADDR_LEN, sizeof(uint8_t));
            if(NULL != steering_policy_tlv->local_steering_macs) {
                for(int i = 0; i < steering_policy_tlv->number_of_local_steering_disallowed; i++) 
                {
                    memcpy((steering_policy_tlv->local_steering_macs + i*MAC_ADDR_LEN), &policy_info->sta_mac[i][0], MAC_ADDR_LEN);
                }
            }
        } else {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, max supported station count exceeded %d\n", __func__, __LINE__, steering_policy_tlv->number_of_local_steering_disallowed);
            goto Failure;
        }
        
        steering_policy_tlv->number_of_btm_steering_disallowed = policy_info->station_count;                
        if((steering_policy_tlv->number_of_btm_steering_disallowed > 0) && (steering_policy_tlv->number_of_btm_steering_disallowed  < MAX_STATIONS)){
            steering_policy_tlv->btm_steering_macs = (uint8_t*)calloc(steering_policy_tlv->number_of_btm_steering_disallowed*MAC_ADDR_LEN, sizeof(uint8_t));
            if(NULL != steering_policy_tlv->btm_steering_macs) {
                for(int i = 0; i < steering_policy_tlv->number_of_btm_steering_disallowed; i++) 
                {
                    memcpy((steering_policy_tlv->btm_steering_macs + i*MAC_ADDR_LEN), &policy_info->sta_mac[i][0], MAC_ADDR_LEN);
                }
            }
        } else {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, max supported station count exceeded %d\n", __func__, __LINE__, steering_policy_tlv->number_of_btm_steering_disallowed);
            goto Failure;
        }
        steering_policy_tlv->number_of_radio = policy_info->radio_count;
        for(int i = 0; i < steering_policy_tlv->number_of_radio; i++) {
            steering_policy_tlv->radio_policy[i].channel_utilization_threshold = 0x10;
            steering_policy_tlv->radio_policy[i].rssi_steering_threshold = 0x30;
            steering_policy_tlv->radio_policy[i].steering_policy = 0x01;
            memcpy(steering_policy_tlv->radio_policy[i].radioId, &policy_info->radio_mac[i][0], MAC_ADDR_LEN);
        }
    }
    ret = map_send_policy_config(handle, metric_policy_tlv, steering_policy_tlv, dst_mac);
    if(0 != ret) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, map_send_policy_config failed\n", __func__, __LINE__);
    }
    else {
        // Mark the status as policy config sent
        for(uint8_t i = 0; i < policy_info->radio_count; i++) {
            map_radio_info_t *radio = get_radio(policy_info->radio_mac[i]);
            if(radio)
                set_radio_state_policy_config_updated(&radio->state);
        }
    }
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->local_steering_macs))
        free(steering_policy_tlv->local_steering_macs);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->btm_steering_macs))
        free(steering_policy_tlv->btm_steering_macs);
    if(NULL != metric_policy_tlv)
        free(metric_policy_tlv);
    if(NULL != steering_policy_tlv)
        free(steering_policy_tlv);
    return ret;
Failure:
    platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Failure \n", __func__, __LINE__);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->local_steering_macs))
        free(steering_policy_tlv->local_steering_macs);
    if((NULL != steering_policy_tlv) && (NULL != steering_policy_tlv->btm_steering_macs))
        free(steering_policy_tlv->btm_steering_macs);
    if(NULL != metric_policy_tlv)
        free(metric_policy_tlv);
    if(NULL != steering_policy_tlv)
        free(steering_policy_tlv);
    return -1;
}

static int client_capability_query_cb ( map_handle_t *handle, client_info_t *client_info)
{
    if (NULL == client_info) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : client data is empty \n", __FUNCTION__);
        return -1;
    }

    //## Client info paramters validation
    if (NULL == client_info->bssid || NULL == client_info->client_mac || NULL == client_info->agent_mac) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Client info parameters are empty \n", __FUNCTION__);
        return -1;
    }
    map_clicap_args_t clicap_args = {0};
    memcpy(clicap_args.sta_mac,client_info->client_mac,MAC_ADDR_LEN);
    memcpy(clicap_args.bssid,client_info->bssid,MAC_ADDR_LEN);

    if(-1 == map_send_client_capability_query(handle, &clicap_args)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s map_send_ap_capability_query failed\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

void get_mcast_macaddr(uint8_t * dest_mac)
{
    dest_mac[0] = MCAST_1905_B0;
    dest_mac[1] = MCAST_1905_B1;
    dest_mac[2] = MCAST_1905_B2;
    dest_mac[3] = MCAST_1905_B3;
    dest_mac[4] = MCAST_1905_B4;
    dest_mac[5] = MCAST_1905_B5;
}
#endif
