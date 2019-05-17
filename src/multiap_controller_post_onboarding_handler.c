/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_post_onboarding_handler.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "multiap_controller_mgmt_ipc.h"
#include "platform_multiap_get_info.h"
#include "platform_utils.h"
#include "map_data_model.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_payloads.h"
#include "map_data_model_dumper.h"

int8_t is_policy_config_required(map_ale_info_t *ale) {
    for(int i = 0; i < ale->num_radios; i++) {
        if(ale->radio_list == NULL)
            continue;
        if(is_policy_config_updated(ale->radio_list[i]->state))
            return 0;
    }
    return 1;
}

int8_t map_build_and_send_policy_config(map_handle_t* handle, void* ale_object) {

    map_ale_info_t *ale = (map_ale_info_t*)ale_object;

    if(ale == NULL)
        return -1;

       // If the policy config is already sent for any of radio by UBUS CLI do not send again
    if(0 == is_policy_config_required(ale))
        return 0;

    metric_policy_tlv_t metric_policy_tlv;
    steering_policy_tlv_t steering_policy_tlv;
    map_policy_config_t uci_steer_policy_config;


    if (MAP_CONTROLLER_EXT_ROAMING_ENGINE_HAS_GET_POLICY_CONFIG()) {
        MAP_CONTROLLER_EXT_ROAMING_ENGINE_GET_POLICY_CONFIG(ale, &uci_steer_policy_config);
    } else {
        /* read steering configuration using uci */
        if(0 != platform_get(MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG, NULL, (void*)&uci_steer_policy_config)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG failed\n", __func__, __LINE__);
            return -1;
        }
    }

    // Update Metric reporting policy TLV
    metric_policy_tlv.number_of_radio           = ale->num_radios;
    metric_policy_tlv.metric_reporting_interval = uci_steer_policy_config.metrics_report_interval;

    // Update steering policy TLV
    steering_policy_tlv.number_of_radio                     = ale->num_radios;
    steering_policy_tlv.number_of_local_steering_disallowed = 0;
    steering_policy_tlv.number_of_btm_steering_disallowed   = 0;
    steering_policy_tlv.local_steering_macs                 = NULL;
    steering_policy_tlv.btm_steering_macs                   = NULL;

    for(int i = 0; i < ale->num_radios; i++) {
        memcpy(metric_policy_tlv.radio_policy[i].radioId, ale->radio_list[i]->radio_id, MAC_ADDR_LEN); 
        metric_policy_tlv.radio_policy[i].reporting_rssi_threshold= uci_steer_policy_config.sta_metrics_rssi_threshold_dbm;
        metric_policy_tlv.radio_policy[i].reporting_rssi_margin_override = uci_steer_policy_config.sta_metrics_rssi_hysteresis_margin;
        metric_policy_tlv.radio_policy[i].channel_utilization_reporting_threshold = uci_steer_policy_config.ap_metrics_channel_utilization_threshold_dbm;
        metric_policy_tlv.radio_policy[i].associated_sta_policy = uci_steer_policy_config.sta_link_sta_traffic_stats;

        memcpy(steering_policy_tlv.radio_policy[i].radioId, ale->radio_list[i]->radio_id, MAC_ADDR_LEN);
        steering_policy_tlv.radio_policy[i].channel_utilization_threshold = 0x00;
        steering_policy_tlv.radio_policy[i].rssi_steering_threshold = 0x00;
        steering_policy_tlv.radio_policy[i].steering_policy = 0x00;
    }

    return map_send_policy_config(handle, &metric_policy_tlv, &steering_policy_tlv, ale->al_mac);
}

int8_t map_agent_handle_channel_selection(map_handle_t *handle, void *chan_sel_action) {

    // Only onboarded agents are allowed to do channel selection
    chan_sel_action_t *ch_sel = (chan_sel_action_t*)chan_sel_action;

    int8_t  status = 0;
    char    retry_id[MAX_TIMER_ID_STRING_LENGTH];
    do
    {
        if(ch_sel == NULL || ch_sel->ale == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Invalid input argument.", __func__);
            ERROR_EXIT(status)
        }

        if(ch_sel->action == MAP_CHAN_SEL_QUERY) {

            // Retry Channel preference query untill we get a report from agent.
            GET_RETRY_ID(ch_sel->ale->al_mac, CHAN_PREF_QUERY_RETRY_ID, retry_id);
            if(-1 == map_register_retry((const char*)retry_id, 10 , 10 ,
                                         ch_sel->ale, NULL, map_send_channel_preference_query)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "Failed Registering retry timer : %s ", retry_id);
                ERROR_EXIT(status)
            }
        }
        else if(ch_sel->action == MAP_CHAN_SEL_REQUEST) {

            // Do not send the Channel selection request if it is already sent by UBUS CLI
            if(ch_sel->ale->radio_list[0] && is_channel_selection_sent(ch_sel->ale->radio_list[0]->state))
                break;

            // Retry Channel selection request untill we get a response.
            // This memory will be freed by cleanup_retry_args during retry completion handler
            map_chan_selec_pref_type_t *pref_type = malloc(sizeof(map_chan_selec_pref_type_t));

            if(pref_type) {
                pref_type->ale  = ch_sel->ale;
                pref_type->radio = NULL;
                pref_type->pref = GET_AGENT_PREFERENCE;
                ch_sel->ale->first_chan_sel_req_done = 1;
                ch_sel->ale->last_chan_sel_req_time = get_current_time();
                GET_RETRY_ID(ch_sel->ale->al_mac, CHAN_SELEC_REQ_RETRY_ID, retry_id);
                if(-1 == map_register_retry((const char*)retry_id, 10 , 10 , pref_type,
                                             cleanup_retry_args, map_send_channel_selection_request)) {
                    platform_log(MAP_CONTROLLER,LOG_ERR, "Failed Registering retry timer : %s ", retry_id);
                    ERROR_EXIT(status)
                }
            }
            else {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to allocate memory.", __func__);
                ERROR_EXIT(status)
            }
        }
    } while (0);
    return status;
}
