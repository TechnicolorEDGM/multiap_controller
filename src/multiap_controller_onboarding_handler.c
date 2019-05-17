/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_post_onboarding_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "multiap_controller_topology_tree_builder.h"
#include "map_topology_tree.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_defines.h"
#include "platform_multiap_get_info.h"
#include "multiap_controller_metrics_handler.h"
#include "platform_utils.h"
#include "map_data_model_dumper.h"
#include "arraylist.h"

#include <sys/time.h>
#include <uv.h>

extern plfrm_config pltfrm_config;

uint8_t  periodic_topology_query(char* timer_id, void *arg);

int8_t init_agent_onboarding_handler()
{
    int8_t status = 0;
    int16_t link_interval = atoi(map_controller_env_link_metric_query_interval);
    int16_t topquery_interval = atoi(map_controller_env_topology_query_interval);

    do {

        /* Registering a timer for topology query */
        if(topquery_interval > 0)
        {
            if(-1 == map_timer_register_callback(topquery_interval, TOPOLOGY_QUERY_TIMER_ID, NULL, periodic_topology_query)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to register topology query timer.",__func__);
                ERROR_EXIT(status)
            }
        }

        /* Registering a timer for link metric query */
        if(link_interval > 0)
        {
            if(-1 == map_timer_register_callback(link_interval, LINK_METRIC_QUERY_TIMER_ID, NULL, periodic_link_metric_query)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to register topology query timer.",__func__);
                ERROR_EXIT(status)
            }
        }

    } while (0);
    return status;
}

// For Controller certification we need not require channel mgmt at post onboarding operation.
// This API will be used a control flag to enable or disable channel selection.

uint8_t is_channel_selection_enabled() {
    // By default channel selection is enabled
    static uint8_t enabled = 1;
    static uint8_t is_first_read = 1;

    if(is_first_read && map_controller_env_channel_selection_enabled != NULL) {
        enabled = atoi(map_controller_env_channel_selection_enabled);
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s :%s:%d", __func__, map_controller_env_channel_selection_enabled, enabled);
        is_first_read = 0;
    }

    return enabled;

}

uint8_t periodic_topology_query(char* timer_id, void *arg) {
    map_ale_info_t *neighbor_ale = NULL;
    // Send topology query to immediate neighbors only
    foreach_child_in(get_root_ale_node(), neighbor_ale) {
        if(is_topology_update_required(neighbor_ale)) {
            map_register_topology_query_retry(neighbor_ale);
        }
    }
    return 0;
}

uint16_t map_get_dead_agent_detection_intervel() {
    static uint16_t dead_agent_detection_time = 0;
    static uint8_t is_first_read = 1;

    if(is_first_read && map_controller_env_dead_agent_detection_interval != NULL) {
        dead_agent_detection_time = atoi(map_controller_env_dead_agent_detection_interval);

        if(dead_agent_detection_time < MIN_DEAD_AGENT_DETECT_TIME_IN_SEC)
            dead_agent_detection_time = MIN_DEAD_AGENT_DETECT_TIME_IN_SEC;
        else if(dead_agent_detection_time > MAX_DEAD_AGENT_DETECT_TIME_IN_SEC)
            dead_agent_detection_time = MAX_DEAD_AGENT_DETECT_TIME_IN_SEC;

        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s : map_controller_env_dead_agent_detection_interval updated as %d", __func__, dead_agent_detection_time);
        is_first_read = 0;
    }

    return dead_agent_detection_time;
}

uint16_t map_get_topology_query_retry_intervel_sec() {
    static uint16_t topology_query_retry_intervel_sec = 0;
    static uint8_t is_first_read = 1;
    uint16_t dead_agent_detection_time = map_get_dead_agent_detection_intervel();

    if(is_first_read && (0 != dead_agent_detection_time)) {
	topology_query_retry_intervel_sec = dead_agent_detection_time/MAX_TOPOLOGY_QUERY_RETRY;
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s : topology_query_retry_intervel_sec updated as %d", __func__, topology_query_retry_intervel_sec);
        is_first_read = 0;
    }

    return topology_query_retry_intervel_sec;
}

map_ale_info_t* map_handle_new_agent_onboarding(uint8_t *al_mac, char* recv_iface) {

    map_ale_info_t* ale = NULL;
    if(NULL == al_mac || NULL == recv_iface)
        return NULL;

    // This will update the topology tree
    ale = get_ale(al_mac);
    if(ale == NULL) {
        ale = create_ale(al_mac);
        if(ale){
            // Update the receiving interface name.
            map_update_ale_recving_iface(ale, recv_iface);

            // Send topology query as soon as we create
            map_send_topology_query(NULL, ale);

            /* Update roaming engine to indicate new agent */
            MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_ALE(ale);

            #ifdef MAP_MGMT_IPC
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_ALE_ONBOARD,(void *)ale);
            #endif
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Failed creating ALE node");
        }
    }

    return ale;
}

map_radio_info_t* map_handle_new_radio_onboarding(uint8_t *radio_id, uint8_t *al_mac) {
    map_radio_info_t* radio = NULL;

    if(NULL == radio_id)
        return NULL;

    radio = create_radio(radio_id, al_mac);
    if(NULL == radio)
        return NULL;

    if(al_mac) {
        map_ale_info_t *ale = get_ale(al_mac);
        if(ale) {
            char retry_id[MAX_TIMER_ID_STRING_LENGTH];
            GET_RETRY_ID(radio->radio_id, POLICY_CONFIG_RETRY_ID, retry_id);
            if(-1 == map_register_retry((const char*)retry_id, 10 , 10 ,
                                        ale, NULL, map_build_and_send_policy_config)) {
                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Failed Registering retry timer : %s ", retry_id);
            }
        }
    }

    /* Update roaming engine to indicate newly created radio */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_RADIO(radio);

    return radio;
}

void mgmt_ipc_agent_hook(map_ale_info_t* ale, uint8_t is_onboarded) {
    uint32_t event = is_onboarded ? MAP_IPC_TAG_NOTIFY_ALE_UPDATE : MAP_IPC_TAG_NOTIFY_ALE_ONBOARD;
    #ifdef MAP_MGMT_IPC
    map_controller_mgmt_ipc_send(event,(void *)ale);
    #endif
}

uint8_t is_agent_onboarded(map_ale_info_t *ale) {
    if(NULL == ale)
        return 0;

    map_radio_info_t *radio     = NULL;
    uint8_t ale_onboarded       = 0;

    for(uint8_t radio_index = 0; radio_index < ale->num_radios; radio_index++, radio = NULL) {
        radio = ale->radio_list[radio_index];
        if(radio == NULL)
            continue;
        // Mark the agent as onboarded if atleast one radio is in configured state
        ale_onboarded |= is_radio_configured(radio->state);
    }
    return ale_onboarded;
}

uint8_t is_all_radio_configured(map_ale_info_t* ale) {
    if(ale) {
        uint8_t num_of_configured_radios = get_configured_radio_count(ale);
        if(num_of_configured_radios && (num_of_configured_radios == ale->num_radios))
            return 1;
    }
    return 0;
}

uint8_t get_configured_radio_count(map_ale_info_t* ale) {
    int8_t num_of_configured_radios = 0;
    if(ale){
        map_radio_info_t *radio = NULL;
        for(uint8_t radio_index = 0; radio_index < ale->num_radios; radio_index++, radio = NULL)
        {
            radio = ale->radio_list[radio_index];
            if(radio) {
                num_of_configured_radios += is_radio_configured(radio->state);
            }
        }
    }
    return num_of_configured_radios;
}
