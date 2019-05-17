/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_action_callbacks.h"
#include "multiap_controller.h"
#include "multiap_controller_callbacks.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_tlv_parser.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_post_onboarding_handler.h"
#include "multiap_controller_topology_tree_builder.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "platform_multiap_get_info.h"
#include "map_data_model.h"
#include "map_data_model_dumper.h"
#include "map_topology_tree.h"
#include "1905_platform.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "monitor_task.h"
#include "mon_platform.h"


int8_t map_action_topology_discovery (struct CMDU *cmdu) {

    int8_t status      = 0;
    int8_t send_update = 0;
    do {
        uint8_t tlv_index        = 0;
        struct alMacAddressTypeTLV *al_mac_tlv       = NULL;
        struct macAddressTypeTLV   *upstream_mac_tlv = NULL;

        while (NULL != cmdu->list_of_TLVs[tlv_index])
        {
            switch (*(uint8_t*)cmdu->list_of_TLVs[tlv_index])
            {
                case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                {

                    al_mac_tlv = (struct alMacAddressTypeTLV*)cmdu->list_of_TLVs[tlv_index];
                    break;
                }
                case TLV_TYPE_MAC_ADDRESS_TYPE:
                {
                    upstream_mac_tlv = (struct macAddressTypeTLV*) cmdu->list_of_TLVs[tlv_index];
                }
                default:
                {
                    // Skip the 1905 TLVs
                    break;
                }
            }
            ++tlv_index;
        }

        char mac_str[MAX_MAC_STRING_LEN];
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "<-- CMDU_TYPE_TOPOLOGY_DISCOVERY - %s (%s)" , MAC_AS_STR(al_mac_tlv->al_mac_address, mac_str), cmdu->interface_name);
        
        map_ale_info_t *ale = NULL;
        if(al_mac_tlv)
            ale = map_handle_new_agent_onboarding(al_mac_tlv->al_mac_address, cmdu->interface_name);

        if(ale) {
            // Update the topology tree
            add_as_child_of_controller(ale);

            // Update Upstream Remote interface mac
            struct interfaceInfo m = {0};
            platform_get(MAP_PLATFORM_GET_INTERFACE_INFO, cmdu->interface_name, (void *)&m);

            send_update |= map_update_ale_upstream_local_mac(ale, upstream_mac_tlv->mac_address);
            send_update |= map_update_ale_upstream_remote_mac(ale, m.mac_address);
            send_update |= map_update_ale_upstream_iface_type(ale,m.interface_type);

            // Update the receiving interface name.
            map_update_ale_recving_iface(ale, cmdu->interface_name);

            if(send_update) {
                /* Send Agent Update whenever upstream MAC/TYPE changes */
                map_controller_send_agent_update(CMDU_TYPE_TOPOLOGY_RESPONSE,ale);
            }
        }
    }
    while(0);

    return status;
}

int8_t map_action_autoconfig_search (struct CMDU *cmdu) {

    struct alMacAddressTypeTLV *al_mac_tlv = NULL;

    if( 0 == get_tlv_fromcmdu(TLV_TYPE_AL_MAC_ADDRESS_TYPE, cmdu, (void *)&al_mac_tlv)) {

        // Create new ALE and send topology query node if it doesn't exists
        if (NULL != map_handle_new_agent_onboarding(al_mac_tlv->al_mac_address, cmdu->interface_name)){

            // Send Auto configuration response
            return map_send_autoconfig_response(cmdu);
        }
    }
    return -1;
}

int8_t map_action_topology_response(struct CMDU *cmdu) {
    int8_t status = 0;
    uint8_t is_ale_updated = 0;
    do{
        struct deviceInformationTypeTLV *dev_info_tlv                      =  NULL;
        ap_oerational_BSS_tlv_t         *operation_bss_tlv                 =  NULL;
        associated_clients_tlv_t        *associated_sta                    =  NULL;
        struct neighborDeviceListTLV    *neigh_dev_tlv[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
        uint8_t neighbor_tlv_count      =  0;
        uint8_t tlv_index               =  0;


        while (NULL != cmdu->list_of_TLVs[tlv_index])
        {
            switch (*(uint8_t*)cmdu->list_of_TLVs[tlv_index])
            {
                case TLV_TYPE_DEVICE_INFORMATION_TYPE:
                {
                    dev_info_tlv = (struct deviceInformationTypeTLV*) cmdu->list_of_TLVs[tlv_index];
                    break;
                }
                case TLV_TYPE_AP_OPERATIONAL_BSS:
                {
                    operation_bss_tlv = (ap_oerational_BSS_tlv_t*) cmdu->list_of_TLVs[tlv_index];
                    break;
                }
                case TLV_TYPE_ASSOCIATED_STA_TLV:
                {
                    associated_sta = (associated_clients_tlv_t*) cmdu->list_of_TLVs[tlv_index];
                    break;
                }
                case TLV_TYPE_NEIGHBOR_DEVICE_LIST:
                {
                    neigh_dev_tlv[neighbor_tlv_count] = (struct neighborDeviceListTLV*)cmdu->list_of_TLVs[tlv_index];
                    neighbor_tlv_count++;
                    break;
                }
                default:
                {
                    break;
                }
            }
            ++tlv_index;
        }

        char mac_str[MAX_MAC_STRING_LEN];
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "<-- CMDU_TYPE_TOPOLOGY_RESPONSE - %s (%s)" , MAC_AS_STR(dev_info_tlv->al_mac_address, mac_str), cmdu->interface_name);

        // Parse and update the local interface list
        status = parse_device_info_tlv(dev_info_tlv);
        map_ale_info_t* ale = get_ale(dev_info_tlv->al_mac_address);
        if(status == 0 && ale != NULL) {
            // Update the receiving interface name.
            map_update_ale_recving_iface(ale, cmdu->interface_name);

            // Parse and update the neighbor list
            parse_neighbor_device_list_tlv(neigh_dev_tlv, neighbor_tlv_count, ale);

            /* Parse and update the radio and BSS info. The ale update is to find if there is 
                        any change in radio/bss/bss type and send Agent Update to VE daemon */
            
            parse_ap_operational_bss_tlv(operation_bss_tlv, ale, &is_ale_updated);

            // Parse and update the connected clients
            parse_associated_clients_tlv(associated_sta);

            // Store the last received topology response message
            ale->keep_alive_time = get_current_time();

            // When there is a new BSS or radio created send updates
            if(is_ale_updated == MAP_VALID_UPDATE) {
                map_controller_send_agent_update(cmdu->message_type,ale); 

            }
        }
    } while(0);

    // TODO: Remove it
    lib1905_set(handle_1905, SET_1905_TOPOLOGY_RESPONSE_CMDU, 1, cmdu);

    return status;
}

int8_t map_action_ap_caps_report (struct CMDU *cmdu)
{
    AP_capability_tlv_t         *ap_caps       = NULL;
    AP_basic_capability_tlv_t   *ap_basic_caps = NULL;
    uint8_t *p;
    int     status = 0;
    uint8_t current_supported_freq = max_freq_type;
    uint8_t is_current_supported_freq_updated = 0;

    for (int8_t i = 0; NULL != (p = cmdu->list_of_TLVs[i]); i++)
    {
        switch (*p)
        {
            case TLV_TYPE_AP_CAPABILITY:
            {
                ap_caps = (AP_capability_tlv_t*) p;
                break;
            }
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
            {
                map_radio_info_t *radio = NULL;
                ap_basic_caps = (AP_basic_capability_tlv_t*) p;
                if(ap_basic_caps != NULL)
                {
                    radio = get_radio(ap_basic_caps->radioId);
                    if(radio != NULL)
                    {
                        current_supported_freq = radio->supported_freq;
                        parse_ap_basic_caps_tlv(ap_basic_caps, NULL);
                        if(current_supported_freq != radio->supported_freq)
                        {
                            platform_log(MAP_CONTROLLER,LOG_DEBUG,"Radio Supported Freq Updated\n");
                            is_current_supported_freq_updated = 1;
                        }
                    }
                }
                break;
            }
            case TLV_TYPE_AP_HT_CAPABILITY:
            {
                parse_ap_ht_caps_tlv((AP_HT_capability_tlv_t*)p);
                break;
            }
            case TLV_TYPE_AP_VHT_CAPABILITY:
            {
                parse_ap_vht_caps_tlv((AP_VHT_capability_tlv_t*)p);
                break;
            }
            case TLV_TYPE_AP_HE_CAPABILITY:
            {
                parse_ap_he_caps_tlv((AP_HE_capability_tlv_t*)p);
                break;
            }
            default:
            {
                status = -1;
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"Unexpected TLV type (%d) inside CMDU\n", *p);
                break;
            }
        }
    }

    if(ap_caps != NULL && ap_basic_caps != NULL) {
        map_radio_info_t *radio = get_radio(ap_basic_caps->radioId);
        if(radio != NULL && radio->ale != NULL) {
            parse_ap_caps_tlv(ap_caps, radio->ale);

            /* This update is done for JIRA - NG-187627. When a controller is restarted, radio_type is sent as 0.
                    Radio type is updated in  AP basic capabilities TLV which is also part of WSC messages for which
                    we send an WSC Agent Update to VE. But when a controller restarts, there is no requirement for an 
                    Agent to re-onboard and so there are no WSC messages and no agent update.
                    AP basic capability TLV is also part of the AP Capability Report, so we now send TOPO message update here instead.
                    The decision to send Agent Update on all WSC message was already taken and hence the below checks are 
                    necessary to not make it duplicate */
            if(is_current_supported_freq_updated == 1)
                map_controller_send_agent_update(CMDU_TYPE_TOPOLOGY_RESPONSE,radio->ale);
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Radio not found! or orphaned Radio!\n",__func__);
        }
    }
    else {
        status = -1;
    }

    return status;
}

int8_t map_action_ap_metrics_response (struct CMDU *cmdu) {

    uint8_t *current_tlv = NULL;

    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ ) {
        switch (*current_tlv)
        {
            case TLV_TYPE_AP_METRICS_RESPONSE:
            {
                parse_ap_metrics_response_tlv((ap_metrics_response_tlv_t*)current_tlv);
                break;
            }
            case TLV_TYPE_ASSOC_STA_TRAFFIC_STATS:
            {
                parse_assoc_sta_traffic_stats_tlv((assoc_sta_traffic_stats_tlv_t*)current_tlv);
                break;
            }
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
            {
                parse_assoc_sta_link_metrics_tlv((associated_sta_link_metrics_t*)current_tlv);
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
                break;
            }
        }
    }

    /* Update roaming engine with new agent metrics */  
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_AP_METRICS_RESPONSE(cmdu);

    return 0;
}

int8_t map_action_assoc_sta_link_metrics(struct CMDU *cmdu) {
    int status = 0;
    do
    {
        if (NULL == cmdu->list_of_TLVs){
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE Malformed structure.");
            ERROR_EXIT(status)
        }

        // An error scenario handling
        error_code_tlv_t *err_code_tlv = NULL;
        get_tlv_fromcmdu(TLV_TYPE_ERROR, cmdu, (void *)&err_code_tlv);
        if(err_code_tlv != NULL) {
            int8_t sta_mac_str[MAX_MAC_STRING_LEN] = {0};
            get_mac_as_str(err_code_tlv->sta_mac_addr, sta_mac_str, MAX_MAC_STRING_LEN);
            platform_log(MAP_CONTROLLER,LOG_ERR, "TLV_TYPE_ASSOCIATED_STA_LINK_METRICS Response Error for STA : %s : Reason : %d.\n",
                                            sta_mac_str, err_code_tlv->reason_code);

            break; // Returning zero for now.
        }

        uint8_t *current_tlv = NULL;
        // Update the metrics to our datamodel
        for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ )
        {
            if(*current_tlv == TLV_TYPE_ASSOCIATED_STA_LINK_METRICS) {
                parse_assoc_sta_link_metrics_tlv((associated_sta_link_metrics_t*)current_tlv);
            }
            else {

                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
            }
        }
    } while (0);

    return status;
}

int8_t map_action_beacon_metrics_response(struct CMDU *cmdu)
{
    map_handle_t map_handle;

    /* TODO: Update DM */

    /* Forward beacon metric response to roaming engine */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_BEACON_METRICS_RESPONSE(cmdu);

    /* Send 1905 ACK */
    memcpy(map_handle.dest_addr, cmdu->cmdu_stream.src_mac_addr, ETHER_ADDR_LEN);
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu   = cmdu;

    if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
        return -1;
    }

    return 0;
}

int8_t map_action_vendor_specific(struct CMDU *cmdu)
{
    struct vendorSpecificTLV *vendor_specific_tlv = NULL;
    uint8_t *p = NULL;
    map_handle_t map_handle;
    
    for ( uint8_t i = 0; NULL != (p = cmdu->list_of_TLVs[i]) ; i++ )  
    {
        switch (*p)
        {
            case TLV_TYPE_VENDOR_SPECIFIC:
            {
                vendor_specific_tlv = (struct vendorSpecificTLV*) p;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"TODO TLV (%d) type inside CMDU\n", (uint8_t)(*p));
                break;
            }
        }
    }
    if(vendor_specific_tlv)
    {
    #ifdef MAP_MGMT_IPC
        if(-1 == map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_1905_DATA, cmdu))
        {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s Failed Sending Vendor Specific Data\n", __func__);
            return -1;
        }
        /* Send 1905 ACK */
        memcpy(map_handle.dest_addr, cmdu->cmdu_stream.src_mac_addr, ETHER_ADDR_LEN);
        map_handle.handle_1905 = handle_1905;
        map_handle.recv_cmdu   = cmdu;

        if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
            return -1;
        }
        return 0;
    #endif
    }
    return -1;
}

int8_t map_action_ack(struct CMDU *cmdu)
{
#ifdef MAP_MGMT_IPC
    platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s CMDU ACK Message ID - %d \n",__func__,cmdu->message_id);
    if(map_controller_mgmt_ipc_is_pending_ack(cmdu->message_id))
    {
        if(-1 == map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_1905_DATA, cmdu))
        {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s Failed Sending 1905 ACK\n", __func__);
            return -1;
        }
    }

    return 0;
#endif

}

int8_t map_ctrl_higher_layer_data_msg_ack(struct CMDU *recv_cmdu)
{
    map_handle_t  map_handle;

    struct mapHigherLayerDataTLV *higher_layer_data = NULL;
    /* Input Parameters Validation */
    if (NULL == recv_cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input Parameters Validation", __func__);
        return -1;
    }

    higher_layer_data = (struct mapHigherLayerDataTLV *) recv_cmdu->list_of_TLVs[0];
    if ((NULL == higher_layer_data) || (TLV_TYPE_HIGHER_LAYER_DATA_MSG != higher_layer_data->tlv_type)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "higher layer data msg tlv missing");
        goto Cleanup;
    }

    /* Send 1905 Ack  */
    memcpy(map_handle.dest_addr, recv_cmdu->cmdu_stream.src_mac_addr, 6);
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu = recv_cmdu;

    if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
        goto Cleanup;
    }

    return 0;

Cleanup:

    if(recv_cmdu != NULL) {
        lib1905_cmdu_cleanup(recv_cmdu);
    }

    return -1;
}


int8_t map_send_unassoc_sta_metrics_ack(struct CMDU *recv_cmdu)
{
    map_handle_t  map_handle;

    struct mapUnassocStaMetricsResponseTLV *unassoc_metrics = NULL;
    /* Input Parameters Validation */
    if (NULL == recv_cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input Parameters Validation", __func__);
        return -1;
    }

    unassoc_metrics = (struct mapUnassocStaMetricsResponseTLV *) recv_cmdu->list_of_TLVs[0];
    if ((NULL == unassoc_metrics) || (TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE != unassoc_metrics->tlv_type)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "unassociated_sta_link_metrics tlv missing");
        goto Cleanup;
    }

    /* Send 1905 Ack  */
    memcpy(map_handle.dest_addr, recv_cmdu->cmdu_stream.src_mac_addr, 6);
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu = recv_cmdu;

    if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
        goto Cleanup;
    }


    /* update the unassoc metrics to corresponding ale */
    map_ale_info_t* ale     = NULL;
    struct mapUnassocStaMetricsResponseTLV * unassoc_sta_metrics = NULL;

    ale = get_ale(map_handle.dest_addr);
    if(ale != NULL) {
        /* free previous unassoc response */
        free(ale->unassoc_metrics);

        unassoc_sta_metrics = (struct mapUnassocStaMetricsResponseTLV *) malloc(sizeof(struct mapUnassocStaMetricsResponseTLV) + (sizeof(struct sta_rcpi_list) * unassoc_metrics->sta_cnt));
        if(unassoc_sta_metrics == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "unable to create unassoc metrics list");
            goto Cleanup;

        }

        unassoc_sta_metrics->oper_class = unassoc_metrics->oper_class;
        unassoc_sta_metrics->sta_cnt  = unassoc_metrics->sta_cnt;

        for(int i = 0; i <unassoc_metrics->sta_cnt; i++){
            memcpy(unassoc_sta_metrics->sta_list[i].sta_mac, unassoc_metrics->sta_list[i].sta_mac, MAC_ADDR_LEN);
            unassoc_sta_metrics->sta_list[i].channel = unassoc_metrics->sta_list[i].channel;
            unassoc_sta_metrics->sta_list[i].time_delta = unassoc_metrics->sta_list[i].time_delta;
            unassoc_sta_metrics->sta_list[i].rcpi_uplink =  unassoc_metrics->sta_list[i].rcpi_uplink;
        }

        ale->unassoc_metrics = (void  *)unassoc_sta_metrics;
    }

    /* Update roaming engine with new unnassoc sta data */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_UNASSOC_STA_METRICS_RESPONSE(recv_cmdu);

    return 0;
Cleanup:
    return -1;
}

int8_t flush_operating_class_data(channel_preference_tlv_t* channel_pref_tlv, 
                                radio_operation_restriction_tlv_t* ops_restriction) {

    map_ale_info_t *ale = NULL;
    map_radio_info_t *radio = (channel_pref_tlv)? get_radio(channel_pref_tlv->radio_id) : get_radio(ops_restriction->radio_id);
    if(radio == NULL)
    {
        return 0;
    }
    ale = radio->ale;
    if(ale){
        for (uint8_t i = 0; i < ale->num_radios; ++i)
        {
            radio = ale->radio_list[i];
            if(radio) {
                if(radio->op_class_count && radio->op_class_list)
                    memset(radio->op_class_list, 0 , radio->op_class_count * sizeof(map_op_class_t));
                radio->op_class_count = 0;
            }
        }
    }
    return 1;
}

int8_t map_action_channel_pref_report(struct CMDU *cmdu) {
    uint8_t *current_tlv = NULL;
    uint8_t is_flushed   = 0;
    map_ale_info_t *ale  = NULL;

    channel_preference_tlv_t *channel_pref_tlv = NULL;
    radio_operation_restriction_tlv_t *ops_restriction = NULL;

    // Flushout all the old data

    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++, channel_pref_tlv = NULL, ops_restriction = NULL ) {
        switch (*current_tlv) {
            case TLV_TYPE_CHANNEL_PREFERENCE:
            {
                channel_pref_tlv = (channel_preference_tlv_t*)current_tlv;
                break;
            }
            case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
            {
                ops_restriction = (radio_operation_restriction_tlv_t*)current_tlv;
                break;
            }
            default: 
            {
                 platform_log(MAP_CONTROLLER,LOG_ERR,"Channel selection response response contains unexpected TLV type (%d)", *current_tlv);
                 break;
            }
        }
        // Flush all the old date when new preference report is received
        if(is_flushed == 0) {
            if(channel_pref_tlv || ops_restriction) {
                is_flushed = flush_operating_class_data(channel_pref_tlv, ops_restriction);
            }
        }

        if(channel_pref_tlv)
            parse_chan_pref_tlv(channel_pref_tlv);
        else if(ops_restriction)
            parse_op_restriction_tlv(ops_restriction);

        // Get the ALE node to send channel selection request
        if(ale == NULL) {
            map_radio_info_t *radio = NULL;
            if(channel_pref_tlv)
                radio = get_radio(channel_pref_tlv->radio_id);
            else if(ops_restriction)
                radio = get_radio(ops_restriction->radio_id);

            if(radio)
                ale = radio->ale;
        }
    }

    // Send Ack to the agent that we received the preference report.
    map_handle_t handle = {{0},{0}, 0, NULL, cmdu, 0, NULL};

    if(-1 == map_send_1905_ack(&handle, NULL, 0)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s Unable to send ack to agent.", __func__);
        return -1;
    }

    // Initialte channel selection request
    chan_sel_action_t ch_sel_action = {ale, MAP_CHAN_SEL_REQUEST};
    map_agent_handle_channel_selection(NULL, &ch_sel_action);

    return 0;
}

int8_t map_action_channel_selec_response(struct CMDU *cmdu) {

    // Validation is already completed. Lets continue with the action
    channel_selection_response_tlv_t *chan_sel_tlv = (channel_selection_response_tlv_t*)cmdu->list_of_TLVs[0];

    if(chan_sel_tlv && chan_sel_tlv->tlv_type == TLV_TYPE_CHANNEL_SELECTION_RESPONSE) {
        if(MAP_CHAN_SEL_ACCEPTED != chan_sel_tlv->channel_selection_response) {
            map_radio_info_t *radio = get_radio(chan_sel_tlv->radio_id);
            if(radio) {
                // If the channel selection is not accepted, Restart the channel selection proccess by
                // starting from the preference query -> preference report -> request -> response.
                // chan_sel_action_t ch_sel_action = {radio->ale, MAP_CHAN_SEL_QUERY};
                // map_agent_handle_channel_selection(NULL, &ch_sel_action);

                // TODO : Broadcom Agent did not accept the preference that we sent
                //         Note : controller sends the same preference received in channele pref report.
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Channel selection request denied. Reason Code: %d", __func__,
                                                                chan_sel_tlv->channel_selection_response);
            }
            else{
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Radio node not found in controller data model", __func__);
                return -1;
            }
        }
        else{
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "Agent channel selection process completed.");
            // TODO: Should we verify the channel selection by current opearating channel query?
        }
    }
    else {
        return -1;
    }

    return 0;
}
int8_t map_action_operating_channel_report(struct CMDU *cmdu)
{
	uint8_t *p = NULL;
	operating_channel_report_tlv_t *rep = NULL;
	map_radio_info_t* radio;
	map_handle_t map_handle={0};

	/*Donot move this code any where below , This has to be the First Function that Executes*/
	 /* !!!!Send 1905 ACK  BEGINS !!!! */
	memcpy(map_handle.dest_addr, cmdu->cmdu_stream.src_mac_addr, ETHER_ADDR_LEN);
	map_handle.handle_1905 = handle_1905;
	map_handle.recv_cmdu   = cmdu;

	if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
		platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
		return -1;
	}
	 /* !!!!Send 1905 ACK  ENDS!!!!*/

	for ( uint8_t i = 0; NULL != (p = cmdu->list_of_TLVs[i]) ; i++ ) {
        switch (*p) {
            case TLV_TYPE_OPERATING_CHANNEL_REPORT: 
            {
                rep = (operating_channel_report_tlv_t*) p;
                if (rep->numOperating_class > 0 && NULL != (radio = get_radio(rep->radio_id))) {
                    radio->current_op_class   = rep->operating_class[0].operating_class;
                    radio->current_op_channel = rep->operating_class[0].current_op_channel;

                    /* Update roaming engine to indicate new channel */
                    MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_RADIO(radio);
                }
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"TODO TLV (%d) type inside CMDU\n", (uint8_t)(*p));
                break;
            }
        }
    }
    if (rep == NULL || rep->numOperating_class==0) {
        return -1;
    }
	return 0;
}
int8_t map_action_topology_notification(struct CMDU *cmdu) {

    struct alMacAddressTypeTLV     *al_mac_tlv      = NULL;
    client_association_event_tlv_t *client_assoc_tlv = NULL;
    uint8_t *current_tlv = NULL;
    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ )  
    {
        switch (*current_tlv)
        {
            case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
            {
                al_mac_tlv = (struct alMacAddressTypeTLV*) current_tlv;
                break;
            }
            case TLV_TYPE_CLIENT_ASSOCIATION_EVENT:
            {
                client_assoc_tlv = (client_association_event_tlv_t *) current_tlv;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"TODO TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
                break;
            }
        }
    }

    int8_t          status = 0;
    map_ale_info_t  *ale   = NULL;
    do
    {
        if(al_mac_tlv) {
            ale = get_ale(al_mac_tlv->al_mac_address);
            if(ale == NULL) {
                ale = map_handle_new_agent_onboarding(al_mac_tlv->al_mac_address, cmdu->interface_name);
                break;
            }

            if(ale) {
                // Update the receiving interface name
                map_update_ale_recving_iface(ale, cmdu->interface_name);

                if(client_assoc_tlv) {
                    parse_client_assoc_tlv(ale, client_assoc_tlv);
                }
                else {
                    // This is an empty topology notification, send Topology query to check what has changed
                    map_send_topology_query(NULL, ale);
                }
            }

        }


    } while (0);

    return status;
}

static void fill_link_met_platform_cmd (struct neighbour_entry *neighbour_list, map_ale_info_t* neighbour_ale) {

    map_ale_info_t *root_ale = NULL;
    do
    {
        if ((NULL == neighbour_list) || (NULL == neighbour_ale)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input data is NULL.",__func__);
            break;
        }

        root_ale = get_root_ale_node();
        memcpy (neighbour_list->local_almac, root_ale->al_mac, MAC_ADDR_LEN);
        memcpy (neighbour_list->neighbour_almac, neighbour_ale->al_mac, MAC_ADDR_LEN);
        memcpy (neighbour_list->neighbour_iface_mac, neighbour_ale->upstream_local_iface_mac, MAC_ADDR_LEN);
        strncpy (neighbour_list->interface_name, neighbour_ale->iface_name, MAX_IFACE_NAME_LEN);
        neighbour_list->interface_name[MAX_IFACE_NAME_LEN-1] = '\0';
    } while (0);

    return;
}

static neighbour_link_met_platform_cmd_t *get_link_met_platform_cmd(struct CMDU *recv_cmdu) {

    neighbour_link_met_platform_cmd_t *platform_cmd = NULL;
    struct linkMetricQueryTLV *link_met_query_tlv   = NULL;
    map_ale_info_t *neighbour_ale = NULL;
    map_ale_info_t *root_ale      = NULL;
    int is_specific_neighbour_req = 0;
    int neighbour_cnt             = 0;
    int counter                   = 0;

    do
    {
        if ((NULL == recv_cmdu) || (NULL == recv_cmdu->list_of_TLVs)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_LINK_METRIC_QUERY Malformed structure.");
            break;
        }

        link_met_query_tlv = (struct linkMetricQueryTLV *) recv_cmdu->list_of_TLVs[0];
        if (NULL == link_met_query_tlv) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"linkMetricQueryTLV missing.");
            break;
        }

        is_specific_neighbour_req = link_met_query_tlv->destination;
        root_ale                  = get_root_ale_node();
        neighbour_cnt             = map_get_child_count(root_ale);

        if (neighbour_cnt <= 0)        break;
        if (is_specific_neighbour_req) neighbour_cnt = 1;

        platform_cmd = (neighbour_link_met_platform_cmd_t *) calloc (1, (sizeof(neighbour_link_met_platform_cmd_t) + (neighbour_cnt * sizeof(struct neighbour_entry))));
        if (NULL == platform_cmd) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s : Calloc Failed for platform_cmd.",__func__);
            break;
        }

        platform_cmd->mid                = recv_cmdu->message_id;
        platform_cmd->request_type       = link_met_query_tlv->link_metrics_type;
        platform_cmd->neighbour_entry_nr = neighbour_cnt;

        memcpy  (platform_cmd->dst_mac, recv_cmdu->cmdu_stream.src_mac_addr, MAC_ADDR_LEN);
        strncpy (platform_cmd->dst_iface_name, recv_cmdu->interface_name, MAX_IFACE_NAME_LEN);
        platform_cmd->dst_iface_name[sizeof(platform_cmd->dst_iface_name)-1] = '\0';

        if(is_specific_neighbour_req) {
            neighbour_ale = get_ale(link_met_query_tlv->specific_neighbor);

            if(neighbour_ale == NULL) {
                platform_log(MAP_CONTROLLER,LOG_ERR,"get_ale failed for neighbour_ale.");
                free(platform_cmd);
                break;
            }

            fill_link_met_platform_cmd(&platform_cmd->neighbour_list[counter], neighbour_ale);
            counter++;
        }
        else {
            foreach_neighbors_of(root_ale, neighbour_ale) {
                if(neighbour_ale) {
                    fill_link_met_platform_cmd(&platform_cmd->neighbour_list[counter], neighbour_ale);
                    counter++;
                }
            }
        }
        platform_cmd->neighbour_entry_nr = counter;

    } while (0);

    return platform_cmd;
}

int8_t map_action_link_metrics_query(struct CMDU *recv_cmdu) {

    int8_t status         = 0;
    map_monitor_cmd_t cmd = {0};
    struct linkMetricQueryTLV         *link_met_query_tlv = NULL;
    neighbour_link_met_platform_cmd_t *platform_cmd       = NULL;
    do
    {
        if ((NULL == recv_cmdu) || (NULL == recv_cmdu->list_of_TLVs)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_LINK_METRIC_QUERY Malformed structure.");
            ERROR_EXIT(status)
        }

        link_met_query_tlv = (struct linkMetricQueryTLV *) recv_cmdu->list_of_TLVs[0];
        if (NULL == link_met_query_tlv) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"linkMetricQueryTLV missing.");
            ERROR_EXIT(status)
        }

        platform_cmd  = get_link_met_platform_cmd(recv_cmdu);
        if (NULL == platform_cmd) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"get_link_met_platform_cmd Failed.");

            if (link_met_query_tlv->destination) {
                if (-1 == map_send_link_metrics_result_code(recv_cmdu)) {
                    platform_log(MAP_CONTROLLER,LOG_ERR,"map_send_link_metrics_result_code failed");
                    ERROR_EXIT(status)
                }
            }
            break;
        }

        cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
        cmd.subcmd = MAP_MONITOR_GET_NEIGHBOUR_LINK_MET_METHOD_SUBCMD;
        cmd.param  = (void *)platform_cmd;

        if(0 != map_monitor_send_cmd(cmd)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
            free(platform_cmd);
        }
    } while (0);

    return status;
}

int compare_neighbor_link_metrics_node(void* link_metrics_node, void* al_mac) {
    if(link_metrics_node && al_mac) {
        if (memcmp(((map_neighbor_link_metric_t*)link_metrics_node)->al_mac, al_mac, MAC_ADDR_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

static uint8_t map_update_tx_params(struct transmitterLinkMetricTLV *tlv, map_neighbor_link_metric_t *neighbor_link_metrics) {
    memcpy(neighbor_link_metrics->al_mac, tlv->neighbor_al_address, MAC_ADDR_LEN);
    memcpy(neighbor_link_metrics->neighbor_iface_mac, tlv->transmitter_link_metrics->neighbor_interface_address, MAC_ADDR_LEN);
    memcpy(neighbor_link_metrics->local_iface_mac,    tlv->transmitter_link_metrics->local_interface_address, MAC_ADDR_LEN);

    neighbor_link_metrics->intf_type = tlv->transmitter_link_metrics->intf_type;
    neighbor_link_metrics->tx_metric.packet_errors           = tlv->transmitter_link_metrics->packet_errors;
    neighbor_link_metrics->tx_metric.transmitted_packets     = tlv->transmitter_link_metrics->transmitted_packets;
    neighbor_link_metrics->tx_metric.mac_throughput_capacity = tlv->transmitter_link_metrics->mac_throughput_capacity;
    neighbor_link_metrics->tx_metric.link_availability       = tlv->transmitter_link_metrics->link_availability;
    neighbor_link_metrics->tx_metric.phy_rate                = tlv->transmitter_link_metrics->phy_rate;

    return 0;
}

static uint8_t map_update_rx_params(struct receiverLinkMetricTLV *tlv, map_neighbor_link_metric_t *neighbor_link_metrics) {
    memcpy(neighbor_link_metrics->al_mac, tlv->neighbor_al_address, MAC_ADDR_LEN);
    memcpy(neighbor_link_metrics->neighbor_iface_mac, tlv->receiver_link_metrics->neighbor_interface_address, MAC_ADDR_LEN);
    memcpy(neighbor_link_metrics->local_iface_mac,    tlv->receiver_link_metrics->local_interface_address, MAC_ADDR_LEN);

    neighbor_link_metrics->intf_type = tlv->receiver_link_metrics->intf_type;
    neighbor_link_metrics->rx_metric.packet_errors        = tlv->receiver_link_metrics->packet_errors;
    neighbor_link_metrics->rx_metric.packets_received     = tlv->receiver_link_metrics->packets_received;
    neighbor_link_metrics->rx_metric.rssi                 = tlv->receiver_link_metrics->rssi;

    return 0;
}

static map_neighbor_link_metric_t* map_get_neighbor_metrics(array_list_t *link_metrics_list, uint8_t *al_mac) {

    // Check if it already exists
    map_neighbor_link_metric_t *link_metrics = find_object(link_metrics_list , al_mac, compare_neighbor_link_metrics_node);

    // Create a new object if it doesn't exists
    if(NULL == link_metrics){
        link_metrics = (map_neighbor_link_metric_t *)calloc(1, sizeof(map_neighbor_link_metric_t));

        if ((link_metrics) && (-1 == push_object(link_metrics_list, link_metrics))) {
            free(link_metrics);
            link_metrics = NULL;
        }
    }
    return link_metrics;
}

static void map_cache_updated_link_metrics(array_list_t *link_metrics_list, map_neighbor_link_metric_t *link_metrics) {
    if(NULL == find_object(link_metrics_list , link_metrics->al_mac, compare_neighbor_link_metrics_node)) {
        if(push_object(link_metrics_list, link_metrics) == -1) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s Failed to add to the new neighbor link metrics list\n",__func__);
        }
    }
}

void map_parse_tx_link_metrics_tlv(struct transmitterLinkMetricTLV  *tx_tlv, array_list_t *link_metrics_cache_list, map_ale_info_t **ale) {
    map_ale_info_t *current_ale = NULL;
    map_ale_info_t *neighbor_ale = NULL;
    map_bss_info_t *bss = NULL;
    map_neighbor_link_metric_t *link_metrics = NULL;
    int8_t send_update = 0;

    do
    {
        // Validate the TLV struct params
        if(tx_tlv->transmitter_link_metrics_nr == 0 || tx_tlv->transmitter_link_metrics == NULL)
            break;

        // Get the current/neighbor ALE for which link metrics reported
        current_ale  = get_ale(tx_tlv->local_al_address);
        neighbor_ale = get_ale(tx_tlv->neighbor_al_address);
        if(current_ale == NULL || neighbor_ale == NULL)
            break;

        // If the reported neighbor is parent update it as a upstream link metrics
        if(is_parent_of(neighbor_ale, current_ale)) {
            // One of the source of updating upstream local interface MAC
            send_update |= map_update_ale_upstream_local_mac(current_ale, tx_tlv->transmitter_link_metrics->local_interface_address);
            send_update |= map_update_ale_upstream_iface_type(current_ale,tx_tlv->transmitter_link_metrics->intf_type);

            map_update_tx_params(tx_tlv, &current_ale->upstream_link_metrics);

            if(send_update) {
                /* Send Agent Update whenever upstream MAC/TYPE changes */
                map_controller_send_agent_update(CMDU_TYPE_TOPOLOGY_RESPONSE,current_ale);
            }

            *ale = current_ale;
            break;
        }

        /* 
         * Check if the current ale is parent of neighbour ale,
         * This will make sure the link between neighbour and current
         * is proper.
         */
        if(is_parent_of(current_ale, neighbor_ale)  || is_local_agent(current_ale)) 
        {

            bss = get_bss(tx_tlv->transmitter_link_metrics->local_interface_address);
    
            if(bss) {
                // Neighbor connected via backhaul wifi interface. Update the link metrics under the BSS metrics list
                if(bss->radio == NULL || bss->radio->ale == NULL || bss->radio->ale != current_ale) {
                    platform_log(MAP_CONTROLLER,LOG_ERR, "Orphan BSS node or BSS is not associated with given ALE");
                    break;
                }

                if( !(bss->type | MAP_BACKHAUL_BSS)) {
                    platform_log(MAP_CONTROLLER,LOG_ERR, "Link metrics reported for non backhaul BSS");
                    break;
                }
    
                link_metrics = map_get_neighbor_metrics(bss->neigh_link_metric_list, tx_tlv->neighbor_al_address);
                if(NULL == link_metrics)
                    break;
            }
            else {
                // Neighbor connected via ethernet interface. Update the link metrics under the ethernet metrics list
                link_metrics = map_get_neighbor_metrics(current_ale->eth_neigh_link_metric_list, tx_tlv->neighbor_al_address);
                if(NULL == link_metrics)
                    break;
            }
    
            // Update the TX metrics into the metrics object
            map_update_tx_params(tx_tlv, link_metrics);
    
            // Store the newly created link mertics
            map_cache_updated_link_metrics(link_metrics_cache_list, link_metrics);
    
            *ale = current_ale;
        }
    } while (0);
}

void map_parse_rx_link_metrics_tlv(struct receiverLinkMetricTLV  *rx_tlv, array_list_t *link_metrics_cache_list, map_ale_info_t **ale) {
    map_ale_info_t *current_ale = NULL;
    map_ale_info_t *neighbor_ale = NULL;
    map_bss_info_t *bss = NULL;
    map_neighbor_link_metric_t *link_metrics = NULL;
    int8_t send_update = 0;

    do
    {
        // Validate the TLV struct params
        if(rx_tlv->receiver_link_metrics_nr == 0 || rx_tlv->receiver_link_metrics == NULL)
            break;

        // Get the current/neighbor ALE for which link metrics reported
        current_ale  = get_ale(rx_tlv->local_al_address);
        neighbor_ale = get_ale(rx_tlv->neighbor_al_address);
        if(current_ale == NULL || neighbor_ale == NULL)
            break;

        // If the reported neighbor is parent update it as a upstream link metrics
        if(is_parent_of(neighbor_ale, current_ale)) {
            // One of the source of updating upstream local interface MAC
            send_update |= map_update_ale_upstream_local_mac(current_ale, rx_tlv->receiver_link_metrics->local_interface_address);
            send_update |= map_update_ale_upstream_iface_type(current_ale,rx_tlv->receiver_link_metrics->intf_type);

            map_update_rx_params(rx_tlv, &current_ale->upstream_link_metrics);

            if(send_update) {
                /* Send Agent Update whenever upstream MAC/TYPE changes */
                map_controller_send_agent_update(CMDU_TYPE_TOPOLOGY_RESPONSE,current_ale);
            }

            *ale = current_ale;
            break;
        }

        /* 
         * Check if the current ale is parent of neighbour ale,
         * This will make sure the link between neighbour and current
         * is proper.
         */
        if(is_parent_of(current_ale, neighbor_ale) || is_local_agent(current_ale)) 
        {

            bss = get_bss(rx_tlv->receiver_link_metrics->local_interface_address);
           
            if(bss) {
                // Neighbor connected via backhaul wifi interface. Update the link metrics under the BSS metrics list
                if(bss->radio == NULL || bss->radio->ale == NULL || bss->radio->ale != current_ale)
                    break;
           
                link_metrics = map_get_neighbor_metrics(bss->neigh_link_metric_list, rx_tlv->neighbor_al_address);
                if(NULL == link_metrics)
                    break;
            }
            else {
                // Neighbor connected via ethernet interface. Update the link metrics under the ethernet metrics list
                link_metrics = map_get_neighbor_metrics(current_ale->eth_neigh_link_metric_list, rx_tlv->neighbor_al_address);
                if(NULL == link_metrics)
                    break;
            }
           
            // Update the RX metrics into the metrics object
            map_update_rx_params(rx_tlv, link_metrics);
           
            // Store the newly created link mertics
            map_cache_updated_link_metrics(link_metrics_cache_list, link_metrics);
           
            *ale = current_ale;
        }
    } while (0);
    return;
}

uint32_t map_get_all_iface_link_metrics_list(map_ale_info_t *ale, array_list_t **link_metrics_list) {
    uint8_t count = 0;
    map_radio_info_t *radio = NULL;
    map_bss_info_t   *bss   = NULL;

    if(ale && link_metrics_list){
        for(uint8_t radio_index = 0; radio_index < ale->num_radios; radio_index++) {
            radio = ale->radio_list[radio_index];
            if(radio == NULL)
                continue;
            for (uint8_t bss_index = 0; bss_index < radio->num_bss; ++bss_index) {
                bss = radio->bss_list[bss_index];
                if(bss && (bss->type | MAP_BACKHAUL_BSS) && bss->neigh_link_metric_list &&\
                    list_get_size(bss->neigh_link_metric_list) && (count <= (MAX_RADIOS_PER_AGENT * MAX_BSS_PER_RADIO))) {
                    link_metrics_list[count++] = bss->neigh_link_metric_list;
                }
            }
        }

        if (ale->eth_neigh_link_metric_list && list_get_size(ale->eth_neigh_link_metric_list) && (count <= (MAX_RADIOS_PER_AGENT * MAX_BSS_PER_RADIO))) {
            link_metrics_list[count++] = ale->eth_neigh_link_metric_list;
        }
    }
    return count;
}

void map_remove_old_link_metrics( map_ale_info_t *ale, array_list_t *new_link_metrics_list) {
    uint32_t list_count = 0;

    /*
     * array of array_list_t * with size as (MAX_RADIOS_PER_AGENT * MAX_BSS_PER_RADIO) + 1(Arraylist for ethernet devices)
     */
    array_list_t *link_metrics_list[(MAX_RADIOS_PER_AGENT * MAX_BSS_PER_RADIO) + 1] = {NULL};
    map_neighbor_link_metric_t      *existing_link_metrics                          = NULL;
    list_iterator_t iter;

    list_count = map_get_all_iface_link_metrics_list(ale, link_metrics_list);

    for (uint32_t i = 0; i < list_count; ++i, existing_link_metrics = NULL) {

        bind_list_iterator(&iter, link_metrics_list[i]);

        while(NULL != (existing_link_metrics = get_next_list_object(&iter))) {
            if(NULL == find_object(new_link_metrics_list , existing_link_metrics->al_mac, compare_neighbor_link_metrics_node)) {
                /*
                 * Remove the old object, since it is not exists in new_link_metrics_list
                 */
                free(remove_object(link_metrics_list[i], existing_link_metrics->al_mac, compare_neighbor_link_metrics_node));
            }
            else {
                // Removing the found object from new list will speedup upcoming search
                remove_object(new_link_metrics_list, existing_link_metrics->al_mac, compare_neighbor_link_metrics_node);
            }
        }
    }

    if(0 != list_get_size(new_link_metrics_list))
        platform_log(MAP_CONTROLLER,LOG_ERR, " Something went wrong....!");
}

int8_t map_action_link_metrics_response(struct CMDU *recv_cmdu)
{
    uint8_t *current_tlv = NULL;
    map_ale_info_t *ale  = NULL;

    // Input Parameters Validation
    if (NULL == recv_cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input Parameters Validation failed", __func__);
        return -1;
    }

    array_list_t *link_metrics_cache_list = new_array_list(eListTypeDefault);
    if(!link_metrics_cache_list) {
        platform_log(MAP_CONTROLLER,LOG_ERR, " %s Failed to create duplicate neighbor list\n",__func__);
        return -1;
    }

    for ( uint8_t i = 0; NULL != (current_tlv = recv_cmdu->list_of_TLVs[i])  ; i++ ) {
        switch (*current_tlv)
        {
            case TLV_TYPE_TRANSMITTER_LINK_METRIC:
            {
                map_parse_tx_link_metrics_tlv((struct transmitterLinkMetricTLV*) current_tlv, link_metrics_cache_list, &ale);
                break;
            }
            case TLV_TYPE_RECEIVER_LINK_METRIC:
            {
                map_parse_rx_link_metrics_tlv((struct receiverLinkMetricTLV*) current_tlv, link_metrics_cache_list,  &ale);
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
                break;
            }
        }
    }

    // Remove the old metrics
    map_remove_old_link_metrics(ale, link_metrics_cache_list);

#ifdef MAP_MGMT_IPC
    if (ale) {
        map_ipc_agent_metric agent_metric;
        agent_metric.agent_count = 1;
        memcpy(agent_metric.agent_table[0].agent_mac,ale->al_mac, MAC_ADDR_LEN);
        agent_metric.agent_table[0].rssi = ale->upstream_link_metrics.rx_metric.rssi;
        agent_metric.agent_table[0].phyrate = ale->upstream_link_metrics.tx_metric.phy_rate;
        map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_AP_METRICS,(void *)&agent_metric);
    }
#endif

    if(link_metrics_cache_list != NULL) {
        while(list_get_size(link_metrics_cache_list)) remove_last_object(link_metrics_cache_list);
        delete_array_list(link_metrics_cache_list);
    }

    return 0;
}
