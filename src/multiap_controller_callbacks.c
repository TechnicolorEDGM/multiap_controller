/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_callbacks.h"
#include "multiap_controller_action_callbacks.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_tlv_parser.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "platform_multiap_get_info.h"
#include "map_data_model.h"
#include "map_data_model_dumper.h"
#include "map_retry_handler.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "monitor_task.h"
#include "mon_platform.h"
#include "map_topology_tree.h"

#define min(a,b) ((a) < (b) ? (a) : (b))

extern plfrm_config pltfrm_config;

extern uv_loop_t *loop;
uv_poll_t uvpoll_handle;

map_cb_config_t gmap_cb_config[]={
    {
        .recv_msg_type          = CMDU_TYPE_TOPOLOGY_DISCOVERY, 
        .send_msg_type          = 0,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_topology_discovery_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_topology_discovery,
    },
    {
        .recv_msg_type          = CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH,
        .send_msg_type          = CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_autoconfig_search_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_autoconfig_search,
    },

    {
        .recv_msg_type          = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
        .send_msg_type          = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_wsc_m1_validation,
        .data_gathering         = NULL,
        .action_cb              = map_send_wscM2,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_AP_CAPABILITY_REPORT,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_ap_capability_report_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_ap_caps_report,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_client_capability_report_validation,
        .data_gathering         = NULL,
        .action_cb                = NULL,
    },
    {
        .recv_msg_type       	= CMDU_TYPE_TOPOLOGY_QUERY,
        .send_msg_type          = CMDU_TYPE_TOPOLOGY_RESPONSE,
        .controller_initiated   = 0,
        .validation_cb          = map_topology_query_validation,
        .data_gathering         = NULL,
        .action_cb              = map_send_topology_response,
    },
    {
        .recv_msg_type          = CMDU_TYPE_TOPOLOGY_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_topology_response_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_topology_response,
    },
    {
        .recv_msg_type          = CMDU_TYPE_TOPOLOGY_NOTIFICATION,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_topology_notification_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_topology_notification,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_AP_METRICS_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_ap_metrics_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_ap_metrics_response,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_associated_sta_link_metrics_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_assoc_sta_link_metrics,
    },
    { 
        .recv_msg_type          = CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_callback_channel_pref_report_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_channel_pref_report,
    },
    { 
        .recv_msg_type          = CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_callback_channel_selec_response_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_channel_selec_response,
    },

    {
        .recv_msg_type          = CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_operating_channel_report_validation,   
        .data_gathering         = NULL,
        .action_cb              = map_action_operating_channel_report,
    },

    {
        .recv_msg_type          = CMDU_TYPE_MAP_STEERING_COMPLETED,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_client_steering_completd_msg_validation,
        .data_gathering         = NULL,
        .action_cb              = map_send_steering_completed_msg_rcvd_ack,
    },

    {
        .recv_msg_type          = CMDU_TYPE_MAP_CLIENT_STEERING_BTM_REPORT,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_client_steering_btm_report_validation,
        .data_gathering         = NULL,
        .action_cb              = map_send_steering_btm_report_ack,
    },
    { 
        .recv_msg_type          = CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_callback_beacon_metrics_response,
        .data_gathering         = NULL,
        .action_cb              = map_action_beacon_metrics_response,
    },
    { 
        .recv_msg_type          = CMDU_TYPE_VENDOR_SPECIFIC,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_vendor_specific_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_vendor_specific,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_ACK,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_ack_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_ack,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_HIGHER_LAYER_DATA,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_ctrl_higher_layer_data_msg_validation, 
        .data_gathering         = NULL,
        .action_cb              = map_ctrl_higher_layer_data_msg_ack,
    },
    {
        .recv_msg_type          = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_unassoc_sta_link_metrics_validation,
        .data_gathering         = NULL,
        .action_cb              = map_send_unassoc_sta_metrics_ack,
    },
    {
        .recv_msg_type          = CMDU_TYPE_LINK_METRIC_RESPONSE,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_link_metrics_response_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_link_metrics_response,
    },
    {
        .recv_msg_type          = CMDU_TYPE_LINK_METRIC_QUERY,
        .controller_initiated   = 0,
        .relay_indicator        = 0,
        .validation_cb          = map_link_metrics_query_validation,
        .data_gathering         = NULL,
        .action_cb              = map_action_link_metrics_query,
    },
};

int init_map_controller_callback() {
    int status = 0;
    do
    {
        if (ipc_1905_connect() < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "ipc_1905_connect() failed.\n");
            ERROR_EXIT(status)
        }

        if (map_apply_msg_filter(handle_1905) < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"Initial registration failed.\n");
            ERROR_EXIT(status)
        }

        uv_poll_init(loop, &uvpoll_handle, pltfrm_config.al_fd);
        uv_poll_start(&uvpoll_handle, (UV_READABLE|UV_DISCONNECT), uvpoll_1905read_cb);
    } while (0);

    return status;
}

int cleanup_map_controller_callback() {
    lib1905_shutdown(&handle_1905);
    return 0;
}

void uvpoll_1905read_cb (uv_poll_t* handle, int status, int events)
{
    if((status < 0) || (events & UV_DISCONNECT))
    {
        uv_poll_stop(handle);
        if (events & UV_DISCONNECT){
            if (ipc_1905_connect() < 0)
                platform_log(MAP_CONTROLLER,LOG_ERR, "ipc_1905_connect() failed");
        }
    }
    else if (events & UV_READABLE) {
            if(lib1905_read(handle_1905) < 0)
                platform_log(MAP_CONTROLLER,LOG_ERR, "libread failure");
    }
    return;
}

int ipc_1905_connect()
{
    int ret;

    lib1905_shutdown(&handle_1905);

    ret = lib1905_connect(&handle_1905, &pltfrm_config.al_fd, MULTIAP_CONTROLLER_MODE);
    while (ret < 0) {
       platform_log(MAP_CONTROLLER,LOG_ERR,"lib1905 connect failed, Retrying..........");
       sleep(2);
       ret = lib1905_connect(&handle_1905, &pltfrm_config.al_fd, MULTIAP_CONTROLLER_MODE);
    }

    return 0;
}


int error_callback(char *message, int code) {
    //## FIXME: add error codes and logs

    return 0;
}

int find_gmap_cb_index(uint16_t msg_type)
{
    int index = 0;
    for ( index = 0; index < ARRAY_LEN(gmap_cb_config, map_cb_config_t); index ++ ) {
       if (gmap_cb_config[index].recv_msg_type == msg_type)
           break;
    }

    if ( index >= ARRAY_LEN(gmap_cb_config, map_cb_config_t) ) {
        return -EINVAL;
    }
    return index;
}

int map_apply_msg_filter (handle_1905_t handle)
{
    int index = 0, ret = 0,max_index=0, msg_index=0;
    message_filter_t message_filter;


    message_filter.length = 0;
    message_filter.error_cb = error_callback;
    max_index=ARRAY_LEN(gmap_cb_config, map_cb_config_t);
    /* Do not register those messages that are controller initiated */
    for ( index = 0; index< max_index; index ++) {
        if(!gmap_cb_config[index].controller_initiated)
        {
            message_filter.mf[msg_index].message_type = gmap_cb_config[index].recv_msg_type;
           //##FIXME: Need to add a ack require field in gmap_cb_config_t data structure 
            platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s:%d registeration of 1905 msg_type %d\n", __func__, __LINE__, message_filter.mf[msg_index].message_type);
            message_filter.mf[msg_index].ack_required = 0;
            message_filter.mf[msg_index].lib1905_cb = map_read_cb;
            message_filter.mf[msg_index].context = NULL;
            msg_index++;
        }
    }
    message_filter.length = msg_index;
    ret = lib1905_register(handle_1905, &message_filter);
    if (ret < 0) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s:%d registeration of 1905 msg_type "
                     "failed\n", __func__, __LINE__);
        return -EINVAL;
    }
    return 0;
}

int map_read_cb (uint8_t *src_mac_addr, struct CMDU *cmdu, 
                           void *context) {

    int status   = 0;
    int index = 0;
    do
    {
        index = find_gmap_cb_index(cmdu->message_type);
        if( index < 0 ) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "msg type %d, not registered in gmap_cb_config"
                                      , cmdu->message_type);
            ERROR_EXIT(status)
        }

        map_cb_config_t *cb_config = &gmap_cb_config[index];

        // Do the validation of received CMDU
        if( (cb_config->validation_cb != NULL) && \
            (0 != cb_config->validation_cb(src_mac_addr, cmdu, context))) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "validation failed for msg_type %d\n", cmdu->message_type);
            ERROR_EXIT(status)
        }

        if( (cb_config->action_cb != NULL) && \
            (0 != cb_config->action_cb(cmdu))) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Action cb Error for msg_type %d\n", cmdu->message_type);
            ERROR_EXIT(status)
        }

        update_retry_handler(cmdu->message_id, cmdu);

    } while (0);

    lib1905_cmdu_cleanup(cmdu);
    return status;

    // TODO : We no more planned to use work queue in controller
    // Below code will be removed
#if 0
    if(gmap_cb_config[index].action_cb)
    {
        // call the send cb immediately if there is no data gathering
        if (gmap_cb_config[index].data_gathering == NULL)
        {
            int        status =  0;
            uv_work_t  req    = {0};
            wq_args    w_args = {0};

            map_handle_t map_handle = {0};

            if(gmap_cb_config[index].action_cb == NULL)
                return 0;

            memcpy (map_handle.dest_addr, src_mac_addr, MAC_ADDR_LEN);
            map_handle.handle_1905   = handle_1905;
            map_handle.recv_cmdu = cmdu;

            w_args.wqdata    = (void*)&map_handle;
            req.data         = (void*)&w_args;

            gmap_cb_config[index].action_cb(&req, status);

            return 0;
        }
        // Dispath the action_cb into work queue as it involves data gathering
        p_work_pool = get_workqueue_handle();

        if(!p_work_pool) {
            platform_log(MAP_CONTROLLER,LOG_CRIT,"No Work Queue Available \n");
            lib1905_cmdu_cleanup(cmdu);
            return -EINVAL;
        } else {
            p_args=(wq_args*)(&p_work_pool->args);
        }

        p_args->wqdata          = (void*)cmdu;
        p_work_pool->workq.data = (void*)p_args;

        uv_queue_work( loop, ((uv_work_t*)&p_work_pool->workq),
        gmap_cb_config[index].data_gathering, gmap_cb_config[index].action_cb);
    } else {
        /* 
         * There is no send_cb present
         * And so we shall clean received cmdu here
         */
         
        if(cmdu != NULL)
            lib1905_cmdu_cleanup(cmdu);
    }

    return 0;
#endif
}

// This validation is required to update the Retry timer handler
int map_ack_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context) {

    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_ACK Malformed structure.");
        return -1;
    }

    return 0;
}

int map_ap_metrics_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {

    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_AP_METRICS_RESPONSE Malformed structure.");
        return -1;
    }

    uint8_t *current_tlv = NULL;
    uint8_t ap_metrics_tlv_present = 0;
    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ )
    {
        switch (*current_tlv)
        {
            case TLV_TYPE_AP_METRICS_RESPONSE:
            {
                ap_metrics_tlv_present = 1;
                break;
            }
            case TLV_TYPE_ASSOC_STA_TRAFFIC_STATS:
            {
                // We are good, Nothing to do
                break;
            }
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
            {
                // We are good, Nothing to do
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
                break;
            }
        }
    }
    // Return error if expected TLV not present in CMDU
    if(ap_metrics_tlv_present == 0)
        return -1;
    return 0;
}

int map_link_metrics_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_LINK_METRICS_RESPONSE Malformed structure.");
        return -1;
    }

    uint8_t *current_tlv = NULL;
    uint8_t tx_metrics_tlv_present = 0;
    uint8_t rx_metrics_tlv_present = 0;

    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ )
    {
        switch (*current_tlv)
        {
            case TLV_TYPE_TRANSMITTER_LINK_METRIC:
            {
                tx_metrics_tlv_present = 1;
                break;
            }
            case TLV_TYPE_RECEIVER_LINK_METRIC:
            {
                rx_metrics_tlv_present = 1;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
                break;
            }
        }
    }
    // Return error if expected TLV not present in CMDU
    if(tx_metrics_tlv_present == 0 && rx_metrics_tlv_present == 0)
        return -1;

    return 0;
}

int map_associated_sta_link_metrics_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
    if (NULL == cmdu->list_of_TLVs){
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE Malformed structure.");
        return -1;
    }

    uint8_t *current_tlv;
    uint8_t assoc_link_metrics_tlv_present = 0;
    uint8_t error_code_tlv_present          = 0;

    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ )
    {
        if(*current_tlv == TLV_TYPE_ASSOCIATED_STA_LINK_METRICS) {
            assoc_link_metrics_tlv_present = 1;
        }
        else if(*current_tlv == TLV_TYPE_ERROR) {
            error_code_tlv_present = 1;
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "Unexpected TLV (%d) type inside CMDU\n", (uint8_t)(*current_tlv));
        }
    }
    // Return error if expected TLV not present in CMDU
    if(!(assoc_link_metrics_tlv_present || error_code_tlv_present) )
        return -1;

    return 0;
}

int map_topology_notification_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    int status = 0;
    do
    {
        if (NULL == cmdu->list_of_TLVs) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_TOPOLOGY_NOTIFICATION Malformed structure.");
            ERROR_EXIT(status);
        }

        uint8_t al_mac_tlv_present = 0;
        uint8_t *current_tlv = NULL;

        for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ ) {
            switch (*current_tlv) {
                case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                {
                    al_mac_tlv_present = 1;
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
        if(!al_mac_tlv_present) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s No ALMAC TLV in CMDU.\n", __func__);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

int map_topology_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    return 0;
}

int map_topology_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    int8_t status = 0;
    do{
        if (NULL == cmdu->list_of_TLVs) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"AP Autoconfig Search Malformed structure.");
            ERROR_EXIT(status)
        }

        struct deviceInformationTypeTLV *dev_info_tlv    = NULL;
        uint8_t *current_tlv = NULL;
        for (int8_t tlv_index = 0; NULL != (current_tlv = cmdu->list_of_TLVs[tlv_index]) ; ++tlv_index) {
            switch (*current_tlv) {
                case TLV_TYPE_DEVICE_INFORMATION_TYPE:
                {
                    dev_info_tlv = (struct deviceInformationTypeTLV*) current_tlv;
                    break;
                }
                default:
                {
                    break;
                }
            }
        }

        if(dev_info_tlv == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s No Device info TLV in Topology response.\n", __func__);
            ERROR_EXIT(status)
        }
    } while(0);
    return status;
}

int map_topology_discovery_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
    int8_t status = 0;
    do {
        if (NULL == cmdu->list_of_TLVs) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"AP Autoconfig Search Malformed structure.");
            ERROR_EXIT(status)
        }
        uint8_t tlv_index        = 0;
        uint8_t al_mac_tlv_found = 0;
        uint8_t tx_mac_tlv_found = 0;

        while (NULL != cmdu->list_of_TLVs[tlv_index])
        {
            switch (*(uint8_t*)cmdu->list_of_TLVs[tlv_index])
            {
                case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                {

                    al_mac_tlv_found = 1;
                    break;
                }
                case TLV_TYPE_MAC_ADDRESS_TYPE:
                {
                    tx_mac_tlv_found = 1;
                    break;
                }
                default:
                {
                    // Skip the 1905 TLVs
                    break;
                }
            }
            ++tlv_index;
        }

        if((0 == al_mac_tlv_found) || (0 ==tx_mac_tlv_found))
            ERROR_EXIT(status)
    }
    while(0);

    return status;
}

int map_autoconfig_search_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    int i = 0,j=0,tlv_cnt=0;
    uint8_t *p;
    uint8_t searched_role=0,freq=0;
    uint8_t supported_services[5]={0};
    uint8_t searched_services[5]={0};
    uint8_t al_mac[6];
    struct alMacAddressTypeTLV *palmac=NULL;
    struct searchedRoleTLV * psearchedrole=NULL;
    struct autoconfigFreqBandTLV * freqband=NULL;
    supported_service_tlv_t *supported_tlv = NULL;
    searched_service_tlv_t* searched_tlv=NULL;

    if (NULL == cmdu->list_of_TLVs)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"AP Autoconfig Search Malformed structure.");
        return -1;
    }
    while (NULL != (p = cmdu->list_of_TLVs[i]))
    {
        switch (*p)
        {
            case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
            {
                palmac= (struct alMacAddressTypeTLV *)p;
                memcpy(al_mac, palmac->al_mac_address, 6);
                tlv_cnt+=1;
                break;
            }
            case TLV_TYPE_SEARCHED_ROLE:
            {
                psearchedrole= (struct searchedRoleTLV *)p;
                searched_role=psearchedrole->role;
                tlv_cnt+=1;
                break;
            }
            case TLV_TYPE_AUTOCONFIG_FREQ_BAND:
            {
                freqband = (struct autoconfigFreqBandTLV *)p;
                freq = freqband->freq_band;
                for(j=0;j<max_freq_type;j++)
                {
                    if(pltfrm_config.map_config.supportedfreq[j] == freq)
                    {
                        tlv_cnt+=1;
                        break;
                    }
                }
                break;
            }
            case TLV_TYPE_SUPPORTED_SERVICE:
            {
                supported_tlv=(supported_service_tlv_t*)p;
                memcpy(supported_services,supported_tlv->supported_service_array,5);
                tlv_cnt+=1;
                break;
            }
            case TLV_TYPE_SEARCHED_SERVICE:
            {
                searched_tlv=(searched_service_tlv_t*)p;
                memcpy(searched_services,searched_tlv->searched_service_array,5);
                tlv_cnt+=1;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"Unexpected TLV (%d) type inside CMDU\n", *p);
                break;
            }
        }
        i++;
    }

    platform_log(MAP_CONTROLLER,LOG_DEBUG,"\nSearched Role: %d FreqBand : %d Supported Service : %d Searched Service :%d\n",\
            searched_role, freq, supported_services[0], searched_services[0]);

    //FIX the Supported Services and serached servics both in 1905 and Controller
    //For now assuming only one functionality per binary, Either Agent or controller
    if( (tlv_cnt < MAP_AP_AUTO_CONFIGURATION_SEARCH_TLV_COUNT ) || // validate TLV count
        (searched_role != ROLE_1905_REGISTRAR) ||               // Searching for controller
        (supported_services[0] != MAP_ROLE_AGENT) ||             // supported service should be Agent
        (searched_services[0] != MAP_ROLE_CONTROLLER) )          // Searched service should be Controller. 
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Failed validating %s\n", __func__);
        return -1;
    }

    return 0;
}

static int get_almac_from_M1(struct wscTLV *M1, uint8_t *al_mac_address)
{
    uint8_t *p  = NULL;
    uint8_t *m1 = NULL;
    uint16_t m1_size = 0;

    if (NULL == M1) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"M1 Tlv is NULL");
        return 0;
    }

    p = m1 = M1->wsc_frame;
    m1_size = M1->wsc_frame_size;
    while (p - m1 < m1_size)
    {
        INT16U attr_type;
        INT16U attr_len;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_MAC_ADDR == attr_type)
        {
            if (MAC_ADDR_LEN != attr_len)
            {
                platform_log(MAP_CONTROLLER,LOG_ERR,"Incorrect length (%d) for ATTR_MAC_ADDR\n", attr_len);
                return 0;
            }
            _EnB(&p, al_mac_address, MAC_ADDR_LEN);

            return 1;
        }
        else
        {
            p += attr_len;
        }
     }

     platform_log(MAP_CONTROLLER,LOG_ERR,"MAC Address Attribute is missing in M1");
     return 0;
}

static int get_manufacturer_name_from_M1(struct wscTLV *M1, char *name, int len)
{
    uint8_t *p  = NULL;
    uint8_t *m1 = NULL;
    uint16_t m1_size = 0;

    if (NULL == M1) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"M1 Tlv is NULL");
        return 0;
    }

    p = m1 = M1->wsc_frame;
    m1_size = M1->wsc_frame_size;
    while (p - m1 < m1_size) {
        INT16U attr_type;
        INT16U attr_len;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_MANUFACTURER == attr_type) {
            len = min(attr_len, len - 1);  /* truncate, leave room for NULL byte */
            _EnB(&p, name, len);
            name[len] = 0;

            return 1;
        }
        p += attr_len;
    }

    platform_log(MAP_CONTROLLER,LOG_ERR,"Manufacturer Mame Attribute is missing in M1");
    return 0;
}

int map_wsc_m1_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{

    int i = 0;
    uint8_t al_mac_address[MAC_ADDR_LEN] = {0};
    uint8_t *p;

    if (NULL == cmdu->list_of_TLVs)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"WSC M1 Malformed structure.");
        return -1;
    }

    AP_basic_capability_tlv_t* ap_basic_capability = NULL;
    struct wscTLV *M1 = NULL;

    while (NULL != (p = cmdu->list_of_TLVs[i]))
    {
        switch (*p)
        {
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
            {
                ap_basic_capability = (AP_basic_capability_tlv_t*) p;
                break;
            }
            case TLV_TYPE_WSC:
            {
                M1 = (struct wscTLV *) p;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"autoconfig_wsc_m1_validation_cb Unexpected TLV (0x%x) type inside CMDU\n", *p);
                break;
            }
        }
        i++;
    }

    if(ap_basic_capability == NULL)
        return -1;

    if(ap_basic_capability) {
        // Extract the AL MAC from M1 and validate if it is a valid AL mac reported already to controller.
        get_almac_from_M1(M1, al_mac_address);
        map_ale_info_t *ale = get_ale(al_mac_address);
        if(ale == NULL) {
            ale = map_handle_new_agent_onboarding(al_mac_address, cmdu->interface_name);
            if(ale == NULL)
                return -1;
        }

        if(strlen(ale->manufacturer_name) == 0)
        {
            get_manufacturer_name_from_M1(M1, ale->manufacturer_name, sizeof(ale->manufacturer_name));
           
        }

        map_controller_send_agent_update(cmdu->message_type,ale);

        if(-1 == parse_ap_basic_caps_tlv(ap_basic_capability, al_mac_address))
            return -1;

        // Update the radio state
        map_radio_info_t *radio = get_radio(ap_basic_capability->radioId);
        if(radio)
            set_radio_state_M1_receive(&radio->state);
    }
    return 0;
}

int map_ap_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{

    int8_t i = 0;
    uint8_t *p;

    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"Ap capability report Malformed structure.\n");
        return -1;
    }

    uint8_t ap_caps_present      = 0;
    uint8_t ap_basic_caps_preset = 0;

    while (NULL != (p = cmdu->list_of_TLVs[i]))
    {
        switch (*p)
        {
            case TLV_TYPE_AP_CAPABILITY:
            {
                ap_caps_present++;
                break;
            }
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITY:
            {
                ap_basic_caps_preset++;
                break;
            }
            case TLV_TYPE_AP_HT_CAPABILITY:
            {
                // We are good, Nothing to do
                break;
            }
            case TLV_TYPE_AP_VHT_CAPABILITY:
            {
                // We are good, Nothing to do
                break;
            }
            case TLV_TYPE_AP_HE_CAPABILITY:
            {
                // We are good, Nothing to do
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"Unexpected TLV type (%d) inside CMDU\n", *p);
                break;
            }
        }
        i++;
    }
    // Return error if expected TLV not present in CMDU
    if(ap_caps_present == 0 && ap_basic_caps_preset == 0)
        return -1;

    return 0;
}

int map_client_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    /* Do proper validation of mid */
    int8_t i = 0;
    uint8_t *p;
    uint8_t ret = -1;
    uint8_t client_info_present       = 0;
    uint8_t client_capability_present = 0;
    uint8_t error_code_present        = 0;
    struct mapClientCapabilityReportTLV *client_capability_report_tlv = NULL;
    struct mapClientInfoTLV             *client_info_tlv              = NULL;
    struct mapErrorCodeTLV              *err_code_tlv = NULL;
    map_sta_info_t	*sta = NULL;

    if (NULL == cmdu->list_of_TLVs)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"Client Capability Query Malformed structure.");
        return -1;
    }

    while (NULL != (p = cmdu->list_of_TLVs[i]))
    {
        switch (*p)
        {
            case TLV_TYPE_CLIENT_INFO:
            {
                client_info_present = 1;
                client_info_tlv = (struct mapClientInfoTLV             *)p;
                break;
            }
            case TLV_TYPE_CLIENT_CAPABILITY_REPORT:
            {
                client_capability_present = 1;
                client_capability_report_tlv = (struct mapClientCapabilityReportTLV *)p;
                break;
            }
            case TLV_TYPE_ERROR:
            {
                error_code_present = 1;
				err_code_tlv = (struct mapErrorCodeTLV*)p;
                break;
            }
            default:
            {
                platform_log(MAP_CONTROLLER,LOG_ERR,"UNEXPECTED TLV INSIDE CMDU");
                return -1;
            }
        }
        i++;
    }

    if (1 == client_info_present && 1 == client_capability_present)
    {
        if (FAILURE == client_capability_report_tlv->result_code)
        {
            if (!error_code_present)
            {
                platform_log(MAP_CONTROLLER,LOG_ERR,"No error code TLV");
                return -1;
            }
        }
    }
    else
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"Expected TLVS are missing");
        return -1;
    }

    /* update the Assoc frame request here */

    if(client_info_tlv != NULL && client_capability_report_tlv != NULL)
    {
        if(client_info_tlv->client_mac == NULL)
            return -1;

        sta = get_sta(client_info_tlv->client_mac);
        if(sta == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s, %d Invalid sta mac addr\n",__func__,__LINE__);
            return -1;
        }
    }
    if(!error_code_present)
        ret = parse_update_client_capability(sta, client_capability_report_tlv->assoc_frame_len, client_capability_report_tlv->assoc_frame);

	/* We only send STA Connect event once assoc frame is received so as to parse the std*/
	/* For stations connected during onboard, client cappability query must be triggered in which case STA connect
	events will be automatically sent. This will be taken care as part of topology hardening */
#ifdef MAP_MGMT_IPC
    if((error_code_present && err_code_tlv->reason_code == UNSPECIFIED_FAILURE) || (ret == 0))
    {
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s %d, STD - %d\n",__func__,__LINE__,sta->sta_caps.supported_standard);
        map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_STA_CONNECT,sta);
    }
#endif
    publish_stn_event(sta, PUBLISH_STN_CONNECT_EVT);

    return ret;
}

int map_unassoc_sta_link_metrics_validation (uint8_t *src_mac_addr,
                                               struct CMDU *cmdu, void *context)
{
    struct mapUnassocStaMetricsResponseTLV *unassoc_metrics = NULL;

    if (NULL == cmdu->list_of_TLVs)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"unassociated_sta_link_metrics Malformed structure.");
        return -1;
    }

    unassoc_metrics = (struct mapUnassocStaMetricsResponseTLV *) cmdu->list_of_TLVs[0];
    if ((NULL == unassoc_metrics) || (TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE != unassoc_metrics->tlv_type)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "unassociated_sta_link_metrics tlv missing");
        return -1;
    }


    platform_log(MAP_CONTROLLER,LOG_DEBUG, "Received Unassoc STA metrics Response");
    platform_log(MAP_CONTROLLER,LOG_DEBUG, "=====================================");
    platform_log(MAP_CONTROLLER,LOG_DEBUG, "-->op_class %d\n", unassoc_metrics->oper_class);
    platform_log(MAP_CONTROLLER,LOG_DEBUG, "-->sta_cnt  %d\n",  unassoc_metrics->sta_cnt);
    
    for(int i = 0; i <unassoc_metrics->sta_cnt; i++){
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------> sta_mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n", unassoc_metrics->sta_list[i].sta_mac[0],
                              unassoc_metrics->sta_list[i].sta_mac[1], unassoc_metrics->sta_list[i].sta_mac[2], 
                              unassoc_metrics->sta_list[i].sta_mac[3], unassoc_metrics->sta_list[i].sta_mac[4],
                              unassoc_metrics->sta_list[i].sta_mac[5]);
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------> channel number %d\n", unassoc_metrics->sta_list[i].channel);
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------> time_delta     %d\n", unassoc_metrics->sta_list[i].time_delta);
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"------> uplink rcpi    %d\n", unassoc_metrics->sta_list[i].rcpi_uplink);
    }


    return 0;
}

int map_ctrl_higher_layer_data_msg_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context)
{
    struct mapHigherLayerDataTLV *higher_layer_data_msg = NULL;
    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_CRIT, "Higher layer data message - malformed structure\n");
        return -1;
    }

    higher_layer_data_msg = (struct mapHigherLayerDataTLV *) cmdu->list_of_TLVs[0];;
    if ((NULL == higher_layer_data_msg) || (TLV_TYPE_HIGHER_LAYER_DATA_MSG != higher_layer_data_msg->tlv_type)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"No valid TLV present in higher layer data CMDU\n");
            return -1;
    }

    platform_log(MAP_CONTROLLER,LOG_DEBUG,"Higher layer data - protocol : %d, payload len - %d\n",
            higher_layer_data_msg->higher_layer_proto, higher_layer_data_msg->tlv_length-1);

    /* If necessary print payload contents here */

    return 0;
}

int map_client_steering_completd_msg_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context)
{
    if (NULL == cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s:No valid CMDU received", __FUNCTION__);
        return -1;
    }
    return 0;
}

int map_client_steering_btm_report_validation (uint8_t *src_mac_addr,
                                               struct CMDU *cmdu, void *context)
{
    struct mapSteeringBTMReportTLV *steering_btm_report_tlv = NULL;

    if (NULL == cmdu->list_of_TLVs)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"Client Steering BTM Report Malformed structure.");
        return -1;
    }

    steering_btm_report_tlv = (struct mapSteeringBTMReportTLV *) cmdu->list_of_TLVs[0];
    if ((NULL == steering_btm_report_tlv) || (TLV_TYPE_BTM_REPORT != steering_btm_report_tlv->tlv_type)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Steering BTM report tlv missing");
        return -1;
    }

    /* Update roaming engine */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_STEERING_BTM_REPORT(cmdu);

    return 0;
}


int map_operating_channel_report_validation(uint8_t *src_mac_addr,
                                 struct CMDU *cmdu, void *context)
{
	int status = 0;

	do
	{
		// Get the Operating channel Report TLV 
		operating_channel_report_tlv_t *rep = NULL;
		if(-1 == get_tlv_fromcmdu(TLV_TYPE_OPERATING_CHANNEL_REPORT, cmdu, (void *)&rep)) {
			platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get TLV_TYPE_OPERATING_CHANNEL_REPORT.\n",__func__, __LINE__);
			ERROR_EXIT(status)
		}
	}while(0);

	return status;
}

int map_callback_beacon_metrics_response(uint8_t *src_mac_addr,
                                       struct CMDU *cmdu, void *context)
{
    beacon_metrics_response_tlv_t *response = NULL;
    uint8_t                       *p = NULL;

    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_BEACON_METRICS_RESPONSE Malformed structure.");
        return -1;
    }

    for ( uint8_t i = 0; NULL != (p = cmdu->list_of_TLVs[i]) ; i++ ) {
        switch (*p) {
            case TLV_TYPE_BEACON_METRICS_RESPONSE:
            {
                if (response) {
                    platform_log(MAP_CONTROLLER,LOG_ERR,"Beacon metrics response contains more than one beacon metrics repsonse TLV");
                    /* Continue... */
                } else {
                    response = (beacon_metrics_response_tlv_t *)p;
                }
                break;
            }
            default: 
            {
                 platform_log(MAP_CONTROLLER,LOG_ERR,"Beacon metrics response contains unexpected TLV type (%d)", *p);
                 break;
            }
        }
    }

    return response ? 0 : -1;
}

int map_vendor_specific_validation (uint8_t *src_mac_addr,
                                               struct CMDU *cmdu, void *context)
{
    struct vendorSpecificTLV *vendor_specific_tlv = NULL;
    uint8_t *p = NULL;
    
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
        return 0;
    }

    return -1;

}

int map_callback_channel_pref_report_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT Malformed structure.");
        return -1;
    }
    int status = 0;
    uint8_t          *current_tlv = NULL;
    map_radio_info_t *radio       = NULL;
    for ( uint8_t i = 0; NULL != (current_tlv = cmdu->list_of_TLVs[i]) ; i++ ) {

        switch (*current_tlv) {

            case TLV_TYPE_CHANNEL_PREFERENCE:
            {
                // Check if this radio is available with us.
                channel_preference_tlv_t *channel_pref_tlv = (channel_preference_tlv_t*)current_tlv;
                radio = get_radio(channel_pref_tlv->radio_id);
                // Validate the operating calss count in the received message
                if(radio){
                    if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
                        status = (channel_pref_tlv->numOperating_class  <= MAX_OPERATING_CLASS_COUNT_FOR_2G_RADIO) ? 0 : -1;
                    else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ)
                        status = (channel_pref_tlv->numOperating_class <= MAX_OPERATING_CLASS_COUNT_FOR_5G_RADIO) ? 0 : -1;
                }
                break;
            }

            case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
            {
                radio_operation_restriction_tlv_t *ops_restriction = (radio_operation_restriction_tlv_t*)current_tlv;
                radio = get_radio(ops_restriction->radio_id);
                // Validate the operating calss count in the received message
                if(radio) {
                    if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
                        status = (ops_restriction->numOperating_class  <= MAX_OPERATING_CLASS_COUNT_FOR_2G_RADIO) ? 0 : -1;
                    else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ)
                        status = (ops_restriction->numOperating_class <= MAX_OPERATING_CLASS_COUNT_FOR_5G_RADIO) ? 0 : -1;
                }
                break;
            }
            default:
            {
                 platform_log(MAP_CONTROLLER,LOG_ERR,"Channel selection response response contains unexpected TLV type (%d)", *current_tlv);
                 break;
            }
        }
    }
    return status;
}

int map_callback_channel_selec_response_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
    int status = 0;
    do
    {
        if (NULL == cmdu->list_of_TLVs) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE Malformed structure.");
            ERROR_EXIT(status)
        }

        channel_selection_response_tlv_t *chan_sel_tlv = (channel_selection_response_tlv_t*)cmdu->list_of_TLVs[0];

        if( !(chan_sel_tlv != NULL && chan_sel_tlv->tlv_type == TLV_TYPE_CHANNEL_SELECTION_RESPONSE))
            ERROR_EXIT(status)
    } while (0);

    return status;
}

int map_link_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {

    int status = 0;
    uint8_t empty_mac[MAC_ADDR_LEN] = {0};
    do
    {
        if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU_TYPE_LINK_METRIC_QUERY Malformed structure.");
            ERROR_EXIT(status)
        }

        struct linkMetricQueryTLV *link_met_query_tlv = (struct linkMetricQueryTLV *) cmdu->list_of_TLVs[0];

        if ( !((NULL != link_met_query_tlv) && (link_met_query_tlv->tlv_type == TLV_TYPE_LINK_METRIC_QUERY))) {

            platform_log(MAP_CONTROLLER,LOG_ERR,"TLV_TYPE_LINK_METRIC_QUERY not found in CMDU_TYPE_LINK_METRIC_QUERY.");
            ERROR_EXIT(status)
        }

        if (link_met_query_tlv->destination != LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS &&
            link_met_query_tlv->destination != LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR) {

            platform_log(MAP_CONTROLLER,LOG_ERR,"Destination type incorrect in TLV_TYPE_LINK_METRIC_QUERY.");
            ERROR_EXIT(status)
        }

        if (link_met_query_tlv->destination == LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR &&
            memcmp(link_met_query_tlv->specific_neighbor, empty_mac, MAC_ADDR_LEN) == 0) {

            platform_log(MAP_CONTROLLER,LOG_ERR,"Destination MAC incorrect in TLV_TYPE_LINK_METRIC_QUERY.");
            ERROR_EXIT(status)
        }

        if (link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY &&
            link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY &&
            link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS) {

            platform_log(MAP_CONTROLLER,LOG_ERR,"Link Metrics type incorrect in TLV_TYPE_LINK_METRIC_QUERY.");
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}
