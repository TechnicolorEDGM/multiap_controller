/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_tlv_parser.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_post_onboarding_handler.h"
#include "multiap_controller_metrics_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "multiap_controller_topology_tree_builder.h"
#include "platform_multiap_get_info.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_defines.h"
#include "map_data_model_dumper.h"
#include "map_data_model.h"
#include "map_topology_tree.h"
#include <stdio.h>
#include <stdint.h>

unsigned int us_24_oprclass[]   =   {81,83,84};
unsigned int eu_24_oprclass[]   =   {81,83,84};
unsigned int us_5_oprclass[]    =   {115,118,121,125,116,119,122,126,117,120,123,127,128,129,130};
unsigned int eu_5_oprclass[]    =   {115,118,121,116,119,122,117,120,123,128,129,130};

// TODO : This API will be re-written when there is a new
// credential configuration updates
uint8_t map_update_bss_type(map_bss_info_t *bss) {
    uint8_t config_status = 0;

    map_cfg* controller_config      = get_controller_config();
    config_credential_t *credential = NULL;

    for (uint8_t i = 0; i < controller_config->map_num_credentials; ++i) {
        credential = controller_config->credential_config + i;
        if( 0 == strncmp(credential->bss_ssid, (char*)bss->ssid, MAX_SSID_LEN)) {

            if( (credential->bss_state & MAP_FRONTHAUL_BSS) && (credential->bss_state & MAP_BACKHAUL_BSS)) {
                bss->type = MAP_FRONTHAUL_BSS | MAP_BACKHAUL_BSS;
                config_status = 1;
                break;
            }
            else if(credential->bss_state & MAP_FRONTHAUL_BSS) {
                bss->type = MAP_FRONTHAUL_BSS;
                config_status = 1;
                break;
            }
            else if(credential->bss_state & MAP_BACKHAUL_BSS){
                bss->type = MAP_BACKHAUL_BSS;
                config_status = 1;
                break;
            }
        }
    }

    return config_status;
}


static int8_t map_remove_missing_radio (ap_oerational_BSS_tlv_t *radio_info_list, map_ale_info_t* ale)
{
    /* Return status indicates the following   -1 - error, 0 - none removed, 1 - radio removed */
    int8_t            status      = MAP_NO_UPDATE;
    int8_t            radio_found = 0;
    map_radio_info_t *radio       = NULL;
    struct radioInfo  radio_info  = {0};
    uint8_t           rem_nodes   = 0;

    do {
        if ((NULL == radio_info_list) || (NULL == ale)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s NULL value on radio list or ale.\n", __func__);
            ERROR_EXIT(status);
        }

        /* Remove those Radios that are not listed in the AP Operational BSS tlv */
        for (uint8_t i = 0; i < ale->num_radios; i++, radio_found = 0, radio = NULL) {
            radio = (map_radio_info_t *)ale->radio_list[i];
            if (NULL != radio) {
                /* Find if the radio is present in the TLV */
                for (uint8_t j = 0; j < radio_info_list->no_of_radios; j++) {
                    radio_info = (struct radioInfo) radio_info_list->radioInfo[j];
                    if (0 == memcmp(radio_info.radioId, radio->radio_id, MAC_ADDR_LEN)) {
                        radio_found = 1;
                        break;
                    }
                }
                if (0 == radio_found) { /* Radio is not present, so Remove Radio */
                    /* Update roaming engine to indicate removed Radio */
                    MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_RADIO(radio);

                    if (-1  == remove_radio(radio->radio_id)) {
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Remove_radio failed",__func__);
                        ERROR_EXIT(status)
                    }
                    /* Even if one radio is removed, update the status to 1*/
                    status = MAP_VALID_UPDATE;
                    /* Replace empty block with the next following valid entries */
                    rem_nodes = ale->num_radios -i -1;
                    if (rem_nodes > 0) {
                        memcpy((void *)((ale->radio_list)+i), (void *)((ale->radio_list)+(i+1)), sizeof(map_radio_info_t *) * rem_nodes);
                    }

                    ale->num_radios--; /* Decrement the Radio count */
                    ale->radio_list[ale->num_radios] = NULL; /* Assign the last value as NULL */
                    i--; /* i should not be moved to next, since we replaced the empty block with the next node */
                }
            }
        }
    } while (0);

    return status;
}

static int8_t map_remove_missing_bss (struct radioInfo *radio_info, map_radio_info_t *radio) {
    /* Return status indicates the following   -1 - error, 0 - none removed, 1 - radio removed */
    int8_t  status    = MAP_NO_UPDATE;
    int8_t  bss_found = 0;
    uint8_t rem_nodes = 0;

    do {
        if((NULL == radio_info) || (NULL == radio)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s NULL value on radio info or in radio node.\n", __func__);
            ERROR_EXIT(status)
        }

        /* Remove those BSS that are not listed in the AP Operational BSS tlv */
        for (int8_t i = 0; (i < radio->num_bss); i++, bss_found = 0) {
            if (NULL != radio->bss_list[i]) {
                /* Find if the BSS is present in the TLV */
                for (uint8_t j = 0; j < radio_info->no_of_bss; j++) {
                    if (0 == memcmp(radio_info->bss_info[j].bssid, radio->bss_list[i]->bssid, MAC_ADDR_LEN)) {
                        bss_found = 1;
                        break;
                    }
                }
                if (0 == bss_found) { /* BSS is not present, so Remove BSS */
                    /* Update roaming engine to indicate removed BSS */
                    MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_BSS(radio->bss_list[i]);

                    if (-1  == remove_bss(radio->bss_list[i]->bssid)) {
                        platform_log(MAP_CONTROLLER,LOG_ERR, "%s : Remove_bss failed",__func__);
                        ERROR_EXIT(status)
                    }
                    /* Update status when bss is removed */
                    status = MAP_VALID_UPDATE;
                    /* Replace empty block with the next following valid entries */
                    rem_nodes = radio->num_bss -i -1;
                    if (rem_nodes > 0) {
                        memcpy((void *)((radio->bss_list) + i ), (void *)((radio->bss_list) + (i+1)), sizeof(map_bss_info_t *) * rem_nodes);
                    }

                    radio->num_bss--; /* Decrement the BSS count */
                    radio->bss_list[radio->num_bss] = NULL; /* Assign the last value as NULL */
                    i--; /* i should not be moved to next, since we replaced the empty block with the next node */
                }
            }
        }
    } while (0);

    return status;
}

static int8_t map_update_radio_data(struct radioInfo *radio_info, map_radio_info_t *radio) {
    /* Return status indicates the following   -1 - error, 0 - none removed, 1 - radio/bss removed */
    int8_t   status       = MAP_NO_UPDATE;
    uint16_t radio_state  = 0;

    do {
        if(radio_info == NULL || radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s NULL value on radio info or in radio node.\n", __func__);
            ERROR_EXIT(status)
        }

        // Validate and update the number of BSS on this radio
        if(radio_info->no_of_bss > MAX_BSS_PER_RADIO) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s Invalid BSS count(%d). \n", __func__, radio_info->no_of_bss);
            ERROR_EXIT(status)
        }

        /* Remove missing BSS and its data from the list */
        status = map_remove_missing_bss(radio_info, radio);

        // Update the BSS info
        for(uint8_t index =0 ; index < radio_info->no_of_bss; index++) {
            map_bss_info_t *bss = NULL;

            bss = get_bss(radio_info->bss_info[index].bssid);
            if(NULL == bss){
                bss = create_bss(radio_info->bss_info[index].bssid, radio->radio_id);
                if(NULL == bss) {
                    platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed creating BSS node.\n", __func__);
                    continue;
                }
                radio->num_bss++;
                /*Agent Update to be sent when even one BSS is added */
                status = MAP_VALID_UPDATE;
            }

            // Validate and update the SSID info
            if(radio_info->bss_info[index].ssid_len && radio_info->bss_info[index].ssid_len < MAX_SSID_LEN ) {

                bss->ssid_len = radio_info->bss_info[index].ssid_len;
                strncpy((char*)bss->ssid, (const char*)radio_info->bss_info[index].ssid, bss->ssid_len);
                bss->ssid[bss->ssid_len] = '\0';

                uint8_t org_bss_type = bss->type;

                // we set the radio state as configured.
                radio_state |= map_update_bss_type(bss);

                if(org_bss_type != bss->type)
                {
                    /*Agent Update to be sent when BSS type is modified */
                    status = MAP_VALID_UPDATE;
                }    

                /* Update roaming engine to indicate new BSS */
                MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_BSS(bss);
            }
            else {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Invalid ssid length (%d) received. \n",__func__, radio_info->bss_info[index].ssid_len);
                ERROR_EXIT(status)
            }
        }
    } while (0);

    // Set the radio state to CONFIGURED on below case to handle controller re-boot after onboarding.
    //      => If at least one BSS is matching the configuration
    if(radio_state){
        set_radio_state_configured(&radio->state);
    }

    return status;
}

static void update_radio_caps(map_radio_info_t *radio)
{
    /* Use HT and VHT cap to fill in global caps */
    map_radio_capablity_t     *caps     = &radio->radio_caps;
    map_radio_vht_capabilty_t *vht_caps = radio->vht_caps;
    map_radio_ht_capabilty_t  *ht_caps  = radio->ht_caps;
    bool                       is_5g    = radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ;

    /* Note: only use vht_caps for 5G (and not for proprietary VHT support on 2.4G) */

    /* Standard (forget about 11B) */
    caps->supported_standard = (is_5g && vht_caps) ? STD_80211_AC :
                               ht_caps             ? STD_80211_N  :
                               is_5g               ? STD_80211_A  : STD_80211_G;

    /* Caps: use most advanced info */
    if (is_5g && vht_caps) {
        caps->max_tx_spatial_streams = vht_caps->max_supported_tx_streams;
        caps->max_rx_spatial_streams = vht_caps->max_supported_rx_streams; 
        caps->max_bandwidth          = vht_caps->support_80_80_mhz || vht_caps->support_160mhz ? 160 : 80;
        caps->sgi_support            = vht_caps->gi_support_160mhz || vht_caps->gi_support_80mhz;
        caps->su_beamformer_capable  = vht_caps->su_beamformer_capable;
        caps->mu_beamformer_capable  = vht_caps->mu_beamformer_capable;
    } else if (ht_caps) {
        caps->max_tx_spatial_streams = ht_caps->max_supported_tx_streams;
        caps->max_rx_spatial_streams = ht_caps->max_supported_rx_streams; 
        caps->max_bandwidth          = ht_caps->ht_support_40mhz ? 40 : 20;
        caps->sgi_support            = ht_caps->gi_support_40mhz || ht_caps->gi_support_20mhz;
        caps->su_beamformer_capable  = 0;
        caps->mu_beamformer_capable  = 0;
    } else {
        caps->max_tx_spatial_streams = 1;
        caps->max_rx_spatial_streams = 1;
        caps->max_bandwidth          = 20;
        caps->sgi_support            = 0;
        caps->su_beamformer_capable  = 0;
        caps->mu_beamformer_capable  = 0;
    }

     /* Update roaming engine with new radio stats */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_RADIO(radio);
}

static int handle_sta_connect(uint8_t *sta_mac,uint8_t *bss)
{
    if(sta_mac == NULL || bss == NULL)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, " %s Input argument(s) NULL ", __func__);
        return -1;
    }
    map_sta_info_t *sta = NULL;
    sta  = get_sta(sta_mac);
    if(sta == NULL) {
        sta  = create_sta(sta_mac, bss);
        if(sta == NULL) {
            int8_t sta_mac_str[MAX_MAC_STRING_LEN] = {0};
            get_mac_as_str(sta_mac, sta_mac_str, MAX_MAC_STRING_LEN);
            platform_log(MAP_CONTROLLER,LOG_ERR, "Failed creating/updating the station %s.\n",sta_mac_str);
        }
        else {
            //retry Client Capability Querry until we get a response
            // This memory will be freed by cleanup_retry_args during retry completion handler
            map_clicap_args_t *clicap_args=(map_clicap_args_t *)calloc(1,sizeof(map_clicap_args_t));
            if(clicap_args == NULL)
            {
                platform_log(MAP_CONTROLLER,LOG_ERR, "Failed allocating memory to station in %s \n ", __func__);
                if(-1 == remove_sta(sta_mac, bss)) {
                    platform_log(MAP_CONTROLLER,LOG_ERR, " Failed to remove the station in %s\n",__func__);
                }
                return -1;
            }
            memcpy(clicap_args->sta_mac,sta_mac,MAC_ADDR_LEN);
            memcpy(clicap_args->bssid,bss,MAC_ADDR_LEN);
            char retry_id[MAX_TIMER_ID_STRING_LENGTH];
            GET_RETRY_ID(sta_mac, CLIENT_CAPS_QUERRY_RETRY_ID, retry_id);
            if(-1 == map_register_retry((const char*)retry_id, 2 , 2 ,clicap_args, cleanup_retry_args, map_send_client_capability_query)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "Failed Registering retry timer : %s ", retry_id);
                free(clicap_args);
            }
            return 0;

        }
    }
    else {
        map_bss_info_t *target_bss = get_bss(bss);
        uint8_t is_bss_switched = 0;
        
        if(target_bss && sta->bss) {
            /* Check if current and old BSS is same */
            if(0 != memcmp(sta->bss->bssid, bss, MAC_ADDR_LEN)) {
                is_bss_switched = 1;
            }
        }
        /* Send the Disconnect event as the STA switches from old BSS */
        if(is_bss_switched == 1) {          
#ifdef MAP_MGMT_IPC        
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_STA_DISCONNECT,sta);
#endif              
            publish_stn_event(sta, PUBLISH_STN_DISCONNECT_EVT);
        }
        
        /* Update the STA details */
        update_sta_bss(sta_mac,bss);

         /* Send the Connect event as the STA switches to new BSS */
        if(is_bss_switched == 1) {
#ifdef MAP_MGMT_IPC         
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_STA_CONNECT,sta);
#endif
            publish_stn_event(sta, PUBLISH_STN_CONNECT_EVT);
        }
    }
    return 0;
}

int publish_stn_event(map_sta_info_t *sta, map_publish_event_t evt)
{
	int status = 0;
	stn_event_platform_cmd_t *pltform_cmd = calloc(1,sizeof(stn_event_platform_cmd_t));
	map_monitor_cmd_t cmd				  = {0};

	if((NULL != pltform_cmd) && (NULL != pltform_cmd->bssid) && (NULL != pltform_cmd->sta)) {
		get_mac_as_str(sta->mac, pltform_cmd->sta, MAX_MAC_STRING_LEN);
		get_mac_as_str(sta->bss->bssid, pltform_cmd->bssid, MAX_MAC_STRING_LEN);		
		pltform_cmd->event = evt;

		cmd.cmd	 = MAP_MONITOR_SEND_UBUS_DATA_CMD;
		cmd.subcmd = MAP_MONITOR_SEND_STN_EVENT_SUBCMD;
		cmd.param  = (void *)pltform_cmd;
		if(0 != map_monitor_send_cmd(cmd)) {
			platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
		}
	} else {
		status = -1;
		platform_log(MAP_AGENT,LOG_ERR, "%s Invalid cmd parameters recieved\n", __FUNCTION__);	
	}
	
	return status;
}

static void handle_sta_disconnect(client_association_event_tlv_t *client_asso_tlv) {

    if (NULL == client_asso_tlv) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"\n %s: Input Parametres validation failed",__func__);
        return;
    }

    map_sta_info_t *sta = get_sta(client_asso_tlv->mac);
    if(sta) {
        map_bss_info_t *remove_request_bss = get_bss(client_asso_tlv->bssid);
        if(sta->bss == remove_request_bss) {
#ifdef MAP_MGMT_IPC
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_STA_DISCONNECT,sta);
#endif
			publish_stn_event(sta, PUBLISH_STN_DISCONNECT_EVT);
		}

        char mac_str1[MAX_MAC_STRING_LEN] = {0};
        char mac_str2[MAX_MAC_STRING_LEN] = {0};
        if(-1 == remove_sta(client_asso_tlv->mac, client_asso_tlv->bssid))
            platform_log(MAP_CONTROLLER,LOG_ERR, " Failed to remove the station %s .\n",\
                            MAC_AS_STR(client_asso_tlv->mac, mac_str1));
        else {
            platform_log(MAP_CONTROLLER,LOG_DEBUG, " STA %s has left BSS : %s",\
                MAC_AS_STR(client_asso_tlv->mac, mac_str1),\
                MAC_AS_STR(client_asso_tlv->bssid, mac_str2));
            print_sta_bss_mapping();
        }
    }
}

#define STATION_DISCONNECT_EVEN 0

int8_t parse_client_assoc_tlv(map_ale_info_t *ale, client_association_event_tlv_t *client_asso_tlv)
{
    int8_t status = -1;
    do
    {
        if(ale == NULL || client_asso_tlv == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s Input argument(s) NULL ", __func__);
            ERROR_EXIT(status)
        }

        // Handle STA disconnect event
        if(client_asso_tlv->association_event == STATION_DISCONNECT_EVEN) {
            map_sta_info_t *sta = NULL;
            sta = get_sta(client_asso_tlv->mac);
            // Remove the STA from datamodel
            if(sta){
                handle_sta_disconnect(client_asso_tlv);
            }
            else {
                platform_log(MAP_CONTROLLER, LOG_ERR, "Received disconnect event for STA not in datamodel");
            }
        }
        // Handle STA connect event
        else {
            handle_sta_connect(client_asso_tlv->mac, client_asso_tlv->bssid);
        }

        /* Forward event to roaming controller */
        MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_ASSOCIATION_EVENT(ale, client_asso_tlv);
    } while (0);

    return status;
}

int8_t parse_associated_clients_tlv(associated_clients_tlv_t* associated_sta) {
    if(associated_sta == NULL) {
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "NULL pointer check failed in %s : %d\n",__func__, __LINE__);
        return -1;
    }
    if (associated_sta->no_of_bss > MAX_BSS_PER_RADIO) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Number of BSS can't be more than %d %s : %d\n", MAX_BSS_PER_RADIO, __func__, __LINE__);
        return -1;
    }

    for (uint8_t bss_index  = 0; bss_index < associated_sta->no_of_bss; ++bss_index) {
        struct bss_info *bss = &associated_sta->bssinfo[bss_index];
        if(bss->no_of_sta > MAX_STA_PER_BSS) {
            continue; // Skip the update if it has more than expected clients
        }

        for (int sta_index = 0; (sta_index < bss->no_of_sta); ++sta_index)
        {
            // Get the station info and store in our database
            struct sta_time *sta_time_info = &bss->sta_assoc_time[sta_index];
            if( 0 == handle_sta_connect(sta_time_info->sta_mac, bss->bssid))
            {
                map_sta_info_t *sta = get_sta(sta_time_info->sta_mac);
                sta->since_assoc_time = sta_time_info->since_assoc_time;
            }
        }
    }
    return 0;
}

int get_radiotype_from_apbasiccap_tlv(AP_basic_capability_tlv_t* ap_basic_capability ,uint8_t* radio_type, uint8_t *band_type_5G)
{
        int k=0, j=0,oprclass_cnt=0;

        for(j=0;j<ap_basic_capability->numOperating_class;j++)
        {
                //Hard coded for US needs Clean up here
                oprclass_cnt=ARRAY_LEN(us_24_oprclass,unsigned int);
                for(k=0;k<oprclass_cnt;k++)
                {
                        if(ap_basic_capability->operating_class[j].operating_class== us_24_oprclass[k])
                        {
                                *radio_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
                                return 0;
                        }
                }
                //Hard coded for US needs Clean up here
                oprclass_cnt=ARRAY_LEN(us_5_oprclass,unsigned int);
                for(k=0;k<oprclass_cnt;k++)
                {
                        if(ap_basic_capability->operating_class[j].operating_class== us_5_oprclass[k])
                        {
                                *radio_type = IEEE80211_FREQUENCY_BAND_5_GHZ;
                                return 0;
                        }
                }
        }
        return -1;

}

int8_t parse_ap_operational_bss_tlv(ap_oerational_BSS_tlv_t* radio_info_list, map_ale_info_t* ale, uint8_t *is_ale_updated)
{
    map_radio_info_t *radio      = NULL;
    uint8_t request_radio_caps   = 0;
    uint8_t request_channel_pref = 0;
    uint8_t request_channel_sel = 0;

    if(NULL == radio_info_list || NULL == ale || NULL == is_ale_updated) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s Missing AP Operational BSS TLV \n",__func__);
        return -1;
    }

    *is_ale_updated = MAP_NO_UPDATE;

    /* Remove missing radio and its data from the radio list */
    if(map_remove_missing_radio(radio_info_list, ale) == MAP_VALID_UPDATE)
    {
        /* Agent update to be sent when radio/bss changes i.e added or removed */
        *is_ale_updated       = MAP_VALID_UPDATE;
    }

    for(uint8_t index = 0; index < radio_info_list->no_of_radios; index++, radio = NULL) {

        radio = get_radio(radio_info_list->radioInfo[index].radioId);
        if(NULL == radio) {
            radio = map_handle_new_radio_onboarding(radio_info_list->radioInfo[index].radioId, ale->al_mac);
            request_radio_caps = 1;
            /* Agent update to be sent when radio/bss changes i.e added or removed */
            *is_ale_updated       = MAP_VALID_UPDATE;
        }

        if(NULL == radio)
            continue;

        if((NULL == radio->ht_caps) && (NULL == radio->vht_caps) && (NULL == radio->he_caps)) {
            request_radio_caps = 1;
        }

        if(radio->op_class_list == NULL) {
            request_channel_pref = 1;
        } else if (ale->first_chan_sel_req_done && radio->current_op_class == 0) {
            uint64_t last_chan_sel_req = get_clock_diff_secs(get_current_time(), ale->last_chan_sel_req_time);
            if (last_chan_sel_req > 90) {
                platform_log(MAP_CONTROLLER, LOG_ERR, "Current oper class not known - do new channel selection request");
                request_channel_sel = 1;
            }
        }

        // Update BSS info
        int8_t ret = map_update_radio_data(&(radio_info_list->radioInfo[index]), radio);
        if(-1 == ret) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to update the radio info \n ", __func__);
            continue;
        }
        else if( MAP_VALID_UPDATE == ret) {
            /* Agent update to be sent when radio/bss changes i.e added or removed */
            *is_ale_updated = MAP_VALID_UPDATE;
        }
    }

    // Send AP Capability query in retry timer until we get a response
    if(request_radio_caps) {
        char retry_id[MAX_TIMER_ID_STRING_LENGTH];
        GET_RETRY_ID(ale->al_mac, AP_CAPS_QUERY_RETRY_ID, retry_id);
        if(-1 == map_register_retry((const char*)retry_id, 10 , 10 ,
                                    ale, NULL, map_send_ap_capability_query)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Failed Registering retry timer : %s ", retry_id);
        }
    }

    // Send channel preference query until we get channel preference
    if(is_channel_selection_enabled() && request_channel_pref) {
        // ********** Handle channel selection of agent*/
        chan_sel_action_t ch_sel_action = {ale, MAP_CHAN_SEL_QUERY};
        map_agent_handle_channel_selection(NULL, &ch_sel_action);
    }
    // Send channel selection request until we get current op class
    if(is_channel_selection_enabled() && request_channel_sel) {
        // ********** Handle channel selection of agent*/
        chan_sel_action_t ch_sel_action = {ale, MAP_CHAN_SEL_REQUEST};
        map_agent_handle_channel_selection(NULL, &ch_sel_action);
    }

    return 0;
}

int8_t parse_ap_caps_tlv(AP_capability_tlv_t* ap_caps_tlv, map_ale_info_t *ale) {
    if(ap_caps_tlv == NULL || ale == NULL) {
        return -1;
    }
    ale->agent_capability.ib_unassociated_sta_link_metrics_supported = ap_caps_tlv->operating_unsupported_link_metrics;
    ale->agent_capability.oob_unassociated_sta_link_metrics_supported = ap_caps_tlv->non_operating_unsupported_link_metrics;
    ale->agent_capability.rssi_agent_steering_supported = ap_caps_tlv->agent_initiated_steering;

    /* Update roaming engine with ale capabilities */
    MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_ALE(ale);

    return 0;
}

static inline void map_referesh_radio_data( map_radio_info_t *radio, uint8_t *al_mac) {
    map_ale_info_t *ale = get_ale(al_mac);
    if(NULL == ale)
        return;

    // Send policy config
    char retry_id[MAX_TIMER_ID_STRING_LENGTH];
    GET_RETRY_ID(radio->radio_id, POLICY_CONFIG_RETRY_ID, retry_id);
    if(-1 == map_register_retry((const char*)retry_id, 10 , 10 ,
                                ale, NULL, map_build_and_send_policy_config)) {
    }

    // When we have a valid current operating class and the 
    // channel selection is juts completed skip channel selection process.
   if (ale->first_chan_sel_req_done) {
       uint64_t last_chan_sel_req = get_clock_diff_secs(get_current_time(), ale->last_chan_sel_req_time);
       if (last_chan_sel_req > 90) {
            if(radio->op_class_list){
                free(radio->op_class_list);
                radio->op_class_list = NULL;
                radio->op_class_count = 0;
            }
            // Reset current op class and channel
            radio->current_op_class = 0;
            radio->current_op_channel = 0;
       }
    }

    // Reset AP Capabilities
    free(radio->ht_caps); free(radio->vht_caps); free(radio->he_caps);
    radio->ht_caps = 0;   radio->vht_caps = 0;   radio->he_caps = 0;
}

int8_t parse_ap_basic_caps_tlv(AP_basic_capability_tlv_t* ap_basic_capability, uint8_t *al_mac)
{
    int8_t status = 0;
    do
    {
        map_ale_info_t   *ale   = NULL;
        map_radio_info_t *radio = NULL;
        uint8_t radio_freq_type = max_freq_type;
        uint16_t band_type_5G    = 0;

        // Get the frequency type from the operating class list
        for( uint8_t j=0; j < ap_basic_capability->numOperating_class; j++) {
            if( 0 == get_frequency_type(ap_basic_capability->operating_class[j].operating_class,\
                                                &radio_freq_type, &band_type_5G))
                break;
        }
        if(radio_freq_type == max_freq_type) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Failed to get the frequency type from AP radio basic capability");
            ERROR_EXIT(status)
        }
        
        radio = get_radio(ap_basic_capability->radioId);

        if(al_mac && (NULL != (ale = get_ale(al_mac)))) {
            if(NULL == radio){
                radio = map_handle_new_radio_onboarding(ap_basic_capability->radioId, al_mac);
            }
            // We received M1 for an already configured radio.
            else if(is_radio_configured(radio->state)) {

                // Clear all the old data and query for the new once.
                // Though query happens from topology response
                map_referesh_radio_data(radio, al_mac);

                // Extend the agent deletion by restarting topology query retry timer
                map_extend_ale_deletion(ale);
            }
        }

        if( NULL == radio)
            ERROR_EXIT(status)

        radio->supported_freq = radio_freq_type;
        radio->band_type_5G   = band_type_5G;
        radio->max_bss        = ap_basic_capability->max_bss;

        if(ap_basic_capability->max_bss == 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s Max BSS in radio can not be zero\n",__func__);
            ERROR_EXIT(status)
        }

        /* Update radio caps with initial defaults based on freq */
        update_radio_caps(radio);

    } while (0);

    return status;
}

int8_t parse_ap_ht_caps_tlv(AP_HT_capability_tlv_t* ap_ht_caps) {
    int8_t status = 0;
    do
    {
        if(ap_ht_caps == NULL)
            ERROR_EXIT(status)

        map_radio_info_t *radio = get_radio(ap_ht_caps->radio_id);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s Radio node not found in controller data model!\n", __func__);
            ERROR_EXIT(status)
        }

        // Allocate memory first time.
        if(radio->ht_caps == NULL) {
           radio->ht_caps = calloc(1, sizeof(map_radio_ht_capabilty_t));
        }
        if(radio->ht_caps) {
            radio->ht_caps->max_supported_tx_streams = ap_ht_caps->max_supported_tx_streams + 1;
            radio->ht_caps->max_supported_rx_streams = ap_ht_caps->max_supported_rx_streams + 1;
            radio->ht_caps->gi_support_20mhz = ap_ht_caps->gi_support_20mhz;
            radio->ht_caps->gi_support_40mhz = ap_ht_caps->gi_support_40mhz;
            radio->ht_caps->ht_support_40mhz = ap_ht_caps->ht_support_40mhz;
            update_radio_caps(radio);
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s calloc failed.\n", __func__);
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}

int8_t parse_ap_vht_caps_tlv(AP_VHT_capability_tlv_t* ap_vht_caps) {
    int8_t status = 0;
    do
    {
        if(ap_vht_caps == NULL)
            ERROR_EXIT(status)

        map_radio_info_t *radio = get_radio(ap_vht_caps->radio_id);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s Radio node not found in controller data model!\n", __func__);
            ERROR_EXIT(status)
        }

        // Allocate memory first time.
        if(radio->vht_caps == NULL) {
           radio->vht_caps = calloc(1, sizeof(map_radio_vht_capabilty_t));
        }

        if(radio->vht_caps) {
            radio->vht_caps->supported_tx_mcs = ap_vht_caps->supported_tx_mcs;
            radio->vht_caps->supported_rx_mcs = ap_vht_caps->supported_rx_mcs;
            radio->vht_caps->max_supported_tx_streams = ap_vht_caps->max_supported_tx_streams + 1;
            radio->vht_caps->max_supported_rx_streams = ap_vht_caps->max_supported_rx_streams + 1;
            radio->vht_caps->gi_support_80mhz = ap_vht_caps->gi_support_80mhz;
            radio->vht_caps->gi_support_160mhz = ap_vht_caps->gi_support_160mhz;
            radio->vht_caps->support_80_80_mhz = ap_vht_caps->support_80_80_mhz;
            radio->vht_caps->support_160mhz = ap_vht_caps->support_160mhz;
            radio->vht_caps->su_beamformer_capable = ap_vht_caps->su_beamformer_capable;
            radio->vht_caps->mu_beamformer_capable = ap_vht_caps->mu_beamformer_capable;
            update_radio_caps(radio);
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s calloc failed.\n", __func__);
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}

int8_t parse_ap_he_caps_tlv(AP_HE_capability_tlv_t *ap_he_caps) {
    int8_t status = 0;
    do
    {
        if(ap_he_caps == NULL)
            ERROR_EXIT(status)

        map_radio_info_t *radio = get_radio(ap_he_caps->radio_id);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s Radio node not found in controller data model!\n", __func__);
            ERROR_EXIT(status)
        }

        // Allocate memory first time.
        if(radio->he_caps == NULL) {
           radio->he_caps = calloc(1, sizeof(map_radio_he_capabilty_t));
        }

        if(radio->he_caps) {
            if(ap_he_caps->supported_mcs_length > 12){
                platform_log(MAP_CONTROLLER,LOG_ERR, "Invalid supported MCS length: %d\n", ap_he_caps->supported_mcs_length);
                ERROR_EXIT(status);
            }

            radio->he_caps->supported_mcs_length = ap_he_caps->supported_mcs_length;
            memcpy(radio->he_caps->supported_tx_rx_mcs, ap_he_caps->supported_tx_rx_mcs, ap_he_caps->supported_mcs_length);
            radio->he_caps->max_supported_tx_streams = ap_he_caps->max_supported_tx_streams + 1;
            radio->he_caps->max_supported_rx_streams = ap_he_caps->max_supported_rx_streams + 1;
            radio->he_caps->support_80_80_mhz = ap_he_caps->support_80_80_mhz;
            radio->he_caps->support_160mhz = ap_he_caps->support_160mhz;
            radio->he_caps->su_beamformer_capable = ap_he_caps->su_beamformer_capable;
            radio->he_caps->mu_beamformer_capable = ap_he_caps->mu_beamformer_capable;
            radio->he_caps->ul_mimo_capable = ap_he_caps->ul_mimo_capable;
            radio->he_caps->ul_mimo_ofdma_capable = ap_he_caps->ul_mimo_ofdma_capable;
            radio->he_caps->dl_mimo_ofdma_capable = ap_he_caps->dl_mimo_ofdma_capable;
            radio->he_caps->ul_ofdma_capable = ap_he_caps->ul_ofdma_capable;
            radio->he_caps->dl_ofdma_capable = ap_he_caps->dl_ofdma_capable;
            update_radio_caps(radio);
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s calloc failed.\n", __func__);
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}

int8_t parse_ap_metrics_response_tlv(ap_metrics_response_tlv_t* ap_metrics_resp) {
    if(ap_metrics_resp == NULL){
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "NULL pointer check failed in %s\n",__func__);
        return -1;
    }
    map_bss_info_t *bss = get_bss(ap_metrics_resp->bssid);
    if(bss == NULL) {
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "BSS Not yet updated in data model %s : %d\n",__func__, __LINE__);
        return -1;
    }

    bss->metrics.channel_utilization   =   ap_metrics_resp->channel_util;
    bss->metrics.sta_count             =   ap_metrics_resp->sta_count;
    bss->metrics.esp_present           =   ap_metrics_resp->esp_present;

    for(uint8_t ac_index = 0; ac_index < MAX_ACCESS_CATEGORIES; ac_index++) {
        if (bss->metrics.esp_present & (1<<(7 - ac_index))) {
            memcpy(bss->metrics.esp[ac_index].byte_stream, ap_metrics_resp->esp[ac_index].byte_stream, 3);
        }
    }
    return 0;
}

int8_t parse_assoc_sta_traffic_stats_tlv(assoc_sta_traffic_stats_tlv_t* sta_traffic_stats) {
    int8_t status = 0;

    do
    {
        if(sta_traffic_stats == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s : %d Invalid STA\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        map_sta_info_t *sta = get_sta(sta_traffic_stats->sta_mac);
        if(sta == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "NULL pointer check failed in %s : %d\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        /// Allocate memory for at first occurance
        if(sta->traffic_stats == NULL) {
            sta->traffic_stats = calloc(1, sizeof(map_sta_traffic_stats_t));
        }

        if(sta->traffic_stats) {
            sta->traffic_stats->txbytes             = sta_traffic_stats->txbytes;
            sta->traffic_stats->rxbytes             = sta_traffic_stats->rxbytes;
            sta->traffic_stats->txpkts              = sta_traffic_stats->txpkts;
            sta->traffic_stats->rxpkts              = sta_traffic_stats->rxpkts;
            sta->traffic_stats->txpkterrors         = sta_traffic_stats->txpkterrors;
            sta->traffic_stats->rxpkterrors         = sta_traffic_stats->rxpkterrors;
            sta->traffic_stats->retransmission_cnt  = sta_traffic_stats->retransmission_cnt;
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "calloc failed in %s : %d\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

int8_t parse_assoc_sta_link_metrics_tlv(associated_sta_link_metrics_t* sta_metrics_tlv) {

    if(!sta_metrics_tlv)
        return -1;

    map_sta_info_t *sta = NULL;
    sta = get_sta(sta_metrics_tlv->associated_sta_mac);
    if(sta == NULL || sta->bss == NULL)
        return -1;

    sta_link_metric_t *sta_metrics = NULL;
    for ( uint8_t i = 0; i < sta_metrics_tlv->reported_bssid_count ; i++, sta_metrics = NULL )
    {
        sta_metrics = &sta_metrics_tlv->sta_metrics[i];
        if (0 == memcmp( sta->bss->bssid, sta_metrics->bssid, MAC_ADDR_LEN)) {
            map_sta_link_metrics_t *link_metrics = calloc(1, sizeof(map_sta_link_metrics_t));
            if(link_metrics) {

                // Update the metrics data
                link_metrics->age = sta_metrics->report_time_interval;
                link_metrics->dl_mac_datarate = sta_metrics->downlink_data_rate;
                link_metrics->ul_mac_datarate = sta_metrics->uplink_data_rate;
                link_metrics->rssi = sta_metrics->uplink_rssi;
                update_assoc_sta_link_metrics(sta, link_metrics);
            }
        }
        else {
            // TODO What should be done here?
            int8_t bssid_str[MAX_MAC_STRING_LEN] = {0};
            int8_t sta_mac_str[MAX_MAC_STRING_LEN] = {0};
            int8_t received_bssid_str[MAX_MAC_STRING_LEN] = {0};

            get_mac_as_str(sta->bss->bssid, bssid_str, MAX_MAC_STRING_LEN);
            get_mac_as_str(sta->mac, sta_mac_str, MAX_MAC_STRING_LEN);
            get_mac_as_str(sta_metrics->bssid, received_bssid_str, MAX_MAC_STRING_LEN);

            platform_log(MAP_CONTROLLER,LOG_DEBUG, "STA %s associated to BSS %s received metrics \
                response with incorrect BSSID: %s ", sta_mac_str, bssid_str, received_bssid_str);
        }
    }

    return 0;
}

static inline void store_channel_preference_set(map_radio_info_t *radio,
                            channel_preference_tlv_t *channel_pref_tlv,
                            uint8_t max_op_class_count) {

    if(radio == NULL || channel_pref_tlv == NULL || max_op_class_count == 0 )
        return;
    
    uint8_t new_op_class_count = 0;
    uint8_t existing_op_class_count = 0;

    map_op_class_t *op_class = NULL;

    // Merge the operating class data with no operable operating class reported by 
    // radio operation restriction TLV
    for(int8_t i = 0; i < channel_pref_tlv->numOperating_class; ++i, op_class = NULL) {

        if(channel_pref_tlv->operating_class[i].number_of_channels > MAX_CHANNEL_IN_OPERATING_CLASS) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Max channels can not be more than %d", __func__, MAX_CHANNEL_IN_OPERATING_CLASS);
            continue;
        }

        for (uint8_t ops_index = 0; ops_index < max_op_class_count; ++ops_index) {

            if(radio->op_class_list[ops_index].op_class == 0) {
                op_class = radio->op_class_list + ops_index;
                new_op_class_count++;
                break;
            }
            else if( radio->op_class_list[ops_index].op_class ==\
                channel_pref_tlv->operating_class[i].operating_class) {
                op_class = radio->op_class_list + ops_index;
                existing_op_class_count++;
                break;
            }
            else {
                continue;
            }
        }


        if(op_class) {

            op_class->op_class = channel_pref_tlv->operating_class[i].operating_class;
            op_class->pref     = channel_pref_tlv->operating_class[i].pref_reason >> NUM_SHIFT_TO_GET_PREF;
            op_class->reason   = channel_pref_tlv->operating_class[i].pref_reason & PREF_REASON_BIT_MASK;
            op_class->agent_channel_count = channel_pref_tlv->operating_class[i].number_of_channels;

            if(channel_pref_tlv->operating_class[i].number_of_channels)
                memcpy( op_class->agent_channel,
                        channel_pref_tlv->operating_class[i].channel_num,
                        channel_pref_tlv->operating_class[i].number_of_channels);


        }
    }

    // Count should be merged with non operating channel list
    if(radio->op_class_count == 0)
        radio->op_class_count = new_op_class_count;
    else
        radio->op_class_count = radio->op_class_count + new_op_class_count;
}



static inline void store_channel_restriction_set(map_radio_info_t *radio,
                            radio_operation_restriction_tlv_t *ops_restriction_tlv,
                            uint8_t max_op_class_count) {

    if(radio == NULL || ops_restriction_tlv == NULL || max_op_class_count == 0 )
        return;

    uint8_t new_op_class_count = 0;
    uint8_t existing_op_class_count = 0;

    map_op_class_t *op_class = NULL;
    // Merge the operating class data with Agent channel preference op class
    for(int8_t i = 0; i < ops_restriction_tlv->numOperating_class; ++i, op_class = NULL) {
        for (uint8_t ops_index = 0; ops_index < max_op_class_count; ++ops_index) {
            if(radio->op_class_list[ops_index].op_class == 0) {
                op_class = radio->op_class_list + ops_index;
                new_op_class_count++;
                break;
            }
            else if( radio->op_class_list[ops_index].op_class ==\
                ops_restriction_tlv->operating_class[i].operating_class) {
                op_class = radio->op_class_list + ops_index;
                existing_op_class_count++;
                break;
            }
            else {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s No space to store OP class",__func__);
            }
        }
        if(op_class) {

            if(ops_restriction_tlv->operating_class[i].number_of_channels > MAX_CHANNEL_IN_OPERATING_CLASS) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "%s Max channels can not be more than %d", __func__, MAX_CHANNEL_IN_OPERATING_CLASS);
                continue;
            }

            op_class->op_class = ops_restriction_tlv->operating_class[i].operating_class ;
            op_class->dynamic_non_operable_count = ops_restriction_tlv->operating_class[i].number_of_channels;

            if(op_class->dynamic_non_operable_count)
                memcpy( op_class->dynamic_non_operable_channel, 
                        ops_restriction_tlv->operating_class[i].channel_restriction_set,
                        ops_restriction_tlv->operating_class[i].number_of_channels);
        }
        else {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Channel restriction TLV did not have channel preference", __func__);
        }
    }

    // Count should be merged with channel preference
    if(radio->op_class_count == 0)
        radio->op_class_count = new_op_class_count;
    else
        radio->op_class_count = radio->op_class_count + new_op_class_count;

}

int8_t update_transmit_power(uint8_t *dst_al_mac, uint8_t *radio_id, uint8_t tx_pwr) {

    int8_t status = 0;

    do
    {
        map_ale_info_t *dst_ale =  NULL;
        map_radio_info_t *radio = NULL;

        dst_ale = get_ale(dst_al_mac);
        if(dst_ale == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s dst_ale not found ", __func__);
            ERROR_EXIT(status)
        }

        for (int8_t radio_index = 0; radio_index < dst_ale->num_radios; ++radio_index) {
            radio = dst_ale->radio_list[radio_index];
            // Send request only to a configured radios
            if (radio && 
               (memcmp(radio->radio_id, radio_id, MAC_ADDR_LEN) == 0)) {
               break;
            }
            radio = NULL;
        }

        // Get the radio info
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Radio node not yet updated in controller data model", __func__);
            ERROR_EXIT(status)
        }

        radio->current_tx_pwr = tx_pwr;
    } while (0);

    return status;
}

int8_t parse_chan_pref_tlv(channel_preference_tlv_t *channel_pref_tlv) {
    int8_t status = 0;
    do
    {
        // Get the radio info
        map_radio_info_t *radio = get_radio(channel_pref_tlv->radio_id);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Radio node not yet updated in controller data model", __func__);
            ERROR_EXIT(status)
        }
        
        uint8_t  max_op_class_count = 0;
        uint16_t memory_required    = 0;
        uint8_t  tlv_op_class_count = channel_pref_tlv->numOperating_class;


        // If the prefered operating class count is zero
        // Allocate one byte to indicate that we received an empty channel pref
        if(tlv_op_class_count == 0) {
            memory_required = sizeof(map_op_class_t);
            max_op_class_count = 1;
        }
        else {
            max_op_class_count = (tlv_op_class_count > radio->op_class_count) ?\
                                        tlv_op_class_count : radio->op_class_count;
            memory_required = max_op_class_count * sizeof(map_op_class_t);
        }

        // Allocate sufficient memory
        if(radio->op_class_list == NULL)
            radio->op_class_list = calloc(1, memory_required);
        else if(max_op_class_count > radio->op_class_count) {

            radio->op_class_list = realloc(radio->op_class_list, memory_required);
            if(radio->op_class_list) {
                memset(&radio->op_class_list[radio->op_class_count], 0,\
                        (max_op_class_count - radio->op_class_count) * sizeof(map_op_class_t));
            }
        }

        if(0 == tlv_op_class_count)
            break;

        if(radio->op_class_list) {
            store_channel_preference_set(radio, channel_pref_tlv, max_op_class_count);
        } else {
            radio->op_class_count = 0;
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to allocate memory for OP class", __func__);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

int8_t parse_op_restriction_tlv(radio_operation_restriction_tlv_t *ops_restriction_tlv) {
    int8_t status = 0;
    do
    {
        // Get the radio info
        map_radio_info_t *radio = get_radio(ops_restriction_tlv->radio_id);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Radio node not yet updated in controller data model", __func__);
            ERROR_EXIT(status)
        }

        if(ops_restriction_tlv->numOperating_class == 0)
            break; // If the operating class count is zero nothing to update

        uint8_t max_op_class_count = (ops_restriction_tlv->numOperating_class > radio->op_class_count) ?\
                                      ops_restriction_tlv->numOperating_class : radio->op_class_count;
        uint16_t memory_required = max_op_class_count * sizeof(map_op_class_t);

        // Allocate sufficient memory
        if(radio->op_class_list == NULL){
            radio->op_class_list = calloc(1, memory_required);
        }
        else if(max_op_class_count > radio->op_class_count) {
            radio->op_class_list = realloc(radio->op_class_list, memory_required);
            if(radio->op_class_list){
                memset(&radio->op_class_list[radio->op_class_count], 0,\
                        (max_op_class_count - radio->op_class_count) * sizeof(map_op_class_t));
            }
        }

        if(radio->op_class_list) {
            // Store the Channel preference first
            store_channel_restriction_set(radio, ops_restriction_tlv, max_op_class_count);
        } else {
            radio->op_class_count = 0;
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s Failed to allocate memory for OP class", __func__);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

int8_t parse_device_info_tlv(struct deviceInformationTypeTLV *dev_info_tlv) {
    int8_t status = 0;
    do {
        // Create new ALE if not exist already
        map_ale_info_t* ale = get_ale(dev_info_tlv->al_mac_address);
        if(ale == NULL)
            ERROR_EXIT(status)

        // TODO: Store the local interface list

    } while (0);

    return status;
}
int8_t parse_neighbor_device_list_tlv(struct neighborDeviceListTLV **neigh_dev_tlv,
                                        uint8_t tlv_count, map_ale_info_t *ale) {
    int8_t status = 0;
    do {

        // Use the neighbor info TLV to build a topology tree
        if(ale && neigh_dev_tlv && tlv_count && !is_local_agent(ale))
            map_build_topology_tree(neigh_dev_tlv, tlv_count, ale);

    } while (0);

    return status;
}
