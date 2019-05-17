/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_utils.h"
#include "multiap_controller.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_metrics_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "platform_multiap_get_info.h"
#include "multiap_controller_payloads.h"
#include "map_80211.h"

extern unsigned int grun_daemon;

int platform_init(plfrm_config* config)
{

    openlog("Multiap_Controller", 0, LOG_DAEMON);

    //Check if daemonize if enabled , only then enable log in console
    if(grun_daemon == 0)
        config->log_output=log_syslog;

    if(platform_config_load(MAP_PLATFORM_GET_CONTROLLER_CONFIG,config))
        return -1;

    if(grun_daemon)
        daemonize(config);

    return 0;
}

int parse_update_client_capability(map_sta_info_t  *sta, uint16_t assoc_frame_len, uint8_t* assoc_frame) 
{

    if(sta == NULL || assoc_frame_len == 0 || assoc_frame == NULL)
        return -EINVAL;

    /* Free the existing memory, and Alloc new memory for assoc_frame. 
     * This will make sure, we will maintain one memory for assoc frame
     * irrespective of the function called multiple times for the same sta.
     */
    free(sta->assoc_frame);
    sta->assoc_frame_len = 0;

    /*
     * 
     * Freeing of sta->assoc_frame is also taken care in remove_sta();
     * being called when sta disconnects from EBSS.
     *
     * If ever we don't need "sta->assoc_frame", we can free(sta->assoc_frame) 
     * the memory and update the sta->assoc_frame_len = 0;
     */
    
    sta->assoc_frame = (uint8_t *)malloc(assoc_frame_len);
    if(sta->assoc_frame == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s %d, malloc failure\n",__func__,__LINE__);
        return -EINVAL;
    }
    

    sta->assoc_frame_len = assoc_frame_len;
    memcpy(sta->assoc_frame, assoc_frame, assoc_frame_len);

    /* Fill in sta capabilities */
    map_80211_parse_assoc_body(&sta->sta_caps, sta->assoc_frame, sta->assoc_frame_len, 
                               sta->bss->radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ, 
                               sta->bss->ssid, sta->bss->ssid_len);
    return 0;
}

/** @brief This function will update the upstream remote MAC of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param pointer to a string of interface MAC
 *  @return status
 */
int8_t map_update_ale_upstream_remote_mac (map_ale_info_t *ale, uint8_t* iface_mac) {
    int8_t status = 0;
    if(ale != NULL && iface_mac != NULL)
    {
        if(0 != memcmp(ale->upstream_remote_iface_mac, iface_mac, MAC_ADDR_LEN)) {
            // Update the upstream remote interface of the neighbor
            memcpy(ale->upstream_remote_iface_mac, iface_mac, MAC_ADDR_LEN);
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s \n",__func__);
            status = 1;
        }
    }
    return status;
}

/** @brief This function will update the upstream local MAC of the ALE
 *
 *  @param ale pointer to ALE node to be updated
 *  @param pointer to a string of interface MAC
 *  @return status
 */
int8_t map_update_ale_upstream_local_mac (map_ale_info_t *ale, uint8_t* iface_mac) {
    int8_t status = 0;
    if(ale != NULL && iface_mac != NULL)
    {
        if(0 != memcmp(ale->upstream_local_iface_mac, iface_mac, MAC_ADDR_LEN)) {
            // Update the upstream remote interface of the neighbor
            memcpy(ale->upstream_local_iface_mac, iface_mac, MAC_ADDR_LEN);
            platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s \n",__func__);
            status = 1;
        }
    }
    return status;
}

int8_t map_update_ale_upstream_iface_type (map_ale_info_t *ale, uint16_t iface_type) {
    int8_t status = 0;
    if (ale) {
        if (ale->upstream_iface_type != iface_type) {
            ale->upstream_iface_type = iface_type;
            status = 1;
        }
    }
    return status;
}
