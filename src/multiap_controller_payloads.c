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
#include "multiap_controller_callbacks.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "multiap_controller_tlv_helper.h"
#include "map_data_model.h"
#include "arraylist.h"
#include "map_topology_tree.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_payloads.h"
#include "map_retry_handler.h"
#include "platform_multiap_get_info.h"
#include "1905_tlvs.h"
#include "multiap_controller_topology_tree_builder.h"

#define ONE_OCTET 	(1)
#define TWO_OCTET	(2)

#define min(a,b) ((a) < (b) ? (a) : (b))

#define catch_mid(handle_ptr, mid_ptr) (handle_ptr)? ({*mid_ptr = &(handle_ptr->mid);}) : ({})

int get_tlv_fromcmdu(uint16_t tlvtype,struct CMDU *cmdu,void** ptlv_data)
{
        uint8_t *p;
        int i=0;

        if (NULL == cmdu->list_of_TLVs)
        {
                platform_log(MAP_CONTROLLER,LOG_ERR,"get_tlv_fromcmdu Input CMDU Malformed structure.");
                return -1;
        }
        while (NULL != (p = cmdu->list_of_TLVs[i]))
        {
                if (*p == tlvtype)
                {
                        *ptlv_data=p;
                        return 0;
                }
                i++;
        }
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"Unexpected TLV (%d) type inside CMDU\n", tlvtype);
        return -1;
}

struct mapErrorCodeTLV * get_error_code_tlv(uint8_t reason_code, uint8_t *sta_mac)
{
    struct mapErrorCodeTLV * error_code_tlv = NULL;
    /* Input Parameters Validation */
    if ((NULL == sta_mac) || (reason_code < STA_ASSOCIATED) || (reason_code > STEERING_REJECTED_BY_TARGET))
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, "get_error_code_tlv Input Validation failed");
        return NULL;
    }

    error_code_tlv = (struct mapErrorCodeTLV *) calloc (1,sizeof(struct mapErrorCodeTLV));
    if (NULL == error_code_tlv)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Malloc failed for error_code_tlv");
        return NULL;
    }

    error_code_tlv->tlv_type = TLV_TYPE_ERROR;
    error_code_tlv->reason_code = reason_code;
    memcpy(error_code_tlv->sta_mac_addr,sta_mac,MAC_ADDR_LEN);

    return error_code_tlv;
}

int map_send_1905_ack(map_handle_t *map_handle, array_list_t* sta_list, uint8_t reason_code)
{
    uint8_t number_of_tlv   = 0;
    uint8_t sta_count       = 0;
    struct  CMDU *cmdu      = NULL;
    struct  CMDU *recv_cmdu = NULL;
    list_iterator_t* it     = NULL;
    uint8_t *sta_mac        = NULL;
    int     i               = 0;
    int     ret             = 0;

    struct mapErrorCodeTLV *error_code_tlv;

    /* Map Handle parameters Validation */
    if ((NULL == map_handle) || ((NULL != map_handle) && (NULL == map_handle->recv_cmdu)))
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"Map Handle parameters Validation Failed");
        ret = -1;
        goto Cleanup;
    }
    recv_cmdu = (struct CMDU*)map_handle->recv_cmdu;

    if (NULL != sta_list)
    {
        sta_count = list_get_size(sta_list);
        number_of_tlv += sta_count;
    }

    /* init payload CMDU */
    cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

    if (NULL == cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"CMDU malloc failed");
        ret = -1;
        goto Cleanup;
    }

    cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu->message_type     =  CMDU_TYPE_MAP_ACK;
    cmdu->message_id       =  recv_cmdu->message_id;
    cmdu->relay_indicator  =  0;

    strncpy(cmdu->interface_name, recv_cmdu->interface_name, MAX_IFACE_NAME_LEN);

    cmdu->list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu->list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        ret = -1;
        goto Cleanup;
    }

    if (sta_count > 0)
    {
        it = new_list_iterator(sta_list);
        if(!it)
        {
            ret = -1;
            goto Cleanup;
        }

        while(it->iter)
        {
            sta_mac = (uint8_t*) get_next_list_object(it);
            if(NULL == sta_mac)
            {
                platform_log(MAP_CONTROLLER,LOG_ERR, "sta_mac is NULL");
                ret = -1;
                goto Cleanup;
            }

            error_code_tlv = get_error_code_tlv(reason_code, sta_mac);
            if (NULL == error_code_tlv)
            {
                platform_log(MAP_CONTROLLER,LOG_ERR, "Get Error Code TLV failed");
                ret = -1;
                goto Cleanup;
            }

            cmdu->list_of_TLVs[i++] = (uint8_t *)error_code_tlv;
            error_code_tlv = NULL;
            sta_mac        = NULL;
        }

        if (i != number_of_tlv)
        {
            platform_log(MAP_CONTROLLER,LOG_ERR, "Count mismatch btwn error code tlvs and sta count");
            ret = -1;
            goto Cleanup;
        }
    }

    if (lib1905_send(handle_1905, &cmdu->message_id, recv_cmdu->cmdu_stream.src_mac_addr, cmdu) < 0) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
        ret = -1;
    }

Cleanup:
    if (NULL != it)
        free_list_iterator(it);

    if (NULL != cmdu)
        lib1905_cmdu_cleanup(cmdu);

    return ret;
}

int8_t map_send_autoconfig_response(struct CMDU *recv_cmdu)
{
    int8_t          status           = 0;
    uint8_t         number_of_tlv    = 3;
    struct CMDU     cmdu             = {0};
    uint16_t        mid              = 0;

    do
    {
        if(recv_cmdu == NULL)
            ERROR_EXIT(status)

        mid = recv_cmdu->message_id;

        // Get the AL MAC TLV to identify the agent node
        struct alMacAddressTypeTLV *al_mac_tlv = NULL;
        if(-1 == get_tlv_fromcmdu(TLV_TYPE_AL_MAC_ADDRESS_TYPE, recv_cmdu, (void *)&al_mac_tlv)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get TLV_TYPE_AL_MAC_ADDRESS_TYPE.\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }
        // Fetch the agent node
        map_ale_info_t* ale = get_ale(al_mac_tlv->al_mac_address);
        if(!ale) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s Get agent node failed\n", __func__);
            ERROR_EXIT(status)
        }

        struct supportedRoleTLV       supported_role_tlv      = {0};
        struct supportedFreqBandTLV   supported_freq_band_tlv = {0};
        struct mapSupportedServiceTLV supported_service_tlv   = {0};

        //##Add Supported Role Tlv
        if (lib1905_get(handle_1905, (lib1905_param_t) GET_1905_SUPPORTEDROLETLV,  NULL , (void *)&supported_role_tlv, NULL)){
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d SEARCHED_ROLE TLV lib1905_get failed\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        //##Add Supported Frequency Band Tlv
        struct autoconfigFreqBandTLV * autoconfig_freq_band_tlv = NULL;

        if(-1 == get_tlv_fromcmdu(TLV_TYPE_AUTOCONFIG_FREQ_BAND, recv_cmdu,(void *)&autoconfig_freq_band_tlv)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get the FREQ Band TLV",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        supported_freq_band_tlv_t  supp_freq_band = {0};
        supp_freq_band.supported_freq_band_tlv = &supported_freq_band_tlv;
        supp_freq_band.freq_band               = autoconfig_freq_band_tlv->freq_band;

        if (lib1905_get(handle_1905, (lib1905_param_t) GET_1905_SUPPORTEDFREQBANDTLV,  NULL , (void *)&supp_freq_band, NULL)){
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d SEARCHED_ROLE TLV lib1905_get failed\n",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        //## Add Supported service TLV
        //TODO: Get supported service from platform abstraction
        supported_service_tlv.tlv_type  = TLV_TYPE_SUPPORTED_SERVICE;
        supported_service_tlv.tlv_length                 = 2;
        supported_service_tlv.number_of_service          = 1;
        supported_service_tlv.supported_service_array[0] = MAP_ROLE_CONTROLLER;

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE;
        cmdu.message_id       =  mid;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        strncpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
        if(cmdu.list_of_TLVs == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
            ERROR_EXIT(status)
        }

        cmdu.list_of_TLVs[0] = (uint8_t *)&supported_role_tlv;
        cmdu.list_of_TLVs[1] = (uint8_t *)&supported_freq_band_tlv;
        cmdu.list_of_TLVs[2] = (uint8_t *)&supported_service_tlv;

        /* The spec implies (certification test plan)the messages to be sent to the AL MAC address of the 1905 device
        intead the source mac address, CMDUs that has ALMAC tlv can be handled this way */
        if (lib1905_send(handle_1905, &mid, al_mac_tlv->al_mac_address, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }

    } while (0);

    free(cmdu.list_of_TLVs);

    return status;
}

int8_t map_send_topology_response(struct CMDU *recv_cmdu)
{
        int     neighbor_count = 0;
	int     status         = -1;
	int     no_of_tlv      = 0;
        int     tlv_count      = 0;
	uint8_t i              = 0;

#define BASIC_TLVS_FOR_TOPOLOGY_RESP 4 /*DEVICE INFO + SUPPORTED SERVICE + AP OPERATIONAL + NULL tlv*/

	struct CMDU  send_cmdu = {0};
        struct deviceInformationTypeTLV     device_info_tlv        = {0};
        struct deviceBridgingCapabilityTLV  bridge_info_tlv        = {0};
	struct mapSupportedServiceTLV       supported_service_tlv  = {0};
	struct mapApOperationalBssTLV       ap_operational_bss_tlv = {0};
        struct neighborDeviceListTLV        neighbor_1905_tlvs[MAX_INTERFACE_COUNT] = {0};

	do
	{
	    if(recv_cmdu == NULL) {
	        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d recv_cmdu(TOPOLOGY QUERY) is null\n",__func__, __LINE__);
	        ERROR_EXIT(status);
	    }

            send_cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
            send_cmdu.message_type    = CMDU_TYPE_TOPOLOGY_RESPONSE;
            send_cmdu.message_id      = recv_cmdu->message_id;
            send_cmdu.relay_indicator = 0;
	    strncpy(send_cmdu.interface_name, recv_cmdu->interface_name, sizeof(send_cmdu.interface_name));

            /* Get 1905 device information tlv */
            if (lib1905_get(handle_1905, (lib1905_param_t)GET_1905_DEVICE_INFO_TLV, NULL, (void *) &device_info_tlv, NULL)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "get_device_info_tlv failed");
                break;
            }

            /* Get 1905 bridge capability tlv */
            if (-1 == map_get_bridge_info_tlv(&bridge_info_tlv)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "get_bridge_capability_tlv failed");
                break;
            }

            /* Get neighbors tlvs */
            if (-1 == map_get_1905_neighbor_tlvs((struct neighborDeviceListTLV *) &neighbor_1905_tlvs, &neighbor_count)) {
                platform_log(MAP_CONTROLLER,LOG_ERR, "get_neighbor_tlvs failed");
                break;
            }


            /* Get supported service tlv */
	    supported_service_tlv.tlv_type           = TLV_TYPE_SUPPORTED_SERVICE;
	    supported_service_tlv.tlv_length         = 2;
	    supported_service_tlv.number_of_service  = 1;
	    supported_service_tlv.supported_service_array[0] = MAP_ROLE_CONTROLLER;

	    /* Get AP OPERATIONAL BSS TLV */
	    ap_operational_bss_tlv.tlv_type     = TLV_TYPE_AP_OPERATIONAL_BSS;
	    ap_operational_bss_tlv.no_of_radios = 0;
	    ap_operational_bss_tlv.tlv_length   = 1;

            /* Intilise list of tlvs */
            no_of_tlv = BASIC_TLVS_FOR_TOPOLOGY_RESP + neighbor_count;

            if (bridge_info_tlv.bridging_tuples_nr > 0) no_of_tlv++; /*Increment for bridge tlv */

            send_cmdu.list_of_TLVs = (uint8_t **) calloc(1, no_of_tlv * sizeof(INT8U *));
            if (!send_cmdu.list_of_TLVs) {
                platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d calloc failed\n",__func__, __LINE__);
                break;
            }

            send_cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&device_info_tlv;           /* Device info tlv*/

            if (bridge_info_tlv.bridging_tuples_nr > 0) {
                send_cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&bridge_info_tlv;       /* Bridge Info tlv */
            }

            for (i = 0; i < neighbor_count; i++) {
                send_cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&neighbor_1905_tlvs[i]; /* 1905 Neighbor tlvs */
            }

	    send_cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&supported_service_tlv;     /* Supported Service tlv */
	    send_cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&ap_operational_bss_tlv;    /* AP Operational BSS tlv */
	    send_cmdu.list_of_TLVs[tlv_count++] = NULL;

            if (tlv_count != no_of_tlv) {
                platform_log(MAP_CONTROLLER,LOG_ERR,"\n%s: Tlv count mismatch",__func__);
                break;
            }

	    if (lib1905_send(handle_1905, &send_cmdu.message_id, recv_cmdu->cmdu_stream.src_mac_addr, &send_cmdu)<0) {
	        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__,send_cmdu.message_type);
	    } else {
                char mac_str[MAX_MAC_STRING_LEN];
                platform_log(MAP_CONTROLLER,LOG_DEBUG,"--> CMDU_TYPE_TOPOLOGY_RESPONSE - %s", MAC_AS_STR(recv_cmdu->cmdu_stream.src_mac_addr, mac_str));
                status = 0;
	    }
	   
	} while(0);

        /* Free Device Info tlv */
        if (NULL != device_info_tlv.local_interfaces)
            free(device_info_tlv.local_interfaces);

        /* Free Bridge info tlv */
        map_free_bridge_info_tlv (&bridge_info_tlv);

        /* Free 1905 neighbor tlvs */
        for (i = 0; i < neighbor_count; i++) {
            map_free_1905_neighbor_tlv(&neighbor_1905_tlvs[i]);
        }

        if (NULL != send_cmdu.list_of_TLVs)
            free(send_cmdu.list_of_TLVs);

	return status;
}

static uint16_t get_freq_band (map_radio_info_t *radio) {

    if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
        return MAP_M2_BSS_RADIO2G;
    else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ && radio->band_type_5G == MAP_M2_BSS_RADIO5GU)
        return MAP_M2_BSS_RADIO5GU;
    else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ && radio->band_type_5G == MAP_M2_BSS_RADIO5GL)
        return MAP_M2_BSS_RADIO5GL;
    else
        return -1;
}

static void clone_credential_config(config_credential_t *dst_cred, config_credential_t *src_cred) {
    if(dst_cred && src_cred) {
        strncpy(dst_cred->bss_ssid, src_cred->bss_ssid, MAX_WIFI_SSID_LEN);
        strncpy(dst_cred->wpa_key, src_cred->wpa_key, MAX_WIFI_PASSWORD_LEN);
        dst_cred->supported_auth_modes = src_cred->supported_auth_modes;
        dst_cred->supported_encryption_types = src_cred->supported_encryption_types;
        dst_cred->bss_freq_bands = src_cred->bss_freq_bands;
        dst_cred->bss_state = src_cred->bss_state;
    }
}

uint8_t get_cred_count_per_freq_band(uint16_t freq_band) {
    uint8_t cred_count = 0;
    map_cfg* controller_config      = get_controller_config();
    for (uint8_t i = 0; i < controller_config->map_num_credentials; ++i) {
        if(controller_config->credential_config[i].bss_freq_bands & freq_band)
            cred_count++;
    }
    return cred_count;
}

int8_t map_get_m2_config(map_radio_info_t *radio, uint8_t *config_count, config_credential_t *m2_config) {
    int8_t status = 0;
    do
    {
        if( (NULL == radio)|| (NULL == m2_config) || (radio->max_bss == 0) ||  (radio->max_bss > MAX_BSS_PER_RADIO) )
            ERROR_EXIT(status)

        platform_log(MAP_CONTROLLER,LOG_DEBUG, " %s MAX BSS Reported in M1 : %d", __func__,radio->max_bss);

        map_cfg* controller_config      = get_controller_config();
        uint16_t freq_band              = get_freq_band(radio);
        config_credential_t *credential = NULL;
        uint8_t bss_state               = 0;

        for (uint8_t i = 0; (i < controller_config->map_num_credentials) && ( *config_count < radio->max_bss); ++i, bss_state = 0) {
            credential = controller_config->credential_config + i;

            // Filter by frequency band
            if( 0 == (credential->bss_freq_bands & freq_band))
                continue;

            // Replicate the UCI credential list
            // Note : 
            //  This will fetch the UCI creditial in order.
            //  Misconfiguration in multiap UCI config will be reflected in here as well
            if((credential->bss_state & MAP_FRONTHAUL_BSS) && \
                  (credential->bss_state & MAP_BACKHAUL_BSS)) {
                bss_state = MAP_FRONTHAUL_BSS | MAP_BACKHAUL_BSS;
            }
            else if(credential->bss_state & MAP_FRONTHAUL_BSS) {
                bss_state = MAP_FRONTHAUL_BSS;
            }
            // If already FH + BH is configured then dedicated BH is not required
            else if((credential->bss_state & MAP_BACKHAUL_BSS)) {
                bss_state = MAP_BACKHAUL_BSS;
            }

            if(bss_state) {
                clone_credential_config(&m2_config[*config_count], credential);
                m2_config[*config_count].bss_state = bss_state;
                (*config_count)++;
            }
        }

        // We do not have a credential for reported radio frequency band. Send the 
        // configuration to tear down the radio
        if(*config_count == 0) {
            // Setting the SSID to NULL will build a WSC TLV with TEAR-DOWN bit set.
            m2_config->bss_ssid[0] = '\0';
            *config_count = 1;
        }

    } while (0);

    return status;
}

static inline int8_t get_wsc_m2_tlv (handle_1905_t handle, lib1905_wscTLV_t *wsc_params,\
                                            struct wscTLV *wsc_m2_tlv, char* iface_name) {
        int length;

        if(lib1905_get(handle, (lib1905_param_t)GET_1905_WSCM2TLV, &length, wsc_params, iface_name))
        {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d TLV_TYPE_WSC_M2  lib1905_get failed\n",__func__, __LINE__);
            return -1;
        }

        wsc_m2_tlv->tlv_type       = wsc_params->m2.tlv_type;
        wsc_m2_tlv->wsc_frame_size = wsc_params->m2.wsc_frame_size;
        wsc_m2_tlv->wsc_frame      = wsc_params->m2.wsc_frame;
        return 0;
}

int8_t map_send_wscM2(struct CMDU *recv_cmdu)
{
    int8_t    status         = 0;
    uint8_t   number_of_tlv  = 1;
    uint8_t   wsc_tlv_count  = 0;
    uint16_t  mid            = 0;
    uint8_t   current_tlv    = 0;
    struct CMDU             cmdu                          = {0};
    struct wscTLV           wsc_m2_tlv[MAX_BSS_PER_RADIO] = {{0}};
    struct mapApRadioIdTLV  radio_id_tlv                  = {0};
    config_credential_t     m2_config[MAX_BSS_PER_RADIO] = {0};

    do {
        cmdu.list_of_TLVs = NULL;
        if(recv_cmdu == NULL)
            ERROR_EXIT(status)

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
        cmdu.message_id       =  recv_cmdu->message_id;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        strncpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        // Get the AP radio basic capabilty
        AP_basic_capability_tlv_t *ap_capability_tlv = NULL;
        if (-1 == get_tlv_fromcmdu (TLV_TYPE_AP_RADIO_BASIC_CAPABILITY, recv_cmdu, (void *)&ap_capability_tlv) || ap_capability_tlv == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get the AP BASIC CAPABILITY TLV",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        // Get the radio node
        map_radio_info_t *radio = get_radio(ap_capability_tlv->radioId);
        if(radio == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get the radio node",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        if(-1 == map_get_m2_config(radio, &wsc_tlv_count, m2_config))
            ERROR_EXIT(status)

        // Get total number of TLVs required and allocate memory accordingly
        number_of_tlv = wsc_tlv_count + NUM_OF_RADIO_ID_TLV + NO_OF_NULL_TLVS;
        cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv, sizeof(uint8_t *));
        if(cmdu.list_of_TLVs == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
            ERROR_EXIT(status)
        }

        // Get M1 from receive CMDU
        struct wscTLV* wscM1 = NULL;
        if(-1 == get_tlv_fromcmdu(TLV_TYPE_WSC, recv_cmdu, (void *)&wscM1) || (wscM1 == NULL)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to get the TLV_TYPE_WSC",__func__, __LINE__);
            ERROR_EXIT(status)
        }
        //## Add Radio Identifier TLV
        radio_id_tlv.tlv_type           = TLV_TYPE_AP_RADIO_IDENTIFIER;
        radio_id_tlv.tlv_length         = MAC_ADDR_LEN;
        memcpy(radio_id_tlv.radioId, ap_capability_tlv->radioId, MAC_ADDR_LEN);
        cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&radio_id_tlv;

        //##Add Wsc M2 Tlv
        lib1905_wscTLV_t wsc_params;
        wsc_params.m1.tlv_type       = wscM1->tlv_type;
        wsc_params.m1.wsc_frame_size = wscM1->wsc_frame_size;
        wsc_params.m1.wsc_frame      = wscM1->wsc_frame;

        for (uint8_t index = 0; index < wsc_tlv_count; index++) {
            wsc_params.m2_config = &m2_config[index];
            if(-1 == get_wsc_m2_tlv(handle_1905, &wsc_params, &wsc_m2_tlv[index], recv_cmdu->interface_name))
                ERROR_EXIT(status)

            cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&wsc_m2_tlv[index];
        }

        if(0 != status)
            break;

        if (lib1905_send(handle_1905, &mid, recv_cmdu->cmdu_stream.src_mac_addr, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }

        set_radio_state_M2_sent(&radio->state);

    } while (0);

    if(cmdu.list_of_TLVs) {
        for(uint8_t index = 1; cmdu.list_of_TLVs[index] != NULL; index++) {
            struct wscTLV* wscM2 = (struct wscTLV*)cmdu.list_of_TLVs[index];
            free(wscM2->wsc_frame);
        }
        free(cmdu.list_of_TLVs);
    }
    return status;
}

int map_send_autoconfig_renew(map_handle_t *map_handle, uint8_t freq_band)
{
    uint8_t     number_of_tlv     = 3;
    uint8_t     relay_indicator   = 1;
    uint16_t    *mid              = NULL;
    struct CMDU cmdu              = {0};

    struct alMacAddressTypeTLV    al_mac_tlv              = {0};
    struct supportedRoleTLV       supported_role_tlv      = {0};
    struct supportedFreqBandTLV   supported_freq_band_tlv = {0};

    if(NULL == map_handle) {
        goto Failure;
    }

    mid = &(map_handle->mid);

    //##Add Al mac address Tlv
    if(lib1905_get(handle_1905, (lib1905_param_t) GET_1905_ALMACTLV,  NULL , (void *)&al_mac_tlv, NULL)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d AL_MAC TLV  lib1905_get failed",__func__, __LINE__);
        goto Failure;
    }

    //##Add Supported Role Tlv
    if (lib1905_get(handle_1905, (lib1905_param_t) GET_1905_SUPPORTEDROLETLV,  NULL , (void *)&supported_role_tlv, NULL)){
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d SEARCHED_ROLE TLV lib1905_get failed\n",__func__, __LINE__);
        goto Failure;
    }

    //##Add Supported Frequency Band Tlv
    supported_freq_band_tlv_t  supp_freq_band = {0};
    supp_freq_band.supported_freq_band_tlv = &supported_freq_band_tlv;
    supp_freq_band.freq_band               = freq_band;

    if (lib1905_get(handle_1905, (lib1905_param_t) GET_1905_SUPPORTEDFREQBANDTLV,  NULL , (void *)&supp_freq_band, NULL)){
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d SEARCHED_ROLE TLV lib1905_get failed\n",__func__, __LINE__);
        goto Failure;
    }

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;
    strncpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
       goto Failure;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&al_mac_tlv;
    cmdu.list_of_TLVs[1] = (uint8_t *)&supported_role_tlv;
    cmdu.list_of_TLVs[2] = (uint8_t *)&supported_freq_band_tlv;

    if (lib1905_send(handle_1905, mid, map_handle->dest_addr, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        free(cmdu.list_of_TLVs);
        goto Failure;
    }

    free(cmdu.list_of_TLVs);

    return 0;

Failure:
    return -1;
}

int8_t map_send_ap_capability_query(map_handle_t *handle, void* ale_object)
{
    uint8_t     end_of_msg[]      = {0,0,0};
    uint8_t     *list[2]          = {end_of_msg,NULL};
    struct CMDU cmdu              = {0};

    // Input Parameters Check
    if (NULL == ale_object)
        goto Failure;

    map_ale_info_t *ale = (map_ale_info_t*)ale_object;
    uint16_t       *mid = NULL;

    catch_mid(handle, &mid);
    
    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_AP_CAPABILITY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;

    // Always send self-triggered unicast message via the interface in which agent is communicating
    if (NULL == ale->iface_name)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Interface name retreival failed", __func__, __LINE__);
        goto Failure;
    }

    strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    // Inorder to avoid malloc for very small memories, stack variables are used.
    cmdu.list_of_TLVs  = list;

    if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }

    return 0;

Failure:
    return -1;
}

int8_t map_send_client_capability_query(map_handle_t *handle, void *args)
{
    struct CMDU cmdu              = {0};
    uint8_t     end_of_msg[]      = {0,0,0};
    uint8_t     *list[3];
    uint16_t       *mid = NULL;
    map_bss_info_t *bss = NULL;

    struct mapClientInfoTLV client_info_tlv = {0}; /* Length - 12 bytes */

    /* Client information validation */
    if(NULL == args) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Client information validation failed");
        return -1;
    }

    catch_mid(handle, &mid);

    map_clicap_args_t *clicap_args=(map_clicap_args_t *)args;

    if(clicap_args->sta_mac == NULL || clicap_args->bssid == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Incorrect arguments passed\n",__func__, __LINE__);
        return -1;
    }

    bss = get_bss(clicap_args->bssid);
    if(bss == NULL || bss->radio == NULL || bss->radio->ale == NULL) {
       platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s BSS node not found\n", __func__);
       return -1;
    }

    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
    strncpy(cmdu.interface_name, bss->radio->ale->iface_name, sizeof(cmdu.interface_name));

    /* Add Client Info TLV */
    client_info_tlv.tlv_type  = TLV_TYPE_CLIENT_INFO;
    memcpy(client_info_tlv.bssid, clicap_args->bssid, MAC_ADDR_LEN);
    memcpy(client_info_tlv.client_mac, clicap_args->sta_mac, MAC_ADDR_LEN);

    list[0] = (uint8_t *)&client_info_tlv;
    list[1] = end_of_msg;
    list[2] = NULL;
    cmdu.list_of_TLVs  = list;

    if (lib1905_send(handle_1905, mid, bss->radio->ale->al_mac, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        return -1;
    }

    return 0;
}

int8_t map_send_link_metric_query(map_handle_t *handle, link_metric_query_t *lm_query)
{
    uint8_t     *agent_addr       = NULL;
    uint16_t    *mid              = NULL;
    map_ale_info_t* ale           = NULL;
    struct CMDU query_message     = {0};
    struct linkMetricQueryTLV metric_query_tlv = {0};
    uint8_t ret = -1;

    if(lm_query == NULL) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Input validation failed \n",__func__, __LINE__);
           goto Cleanup;
    }

    agent_addr  =  lm_query->al_mac;

    ale = get_ale(agent_addr);
    if(!ale || (NULL == ale->iface_name)) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node or invalid iface_name\n",__func__, __LINE__);
           goto Cleanup;
    }

    catch_mid(handle, &mid);

    char mac_str[MAX_MAC_STRING_LEN];
    platform_log(MAP_CONTROLLER,LOG_DEBUG,"--> CMDU_TYPE_LINK_METRIC_QUERY-(%s)\n", MAC_AS_STR(lm_query->al_mac, mac_str));

    // Fill all the needed TLVs

    metric_query_tlv.tlv_type             = TLV_TYPE_LINK_METRIC_QUERY;

    if(lm_query->specific_neighbor == MAP_LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR)
        memcpy(metric_query_tlv.specific_neighbor, lm_query->neighbor_mac, MAC_ADDR_LEN);

    metric_query_tlv.destination          = lm_query->specific_neighbor;
    metric_query_tlv.link_metrics_type    = lm_query->metric_req;

    // Build the CMDU
    query_message.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    query_message.message_type    = CMDU_TYPE_LINK_METRIC_QUERY;
    query_message.message_id      = 0;
    query_message.relay_indicator = 0;
    query_message.list_of_TLVs    = (uint8_t **)malloc(sizeof(uint8_t *)*2);

    if(query_message.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, malloc failed list_of_TLVs", __func__, __LINE__);
       goto Cleanup;
    }

    query_message.list_of_TLVs[0] = (uint8_t *)&metric_query_tlv;
    query_message.list_of_TLVs[1] = NULL;
    strncpy(query_message.interface_name, ale->iface_name, sizeof(query_message.interface_name));

    if (lib1905_send(handle_1905, mid, agent_addr, &query_message)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, query_message.message_type);
        goto Cleanup;
    }

    ret = 0;

Cleanup:

    if(NULL != query_message.list_of_TLVs) {
        free(query_message.list_of_TLVs);
    }
    return ret;
}

int8_t map_send_higher_layer_data_msg(map_handle_t *map_handle, higherlayer_info_t *higherlayer_data)
{
    uint16_t payload_len          = 0;
    uint8_t    *agent_addr        = NULL;
    uint16_t   *mid               = NULL;
    uint8_t  ret                  = -1;
    map_ale_info_t* ale           = NULL;
    struct CMDU query_message     = {0};
    struct mapHigherLayerDataTLV higher_layer_info_tlv = {0};

    if(higherlayer_data == NULL) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Input validation failed \n",__func__, __LINE__);
           goto Cleanup;
    }

    agent_addr  = higherlayer_data->dest_mac;
    payload_len = higherlayer_data->payload_len; 

    ale = get_ale(agent_addr);
    if(!ale || (NULL == ale->iface_name)) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node or invalid iface_name\n",__func__, __LINE__);
           goto Cleanup;
    }

    catch_mid(map_handle, &mid);

    char mac_str[MAX_MAC_STRING_LEN];
    platform_log(MAP_CONTROLLER,LOG_DEBUG,"--> CMDU_TYPE_MAP_HIGHER_LAYER_DATA (%s)\n", MAC_AS_STR(higherlayer_data->dest_mac, mac_str));

    // Fill all the needed TLVs
    higher_layer_info_tlv.tlv_type             = TLV_TYPE_HIGHER_LAYER_DATA_MSG;
    higher_layer_info_tlv.tlv_length           = ONE_OCTET + (sizeof(uint8_t) * payload_len);
    higher_layer_info_tlv.higher_layer_proto   = higherlayer_data->protocol;

    if(higherlayer_data->payload_pattern)
    {    
        higher_layer_info_tlv.payload = calloc(sizeof(uint8_t) * payload_len,1);
        if(higher_layer_info_tlv.payload == NULL) 
        {
             platform_log(MAP_CONTROLLER,LOG_ERR, "%s: Payload Memory allocation failure\n", __FUNCTION__);
             goto Cleanup;
        }
        memcpy(higher_layer_info_tlv.payload, higherlayer_data->payload_pattern, (sizeof(uint8_t))*payload_len);
    } 
    else 
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, "%s: Payload is null\n",__FUNCTION__);
    }

    // Build the CMDU
    query_message.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    query_message.message_type    = CMDU_TYPE_MAP_HIGHER_LAYER_DATA;
    query_message.message_id      = 0;
    query_message.relay_indicator = 0;
    query_message.list_of_TLVs    = (uint8_t **)malloc(sizeof(uint8_t *)*2);

    if(query_message.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, malloc failed list_of_TLVs", __func__, __LINE__);
       goto Cleanup;
    }

    query_message.list_of_TLVs[0] = (uint8_t *)&higher_layer_info_tlv;
    query_message.list_of_TLVs[1] = NULL;
    strncpy(query_message.interface_name, ale->iface_name, sizeof(query_message.interface_name));

    if (lib1905_send(handle_1905, mid, agent_addr, &query_message)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, query_message.message_type);
        goto Cleanup;
    }

    ret = 0;

Cleanup:

    if(NULL != query_message.list_of_TLVs) {
        free(query_message.list_of_TLVs);
    }

    if(NULL != higher_layer_info_tlv.payload) {
        free(higher_layer_info_tlv.payload);
    }

    return ret;
}

int compare_neighbor_node(void* node, void* neighbor_mac) {
    if(node && neighbor_mac) {
        if (memcmp(((map_neighbor_link_metric_t*)node)->al_mac, neighbor_mac, MAC_ADDR_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

int dump_neighbor_obj_list(array_list_t *list)
{
    int8_t index = 0;
    map_neighbor_link_metric_t *neighbor_obj = NULL;
    list_iterator_t* it = new_list_iterator(list);
    if(!it)
        return -1;

    platform_log(MAP_CONTROLLER,LOG_DEBUG, "********************* DUMP NEIGHBOR OBJECT LIST*******************************");

    while(it->iter)
    {
        neighbor_obj = (map_neighbor_link_metric_t*) get_next_list_object(it);
        if (neighbor_obj == NULL)
        {
            free_list_iterator(it);
            return 0;
        }

        platform_log(MAP_CONTROLLER,LOG_DEBUG,"  Index %d :  %02x:%02x:%02x:%02x:%02x:%02x\n", index, neighbor_obj->al_mac[0], neighbor_obj->al_mac[1], neighbor_obj->al_mac[2], neighbor_obj->al_mac[3], neighbor_obj->al_mac[4], neighbor_obj->al_mac[5]);
        index++;
    }

    free_list_iterator(it);
    return 0;
}


int8_t map_send_ap_metric_query(map_handle_t *handle, ap_metric_query_t *ap_query)
{
    uint16_t    *mid              = NULL;
    uint8_t ret                   = -1;
    map_ale_info_t* ale           = NULL;
    struct CMDU query_message     = {0};
    struct mapApMetricsQueryTLV metric_query_tlv = {0};

    if(ap_query == NULL) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Input validation failed \n",__func__, __LINE__);
           goto Cleanup;
    }

    ale = get_ale(ap_query->al_mac);
    if(!ale || (NULL == ale->iface_name)) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node or invalid iface_name\n",__func__, __LINE__);
           goto Cleanup;
    }

    char mac_str[MAX_MAC_STRING_LEN];
    platform_log(MAP_CONTROLLER,LOG_DEBUG,"--> CMDU_TYPE_MAP_AP_METRICS_QUERY (%s)\n", MAC_AS_STR(ap_query->al_mac, mac_str));

    catch_mid(handle, &mid);
    uint8_t len = ONE_OCTET + (ap_query->bss_cnt *  sizeof(mac_struct_t));

    // Fill all the needed TLVs
    metric_query_tlv.tlv_type             = TLV_TYPE_AP_METRICS_QUERY;
    metric_query_tlv.tlv_length           = len;
    metric_query_tlv.numBss               = ap_query->bss_cnt;

    for(uint8_t i = 0; i < ap_query->bss_cnt; i++)
        memcpy(metric_query_tlv.bssid[i], ap_query->bss_list[i].mac, MAC_ADDR_LEN);

    // Build the CMDU
    query_message.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    query_message.message_type    = CMDU_TYPE_MAP_AP_METRICS_QUERY;
    query_message.message_id      = 0;
    query_message.relay_indicator = 0;
    query_message.list_of_TLVs    = (uint8_t **)malloc(sizeof(uint8_t *)*2);

   if(query_message.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, malloc failed list_of_TLVs", __func__, __LINE__);
       goto Cleanup;
    }

    query_message.list_of_TLVs[0] = (uint8_t *)&metric_query_tlv;
    query_message.list_of_TLVs[1] = NULL;
    strncpy(query_message.interface_name, ale->iface_name, sizeof(query_message.interface_name));

    if (lib1905_send(handle_1905, mid, ale->al_mac, &query_message)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, query_message.message_type);
        goto Cleanup;
    }

    ret = 0;

Cleanup:

    if(NULL != query_message.list_of_TLVs) {
        free(query_message.list_of_TLVs);
    }
    return ret;
}

int map_send_steering_request(map_handle_t *handle, struct sta_steer_params *steer_info, uint8_t *dst_mac)
{
	int i						  = 0;
    uint8_t     number_of_tlv     = 1;
    uint8_t     relay_indicator   = 0;
    uint16_t    *mid              = NULL;
    struct CMDU cmdu              = {0};
	map_ale_info_t* ale           = NULL;
	
	steering_request_tlv sta_steer_req_tlv = {0};

	ale = get_ale(steer_info->dst_mac);
    if(!ale)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node\n",__func__, __LINE__);
        goto Failure;
    }

    // Copy the mid if available
    catch_mid(handle, &mid);

	//## form tlv
	sta_steer_req_tlv.tlv_type = TLV_TYPE_STEERING_REQUEST;	
	memcpy(sta_steer_req_tlv.bssid, steer_info->source_bssid, MAC_ADDR_LEN);
	sta_steer_req_tlv.flag = steer_info->flag;
	sta_steer_req_tlv.opportunity_wnd = steer_info->opportunity_wnd;
	sta_steer_req_tlv.disassociation_timer = steer_info->disassociation_timer;
	sta_steer_req_tlv.sta_count = steer_info->sta_count;
	/* update length for TLV data */
	sta_steer_req_tlv.tlv_length += (MAC_ADDR_LEN + ONE_OCTET + TWO_OCTET + TWO_OCTET + ONE_OCTET);
	for(i = 0; i < sta_steer_req_tlv.sta_count; i++) {
		memcpy(sta_steer_req_tlv.mac_addr[i], steer_info->sta_info[i].sta_mac, MAC_ADDR_LEN);
		sta_steer_req_tlv.tlv_length += MAC_ADDR_LEN;
	}
	
	sta_steer_req_tlv.bssid_count = steer_info->bssid_count;
	sta_steer_req_tlv.tlv_length += ONE_OCTET;
	for(i = 0; i < sta_steer_req_tlv.bssid_count ; i++) {
		sta_steer_req_tlv.target_bss[i].channel_no = steer_info->sta_info[i].channel;
		sta_steer_req_tlv.target_bss[i].operating_class = steer_info->sta_info[i].operating_class;
		memcpy(sta_steer_req_tlv.target_bss[i].target_bssid, steer_info->sta_info[i].bssid, MAC_ADDR_LEN);
		/* update tlv length */
		sta_steer_req_tlv.tlv_length += (MAC_ADDR_LEN + ONE_OCTET + ONE_OCTET);
	}
	
    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;

	// Always send self-triggered unicast message via the interface in which agent is communicating
    if (NULL == ale->iface_name)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Interface name retreival failed", __func__, __LINE__);
        goto Failure;
    }

    strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
       goto Failure;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&sta_steer_req_tlv;

    if (lib1905_send(handle_1905, mid, dst_mac, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
		if(NULL != cmdu.list_of_TLVs)
			free(cmdu.list_of_TLVs);
        goto Failure;
    }
	if(NULL != cmdu.list_of_TLVs) {
	    free(cmdu.list_of_TLVs);
	}
    return 0;

Failure:
    return -1;
}

int8_t map_send_topology_query(map_handle_t *handle, void* ale_object)
{
    int8_t status = 0;
    do
    {
        if (NULL == ale_object)
            ERROR_EXIT(status)

        map_ale_info_t *ale           = (map_ale_info_t*) ale_object;
        uint8_t     relay_indicator   = 0;
        uint16_t    *mid              = NULL;
        struct      CMDU cmdu         = {0};
        uint8_t     *list[2]          = {NULL, NULL};

        catch_mid(handle, &mid);

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_QUERY;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  relay_indicator;
        cmdu.list_of_TLVs     =  list;

        strncpy(cmdu.interface_name, ale->iface_name, strlen(ale->iface_name));

        if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }

        char mac_str[MAX_MAC_STRING_LEN];
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "--> CMDU_TYPE_TOPOLOGY_QUERY - %s (%s)", MAC_AS_STR(ale->al_mac, mac_str), ale->iface_name);
    } while (0);

    return status;
}

int8_t map_send_channel_preference_query(map_handle_t *handle, void *ale_object)
{
    int status              = 0;
    map_ale_info_t *ale     = (map_ale_info_t*)ale_object;
    uint16_t  *mid          = NULL;
    struct    CMDU cmdu     = {0};
    uint8_t   end_of_msg[]  = {0,0,0};
    uint8_t   *list[2]      = {end_of_msg,NULL};
    do
    {
        if(ale == NULL) {
          platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node\n",__func__, __LINE__);
          ERROR_EXIT(status)
        }

        catch_mid(handle, &mid);

        //## Construct Preference query payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));
        cmdu.list_of_TLVs  =  list;

        if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

// When the Preference Type is 
//  GET_CONTROLLER_PREFERENCE:
//      It gets the data from Data model "cntlr_channel_count" and "cntrl_channel"
//  GET_AGENT_PREFERENCE
//      It gets the data from Data model "agent_channel_count" and "agent_channel_count"

static void build_channel_pref_tlv ( channel_preference_tlv_t *pref_tlv, 
                                       map_radio_info_t *radio,
                                       uint8_t pref_type) {
    pref_tlv->tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;
    memcpy(pref_tlv->radio_id, radio->radio_id, MAC_ADDR_LEN);
    pref_tlv->numOperating_class = radio->op_class_count;
    pref_tlv->tlv_length = MAC_ADDR_LEN + 1;
    if(radio->op_class_list) {

        for (int8_t i = 0; i < radio->op_class_count; ++i) {
            map_op_class_t                 *op_class_in_dm  = (radio->op_class_list + i);
            channel_pref_operating_class_t *op_class_in_tlv = (pref_tlv->operating_class + i);

            op_class_in_tlv->operating_class = op_class_in_dm->op_class;

            // TODO : Store and the Controller/agent preference and reason separately
            if(GET_CONTROLLER_PREFERENCE == pref_type) {
                op_class_in_tlv->number_of_channels = op_class_in_dm->cntlr_channel_count;
                op_class_in_tlv->pref_reason = 0x0E; // Hardcode the PREF_15 with reason "Unspecified"
                if(op_class_in_dm->cntlr_channel_count > 0)
                    memcpy(op_class_in_tlv->channel_num, op_class_in_dm->cntrl_channel , op_class_in_dm->cntlr_channel_count);
            }
            else {
                op_class_in_tlv->number_of_channels = op_class_in_dm->agent_channel_count;
                op_class_in_tlv->pref_reason = (op_class_in_dm->pref << NUM_SHIFT_TO_GET_PREF) | op_class_in_dm->reason;
                if(op_class_in_dm->agent_channel_count > 0)
                    memcpy(op_class_in_tlv->channel_num, op_class_in_dm->agent_channel , op_class_in_dm->agent_channel_count);
            }

            // Update the length of the TLV
            // 3 bytes for "OP Class", "Channel Count", "Preference & reason"
            (pref_tlv->tlv_length) += (op_class_in_tlv->number_of_channels + 3);
        }
    }
}

static void build_transmit_power_tlv ( transmit_power_tlv_t *tx_pwr_tlv, 
                                       map_radio_info_t *radio) {
    if (tx_pwr_tlv != NULL) {
        tx_pwr_tlv->tlv_type = TLV_TYPE_TRANSMIT_POWER;
      
        memcpy(tx_pwr_tlv->radio_id, radio->radio_id, MAC_ADDR_LEN);
        tx_pwr_tlv->transmit_power_eirp = radio->current_tx_pwr;
        tx_pwr_tlv->tlv_length = MAC_ADDR_LEN + 1;
    }
}

#define  MAX_TLVS_CHANNEL_SEL_REQ  (MAX_RADIOS_PER_AGENT * 2)

int8_t map_send_channel_selection_request(map_handle_t *handle, void *preference_type) {

    int8_t      status                    = 0;
    uint16_t    *mid                      = NULL;
    struct CMDU cmdu                      = {0};
    uint8_t     *list_of_tlvs[MAX_TLVS_CHANNEL_SEL_REQ] = {0};
    map_chan_selec_pref_type_t* pref_type = (map_chan_selec_pref_type_t*)preference_type;

    do
    {
        if( (pref_type == NULL) || (pref_type->ale == NULL) ) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Invalid input arguments \n",__func__, __LINE__);
            ERROR_EXIT(status)
        }

        catch_mid(handle, &mid);

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        strncpy(cmdu.interface_name, pref_type->ale->iface_name, sizeof(cmdu.interface_name));

        cmdu.list_of_TLVs  =  list_of_tlvs;

        // ADD Channel preference TLV
        channel_preference_tlv_t chan_pref_tlv[MAX_RADIOS_PER_AGENT] = {0};
        transmit_power_tlv_t  transmit_pwr_tlv[MAX_RADIOS_PER_AGENT] = {0};

        uint8_t tlv_count = 0;


        if(pref_type->radio != NULL) {
            map_radio_info_t radio = {0};
            for (int8_t radio_index = 0; radio_index < pref_type->radio_cnt; ++radio_index) {
                radio = pref_type->radio[radio_index];
                    build_channel_pref_tlv(&chan_pref_tlv[tlv_count], &radio, pref_type->pref);
                    cmdu.list_of_TLVs[tlv_count] = (uint8_t *)&chan_pref_tlv[tlv_count];
                    tlv_count++;

                    if(radio.current_tx_pwr != 0) {
                         /* build transmit power tlv */
                         build_transmit_power_tlv (&transmit_pwr_tlv[tlv_count], &radio);
                         cmdu.list_of_TLVs[tlv_count] = (uint8_t *)&transmit_pwr_tlv[tlv_count];
                         tlv_count++;
                    }
            }
        } else {
            map_radio_info_t *radio = NULL;

            for (int8_t radio_index = 0; radio_index < pref_type->ale->num_radios; ++radio_index) {
                radio = pref_type->ale->radio_list[radio_index];
                // Send request only to a configured radios
                if(radio) {
                    build_channel_pref_tlv(&chan_pref_tlv[tlv_count], radio, pref_type->pref);
                    cmdu.list_of_TLVs[tlv_count] = (uint8_t *)&chan_pref_tlv[tlv_count];
                    tlv_count++;

                    if(radio->current_tx_pwr != 0) {
                        /* build transmit power tlv */
                        build_transmit_power_tlv (&transmit_pwr_tlv[tlv_count], radio);
                        cmdu.list_of_TLVs[tlv_count] = (uint8_t *)&transmit_pwr_tlv[tlv_count];
                        tlv_count++;
                    }
                }
            }
        }

        if (lib1905_send(handle_1905, mid, pref_type->ale->al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Failed to send channel_pref_tlv",__func__, __LINE__);
            ERROR_EXIT(status)
        }

    } while (0);
	
    return status;
}


int map_send_policy_config(map_handle_t *handle, metric_policy_tlv_t *metric_policy_tlv, steering_policy_tlv_t *steering_policy_tlv, uint8_t *al_mac)
{
    int         ret               = 0;
    uint8_t     number_of_tlv     = 0;
    uint8_t     tlv_index         = 0;
    struct CMDU cmdu              = {0};
    uint16_t    *mid              = NULL;

    catch_mid(handle, &mid);

    if(NULL != metric_policy_tlv) {
        metric_policy_tlv->tlv_length = 0;
        metric_policy_tlv->tlv_type = TLV_TYPE_METRIC_REPORTING_POLICY;
        /* one octet for metric policy reporting period and one octet for radio count*/
        metric_policy_tlv->tlv_length += 2*ONE_OCTET;                       
        for(int i=0; i<metric_policy_tlv->number_of_radio; i++)
        {
            /* 4 bytes for config and 6 bytes for radio ID*/
            metric_policy_tlv->tlv_length += (4*ONE_OCTET + MAC_ADDR_LEN);
        }
        number_of_tlv++;
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s: %d metric_policy_tlv tlvlength %d \n",__func__, __LINE__, metric_policy_tlv->tlv_length);
    }

    if(NULL != steering_policy_tlv) {       
        steering_policy_tlv->tlv_length = 0;
        steering_policy_tlv->tlv_type = TLV_TYPE_STEERING_POLICY;       
        /* one octet for local steering dis allowed station count */    
        steering_policy_tlv->tlv_length += ONE_OCTET;
        for(int i = 0; i < steering_policy_tlv->number_of_local_steering_disallowed; i++) 
        {           
            /* 6 bytes for each station ID*/
            steering_policy_tlv->tlv_length += MAC_ADDR_LEN;
        }
        /* one octet for BTM steering dis allowed station count */
        steering_policy_tlv->tlv_length += ONE_OCTET;
        for(int i = 0; i < steering_policy_tlv->number_of_btm_steering_disallowed; i++) 
        {
            /* 6 bytes for each station ID*/
            steering_policy_tlv->tlv_length += MAC_ADDR_LEN;
        }
        /* one octet for radio count */
        steering_policy_tlv->tlv_length += ONE_OCTET;
        for(int i = 0; i < steering_policy_tlv->number_of_radio; i++) {
            /* 3 bytes for config and 6 bytes for each radio ID */
            steering_policy_tlv->tlv_length += (3*ONE_OCTET + MAC_ADDR_LEN);
        }
        number_of_tlv++;
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s: %d steering_policy_tlv tlvlength %d \n",__func__, __LINE__, steering_policy_tlv->tlv_length);
    }

    do {
        // Intialize the dynamic pointer storage to NULL for a clean free
        cmdu.list_of_TLVs = NULL;

        // Skip send if no TLVs
        if(number_of_tlv == 0)
            ERROR_EXIT(ret)
        else
            number_of_tlv += NO_OF_NULL_TLVS;

        map_ale_info_t* ale = get_ale(al_mac);
        if (NULL == ale) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " %s Get agent node failed\n", __func__);
            ERROR_EXIT(ret)
        }

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

        cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv, sizeof(uint8_t *));
        if(cmdu.list_of_TLVs == NULL) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs\n", __func__, __LINE__);
            ERROR_EXIT(ret)
        }

        // Fill Steering policy TLV if exist
        if( (NULL != steering_policy_tlv) && (tlv_index < number_of_tlv) )
            cmdu.list_of_TLVs[tlv_index++] = (uint8_t*)steering_policy_tlv;
        
        // Fill Metrics policy TLV if exist
        if( (NULL != metric_policy_tlv) && (tlv_index < number_of_tlv) )
            cmdu.list_of_TLVs[tlv_index++] = (uint8_t*)metric_policy_tlv;
        
        if (lib1905_send(handle_1905, mid, al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d\n",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(ret)
        }
    } while (0);

    if(NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);

	return ret;
}

int8_t map_send_associated_sta_link_metrics_query(map_handle_t *handle, uint8_t *sta_mac) {

    int8_t status = 0;
    do {
        if (NULL == sta_mac)
            ERROR_EXIT(status)

        uint16_t    *mid         = NULL;
        struct      CMDU cmdu    = {0};
        map_sta_info_t *sta_node = NULL;
        map_ale_info_t *ale      = NULL;

        sta_node = get_sta(sta_mac);
        if(NULL == sta_node) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "get_sta node failed");
            ERROR_EXIT(status)
        }

        ale = sta_node->bss->radio->ale;
        if (NULL == ale) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "ALE info is NULL");
            ERROR_EXIT(status)
        }

        catch_mid(handle, &mid);

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;

        sta_mac_address_tlv_t sta_mac_tlv;
        sta_mac_tlv.tlv_type = TLV_TYPE_STA_MAC_ADDRESS;
        memcpy(sta_mac_tlv.associated_sta_mac, sta_mac , MAC_ADDR_LEN);

        uint8_t *tlv_list[3] = { (uint8_t*)&sta_mac_tlv, NULL, NULL};

        cmdu.list_of_TLVs  =  tlv_list;

        strncpy(cmdu.interface_name, ale->iface_name, strlen(ale->iface_name));

        if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }
    } while(0);

    return status;
}

int map_send_beacon_metrics_query(map_handle_t *handle, beacon_metrics_query_t *bm_query, uint8_t *dst_mac)
{
    map_ale_info_t             *ale;
    struct CMDU                 cmdu        = {0};
    beacon_metrics_query_tlv_t *tlv         = NULL;
    int                         status      = 0;
    int                         alloc_size;
    int                         i;
    uint16_t                    *mid        = NULL;
    uint8_t                    *tlv_list[2] = {0};

    do {
        /* Get ALE */
        ale = get_ale(dst_mac);
        if (NULL == ale) {
            ERROR_EXIT(status);
        }

        catch_mid(handle, &mid);

        /* Alloc TLV (take channel reports into account) */
        alloc_size = sizeof(beacon_metrics_query_tlv_t);
        if (bm_query->ap_channel_report_count > 1) {
            alloc_size += (bm_query->ap_channel_report_count -1) * sizeof(struct ap_channel_report_elem);
        }
        tlv = (beacon_metrics_query_tlv_t *)calloc(1, alloc_size);
        if (NULL == tlv) {
            break;
        }
        tlv_list[0] = (uint8_t*)tlv;

        /* Fill in TLV */
        tlv->tlv_type = TLV_TYPE_BEACON_METRICS_QUERY;

        memcpy(tlv->sta_mac, bm_query->sta_mac, MAC_ADDR_LEN);
        tlv->tlv_length += MAC_ADDR_LEN;

        tlv->operating_class = bm_query->operating_class;
        tlv->tlv_length += ONE_OCTET;

        tlv->channel = bm_query->channel;
        tlv->tlv_length += ONE_OCTET;

        memcpy(tlv->bssid, bm_query->bssid, MAC_ADDR_LEN);
        tlv->tlv_length += MAC_ADDR_LEN;

        tlv->reporting_detail = bm_query->report_detail;
        tlv->tlv_length += ONE_OCTET;

        tlv->ssid_len = min(sizeof(tlv->ssid), bm_query->ssid_len);
        memcpy(tlv->ssid, bm_query->ssid, tlv->ssid_len);
        tlv->tlv_length += ONE_OCTET + tlv->ssid_len;

        tlv->element_id_count = min(sizeof(tlv->elementIds), bm_query->element_id_count);
        memcpy(tlv->elementIds, bm_query->elementIds, bm_query->element_id_count);
        tlv->tlv_length += ONE_OCTET + bm_query->element_id_count;

        tlv->ap_channel_report_count = bm_query->ap_channel_report_count;
        tlv->tlv_length += ONE_OCTET;       

        for (i=0; i<bm_query->ap_channel_report_count; i++) {
            /* Length includes operating class and channel list */
            tlv->ap_channel_report[i].length = min(sizeof(tlv->ap_channel_report[i].channel_list) + 1, bm_query->ap_channel_report[i].length);
            tlv->ap_channel_report[i].operating_class = bm_query->ap_channel_report[i].operating_class;
            memcpy(tlv->ap_channel_report[i].channel_list, bm_query->ap_channel_report[i].channel_list, tlv->ap_channel_report[i].length - 1);
            tlv->tlv_length += ONE_OCTET + tlv->ap_channel_report[i].length;
        }

        //## init payload CMDU
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;   
        cmdu.message_type     =  CMDU_TYPE_MAP_BEACON_METRICS_QUERY;
        cmdu.message_id       =  0;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        cmdu.list_of_TLVs     =  tlv_list;

        strncpy(cmdu.interface_name, ale->iface_name, strlen(ale->iface_name));
        if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }
    } while(0);

    free(tlv);

    return status;
}

int map_send_client_acl_request(map_handle_t *handle, client_acl_data_t *acl_data)
{
    struct CMDU cmdu     = {0};
    uint8_t* agent_addr  = NULL;
    int number_of_tlv    = 1; /* Client ACL request TLV */
    map_bss_info_t *bss  = NULL;
    uint16_t *mid        = NULL;
    int len              = 0;
    int  i               = 0;
    int ret              = -1;
    map_ale_info_t *ale  = NULL;

    struct mapClientAsociationControlRequestTLV *client_acl_req_tlv = NULL;

    /* Client information validation */
    if(NULL == acl_data) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Client ACL Validation failed");
        goto Cleanup;
    }

    agent_addr  =  acl_data->al_mac;

    ale = get_ale(agent_addr);
    if(!ale) {
           platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node\n",__func__, __LINE__);
           goto Cleanup;
    }

    bss = get_bss(acl_data->bssid);
    if ((NULL == bss) || (ale != bss->radio->ale) || (NULL == ale->iface_name)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Invalid BSSID for given AL_MAC or viceversa");
        goto Cleanup;
    }

    len = sizeof(struct mapClientAsociationControlRequestTLV) + ((acl_data->sta_count - 1) * sizeof(sta_list_t));
    client_acl_req_tlv = (struct mapClientAsociationControlRequestTLV *) calloc(1,len);

    if (NULL == client_acl_req_tlv) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed client_acl_req_tlv", __func__, __LINE__);
        goto Cleanup;
    }

    catch_mid(handle, &mid);

    /* Add Client Info TLV */
    client_acl_req_tlv->tlv_type            = TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST;
    client_acl_req_tlv->validity_period     = acl_data->validity_period;
    client_acl_req_tlv->sta_count           = acl_data->sta_count;
    memcpy(client_acl_req_tlv->bssid, acl_data->bssid, MAC_ADDR_LEN);

    if (1 == acl_data->block)
        client_acl_req_tlv->association_control = STA_BLOCK;
    else if (0 == acl_data->block)
        client_acl_req_tlv->association_control = STA_UNBLOCK;
    else {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, Invalid Action in association_control", __func__, __LINE__);
        goto Cleanup;
    }

    for (i = 0; i < acl_data->sta_count; i++)
        memcpy(client_acl_req_tlv->sta_list[i].sta_mac, acl_data->sta_list[i].sta_mac, MAC_ADDR_LEN);

    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;

    strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        goto Cleanup;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)client_acl_req_tlv;
    cmdu.list_of_TLVs[1] = NULL;

    if (lib1905_send(handle_1905, mid, agent_addr, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Cleanup;
    }
    ret = 0;

Cleanup:
    if (NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);

    if (NULL != client_acl_req_tlv)
        free(client_acl_req_tlv);

    return ret;
}

int8_t map_send_steering_completed_msg_rcvd_ack(struct CMDU *recv_cmdu)
{
    map_handle_t map_handle;
    
    /* Input Parameters Validation */
    if (NULL == recv_cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Not a valid CMDU", __func__);
        return -1;
    }

    memcpy(map_handle.dest_addr, recv_cmdu->cmdu_stream.src_mac_addr, 6);
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu = recv_cmdu;

    if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
        return -1;
    }

    return 0;
}

int8_t map_send_steering_btm_report_ack(struct CMDU *recv_cmdu)
{
    struct mapSteeringBTMReportTLV *steering_btm_report_tlv = NULL;

    /* Input Parameters Validation */
    if (NULL == recv_cmdu) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input Parameters Validation", __func__);
        return -1;
    }

    steering_btm_report_tlv = (struct mapSteeringBTMReportTLV *) recv_cmdu->list_of_TLVs[0];

    if (NULL == steering_btm_report_tlv) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: steering_btm_report_tlv is missing", __func__);
        return -1;
    }

    /**************************************************************************************
     * TODO: The Advanced controller must validate whether the station is properly associated
     * with the specified BSS. Also check for the BTM Status Code and take necessary actions
     * if the status code is error.
     *************************************************************************************/
    // TODO: Update signature of map_send_1905_ack to just recv_cmdu
    map_handle_t map_handle;
    memcpy(map_handle.dest_addr, recv_cmdu->cmdu_stream.src_mac_addr, 6);
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu = recv_cmdu;

    if (-1 == map_send_1905_ack(&map_handle, NULL, -1)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "map_send_1905_ack failed");
        return -1;
    }

    return 0;
}

#define NO_OF_TLV_IN_UNASSOC_STA_REQ 2
int map_send_unassoc_sta_metrics_query (map_handle_t *handle, struct unassoc_sta_dm_s *unassoc_sta_metrics) {
    uint16_t   *mid               = NULL;
    struct CMDU cmdu              = {0};
    map_ale_info_t* ale           = NULL;
    uint16_t unassoc_sta_tlv_len  = 0;

    struct mapUnassocStaMetricsQueryTLV unassoc_sta_tlv;
    uint8_t  *list_of_tlv[NO_OF_TLV_IN_UNASSOC_STA_REQ]    = {0};

    ale = get_ale(unassoc_sta_metrics->al_mac);
    if(!ale) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d Unable to find the agent node\n",__func__, __LINE__);
        goto Failure;
    }

    catch_mid(handle, &mid);

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;

    // Always send self-triggered unicast message via the interface in which agent is communicating
    strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs = (uint8_t **)list_of_tlv;

    memset(&unassoc_sta_tlv, 0, sizeof(struct mapUnassocStaMetricsQueryTLV));
    /* update unassoc_sta_tlv params */
    unassoc_sta_tlv.channel_list_cnt = unassoc_sta_metrics->channel_list_cnt;
    unassoc_sta_tlv.oper_class       = unassoc_sta_metrics->oper_class;

    /*
     * Calculate the length of unassoc sta query TLV
     */
    unassoc_sta_tlv_len += 2;
    for(int i = 0; i <unassoc_sta_tlv.channel_list_cnt; i++) {
        unassoc_sta_tlv.sta_list[i].channel   = unassoc_sta_metrics->sta_list[i].channel;
        unassoc_sta_tlv.sta_list[i].sta_count = unassoc_sta_metrics->sta_list[i].sta_count;
        unassoc_sta_tlv.sta_list[i].sta_mac   = unassoc_sta_metrics->sta_list[i].sta_mac;

        unassoc_sta_tlv_len += (unassoc_sta_tlv.sta_list[i].sta_count * MAC_ADDR_LEN);
        unassoc_sta_tlv_len += 2;
    }

    unassoc_sta_tlv.tlv_type   = TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY;
    unassoc_sta_tlv.tlv_length = unassoc_sta_tlv_len;

    cmdu.list_of_TLVs[0] = (uint8_t*)&unassoc_sta_tlv;

    if (lib1905_send(handle_1905, mid, ale->al_mac, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }

    return 0;

Failure:
    return -1;
}

int8_t map_send_vendor_specific(map_handle_t *handle,void* vendor_obj)
{
    // Input Parameters Check
    map_ipc_write_1905_ve* vendor_buff = (map_ipc_write_1905_ve* )vendor_obj;

    if (NULL == vendor_buff)
        return -1;

    uint16_t    *mid              = NULL;
    struct      CMDU cmdu         = {0};
    struct vendorSpecificTLV vendor_tlv = {0};
    uint8_t     *list[2] = {0};

    int8_t mac_str[MAX_MAC_STRING_LEN] = {0};

    catch_mid(handle, &mid);

    // Convert the MAC into string and print
    get_mac_as_str((uint8_t *)vendor_buff->ale_mac, mac_str, MAX_MAC_STRING_LEN);
    platform_log(MAP_CONTROLLER,LOG_DEBUG," VENDOR MAC : %s \n", mac_str);

    map_ale_info_t * ale = get_ale((uint8_t *)vendor_buff->ale_mac);

    if(ale == NULL)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: Input Parameters Validation", __func__);
        return -1;
    }
    strncpy(cmdu.interface_name, ale->iface_name, strlen(ale->iface_name));
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_VENDOR_SPECIFIC;
    cmdu.message_id       =  0;

    vendor_tlv.tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
    memcpy(vendor_tlv.vendorOUI,vendor_buff->oui_id,3);
    vendor_tlv.m_nr = vendor_buff->len;
    vendor_tlv.m = (uint8_t *)vendor_buff->data;

    list[0] = (uint8_t *)&vendor_tlv;
    cmdu.list_of_TLVs  =  list;

    if (lib1905_send(handle_1905, mid, (uint8_t *)vendor_buff->ale_mac, &cmdu)) 
    {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }

    platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s: %d MSG SENT",__func__, __LINE__);

    return 0;

Failure:
    return -1;

}

int get_ale_bss_list (map_ale_info_t *ale, map_bss_info_t *bsslist[])
{
    int i = 0;
    int j = 0;
    int cnt = 0;

    if((NULL == ale) || (NULL == bsslist)) return -EINVAL;

    while ((i < MAX_RADIOS_PER_AGENT) && (ale->radio_list[i] != NULL)) {
        map_radio_info_t *radio = ale->radio_list[i];

        platform_log(MAP_CONTROLLER,LOG_ERR,"%s, radio %s bss count %d\n", __func__, radio->radio_name,radio->num_bss);
        j = 0;
        while((j < MAX_BSS_PER_RADIO) && (NULL != radio->bss_list[j])) {
            bsslist[cnt] = radio->bss_list[j];
            cnt++;
            j++;
        }
        i++;
    }

    return cnt;
}

struct mapApMetricsResponseTLV* build_ap_metrics_tlv (map_bss_info_t * bss_node) {
     uint8_t i = 0;
     uint16_t sta_count = 0;
     struct mapApMetricsResponseTLV *ap_metrics_response = NULL;

     ap_metrics_response = (struct mapApMetricsResponseTLV*) calloc(1, sizeof(struct mapApMetricsResponseTLV));
     if(ap_metrics_response == NULL)  return ap_metrics_response;

      ap_metrics_response->tlv_type = TLV_TYPE_AP_METRICS_RESPONSE;
      memcpy(ap_metrics_response->bssid, bss_node->bssid, ETHER_ADDR_LEN);
      ap_metrics_response->tlv_length = ETHER_ADDR_LEN;

      ap_metrics_response->channel_util = bss_node->metrics.channel_utilization;
      ap_metrics_response->tlv_length += 1;

      sta_count = list_get_size(bss_node->sta_list);

      ap_metrics_response->sta_count = sta_count;
      ap_metrics_response->tlv_length += 2;

      ap_metrics_response->esp_present = bss_node->metrics.esp_present;
      if(bss_node->metrics.esp_present == 0) {
          /* ESP info not found */
          free(ap_metrics_response);
          return NULL;
      }
      ap_metrics_response->tlv_length += 1;

      for(i = 0; i<MAX_ACCESS_CATEGORIES; i++) {
         if(bss_node->metrics.esp_present & (1<<(7-i))) {
             memcpy(&ap_metrics_response->esp[i], &bss_node->metrics.esp[i], sizeof(bss_node->metrics.esp[i]));
             ap_metrics_response->tlv_length += 3;
         }
      }

     return ap_metrics_response;
}

int build_rx_link_met (map_neighbor_link_metric_t *neighbor_link_metrics, uint8_t *local_al_mac, uint8_t** rx_tlv_ptr) {

   struct receiverLinkMetricTLV* rx_tlv = NULL;

   rx_tlv = (struct receiverLinkMetricTLV*)malloc(sizeof(struct receiverLinkMetricTLV));
   if(rx_tlv == NULL) return -EINVAL;

   memcpy(rx_tlv->local_al_address,    local_al_mac,                   MAC_ADDR_LEN);
   memcpy(rx_tlv->neighbor_al_address, neighbor_link_metrics->al_mac, MAC_ADDR_LEN);

   rx_tlv->receiver_link_metrics = (struct _receiverLinkMetricEntries *) calloc(1, sizeof(struct _receiverLinkMetricEntries));
   if(rx_tlv->receiver_link_metrics == NULL) return -EINVAL;


   rx_tlv->tlv_type = TLV_TYPE_RECEIVER_LINK_METRIC;
   rx_tlv->receiver_link_metrics_nr = 1;

   rx_tlv->receiver_link_metrics->intf_type  = neighbor_link_metrics->intf_type;
   memcpy(rx_tlv->receiver_link_metrics->neighbor_interface_address, neighbor_link_metrics->neighbor_iface_mac, MAC_ADDR_LEN);
   memcpy(rx_tlv->receiver_link_metrics->local_interface_address, neighbor_link_metrics->local_iface_mac, MAC_ADDR_LEN);

   rx_tlv->receiver_link_metrics->packet_errors    = neighbor_link_metrics->rx_metric.packet_errors;
   rx_tlv->receiver_link_metrics->packets_received = neighbor_link_metrics->rx_metric.packets_received;
   rx_tlv->receiver_link_metrics->rssi             = neighbor_link_metrics->rx_metric.rssi;

   *rx_tlv_ptr = (uint8_t *)rx_tlv;

   return 0;
}

int build_tx_link_met (map_neighbor_link_metric_t *neighbor_link_metrics, uint8_t *local_al_mac, uint8_t** tx_tlv_ptr) {

  struct transmitterLinkMetricTLV* tx_tlv = NULL;

  tx_tlv = (struct transmitterLinkMetricTLV *)malloc(sizeof(struct transmitterLinkMetricTLV));
  if(tx_tlv == NULL) return -EINVAL;

   memcpy(tx_tlv->local_al_address,    local_al_mac,                   MAC_ADDR_LEN);
   memcpy(tx_tlv->neighbor_al_address, neighbor_link_metrics->al_mac, MAC_ADDR_LEN);

   tx_tlv->tlv_type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
   tx_tlv->transmitter_link_metrics_nr = 1;

   tx_tlv->transmitter_link_metrics = (struct _transmitterLinkMetricEntries *) calloc(1, sizeof(struct _transmitterLinkMetricEntries));
   if(tx_tlv->transmitter_link_metrics == NULL) return -EINVAL;

   memcpy(tx_tlv->transmitter_link_metrics->neighbor_interface_address,  neighbor_link_metrics->neighbor_iface_mac, MAC_ADDR_LEN);
   memcpy(tx_tlv->transmitter_link_metrics->local_interface_address,     neighbor_link_metrics->local_iface_mac, MAC_ADDR_LEN);

   tx_tlv->transmitter_link_metrics->intf_type  = neighbor_link_metrics->intf_type;
   tx_tlv->transmitter_link_metrics->packet_errors            = neighbor_link_metrics->tx_metric.packet_errors;
   tx_tlv->transmitter_link_metrics->transmitted_packets      = neighbor_link_metrics->tx_metric.transmitted_packets;
   tx_tlv->transmitter_link_metrics->mac_throughput_capacity  = neighbor_link_metrics->tx_metric.mac_throughput_capacity;
   tx_tlv->transmitter_link_metrics->link_availability        = neighbor_link_metrics->tx_metric.link_availability;
   tx_tlv->transmitter_link_metrics->phy_rate                 = neighbor_link_metrics->tx_metric.phy_rate;

   *tx_tlv_ptr = (uint8_t *)tx_tlv;
   return 0;
}

int fill_upstream_iface_link_met(map_ale_info_t *ale, uint8_t** tlv_list) {

    map_neighbor_link_metric_t *up_link_met = &ale->upstream_link_metrics; 
    uint8_t empty_mac[MAC_ADDR_LEN] = {0};

    /* 
     * We only need to take link between two agents only,
     * If its controller, we need to skip
     */
    map_ale_info_t *root = get_root_ale_node();
    if ((memcmp(root->al_mac, up_link_met->al_mac, MAC_ADDR_LEN) == 0) && (is_local_agent(ale))) return -EINVAL;
    if(memcmp(empty_mac, up_link_met->al_mac, MAC_ADDR_LEN) == 0) return -EINVAL;


    build_tx_link_met (up_link_met, ale->al_mac, tlv_list++);
    build_rx_link_met (up_link_met, ale->al_mac, tlv_list);

    return 0;
}

int fill_all_ethernet_iface_link_met (map_ale_info_t *ale, uint8_t** tlv_list) {

    map_neighbor_link_metric_t *neigh_link_met = NULL; 
    list_iterator_t            iterator        = {0};
    int                        cnt             =  0;

    map_ale_info_t *root = get_root_ale_node();

    bind_list_iterator(&iterator, ale->eth_neigh_link_metric_list);

    while(1) {
        neigh_link_met = (map_neighbor_link_metric_t *)get_next_list_object(&iterator);

        if(neigh_link_met == NULL) break;

        /* 
         * We only need to take link between two agents only,
         * If its controller, we need to skip
         */
        if(memcmp(root->al_mac, neigh_link_met->al_mac, MAC_ADDR_LEN) == 0) continue;

        if (build_tx_link_met (neigh_link_met, ale->al_mac, tlv_list++) < 0) return -EINVAL;
        cnt++;

        if (build_rx_link_met (neigh_link_met, ale->al_mac, tlv_list++) < 0) return -EINVAL;
        cnt++;
    }

    return cnt;
}


int fill_all_wireless_iface_link_met (map_ale_info_t *ale, map_bss_info_t* bss_node, uint8_t** tlv_list)
{
    map_neighbor_link_metric_t *neigh_link_met = NULL; 
    list_iterator_t            iterator        = {0};
    int                        cnt             =  0;

    bind_list_iterator(&iterator, bss_node->neigh_link_metric_list);


    map_ale_info_t *root = get_root_ale_node();


    while(1) {
        neigh_link_met = (map_neighbor_link_metric_t *)get_next_list_object(&iterator);

        if(neigh_link_met == NULL) break;

        /* 
         * We only need to take link between two agents only,
         * If its controller, we need to skip
         */
        if(memcmp(root->al_mac, neigh_link_met->al_mac, MAC_ADDR_LEN) == 0) continue;

        if(build_tx_link_met (neigh_link_met, ale->al_mac, tlv_list++) < 0) return -EINVAL;
        cnt++;

        if(build_rx_link_met (neigh_link_met, ale->al_mac, tlv_list++) < 0) return -EINVAL;
        cnt++;
    }

    return cnt;
}

#define MAX_TLVS_IN_COMBINED_INFRA 512

int8_t map_send_combined_infra_metrics(map_handle_t *handle, uint8_t *dst_al_mac) {
    int     j          = 0;
    int     ret        = -EINVAL;
    int     tlv_cnt    = 0;
    struct  CMDU cmdu  = {0};
    uint8_t *apmetrics = NULL;
    uint8_t **list_of_tlvs = NULL; 
    int cnt = 0;
    char mac[64] = {0};
    map_ale_info_t *ale = NULL;
    const char* key     = NULL;
    uint16_t *mid       = NULL;

    map_ale_info_t * dst_ale = get_ale(dst_al_mac);
    if(dst_ale == NULL) {
        return -EINVAL;
    }
    catch_mid(handle, &mid);

    list_of_tlvs = (uint8_t **)calloc (MAX_TLVS_IN_COMBINED_INFRA, sizeof(uint8_t *));
    if(list_of_tlvs == NULL)
        return -EINVAL;
 
    foreach_hash_node(key) {
        filter_ale(key, ale);

        if(ale == NULL) {
            goto Failure;
        }

        /* 
         * We only need to take link between two agents only,
         * If its controller, we need to skip
         */
        map_ale_info_t *root = get_root_ale_node();
        if(memcmp(root->al_mac, ale->al_mac, MAC_ADDR_LEN) == 0) continue;


        get_mac_as_str(ale->al_mac, (int8_t *)mac, MAX_MAC_STRING_LEN);
        platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s iterate_through ale %s\n",__func__, mac);

        if (fill_upstream_iface_link_met (ale, &list_of_tlvs[tlv_cnt]) != -EINVAL) {
            tlv_cnt += 2;
        
            platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s, ale %s - upstream link met cnt 2, total %d\n",__func__, mac, tlv_cnt);
        }

        cnt = fill_all_ethernet_iface_link_met (ale, &list_of_tlvs[tlv_cnt]); if(cnt<0) goto Failure;
        tlv_cnt += cnt;

        platform_log(MAP_CONTROLLER,LOG_DEBUG,"%s, ale %s - eth link met cnt %d\n",__func__, mac, cnt);


        /* Get bss list and form apmetrics tlv for each bss of the ale*/
        map_radio_info_t *radio = NULL;
        map_bss_info_t   *bss   = NULL;

        foreach_radio_of(ale, radio) {
            foreach_bss_of(radio, bss) {

                cnt = fill_all_wireless_iface_link_met (ale, bss, &list_of_tlvs[tlv_cnt]); if(cnt<0) goto Failure;
                tlv_cnt += cnt;

                apmetrics = (uint8_t *)build_ap_metrics_tlv(bss);
                if(apmetrics != NULL) list_of_tlvs[tlv_cnt++] = apmetrics;
            }
        }
    }

    /* End of TLV */
    list_of_tlvs[tlv_cnt] = NULL;
    cmdu.message_version      =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS;
    cmdu.message_id       =  0;
    cmdu.list_of_TLVs         =  list_of_tlvs;
    strncpy(cmdu.interface_name, dst_ale->iface_name, sizeof(cmdu.interface_name));


    if (lib1905_send(handle_1905, mid, dst_al_mac, &cmdu)) {
        platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d\n",__func__, __LINE__, cmdu.message_type);
    }

    ret = 0;

Failure:
    for (j = 0; j<tlv_cnt; j++) {
        free_1905_TLV_structure(cmdu.list_of_TLVs[j]);
    }

    free(list_of_tlvs);

    return ret;
}

int8_t map_send_link_metrics_result_code (struct CMDU *recv_cmdu) {
    int8_t status    = 0;
    struct CMDU cmdu = {0};
    uint8_t *list[2] = {0};
    struct linkMetricResultCodeTLV link_met_result_code = {0};

    do
    {
        /* Input Parameters Check */
        if ((NULL == recv_cmdu) || (NULL == recv_cmdu->list_of_TLVs)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "CMDU_TYPE_LINK_METRIC_QUERY Malformed structure.");
            ERROR_EXIT(status)
        }

        /* init payload CMDU */
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_LINK_METRIC_RESPONSE;
        cmdu.message_id       =  recv_cmdu->message_id;
        cmdu.relay_indicator  =  0;
        strncpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        link_met_result_code.tlv_type = TLV_TYPE_LINK_METRIC_RESULT_CODE;
        link_met_result_code.result_code = LINK_METRIC_RESULT_CODE_TLV_INVALID_NEIGHBOR;

        list[0] = (uint8_t *)&link_met_result_code;
        list[1] = NULL;

        cmdu.list_of_TLVs  = list;

        if (lib1905_send(handle_1905, &cmdu.message_id, recv_cmdu->cmdu_stream.src_mac_addr, &cmdu) < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

int8_t map_send_link_metrics_report (struct neighbour_link_met_response *link_met_resp) {
    int8_t status    = 0;
    struct CMDU cmdu = {0};

    do
    {
        if (NULL == link_met_resp) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "%s : link_met_resp is NULL.",__func__);
            ERROR_EXIT(status)
        }

        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_LINK_METRIC_RESPONSE;
        cmdu.message_id       =  link_met_resp->mid;
        cmdu.relay_indicator  =  0;
        cmdu.list_of_TLVs     = link_met_resp->list_of_tlvs;
        strncpy(cmdu.interface_name, link_met_resp->dst_iface_name, MAX_IFACE_NAME_LEN);
        cmdu.interface_name[MAX_IFACE_NAME_LEN-1] = '\0';

        if (lib1905_send(handle_1905, &cmdu.message_id, link_met_resp->dst_mac, &cmdu) < 0 ) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s : lib1905_send failed.",__func__);
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}
