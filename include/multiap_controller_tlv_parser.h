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

#ifndef MULTIAP_CONTROLLER_TLV_PARSER_H
#define MULTIAP_CONTROLLER_TLV_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include "multiap_controller.h"
#include "map_data_model.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "map_ipc_lib.h"
#include "multiap_controller_utils.h"


/* Status defines incase of any radio/bss updates */
#define MAP_ERROR_UPDATE    -1
#define MAP_NO_UPDATE       0
#define MAP_VALID_UPDATE    1

// Get Radio type from ap basic capabiltity tlv
int get_radiotype_from_apbasiccap_tlv(AP_basic_capability_tlv_t* ap_basic_capability ,uint8_t* radio_type, uint8_t *band_type_5G);

// Update the client station info
int8_t parse_client_assoc_tlv(map_ale_info_t *ale, client_association_event_tlv_t *client_asso_tlv);

int8_t parse_ap_operational_bss_tlv(ap_oerational_BSS_tlv_t*, map_ale_info_t*, uint8_t *is_ale_updated);
int8_t parse_ap_caps_tlv(AP_capability_tlv_t*, map_ale_info_t*);
int8_t parse_ap_basic_caps_tlv(AP_basic_capability_tlv_t*, uint8_t *al_mac);
int8_t parse_ap_ht_caps_tlv(AP_HT_capability_tlv_t*);
int8_t parse_ap_vht_caps_tlv(AP_VHT_capability_tlv_t*);
int8_t parse_ap_he_caps_tlv(AP_HE_capability_tlv_t*);
int8_t parse_ap_metrics_response_tlv(ap_metrics_response_tlv_t* ap_metrics_resp);
int8_t parse_assoc_sta_link_metrics_tlv(associated_sta_link_metrics_t*);
int8_t parse_assoc_sta_traffic_stats_tlv(assoc_sta_traffic_stats_tlv_t* sta_traffic_stats);
int8_t parse_associated_clients_tlv(associated_clients_tlv_t*);
int8_t parse_chan_pref_tlv(channel_preference_tlv_t *channel_pref_tlv);
int8_t parse_op_restriction_tlv(radio_operation_restriction_tlv_t *ops_restriction_tlv);
int8_t parse_device_info_tlv(struct deviceInformationTypeTLV *dev_info_tlv);
int8_t parse_neighbor_device_list_tlv(struct neighborDeviceListTLV **neigh_dev_tlv,
                                        uint8_t tlv_count, map_ale_info_t *ale);

int8_t update_transmit_power(uint8_t *dst_al_mac, uint8_t *radio_id, uint8_t tx_pwr);
int publish_stn_event(map_sta_info_t *sta, map_publish_event_t evt);
#endif

#ifdef __cplusplus
}
#endif
