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

#ifndef MULTIAP_CONTROLLER_PAYLOADS_H
#define MULTIAP_CONTROLLER_PAYLOADS_H

#include <stdio.h>
#include <uv.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "controller_platform.h"
#include "map_tlvs.h"
#include "map_data_model.h"
#include "map_retry_handler.h"
#include "monitor_task.h"
#include "multiap_controller_callbacks.h"
#include "multiap_controller_cli_event_handler.h"
#include "multiap_controller_mgmt_ipc.h"

#define MAX_TLV_PER_MSG 32
#define MAX_MAP_MSG 32

#define ROLE_1905_REGISTRAR 0x00
#define MAP_ROLE_CONTROLLER 0x00
#define MAP_ROLE_AGENT 0x01
#define MULTIAP_BOTH_CONTROLLER_AGENT 0x02
#define NO_OF_NULL_TLVS        1
#define NUM_OF_RADIO_ID_TLV 1
// Extract required tlv from the given cmdu
int get_tlv_fromcmdu(uint16_t tlvtype,struct CMDU *cmdu,void** ptlv_data);

/* Get Error Code TLV */
struct mapErrorCodeTLV * get_error_code_tlv(uint8_t reason_code, uint8_t *sta_mac);

/***********************************************************************************************/
//-----------------------------       SEND CALLBACKS     ---------------------------------------/
/***********************************************************************************************/

/* 1905 ACK send */
int map_send_1905_ack(map_handle_t *map_handle, array_list_t *sta_list, uint8_t reason_code);

// Autoconfiguration response packet send
int8_t map_send_autoconfig_response(struct CMDU *recv_cmdu);

// Autoconfiguration WSC M2 packet send
int8_t map_send_wscM2(struct CMDU *recv_cmdu);

// Autoconfiguration Renew packet send
int map_send_autoconfig_renew(map_handle_t *map_handle, uint8_t freq_band);

// AP Capability Query send
int8_t map_send_ap_capability_query(map_handle_t *handle, void* ale);

/* Client Capability Query send */
int8_t map_send_client_capability_query(map_handle_t *handle, void *sta_mac);

/* Client ACL Request send */
int map_send_client_acl_request(map_handle_t *handle, client_acl_data_t *acl_data);

// Send steer request cmdu
int map_send_steering_request(map_handle_t *handle, struct sta_steer_params *steer_info, uint8_t *dst_mac);

// Send policy config
int map_send_policy_config(map_handle_t *handle, metric_policy_tlv_t *metric_policy_tlv, steering_policy_tlv_t *steering_policy_tlv, uint8_t *dst_mac);

// Send topology query response
int8_t map_send_topology_query (map_handle_t *handle, void* ale_object);

//Send topology response
int8_t map_send_topology_response(struct CMDU *recv_cmdu);

// Channel Preference Query
int8_t map_send_channel_preference_query(map_handle_t *handle, void* ale_object);

typedef struct map_chan_selec_pref_type_s
{
    map_ale_info_t  *ale;
    uint8_t         radio_cnt;
    map_radio_info_t *radio;   // This must be array of radio's
    uint8_t         pref;      // GET_CONTROLLER_PREFERENCE or GET_AGENT_PREFERENCE
} map_chan_selec_pref_type_t;

// Channel Selection Request
int8_t map_send_channel_selection_request(map_handle_t *map_handle, void *chan_selec_pref_type);

// Station link metrics query
int8_t map_send_associated_sta_link_metrics_query(map_handle_t *map_handle, uint8_t *sta_mac);

// Send beacon metrics query
int map_send_beacon_metrics_query(map_handle_t *handle, beacon_metrics_query_t *beacon_metrics_query, uint8_t *dst_mac);

/* Send 1905 Ack for this callback */
int8_t map_send_steering_completed_msg_rcvd_ack(struct CMDU *recv_cmdu);

/* Send 1905 Ack from this callback */
int8_t map_send_steering_btm_report_ack(struct CMDU *recv_cmdu);

/* Send Vendor Specific Payload */
int8_t map_send_vendor_specific(map_handle_t *handle,void* buff);

/* unassoc sta metrics query */
int map_send_unassoc_sta_metrics_query (map_handle_t *handle, struct unassoc_sta_dm_s *unassoc_sta_tlv);

/* Link Metrics Query */
int8_t map_send_link_metric_query(map_handle_t *handle, link_metric_query_t *lm_query);

/* Update Link Metrics Response in data model */
int8_t map_action_link_metrics_response(struct CMDU *recv_cmdu);

/*  Send Higher Layer Data Message*/
int8_t map_send_higher_layer_data_msg(map_handle_t *handle, higherlayer_info_t *hl_data);

/* AP Metrics Query */
int8_t map_send_ap_metric_query(map_handle_t *handle, ap_metric_query_t *ap_query);

/* Combined infra metrics */
int8_t map_send_combined_infra_metrics(map_handle_t *handle, uint8_t *dst_al_mac);

/* Link metrics response with result code */
int8_t map_send_link_metrics_result_code(struct CMDU *recv_cmdu);

/* Link metrics response */
int8_t map_send_link_metrics_report (struct neighbour_link_met_response *link_met_resp);

#endif

#ifdef __cplusplus
}
#endif
