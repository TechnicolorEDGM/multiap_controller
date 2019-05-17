#ifndef MULTIAP_CONTROLLER_EXT_ROAMING_ENGINE_H
#define MULTIAP_CONTROLLER_EXT_ROAMING_ENGINE_H

#ifdef EXT_ROAMING_ENGINE
#include <stdint.h>

#include "platform_map.h"
#include "1905_cmdus.h"
#include "map_tlvs.h"

typedef void (*map_controller_ext_roaming_engine_update_ale_cb)(map_ale_info_t* ale);
typedef void (*map_controller_ext_roaming_engine_remove_ale_cb)(map_ale_info_t* ale);
typedef void (*map_controller_ext_roaming_engine_update_radio_cb)(map_radio_info_t* radio);
typedef void (*map_controller_ext_roaming_engine_remove_radio_cb)(map_radio_info_t* radio);
typedef void (*map_controller_ext_roaming_engine_update_bss_cb)(map_bss_info_t* bss);
typedef void (*map_controller_ext_roaming_engine_remove_bss_cb)(map_bss_info_t* bss);
typedef void (*map_controller_ext_roaming_enging_get_policy_config_cb)(map_ale_info_t* ale, map_policy_config_t *policy);
typedef void (*map_controller_ext_roaming_engine_handle_association_event)(map_ale_info_t *ale, client_association_event_tlv_t *association_event_tlv);
typedef void (*map_controller_ext_roaming_engine_handle_ap_metrics_response_cb)(struct CMDU *cmdu);
typedef void (*map_controller_ext_roaming_engine_handle_steering_btm_report_cb)(struct CMDU *cmdu);
typedef void (*map_controller_ext_roaming_engine_handle_beacon_metrics_response_cb)(struct CMDU *cmdu);
typedef void (*map_controller_ext_roaming_engine_handle_unassoc_sta_metrics_response_cb)(struct CMDU *cmdu);
typedef void (*map_controller_ext_roaming_engine_deinit_cb)(void);

typedef struct map_controller_ext_roaming_engine_cbs_s {
    map_controller_ext_roaming_engine_update_ale_cb                          update_ale_cb;
    map_controller_ext_roaming_engine_remove_ale_cb                          remove_ale_cb;
    map_controller_ext_roaming_engine_update_radio_cb                        update_radio_cb;
    map_controller_ext_roaming_engine_remove_radio_cb                        remove_radio_cb;
    map_controller_ext_roaming_engine_update_bss_cb                          update_bss_cb;
    map_controller_ext_roaming_engine_remove_bss_cb                          remove_bss_cb;
    map_controller_ext_roaming_enging_get_policy_config_cb                   get_policy_config_cb;
    map_controller_ext_roaming_engine_handle_association_event               handle_association_event_cb;
    map_controller_ext_roaming_engine_handle_ap_metrics_response_cb          handle_ap_metrics_response_cb;
    map_controller_ext_roaming_engine_handle_steering_btm_report_cb          handle_steering_btm_report_cb;
    map_controller_ext_roaming_engine_handle_beacon_metrics_response_cb      handle_beacon_metrics_response_cb;
    map_controller_ext_roaming_engine_handle_unassoc_sta_metrics_response_cb handle_unassoc_sta_metrics_response_cb;
    map_controller_ext_roaming_engine_deinit_cb                              deinit_cb;
} map_controller_ext_roaming_engine_cbs_t;

extern map_controller_ext_roaming_engine_cbs_t g_map_controller_ext_roaming_engine_cbs;

int map_controller_ext_roaming_engine_init(uv_loop_t *uv_loop, map_controller_ext_roaming_engine_cbs_t *cbs);

#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_RUNNING() \
    (NULL != g_map_controller_ext_roaming_engine_cbs.update_ale_cb)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_ALE(ale) \
    if (g_map_controller_ext_roaming_engine_cbs.update_ale_cb) { g_map_controller_ext_roaming_engine_cbs.update_ale_cb(ale); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_ALE(ale) \
    if (g_map_controller_ext_roaming_engine_cbs.remove_ale_cb) { g_map_controller_ext_roaming_engine_cbs.remove_ale_cb(ale); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_RADIO(radio) \
    if (g_map_controller_ext_roaming_engine_cbs.update_radio_cb) { g_map_controller_ext_roaming_engine_cbs.update_radio_cb(radio); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_RADIO(radio) \
    if (g_map_controller_ext_roaming_engine_cbs.remove_radio_cb) { g_map_controller_ext_roaming_engine_cbs.remove_radio_cb(radio); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_BSS(bss) \
    if (g_map_controller_ext_roaming_engine_cbs.update_bss_cb) { g_map_controller_ext_roaming_engine_cbs.update_bss_cb(bss); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_BSS(bss) \
    if (g_map_controller_ext_roaming_engine_cbs.remove_bss_cb) { g_map_controller_ext_roaming_engine_cbs.remove_bss_cb(bss); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HAS_GET_POLICY_CONFIG() \
    (NULL != g_map_controller_ext_roaming_engine_cbs.get_policy_config_cb)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_GET_POLICY_CONFIG(ale, policy) \
    if (g_map_controller_ext_roaming_engine_cbs.get_policy_config_cb) { g_map_controller_ext_roaming_engine_cbs.get_policy_config_cb(ale, policy); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_ASSOCIATION_EVENT(ale, association_event_tlv) \
    if (g_map_controller_ext_roaming_engine_cbs.handle_association_event_cb) {g_map_controller_ext_roaming_engine_cbs.handle_association_event_cb(ale, association_event_tlv); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_AP_METRICS_RESPONSE(cmdu) \
    if (g_map_controller_ext_roaming_engine_cbs.handle_ap_metrics_response_cb) { g_map_controller_ext_roaming_engine_cbs.handle_ap_metrics_response_cb(cmdu); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_STEERING_BTM_REPORT(cmdu) \
    if (g_map_controller_ext_roaming_engine_cbs.handle_steering_btm_report_cb) { g_map_controller_ext_roaming_engine_cbs.handle_steering_btm_report_cb(cmdu); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_BEACON_METRICS_RESPONSE(cmdu) \
    if (g_map_controller_ext_roaming_engine_cbs.handle_beacon_metrics_response_cb) { g_map_controller_ext_roaming_engine_cbs.handle_beacon_metrics_response_cb(cmdu); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_UNASSOC_STA_METRICS_RESPONSE(cmdu) \
    if (g_map_controller_ext_roaming_engine_cbs.handle_unassoc_sta_metrics_response_cb) { g_map_controller_ext_roaming_engine_cbs.handle_unassoc_sta_metrics_response_cb(cmdu); }
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_DEINIT() \
    if (g_map_controller_ext_roaming_engine_cbs.deinit_cb) {g_map_controller_ext_roaming_engine_cbs.deinit_cb(); }
#else
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_RUNNING() 0
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_ALE(ale)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_ALE(ale)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_RADIO(radio)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_RADIO(radio)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_UPDATE_BSS(bss)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_BSS(bss)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HAS_GET_POLICY_CONFIG() 0
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_GET_POLICY_CONFIG(ale, policy)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_ASSOCIATION_EVENT(ale, association_event_tlv)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_AP_METRICS_RESPONSE(cmdu)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_STEERING_BTM_REPORT(cmdu)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_BEACON_METRICS_RESPONSE(cmdu)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_HANDLE_UNASSOC_STA_METRICS_RESPONSE(cmdu)
#define MAP_CONTROLLER_EXT_ROAMING_ENGINE_DEINIT()

#endif /* EXT_ROAMING_ENGINE */

#endif /* MULTIAP_CONTROLLER_EXT_ROAMING_ENGINE_H */
