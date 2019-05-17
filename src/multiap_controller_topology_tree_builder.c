/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_topology_tree_builder.h"
#include "multiap_controller_onboarding_handler.h"
#include "multiap_controller_defines.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "map_topology_tree.h"
#include "platform_utils.h"
#include <syslog.h>
#include "string.h"

int8_t init_controller_topology_tree()
{
    /* Get the Controller MAC and create the
    Controller root node on the topology tree*/
    uint8_t controller_mac[MAC_ADDR_LEN];
    char mac_addr[MAX_MAC_STRING_LEN];

    memset(&mac_addr,0,sizeof(mac_addr));

    if(map_controller_env_macaddress != NULL)
    {
        strncpy(mac_addr, map_controller_env_macaddress, sizeof(mac_addr)-1);
        mac_addr[sizeof(mac_addr)-1] = '\0';

        if(!platform_get_mac_from_string(mac_addr,controller_mac)){
            platform_log(MAP_CONTROLLER,LOG_ERR, "Controller_mac failed");
            return -1;
        }
    }

    if(init_topology_tree(controller_mac) < 0)
    {
        platform_log(MAP_CONTROLLER,LOG_ERR, " %s Failed to create controller topology tree\n",__func__);
        return -1;
    }

    return 0;
}

void add_as_child_of_controller (map_ale_info_t *ale) {
    if(ale)
        topology_tree_insert(get_root_ale_node(), ale);
}

void map_build_topology_tree(struct neighborDeviceListTLV **neigh_dev_tlv,
                uint8_t tlv_count, map_ale_info_t *current_ale) {
    // If the current ALE is orphaned lets not process the neighbors
    if((current_ale == NULL) || (NULL == get_parent_ale_node(current_ale)))
        return;

    map_ale_info_t *neighbor_ale                              = NULL;
    map_ale_info_t *parent_of_neighbor_ale                    = NULL;
    map_ale_info_t *parent_of_current_ale_found               = NULL;
    struct neighborDeviceListTLV *current_tlv                 = NULL;
    map_ale_info_t *conflict_ale_list[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
    uint8_t conflict_list_count                               = 0;
    int     new_neighbor_count                                = 0;

    // Iterate through all the neighbor device TLV
    for(uint8_t tlv_index = 0; tlv_index < tlv_count; ++tlv_index, current_tlv = NULL) {
        current_tlv = neigh_dev_tlv[tlv_index];
        if(current_tlv == NULL)
            continue;
        for (uint8_t nbr_index = 0; nbr_index < current_tlv->neighbors_nr; ++nbr_index , neighbor_ale = NULL, parent_of_neighbor_ale = NULL) {
            neighbor_ale = get_ale(current_tlv->neighbors[nbr_index].mac_address);
            if(neighbor_ale == NULL){
                // This new neighbor may be a parent of current node. Skip proccessing it.
                neighbor_ale = map_handle_new_agent_onboarding(current_tlv->neighbors[nbr_index].mac_address, current_ale->iface_name);
                continue;
            }

            if(neighbor_ale) {
                // Avoid handling local agent and controller as a neighbor
                if(is_local_agent(neighbor_ale))
                    continue;

                // Skip this existing parent from neighbor list
                if(neighbor_ale == get_parent_ale_node(current_ale)) {
                    parent_of_current_ale_found = get_parent_ale_node(current_ale);
                    continue;
                }

                // If the controller is reported as the neighbor then
                // make the current ALE as the child of controller.
                if(is_controller(neighbor_ale)) {
                    topology_tree_insert(neighbor_ale, current_ale);
                    parent_of_current_ale_found = get_parent_ale_node(current_ale);
                    continue;
                }

                parent_of_neighbor_ale = get_parent_ale_node(neighbor_ale);
                if(parent_of_neighbor_ale == NULL) {
                    // Add this neighbor as child of current ALE
                    topology_tree_insert(current_ale, neighbor_ale);
                    new_neighbor_count++;
                    // Update the upstream remote interface of the neighbor
                    if (1 == map_update_ale_upstream_remote_mac(neighbor_ale, current_tlv->local_mac_address)) {
                        /* Send Agent Update whenever upstream MAC/TYPE changes */
                        map_controller_send_agent_update(CMDU_TYPE_TOPOLOGY_RESPONSE,neighbor_ale);
                    }

                    // Update the receiving interface name.
                    strncpy(neighbor_ale->iface_name, current_ale->iface_name, MAX_IFACE_NAME_LEN);
                }
                else if(parent_of_neighbor_ale == current_ale) {
                    // Alread a child node. Remove from the list and add it to the front for easy deletion
                    make_ale_orphaned(neighbor_ale); // O(1)
                    topology_tree_insert(current_ale, neighbor_ale); // O(1)
                    new_neighbor_count++;
                }
                else if(parent_of_neighbor_ale != current_ale) {
                    // This conflict can only be resolved after iterating all the TLVs
                    if(conflict_list_count < MAX_ALE_NEIGHBOR_COUNT)
                        conflict_ale_list[conflict_list_count++] = neighbor_ale;
                }
            }
        }
    }

    // If the old parent is not found in the new neighbor list disassemble the subtree
    if(parent_of_current_ale_found == NULL) {

        // Disassemble the subtree
        disassemble_tree(current_ale);
    }

    // Send topology query to the conflict nodes
    for(uint8_t i = 0; i < conflict_list_count; i++) {
        // Update the receiving interface name
        map_update_ale_recving_iface(conflict_ale_list[i], current_ale->iface_name);

        // Send topology query
        map_register_topology_query_retry(conflict_ale_list[i]);
    }

    // Handle neighbor deletion
    // Old neighbors are bubbled towards the end of the list.
    // Remove all old nodes at the end.
    foreach_child_in(current_ale, neighbor_ale) {
        if(new_neighbor_count == 0) {
            map_register_topology_query_retry(neighbor_ale);
            make_ale_orphaned(neighbor_ale);
        }
        else if(is_topology_update_required(neighbor_ale)) {
            map_register_topology_query_retry(neighbor_ale);
        }
        if(new_neighbor_count)
            new_neighbor_count--;
    }
}

map_ale_info_t* get_local_agent_ale() {
    map_ale_info_t *local_agent_ale = NULL;
    static uint8_t is_first_time = 1;
    uint8_t agent_almac[MAC_ADDR_LEN];
    uint8_t status = 0;

    if(map_agent_env_macaddress != NULL && is_first_time) {
        char mac_str[MAX_MAC_STRING_LEN];
        strncpy(mac_str, map_agent_env_macaddress, MAX_MAC_STRING_LEN-1);
        mac_str[MAX_MAC_STRING_LEN-1] = '\0';

        if(platform_get_mac_from_string(mac_str, agent_almac))
            status = 1;
    }

    if(status)
        local_agent_ale = get_ale(agent_almac);

    return local_agent_ale;
}

uint8_t is_local_agent(map_ale_info_t *ale) {
    if(ale == get_local_agent_ale())
        return 1;
    return 0;
}

uint8_t is_controller(map_ale_info_t *ale) {
    if(ale == get_root_ale_node())
        return 1;
    return 0;
}

void map_register_topology_query_retry(map_ale_info_t *ale) {
    uint16_t topology_query_retry_intervel_sec = map_get_topology_query_retry_intervel_sec();
    if(topology_query_retry_intervel_sec > 0)
    {
	platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s:topology_query_retry_intervel_sec is %d ", __func__, topology_query_retry_intervel_sec);
        char retry_id[MAX_TIMER_ID_STRING_LENGTH];

        GET_RETRY_ID(ale->al_mac, TOPOLOGY_QUERY_RETRY_ID, retry_id);
        map_register_retry((const char*)retry_id, topology_query_retry_intervel_sec,\
                        MAX_TOPOLOGY_QUERY_RETRY, ale, map_detect_and_cleanup_dead_agent, map_send_topology_query);
    }
    else
        platform_log(MAP_CONTROLLER,LOG_DEBUG, "%s : topology_query_retry_intervel_sec NOT updated properly", __func__);
}
void map_extend_ale_deletion(map_ale_info_t *ale) {
    char retry_id[MAX_TIMER_ID_STRING_LENGTH];
    GET_RETRY_ID(ale->al_mac, TOPOLOGY_QUERY_RETRY_ID, retry_id);
    restart_retry_timer(retry_id);
}

int8_t map_detect_and_cleanup_dead_agent(int status, void *ale_object, void *cmdu) {
    map_ale_info_t *ale = (map_ale_info_t*)ale_object;
    char mac_str[MAX_MAC_STRING_LEN];
    if(ale){
        uint64_t no_update_since = get_clock_diff_secs( get_current_time(), ale->keep_alive_time);
        if((map_get_dead_agent_detection_intervel()) < no_update_since){
            platform_log(MAP_CONTROLLER,LOG_INFO, "-------------------------------------------");
            platform_log(MAP_CONTROLLER,LOG_INFO, " Deleting ALE : %s from DM", MAC_AS_STR(ale->al_mac, mac_str));
            platform_log(MAP_CONTROLLER,LOG_INFO, "-------------------------------------------");
            #ifdef MAP_MGMT_IPC
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD,(void *)ale);
            #endif

            /* Update roaming engine to indicate removed ALE */
            MAP_CONTROLLER_EXT_ROAMING_ENGINE_REMOVE_ALE(ale);

            /* Trigger topology query for all child nodes before removing the ALE */
            map_send_topology_query_for_children(ale);

            remove_ale(ale->al_mac);
        }
    }
    return 0;
}

uint8_t is_topology_update_required(map_ale_info_t *ale) {
    if(ale) {
        uint64_t no_update_since = get_clock_diff_secs( get_current_time(), ale->keep_alive_time);
        if(ALE_KEEP_ALIVE_THRESHOLD_IN_SEC < no_update_since) {
            return 1;
        }
    }
    return 0;
}

void map_send_topology_query_for_children(map_ale_info_t *ale)
{
    map_ale_info_t *neighbor_ale = NULL;
    // Send topology query to immediate neighbors only
    foreach_child_in(ale, neighbor_ale) {
        if(neighbor_ale) {
            map_register_topology_query_retry(neighbor_ale);
        }
    }
}

