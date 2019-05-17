/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_tlv_helper.h"
#include "map_data_model.h"
#include "arraylist.h"
#include "map_topology_tree.h"
#include "1905_platform.h"

int map_get_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info) {
    int i      = 0;
    int j      = 0;
    int status = 0;
    int br_nr  = 0;
    struct bridge *br = NULL;
    uint8_t empty_str[MAX_IFACE_NAME_LEN] = {0};
    struct interfaceInfo if_info = {0};

    do {
        if (!bridge_info) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s : device_info is NULL",__func__);
            break;
        }

        bridge_info->tlv_type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES;
        if (-1 == platform_get(MAP_PLATFORM_GET_BRIDGE_INFO, NULL, (void *)&br)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s : platform_get failed for MAP_PLATFORM_GET_BRIDGE_INFO",__func__);
            break;
        }

        if (br) {
            while ((memcmp(br[br_nr].name, empty_str, MAX_IFACE_NAME_LEN) != 0)) {
                br_nr++;

                /* This check is to avoid infinite loop */
		if(br_nr >= MAX_BRIDGES_PER_DEV) {
                    break;
                }
            }
        }
        bridge_info->bridging_tuples_nr = br_nr;

        if (0 == br_nr) {
            bridge_info->bridging_tuples = NULL;
        }
        else {
            bridge_info->bridging_tuples = (struct _bridgingTupleEntries *) calloc(1, sizeof(struct _bridgingTupleEntries) *br_nr);

            for (i = 0; i < br_nr; i++) {
                bridge_info->bridging_tuples[i].bridging_tuple_macs_nr = br[i].bridged_interfaces_nr;

                if (0 == br[i].bridged_interfaces_nr) {
                    bridge_info->bridging_tuples[i].bridging_tuple_macs = NULL;
                }
                else {
                    bridge_info->bridging_tuples[i].bridging_tuple_macs = (struct _bridgingTupleMacEntries *) calloc(1, sizeof(struct _bridgingTupleMacEntries) * br[i].bridged_interfaces_nr);

                    for (j = 0; j < br[i].bridged_interfaces_nr; j++) {
                        if((memcmp(br[i].bridged_interfaces[j], empty_str, MAX_IFACE_NAME_LEN) != 0)) {
                            platform_get(MAP_PLATFORM_GET_INTERFACE_INFO, br[i].bridged_interfaces[j], (void *)&if_info);
                            memcpy(bridge_info->bridging_tuples[i].bridging_tuple_macs[j].mac_address, if_info.mac_address, MAC_ADDR_LEN);
                        }
                    }
                }
            }
        }
    } while (0);

    return status;
}

void map_free_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info_tlv) {
    int  i = 0;
    if (bridge_info_tlv) {
        if (bridge_info_tlv->bridging_tuples_nr > 0) {
            for (i = 0; i < bridge_info_tlv->bridging_tuples_nr; i++) {
                if (bridge_info_tlv->bridging_tuples[i].bridging_tuple_macs_nr > 0) {
                    free(bridge_info_tlv->bridging_tuples[i].bridging_tuple_macs);
                }
            }
            free(bridge_info_tlv->bridging_tuples);
        }
    }
    return;
}

int map_get_1905_neighbor_tlvs (struct neighborDeviceListTLV *neighbor_1905_tlvs, int *neighbor_count) {
    int tlv_already_added = 0;
    int status = 0;
    int count  = 0;
    int i      = 0;
    map_ale_info_t* neighbor_ale = NULL;
    map_ale_info_t* root_ale     = NULL;

    do {
        if ((!neighbor_1905_tlvs) || (!neighbor_count)) {
            platform_log(MAP_CONTROLLER,LOG_ERR,"%s : neighbor_1905_tlvs or neighbor_count is NULL",__func__);
            break;
        }

        root_ale = get_root_ale_node();
        if (root_ale) {
            foreach_neighbors_of(root_ale, neighbor_ale) {
                if (neighbor_ale) {
                    for (i = 0; i < count; i++) {
                        if (0 == memcmp(neighbor_1905_tlvs[i].local_mac_address, neighbor_ale->upstream_remote_iface_mac, MAC_ADDR_LEN)) {
                            tlv_already_added = 1;
                            break;
                        }
                    }
                    if (i < MAX_INTERFACE_COUNT) {
                        struct neighborDeviceListTLV *neigh = (struct neighborDeviceListTLV *) &neighbor_1905_tlvs[i];
                        if (!tlv_already_added) {
                            /* Add a tlv for this new interface */
                            neigh->tlv_type = TLV_TYPE_NEIGHBOR_DEVICE_LIST;
                            memcpy(neigh->local_mac_address, neighbor_ale->upstream_remote_iface_mac, MAC_ADDR_LEN);
                            neigh->neighbors_nr = 0;
                            neigh->neighbors = (struct _neighborEntries *) calloc(1, sizeof(struct _neighborEntries));
                            count++;
                        }
                        else {
                            /* Tlv for this interface already exits, hence update */
                            neigh->neighbors = (struct _neighborEntries *) realloc(neigh->neighbors, sizeof(struct _neighborEntries) * (neigh->neighbors_nr+1));
                        }
                        memcpy(neigh->neighbors[neigh->neighbors_nr].mac_address, neighbor_ale->al_mac, MAC_ADDR_LEN);
                        neigh->neighbors[neigh->neighbors_nr].bridge_flag = 0;
                        neigh->neighbors_nr++;
                    }
                }
                tlv_already_added = 0;
            }
            *neighbor_count = count;
        }
    } while (0);

    return status;
}

void map_free_1905_neighbor_tlv (struct neighborDeviceListTLV *neighbor_1905_tlv) {
    if (neighbor_1905_tlv) {
        if (neighbor_1905_tlv->neighbors_nr > 0) {
            free(neighbor_1905_tlv->neighbors);
        }
    }
    return;
}
