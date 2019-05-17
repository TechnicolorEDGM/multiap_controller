/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <stdlib.h>
#include "multiap_controller_metrics_handler.h"
#include "platform_map.h"
#include "arraylist.h"
#include "map_topology_tree.h"
#include "multiap_controller_payloads.h"

#define MAX_STA_METRICS_COUNT 16

void update_assoc_sta_link_metrics(map_sta_info_t* sta, map_sta_link_metrics_t* link_metrics) {
    if(sta == NULL || link_metrics == NULL )
        return;

    int count = list_get_size(sta->metrics);
    if(count >= MAX_STA_METRICS_COUNT) {
        map_sta_link_metrics_t* node = remove_last_object(sta->metrics);
        free(node);
    }
    if(-1 == push_object(sta->metrics, (void*)link_metrics)) {
        platform_log(MAP_CONTROLLER,LOG_ERR, "Failed updating the station metrics\n");
    }
}

uint8_t periodic_link_metric_query(char* timer_id, void *arg) {
    int32_t level = 0;
    map_ale_info_t* ale = NULL;
    link_metric_query_t link_query = {{0},{0},MAP_LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS,MAP_BOTH_TX_AND_RX_LINK_METRICS};
    int8_t al_mac_str[MAX_MAC_STRING_LEN] = {0};

    /* Get the level of the tree */
    level = map_get_topology_tree_height();
    platform_log(MAP_CONTROLLER,LOG_DEBUG," %s Number of levels in topology tree %d \n",__func__, level);

    /* Ignore the first level as it is the controller node itself. For each node in each level, send link metric query*/
    while(level > 1)
    {
        foreach_child_in_level(level, ale) {
            if(ale) {
                get_mac_as_str(ale->al_mac, al_mac_str, MAX_MAC_STRING_LEN);
                memcpy(link_query.al_mac, ale->al_mac , MAC_ADDR_LEN);
                map_send_link_metric_query(NULL,&link_query);
            }
        }

        level--;
    }
    return 0;
}


