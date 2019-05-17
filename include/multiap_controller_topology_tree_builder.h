/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef MULTIAP_CONTROLLER_TOP_TREE_BUILDER_H
#define MULTIAP_CONTROLLER_TOP_TREE_BUILDER_H

#include "map_data_model.h"
#include "platform_map.h"
#include "1905_tlvs.h"
#include <stdint.h>
#include <string.h>

/** @brief Intialize controller's topology tree.
*
*   This will be used to intialize the internally maintained
*   topology tree data structures
*
*   @return The status code 0-success, -ve for failure
*/
int8_t init_controller_topology_tree();

/** @brief This function will update topology 
*   tree to add controller's child.
*
*   This will be used to add the immediate neighbors of controller
*   as the child of controller in topology tree data structures.
*
*   @return None
*/
void add_as_child_of_controller(map_ale_info_t *ale);

/** @brief This function will update tree from the neighbor list
*   tree to add 
*
*   This will be used to create a topology tree from 1905 neighbor list TLV
*
*   @return None
*/
void map_build_topology_tree(struct neighborDeviceListTLV **neigh_dev_tlv,
                uint8_t tlv_count, map_ale_info_t *current_ale);

/** @brief This function will return true the ALE node passed is local agent
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @return The 1- for local agent, 0 - other agents
 */
uint8_t is_local_agent(map_ale_info_t *ale);

/** @brief This function will return true the ALE node passed is controller
 *
 *  @param ale pointer to ALE node to check for controller
 *  @return The 1- for controller, 0 - for other ALEs
 */
uint8_t is_controller(map_ale_info_t *ale);

/** @brief This function returns if we need to update the topology or not
 *
 *  This functions checks the last received topology response time stamp
 *  and take decision to register for topology query retry or not to 
 *  control topology query flooding.
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @return The 0- Expired , 1 - Query required
 */
uint8_t is_topology_update_required(map_ale_info_t *ale);

/** @brief This function create a retry timer to send topology query
 *
 *  This function registers to a retry timer to send topology query
 *  until we get a topology response
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @return The 0- Expired , 1 - Query required
 */
void map_register_topology_query_retry(map_ale_info_t *ale);

/** @brief This function will remove the dead ALE from controller DM
 *
 *  This API will cleanup all the resources assocciated with the ALE.
 *
 *  @param status of retry when it completes
 *  @param ale pointer to ALE node to check for local agent
 *  @param cmdu that lead to completion of retry
 *  @return The 0- Expired , 1 - Query required
 */
int8_t map_detect_and_cleanup_dead_agent(int status, void *ale_object, void *cmdu);

/** @brief This function will extend the ALE deletion
 *
 *  This API restart the retry handler which extends the ALE deletion
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @param cmdu that lead to completion of retry
 *  @return The 0- Expired , 1 - Query required
 */
void map_extend_ale_deletion(map_ale_info_t *ale);


/** @brief This function will send topology query for all children
 *
 *  This API sends topology query for all child nodes
 *
 *  @param ale pointer to ALE node to check for local agent
 */
void map_send_topology_query_for_children(map_ale_info_t *ale);


#endif //MULTIAP_CONTROLLER_TOP_TREE_BUILDER_H

