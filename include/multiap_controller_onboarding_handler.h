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

#ifndef MULTIAP_CONTROLLER_ONBOARDING_HANDLER_H
#define MULTIAP_CONTROLLER_ONBOARDING_HANDLER_H

#include "map_data_model.h"

/** @brief Intialize onborading agent.
 *
 *  This will be used to intialize the internally maintained
 *  onboarding data structures
 *
 *  @return The status code 0-success, -ve for failure
 */
int8_t init_agent_onboarding_handler();

/** @brief This API prepares the controller for new agent onboarding  
 *
 *  This API will 
 *      Create a new ALE data structure if not created already.
 *      Intiate a topology query
 *
 *  @param
 *      al_mac      - AL MAC address of the agent
 *      recv_ifname - Receiving interface Name
 *  @return The reference to map_ale_info_t on success otherwise NULL.
 */
map_ale_info_t* map_handle_new_agent_onboarding(uint8_t *al_mac, char* recv_ifname);

/** @brief This API prepares the controller for new radio onboarding  
 *
 *  This API will 
 *      Create new Radio info node in data model if not created already.
 *      Intiates Policy configuration request message
 *
 *  @param
 *      al_mac      - AL MAC address of the agent
 *      recv_ifname - Receiving interface Name
 *  @return The reference to map_ale_info_t on success otherwise NULL.
 */
map_radio_info_t* map_handle_new_radio_onboarding(uint8_t *radio_id, uint8_t *al_mac);

/** @brief Validates the Agent onborading
 *
 *  This will validate the agents ssids and stop the 
 *  onboarding timer if the validation is successfull
 *
 *  @return The status code 0-success, -ve for failure
 */
void  valildate_agent_onborading(map_ale_info_t* ale);

/** @brief Check if agent is onboarded   
 *
 *  Returns true when agent is no longer in the onboarding list
 *
 *  @return True when agent is onboarded, false when onboarding is still ongoing
 */
uint8_t is_agent_onboarded(map_ale_info_t *ale);

/** @brief Get the agent onborading
 *
 *  @param
 *      ale - Pointer to map_ale_info_t structure
 *
 *  @return The true if successfully onboarded otherwise false
 */
uint8_t  is_all_radio_configured(map_ale_info_t* ale);

/** @brief Get the number of configured radios in agent
 *
 *  @param
 *      ale - Pointer to map_ale_info_t structure
 *
 *  @return Number of configured radios. 
 */
uint8_t get_configured_radio_count(map_ale_info_t* ale);

/** @brief Get the BSS configuration of the radio
 *
 *  @param
 *      radio - Pointer to the radio to be configured
 *      num_of_bh_bss - Number of BSS to be configured as backhaul
 *      num_of_fh_bss - Number of BSS to be configured as frounthaul
 *  @return None
 */
void get_bss_config( map_radio_info_t *radio, uint8_t *num_of_bh_bss, uint8_t *num_of_fh_bss);

/** @brief Checks if channel selection is enabled/disabled in UCI
 *
 *  @param 	None
 *  @return None
 */
uint8_t is_channel_selection_enabled();

/** @brief Get dead agent detection intervel from UCI
 *
 *  @param      None
 *  @return dead_agent_detection_intervel from uci
 */
uint16_t map_get_dead_agent_detection_intervel();

/** @brief Get topology query retry intervel in sec
 *
 *  @param      None
 *  @return topology_query_retry_intervel_sec
 */
uint16_t map_get_topology_query_retry_intervel_sec();

#endif // MULTIAP_CONTROLLER_AGENT_ONBORADING_HANDLER_H

#ifdef __cplusplus
}
#endif
