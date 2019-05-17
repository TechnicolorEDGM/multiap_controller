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

#ifndef MULTIAP_CONTROLLER_POST_ONBOARDING_HANDLER_H
#define MULTIAP_CONTROLLER_POST_ONBOARDING_HANDLER_H

#include "map_data_model.h"
#include "map_retry_handler.h"


// Channel selection handling declarations
#define MAP_CHAN_SEL_QUERY   1
#define MAP_CHAN_SEL_REQUEST 2

typedef struct chan_sel_action_s {
    map_ale_info_t *ale;
    uint8_t        action;
} chan_sel_action_t;

int8_t map_agent_handle_channel_selection(map_handle_t *handle, void *chan_sel_action);

int8_t map_build_and_send_policy_config(map_handle_t *handle, void *radio_object);

#endif // MULTIAP_CONTROLLER_POST_ONBOARDING_HANDLER_H

#ifdef __cplusplus
}
#endif
