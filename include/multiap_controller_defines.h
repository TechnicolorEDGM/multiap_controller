/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef _MULTIAP_CONTROLLER_DEFINES_H_
#define _MULTIAP_CONTROLLER_DEFINES_H_

// Timer ID's
#define ONBOARDING_TIMER_ID         "ONBOARDING-TIMER"
#define TOPOLOGY_QUERY_TIMER_ID     "TOPOLOGY-QUERY-TIMER"
#define LINK_METRIC_QUERY_TIMER_ID  "LINK-METRIC-TIMER"

static inline const char* MAC_AS_STR(uint8_t *mac, char *mac_str) {
    get_mac_as_str(mac, (int8_t*)mac_str, MAX_MAC_STRING_LEN);
    return mac_str;
}

// TODO: Read from UCI
#define MAX_TOPOLOGY_QUERY_RETRY            5
#define ALE_KEEP_ALIVE_THRESHOLD_IN_SEC     30

#define NUM_SHIFT_TO_GET_PREF               4
#define PREF_REASON_BIT_MASK                0x0F
#define GET_AGENT_PREFERENCE                0
#define GET_CONTROLLER_PREFERENCE           1
#define MAP_CHAN_SEL_ACCEPTED               0
#define MAX_NEIGHBOR_COUNT                  256
#define MAX_ALE_NEIGHBOR_COUNT              32

#define MAX_DEAD_AGENT_DETECT_TIME_IN_SEC   240
#define MIN_DEAD_AGENT_DETECT_TIME_IN_SEC   15

#endif
