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

#ifndef MULTIAP_CONTROLLER_TLV_HELPER_H
#define MULTIAP_CONTROLLER_TLV_HELPER_H

#include <stdio.h>
#include <stdint.h>
#include "multiap_controller.h"
#include "1905_tlvs.h"

int map_get_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info);
void map_free_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info_tlv);

int map_get_1905_neighbor_tlvs (struct neighborDeviceListTLV *neighbor_1905_tlvs, int *neighbor_count);
void map_free_1905_neighbor_tlv (struct neighborDeviceListTLV *neighbor_1905_tlv);

#endif

#ifdef __cplusplus
}
#endif
