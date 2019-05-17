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

#ifndef MULTIAP_CONTROLLER_METRICS_HANDLER_H
#define MULTIAP_CONTROLLER_METRICS_HANDLER_H

#include "arraylist.h"
#include "map_data_model.h"

void update_assoc_sta_link_metrics(map_sta_info_t* sta, map_sta_link_metrics_t* link_metrics);
uint8_t  periodic_link_metric_query(char* timer_id, void *arg);

#endif // MULTIAP_CONTROLLER_METRICS_HANDLER_H

#ifdef __cplusplus
}
#endif
