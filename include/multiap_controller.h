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

#ifndef MULTIAP_CONTROLLER_H
#define MULTIAP_CONTROLLER_H

#include <stdio.h>
#include <uv.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "platform.h"
#include "controller_platform.h"
#include "1905_lib.h"
#include "map_tlvs.h"

typedef int32_t handle_1905_t;

int  map_controller_init(int argc, char *argv[]);
void map_controller_run();
void map_controller_cleanup();

extern handle_1905_t handle_1905;

#endif

#ifdef __cplusplus
}
#endif
