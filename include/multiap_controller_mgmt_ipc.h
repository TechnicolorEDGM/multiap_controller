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

#ifndef MULTIAP_CONTROLLER_VENDOR_IPC_H
#define MULTIAP_CONTROLLER_VENDOR_IPC_H

#include "map_ipc_lib.h"


/* Socket buffer */
#define SOCKET_BUFFER_LEN 8192
#define MAX_CLIENTS 2

#define SHIFT_3BYTE 24
#define SHIFT_2BYTE 16
#define SHIFT_1BYTE  8
#define BYTE_MASK   0xFF

/* These should be exactly similar to the defines in 1905_lib_internal.h*/
#define MAX_1905_MESSAGE 19
#define MAX_MULTIAP_MESSAGE 27



typedef struct _map_ipc_mcast_msg
{
    uint16_t uuid; /* UUID from VE */
    array_list_t* ale_msglist;  
    array_list_t* no_ack_ale_msglist;
}map_ipc_mcast_msg;

typedef struct _map_controller_mgmt_ipc{
    uv_loop_t *ctrlr_loop;/* The global controller uv loop */
    int32_t client_fd;  /* Management daemon client socket FD */
    int32_t server_fd;       /* Initial controller sock FD */
    uv_poll_t uvpoll_client_handle;
    uv_poll_t uvpoll_server_handle;
    array_list_t*  message_id_list;
    map_ipc_mcast_msg mcast_msg_info;
    uint8_t sock_buffer[SOCKET_BUFFER_LEN];
}map_controller_mgmt_ipc;


/* callback function prototype to handle IPC events */
typedef int (*mgmt_ipc_event_handler_t)(void *data);

typedef struct {
    uint8_t interest_set;
    uint32_t msgdata;
} map_ipc_message_interest_t;

typedef struct {
    map_ipc_message_interest_t lib1905_messages[MAX_1905_MESSAGE];
    map_ipc_message_interest_t multiap_messages[MAX_MULTIAP_MESSAGE];
} map_ipc_register_data_t;

typedef struct _map_ipc_event_t {
    map_ipc_tags subcmd;
    uint8_t registered; 
    map_ipc_register_data_t data;
    mgmt_ipc_event_handler_t ipc_event_handler;
    
} map_ipc_event_t;

typedef struct
{
    uint16_t	    msg_type;
    void*           ale_info;
}map_ipc_agent_data;


/** @brief This will setup sockets for vendor daemon IPC.
 *
 *  This will take care of setting up sockets for
 *  communication with vendor daemon
 *  
 *  @param loop the global controller loop context
 *  @param data the output pointer in which the socket descriptor of vendor daemon is updated
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_init_mgmt_ipc(uv_loop_t *loop);

/** @brief This will send data to daemon via socket IPC.
 *
 *  This will take care of sending required data to the mgmnt daemon via sockets
 *  
 *  @param cmd the type of event to data
 *  @param data the data required to populate and send the data
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_mgmt_ipc_send(map_ipc_tags cmd,void *data);
/** @brief This will update the message id for which we expect a ACK.
 *
 *  This will update the message id for which we expect a ACK that controller has to send to mgmt IPC
 * 
 *  @param mid the message id for which ACK is expected
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_mgmt_ipc_update_message_id(uint16_t mid);


/** @brief This checks if ACK is expected for the message id
 *
 *  This checks if we expect a ACK for a message id
 * 
 *  @param mid the message id for which ACK is expected
 *  @return 1- true 0-false
 */
uint8_t map_controller_mgmt_ipc_is_pending_ack(uint16_t mid);

/** @brief This sends an Agent Update event to VE IPC
 *
 *  
 *  @param msg_type the message type that triggers the update
 *  @param map_ale_info_t * the ALE for which update is to be sent
 *  @return 0 success
 */
int32_t map_controller_send_agent_update(uint16_t msg_type, map_ale_info_t *ale_info);

int8_t map_mgmt_ipc_cleanup_retry_vendor_specific(int status, void *args, void *opaque_cmdu);

#endif

#ifdef __cplusplus
}
#endif
