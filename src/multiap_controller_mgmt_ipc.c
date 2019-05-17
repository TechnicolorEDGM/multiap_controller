/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller_utils.h"
#include "multiap_controller.h"
#include "multiap_controller_mgmt_ipc.h"
#include "multiap_controller_payloads.h"
#include "multiap_controller_topology_tree_builder.h"
#include "multiap_controller_defines.h"
#include "map_topology_tree.h"
#include "1905_platform.h"


#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/un.h>
#include <uv.h>

/* Global data */
map_controller_mgmt_ipc gmap_mgmt_ipc = {0};
const char* mgmt_ipc_report_timer = "mgmt_ipc_report_timer";


#define MAX_SOCK_PATH 32

#define EVENT_TYPE_LENGTH           3
#define MSG_TYPE_LENGTH 2
#define VENDOR_MSG_DATA_LENGTH      11
#define AGENT_FIXED_DATA_LENGTH     23
#define AGENT_RADIO_DATA_LENGTH     8
#define AGENT_BSS_DATA_LENGTH       7
#define STA_CONNECT_DATA_LENGTH     20
#define STA_DISCONNECT_DATA_LENGTH  19
#define STA_METRICS_DATA_LENGTH 39 /* 6 + 8*4 + 1 */
#define SINGLE_AGENT_METRICS_DATA_LENGTH 9 /*6+2+1*/
#define MCAST_COMPLETED_LENGTH   4

/* This empty does not free as this message list used numbers(message id) as each node and not MAC or structures */
#define empty_message_list(list) for(void* obj = NULL; (NULL != (obj = pop_object(list)));)


#define MCAST_MSG_LIST gmap_mgmt_ipc.mcast_msg_info.ale_msglist
#define MCAST_NO_ACK_MSG_LIST gmap_mgmt_ipc.mcast_msg_info.no_ack_ale_msglist
#define VENDOR_RETRY_COUNT       6
#define VENDOR_RETRY_INTERVAL    5

#define VENDOR_SPECIFIC_MSG_RETRY_ID "-VENDOR-SPEC-MSG"
#define MCAST_MSG "-MCAST-"

#define UVPOLL_INIT_START(fd, handle, callbck_fn) \
uv_poll_init(gmap_mgmt_ipc.ctrlr_loop, &handle, fd); \
uv_poll_start(&handle, (UV_READABLE|UV_DISCONNECT), callbck_fn);



static inline void GET_RETRY_MCAST_MSG_ID( uint8_t *mac,
                                 const char* retry_type,
                                 char* retry_id,
                                 uint16_t msg_id) {
    snprintf((char*)retry_id, MAX_TIMER_ID_STRING_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x%s%d%s",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],MCAST_MSG,msg_id,retry_type);
}

static int map_controller_mgmt_ipc_send_agent_onboard(void *data);
static int map_controller_mgmt_ipc_send_agent_offboard(void *data);
static int map_controller_mgmt_ipc_send_agent_update(void *data);
static int map_controller_mgmt_ipc_send_sta_connect(void *data);
static int map_controller_mgmt_ipc_send_sta_disconnect(void *data);
static int map_controller_mgmt_ipc_send_ap_metrics(void *data);
static int map_controller_mgmt_ipc_send_sta_metrics(void *data);
static int map_controller_mgmt_ipc_send_1905_data(void *data);
static int map_controller_mgmt_ipc_send_mcast_completed(void *data);
static void map_mgmt_ipc_cleanup(uv_poll_t* handle);
static void map_mgmt_ipc_poll(bool is_server_poll);

/* Make sure to keep this updated in the same ORDER as in map_ipc_tags 
If the order is maintained, there is no need to maintain subcmd, but still keeping it for future uses
and easy readability*/
map_ipc_event_t map_ipc_evnt_table[] = {
    {MAP_IPC_TAG_FIRST,                 1, {{{0}},{{0}}}, NULL}, /* Dummy for maintaining the order */
    {MAP_IPC_TAG_EVNT_REG,              1, {{{0}},{{0}}}, NULL},/* VE to Ctrlr ,so this index not really used. Just for array iteration */
    {MAP_IPC_TAG_NOTIFY_ALE_ONBOARD,    0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_agent_onboard}, /* event data is nil */
    {MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD,   0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_agent_offboard}, /* event data is nil */
    {MAP_IPC_TAG_NOTIFY_ALE_UPDATE,     0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_agent_update}, /* event data is nil */
    {MAP_IPC_TAG_NOTIFY_STA_CONNECT,    0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_sta_connect}, /* event data is nil */
    {MAP_IPC_TAG_NOTIFY_STA_DISCONNECT, 0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_sta_disconnect}, /* event data is nil */
    {MAP_IPC_TAG_NOTIFY_1905_DATA,      0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_1905_data}, /* event data is string that consist of "TLV type" & "TLV Data". 
    									For eg, to register Vendor Ext TLV, callee has to pass "0x0004", "oui_id" */
    {MAP_IPC_TAG_NOTIFY_STA_METRICS,    0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_sta_metrics},/* event data is nil */
    {MAP_IPC_TAG_NOTIFY_AP_METRICS,     0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_ap_metrics},/* event data is nil */
    {MAP_IPC_TAG_WRITE_1905_VE,         1, {{{0}},{{0}}}, NULL},/* VE to Ctrlr ,so this index not really used. Just for array iteration*/
    {MAP_IPC_TAG_NOTIFY_MCAST_STATUS,   0, {{{0}},{{0}}}, map_controller_mgmt_ipc_send_mcast_completed},/* event data is nil */
};


/* Get the index of the event from the global IPC Event Table based on event tag
This function is actually redundant for now as we do not iterate through the table
Rather just use event itself as index. This function can be re-purposed lated for efficient use*/
static int get_map_ipc_event_index(uint8_t event)
{
    int ret = -1;

    /* Iterate through the platform event table and get the index
    for the pattern */
    if(event > MAP_IPC_TAG_FIRST && event <  MAP_IPC_TAG_LAST)
    {
        ret = event;
    }

    return ret;
}



/* Updates the data (message type and OUID ) for event */
static void update_messagetype(uint8_t event_index,uint32_t data)
{
    uint8_t message_type = data >> SHIFT_3BYTE;
    uint32_t message_data = data & 0xFFFFFF ;

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s Message Type %d \n",__func__, message_type);
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s Message Data %d \n",__func__, message_data);
    /* Since message type parsed from data is only one byte - MultiAP messages are not handled (except MAP Ack) */
    if (message_type  > CMDU_TYPE_1905_FIRST_MESSAGE && message_type  < CMDU_TYPE_1905_LAST_MESSAGE) {
        map_ipc_evnt_table[event_index].data.lib1905_messages[message_type].interest_set = 1;
        map_ipc_evnt_table[event_index].data.lib1905_messages[message_type].msgdata = message_data;
    }
}

/* Is message type registered for notifying 1905 data*/
static uint8_t is_messagetype_registered(uint16_t message_type)
{
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s Message Type %d \n",__func__, message_type);

    if (message_type  > CMDU_TYPE_1905_FIRST_MESSAGE && message_type  < CMDU_TYPE_1905_LAST_MESSAGE) {
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s INTEREST SET %d \n",__func__, map_ipc_evnt_table[MAP_IPC_TAG_NOTIFY_1905_DATA].data.lib1905_messages[message_type].interest_set);
        return map_ipc_evnt_table[MAP_IPC_TAG_NOTIFY_1905_DATA].data.lib1905_messages[message_type].interest_set;
    }
    else if(message_type == CMDU_TYPE_MAP_ACK)
    {
        return 1;
    }

    return 0;
}

/* Is Vendor OUI registered for notifying 1905 data*/
static uint8_t is_vendor_OUI_registered(uint8_t *vendor_oui)
{
    uint8_t registered = 0;

    uint32_t OUI = map_ipc_evnt_table[MAP_IPC_TAG_NOTIFY_1905_DATA].data.lib1905_messages[CMDU_TYPE_VENDOR_SPECIFIC].msgdata;
    if( (((OUI >> SHIFT_2BYTE) & BYTE_MASK) == vendor_oui[0] ) &&
         (((OUI >> SHIFT_1BYTE) & BYTE_MASK) == vendor_oui[1] ) &&
         ((OUI & BYTE_MASK) == vendor_oui[2] ) )
    {
        registered = 1;
    }

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s OUID Registered %d\n",__func__, registered);
    return registered;
}

/* Is address a MCAST addresss */
static uint8_t is_macaddr_mcast(uint8_t * ale_mac)
{
    uint8_t ret = 0;

    if( ale_mac[0] == MCAST_1905_B0 && ale_mac[1] == MCAST_1905_B1 &&
        ale_mac[2] == MCAST_1905_B2 && ale_mac[3] == MCAST_1905_B3 &&
        ale_mac[4] == MCAST_1905_B4 && ale_mac[5] == MCAST_1905_B5)
    {
        ret = 1;
    }

    return ret;
}

/* Adds the agent based on current topology tree */
static void map_mgmt_ipc_create_agent_msg_list()
{
    int32_t level = 0;
    map_ale_info_t* ale = NULL;
    int8_t al_mac_str[MAX_MAC_STRING_LEN] = {0};

    /* Get the level of the tree */
    level = map_get_topology_tree_height();
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s MCAST Number of levels in topology tree %d \n",__func__, level);
    dump_topology_tree();

    /* Ignore the first level as it is the controller node itself. For each node in each level, add the agent mac
            to the mcast msg list. The local agent also needs to be ignored*/
    while(level > 1)
    {
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s MCAST LEVEL %d \n",__func__, level);
        foreach_child_in_level(level, ale) {
            if(ale) {
                /* To skip local agent. The level check is to avoid checking is_local_agent for every 
                                node as the local agent will definitely be in the immediate next level of controller */
                get_mac_as_str(ale->al_mac, al_mac_str, MAX_MAC_STRING_LEN);
                platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"MCAST ALE MAC %s \n",al_mac_str);
                platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s IS LOCAL AGENT %d \n",__func__, is_local_agent(ale)); 
                if(level == 2 && is_local_agent(ale))
                    continue;

                /* The following allocation needs to be freed when each node is popped */
                uint8_t *mac = (uint8_t*) calloc(1, MAC_ADDR_LEN);
                if(mac) 
                {
                    memcpy(mac, ale->al_mac , MAC_ADDR_LEN);
                    insert_last_object(MCAST_MSG_LIST, (void *)mac);
                    get_mac_as_str(mac, al_mac_str, MAX_MAC_STRING_LEN);
                    platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"MCAST ALE MAC Added to MSG List%s \n",al_mac_str);
                }
            }
        }

        level--;
    }

    return;
}

static uint8_t map_mgmt_ipc_cleanup_mcast_msg_list(map_ipc_write_1905_ve *vendor_buff )
{
    /* Reset global values once MCAST status is sent - UUID */
    gmap_mgmt_ipc.mcast_msg_info.uuid = 0;

    /* Free the vendor buff which is passed as args */
    if(NULL != vendor_buff)
        free(vendor_buff);

    /* Ideally this should not be doing anything as we already popped every item in the list */
    empty_array_list(MCAST_MSG_LIST);
    empty_array_list(MCAST_NO_ACK_MSG_LIST);

    return MAP_IPC_SUCCESS;
}

/* Handles each item in the mcast msg list */
static int32_t map_mgmt_ipc_handle_mcast_msg_list(map_ipc_write_1905_ve *vendor_buff)
{
    uint8_t *agent_mac = NULL;
    int32_t status = MAP_IPC_ERR_INVALID_HANDLE;

    agent_mac = pop_object(MCAST_MSG_LIST);

    /* Ideally this is always called after checking for list is empty, so this shouldnt 
            return NULL */
    if(NULL != agent_mac)
    {
        /* Update the vendor_buff ALE MAC  */
        memcpy(vendor_buff->ale_mac, agent_mac, MAC_ADDR_LEN);

        map_ale_info_t * ale = get_ale((uint8_t *)vendor_buff->ale_mac);

        if(ale != NULL)
        {
            status = MAP_IPC_SUCCESS;
        }

        free(agent_mac);
    }
    return status;
}

/* Start retry timer for each ALE MAC in msg list for sending vendor specific message */
static int32_t map_mgmt_ipc_send_mcast_msg(map_ipc_write_1905_ve *vendor_buff )
{
    char retry_id[MAX_TIMER_ID_STRING_LENGTH];
    int8_t al_mac_str[MAX_MAC_STRING_LEN] = {0};
    int32_t status = MAP_IPC_SUCCESS;

    do
    {
        /* To start with itself, list is empty */
        if(list_get_size(MCAST_MSG_LIST) == 0)
        {
            platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s List is empty\n",__func__);
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_MCAST_STATUS,NULL);
            status =  map_mgmt_ipc_cleanup_mcast_msg_list(vendor_buff);
        }
        else
        {
            /* Iterate through the list, all error conditions are handled within the do while loop 
                        in case of success, the retry is triggered and we break the loop*/
            status = map_mgmt_ipc_handle_mcast_msg_list(vendor_buff);
            if(status == MAP_IPC_SUCCESS)
            {
                get_mac_as_str((uint8_t *)vendor_buff->ale_mac, al_mac_str, MAX_MAC_STRING_LEN);
                platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"MCAST Starting Retry for Agent %s \n",al_mac_str);
                GET_RETRY_MCAST_MSG_ID((uint8_t *)vendor_buff->ale_mac, VENDOR_SPECIFIC_MSG_RETRY_ID, retry_id,gmap_mgmt_ipc.mcast_msg_info.uuid);
                if(-1 == map_register_retry((const char*)retry_id, VENDOR_RETRY_INTERVAL, VENDOR_RETRY_COUNT , vendor_buff,
                            map_mgmt_ipc_cleanup_retry_vendor_specific, map_send_vendor_specific)) {
                    platform_log(MAP_VENDOR_IPC,LOG_ERR, "MCAST Failed Registering retry timer : %s ", retry_id);
                    status = MAP_IPC_ERR_INVALID_HANDLE;
                }
            }
        }
    }while(status != MAP_IPC_SUCCESS);

    return status;
}

int8_t map_mgmt_ipc_cleanup_retry_vendor_specific(int status, void *args, void *opaque_cmdu)
{
    map_ipc_write_1905_ve *vendor_buff = (map_ipc_write_1905_ve *)args;
    int8_t al_mac_str[MAX_MAC_STRING_LEN] = {0};

    char retry_id[MAX_TIMER_ID_STRING_LENGTH];

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s MCAST cLEANUP mcast RETRY %d\n",__func__, status);

    /* Update that ACK based on status */
    if (vendor_buff != NULL && status == MAP_RETRY_STATUS_TIMEOUT)
    {
        get_mac_as_str((uint8_t *)vendor_buff->ale_mac, al_mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"MCAST Ack not received for agent %s \n",al_mac_str);
        add_sta_to_list((uint8_t *)vendor_buff->ale_mac,MCAST_NO_ACK_MSG_LIST);
    }

    do
    {
        /* Check if message has been sent for all agents and send status back to VE.
                    Else  continue sending to rest of agents in list */
        if(list_get_size(MCAST_MSG_LIST) == 0)
        {
            platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s List is empty\n",__func__);
            map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_MCAST_STATUS,NULL);
            status =  map_mgmt_ipc_cleanup_mcast_msg_list(vendor_buff);
        }
        else
        {
            /* Iterate through the list, all error conditions are handled within the do while loop 
                        in case of success, the retry is triggered and we break the loop*/
            status = map_mgmt_ipc_handle_mcast_msg_list(vendor_buff);
            if(status == MAP_IPC_SUCCESS)
            {
                GET_RETRY_MCAST_MSG_ID((uint8_t *)vendor_buff->ale_mac, VENDOR_SPECIFIC_MSG_RETRY_ID, retry_id,gmap_mgmt_ipc.mcast_msg_info.uuid);
                if(-1 == map_register_retry((const char*)retry_id, VENDOR_RETRY_INTERVAL, VENDOR_RETRY_COUNT, vendor_buff,
                            map_mgmt_ipc_cleanup_retry_vendor_specific, map_send_vendor_specific)) {
                    platform_log(MAP_VENDOR_IPC,LOG_ERR, "MCAST Failed Registering retry timer : %s ", retry_id);
                    status = MAP_IPC_ERR_INVALID_HANDLE;
                }
            }
        }
    }while(status != MAP_IPC_SUCCESS);

    return MAP_IPC_SUCCESS;
}

/* Parse the Event Register Messages */
static void parse_event_register(uint8_t * buff)
{
    uint8_t event_count = 0;
    uint8_t index = 0;
    uint8_t event_type = 0;
    uint8_t event_index = 0;
    uint8_t *p = buff;
    uint32_t data = 0;

    /* After event type, length and data is received */
    /* Following parsing is done as per map_ipc_event_reg */
    _E1B(&p, &event_count);

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s Event Count %d \n",__func__, event_count);

    for(index =0; index < event_count ; index++)
    {
        _E1B(&p, &event_type);
        event_index = get_map_ipc_event_index(event_type);
        if(event_index != -1)
        {           
            map_ipc_evnt_table[event_index].registered = 1;
            /* The data expected is 4 byte of which 3 bytes are OUID and 1 byte is Message type
                    But one byte is not enough to handle MAP messages. So for now, only 1905 messages 
                    are supported. Inorder to support MAP messages, some logic can be implemented - TBD. 
                    Exception is the MAP Ack which is now sent from controller to daemon inspite of it not being
                    registered.*/
            _E4B(&p, &data);
            update_messagetype(event_index,data);
        }
        else
            platform_log(MAP_VENDOR_IPC,LOG_WARNING," %s Not a Valid event type %d, Ignore \n",__func__, event_type);		
    }

}

/* Parse the Vendor Message received */
static void parse_vendor_message(uint16_t event_len,uint8_t * buff)
{
    uint8_t *p = buff;
    map_ipc_write_1905_ve *vendor_buff ;
    uint8_t 	oui_id[3] = {0} ;
    uint8_t num_agents = 0, index = 0;
    uint8_t to_be_freed = 0;   

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s Event Length - %d \n", __func__,event_len);

    /* Allocate Memory - To Be freed after sending the Vendor Packet */
    vendor_buff = (map_ipc_write_1905_ve *)calloc(1, (sizeof(map_ipc_write_1905_ve) + event_len));
    if(vendor_buff == NULL)
        return;

    /* The below step is needed to set the data pointer */
    vendor_buff->data = (uint8_t *)vendor_buff + sizeof(map_ipc_write_1905_ve);

    /* Following parsing is done as per map_ipc_write_1905_ve */

    _E2B(&p,&vendor_buff->uuid);
    _EnB(&p,oui_id ,3);
    _E1B(&p,&num_agents);
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s MCAST No of agents- %d \n", __func__,num_agents);
    for(index = 0 ; index < num_agents ; index++)
    {
        memcpy(vendor_buff->oui_id,oui_id ,3);
        _EnB(&p,vendor_buff->ale_mac,MAC_ADDR_LEN);
        _E2B(&p,&vendor_buff->len);
        _EnB(&p,vendor_buff->data,vendor_buff->len);

        platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s Send Vendor Specific Data \n", __func__);
        if(num_agents ==1 && is_macaddr_mcast((uint8_t *)vendor_buff->ale_mac))
        {
            platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s MCAST MCAST Address \n", __func__);
            /* Check if a previous MCAST message is being handled in which case ignore the new message.
                    Assumption here is UUID will never be 0 and also checking msg_list is empty*/
            if(gmap_mgmt_ipc.mcast_msg_info.uuid == 0 && 
               list_get_size(MCAST_MSG_LIST) == 0)
            {
                map_mgmt_ipc_create_agent_msg_list();
                /* Update global UUID */
                gmap_mgmt_ipc.mcast_msg_info.uuid = vendor_buff->uuid;
                map_mgmt_ipc_send_mcast_msg(vendor_buff);
            }
            else
            {
                /* Free vendor buff in this case */
                to_be_freed = 1;
                map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_MCAST_STATUS,&vendor_buff->uuid);
                platform_log(MAP_VENDOR_IPC,LOG_ERR,"%s MCAST already being handled %d \n", __func__,gmap_mgmt_ipc.mcast_msg_info.uuid);
            }
            /* No of agents should have been 1 for a MCAST address, but as a added precaution 
                        breaking the loop */
            break;
        }
        else
        {
        /* Send the Vendor Specific CMDU. We do not vaidate OUID or anything, we trust the daemon
                to just send it across as it is*/
            map_handle_t map_handle = {0};

            map_handle.handle_1905 = handle_1905;
            map_handle.recv_cmdu   = NULL;
            map_send_vendor_specific(&map_handle,vendor_buff);
            map_controller_mgmt_ipc_update_message_id(map_handle.mid);
            to_be_freed = 1;
        }
    }

    /* Free the allocated memory once its send, only for unicast messages */
    if(to_be_freed == 1)
    free(vendor_buff);

    return;
}

/* Parse messages received on the socket */
static void parse_message(int32_t read_len,uint8_t *buff)
{
    uint8_t event_tag = 0;
    uint16_t event_len = 0;
    uint8_t *p = buff;

    /* First parse the event tag */
    _E1B(&p, &event_tag);
    
    /* After event type, length and data is received */
    _E2B(&p, &event_len); 

    if(event_len >= read_len)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR," %s Length Mismatch - %d > %d\n",__func__, event_len, read_len);
        return;
    }

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s Event Received - %d \n",__func__, event_tag);

    switch(event_tag)
    {
        case MAP_IPC_TAG_EVNT_REG:
            parse_event_register(p);
            break;

        case MAP_IPC_TAG_WRITE_1905_VE:
            parse_vendor_message(event_len,p);
            break;

        default:
            break;
    }

    return;
}



/* Timer callback to send metrics data*/
uint8_t mgmt_ipc_report_timer_callback(char* timer_id, void* args) {

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, "\nHandling the metrics reporting to mgmt ipc\n");

    map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_STA_METRICS, NULL);

    return 0;
}

/* This is used for comparing data message id's for 1905 ACK */
static int compare_message_id(void* msg_id, void* msg_id_new) {
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, "%s Msg id - %d, %d \n", __func__, (uintptr_t)msg_id, (uintptr_t)msg_id_new);

    if(msg_id == msg_id_new) {
        return 1;
    }
    return 0;
}


/* The UV Poll callback which triggered on event READ/DISCONNECT on client socket */
static void uvpoll_mgmt_ipc_client_socket_read_cb (uv_poll_t* handle, int status, int events)
{
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s \n", __func__);
    if((status < 0) || (events & UV_DISCONNECT))
    {
        platform_log(MAP_VENDOR_IPC,LOG_INFO, " %s Client Socket Disconnect \n", __func__);
        map_mgmt_ipc_cleanup(handle);
    }
    else if (events & UV_READABLE) {
        int32_t valread = 0;
        /* Might be costly but safer */
        memset(gmap_mgmt_ipc.sock_buffer, 0,SOCKET_BUFFER_LEN);

        platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Read Data \n", __func__);
        if(gmap_mgmt_ipc.client_fd != -1)
        {
            valread = read( gmap_mgmt_ipc.client_fd , gmap_mgmt_ipc.sock_buffer, SOCKET_BUFFER_LEN);

            parse_message(valread,gmap_mgmt_ipc.sock_buffer);
        }
    }
    return;
}

/* The UV Poll callback which triggered on event READ/DISCONNECT on server socket */
static void uvpoll_mgmt_ipc_server_socket_read_cb (uv_poll_t* handle, int status, int events)
{
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s \n", __func__);
    if((status < 0) || (events & UV_DISCONNECT))
    {
        platform_log(MAP_VENDOR_IPC,LOG_INFO, " %s Server Socket Disconnect \n", __func__);
    }
    else if (events & UV_READABLE) {
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Start Accept \n", __func__);
        gmap_mgmt_ipc.client_fd = accept(gmap_mgmt_ipc.server_fd, NULL, NULL);
        if (gmap_mgmt_ipc.client_fd < 0)
        {
            platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Socket Accept Failed \n", __func__);
            return ;
        }

        /* Start client socket poll now for new messages from VE*/
        map_mgmt_ipc_poll(false);

        /* Stop polling for new connections until this connection ends*/
        uv_poll_stop(handle);
    }
    return;
}

static void map_mgmt_ipc_poll(bool is_server_poll) {

    if(is_server_poll == true)
    {
        /*Start polling the server socket for new connections */
        if(gmap_mgmt_ipc.server_fd != -1)
        {
            platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Start Server Poll \n", __func__);
            UVPOLL_INIT_START(gmap_mgmt_ipc.server_fd,gmap_mgmt_ipc.uvpoll_server_handle,uvpoll_mgmt_ipc_server_socket_read_cb);
        }
    }
    else
    {
        /* Start polling on the vendor socket descriptor */
        if(gmap_mgmt_ipc.client_fd != -1)
        {
            platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Start Client Poll \n", __func__);
            UVPOLL_INIT_START(gmap_mgmt_ipc.client_fd,gmap_mgmt_ipc.uvpoll_client_handle,uvpoll_mgmt_ipc_client_socket_read_cb);
        }
    }
}


/* Clean up everything related to current client connection */
static void map_mgmt_ipc_cleanup(uv_poll_t* handle)
{
    if(&gmap_mgmt_ipc.uvpoll_client_handle == handle)
    {
        /* Reset the client socket fd */
        if(gmap_mgmt_ipc.client_fd != -1)
        {
            /* Close the client socket */
            close(gmap_mgmt_ipc.client_fd);
            gmap_mgmt_ipc.client_fd = -1;
        }

        /* Reset the global event table*/
        for(uint8_t i = MAP_IPC_TAG_FIRST; i < MAP_IPC_TAG_LAST; i++)
        {
            map_ipc_evnt_table[i].registered = 0;
            memset(&map_ipc_evnt_table[i].data, 0, sizeof(map_ipc_register_data_t));
        }

        /* Clear the mcast message list */
        if(MCAST_MSG_LIST)
        {
            empty_message_list(MCAST_MSG_LIST);
        }

        if(MCAST_NO_ACK_MSG_LIST)
        {
            empty_message_list(MCAST_NO_ACK_MSG_LIST);
        }

        /* Clear the message list */
        if(gmap_mgmt_ipc.message_id_list)
        {
            empty_message_list(gmap_mgmt_ipc.message_id_list);
        }

        /* Stop UV polling for events */
        uv_poll_stop(handle);

        /* Start server socket poll now for new client connections*/
        map_mgmt_ipc_poll(true);

    }
}

static inline void map_mgmt_ipc_socket_send( uint32_t event_len) {
    send(gmap_mgmt_ipc.client_fd ,gmap_mgmt_ipc.sock_buffer , event_len , 0 );
}

#if MULTIPLE_STA_CONNECT

/* API to send multiple STA details on an agent onboard/update */
static void map_mgmt_send_multiple_sta_connect(map_ale_info_t* agent_info, uint8_t sta_count)
{
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;
    uint16_t data_len = 0;
    uint8_t event = 0;
    uint8_t radio_index = 0, bss_index = 0;
    map_radio_info_t *radio_node      = NULL;
    map_sta_info_t *sta_node = NULL;

    if(agent_info == NULL)
        return;

    event = MAP_IPC_TAG_NOTIFY_STA_CONNECT;

    data_len = sizeof(map_ipc_sta_connect) + (sta_count * sizeof(map_ipc_sta_table));
    /* Fill the IPC Socket Buffer with the data */
    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&data_len, &p);

    /* IPC Packet - Data - Agent MAC */
    _InB(agent_info->al_mac, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - No of stations */
    _I1B(&sta_count, &p);

    for(radio_index = 0; radio_index < agent_info->num_radios; radio_index++)
    {
        radio_node = agent_info->radio_list[radio_index];
        if(radio_node) {
            for (bss_index = 0;bss_index < radio_node->num_bss; bss_index++)
            {
                list_iterator_t* it = new_list_iterator(radio_node->bss_list[bss_index]->sta_list);

                while(it->iter != NULL)
                {
                    uint8_t* sta_mac = (uint8_t*) get_next_list_object(it);
                    if(sta_mac)
                    {
                        sta_node = get_sta(sta_mac);
                        if(sta_node)
                        {
                            platform_log(MAP_VENDOR_IPC,LOG_DEBUG, "[MAP]: %s %d, STA MAC %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx \n",__func__, __LINE__, 
                                                    sta_node->mac[0], sta_node->mac[1], 
                                                    sta_node->mac[2], sta_node->mac[3], 
                                                    sta_node->mac[4], sta_node->mac[5]);
                            /* IPC Packet - Data - Sta Data */
                            _InB(sta_node->mac, &p, MAC_ADDR_LEN);
                            _InB(radio_node->bss_list[bss_index]->bssid, &p, MAC_ADDR_LEN);
                            _I1B(&sta_node->sta_caps.supported_standard, &p);
                        }
                    }
                }
                free_list_iterator(it);
            }
        }
    }

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);

    return;

}
#endif

/* API to send Agent details on an agent onboard/update */
static void map_mgmt_send_agent_data(uint8_t event, map_ale_info_t *agent_info, uint16_t msg_type)
{
    map_radio_info_t *radio_node      = NULL;
    uint8_t sta_count = 0, bss_count = 0;
    uint16_t agent_data_len = 0;
    uint8_t radio_index = 0, bss_index = 0;
    uint8_t radio_type = 0;
    uint8_t bss_type = 0;
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;
    uint8_t parent_mac[MAC_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint16_t interface_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;
    uint8_t manufacturer_len = strlen(agent_info->manufacturer_name);

    /* This iteration is only to get the bss_count and sta_count
      TBD - If we can avoid this extra loop*/
    for(uint8_t radio_index = 0; radio_index < agent_info->num_radios; radio_index++) 
    {
        radio_node = agent_info->radio_list[radio_index];
        if(radio_node) {
            bss_count += radio_node->num_bss;
            for (bss_index = 0;bss_index < radio_node->num_bss; bss_index++) 
            {	
                sta_count += list_get_size(radio_node->bss_list[bss_index]->sta_list);
            }
        }
    }

    interface_type = agent_info->upstream_iface_type;
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"%s Interface Type - %d, Manufacturer Len - %d  \n", __func__,interface_type, manufacturer_len);

    /* Allocate and fill data for the local structure */
    agent_data_len = AGENT_FIXED_DATA_LENGTH + (agent_info->num_radios * AGENT_RADIO_DATA_LENGTH) + (bss_count * AGENT_BSS_DATA_LENGTH) + manufacturer_len;
    if(msg_type == CMDU_TYPE_AP_AUTOCONFIGURATION_WSC || msg_type == CMDU_TYPE_TOPOLOGY_RESPONSE)
        agent_data_len += MSG_TYPE_LENGTH;
    
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," Length %d \n",agent_data_len);

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&agent_data_len, &p);

    /* IPC Packet - Data - ale_mac */
    _InB(agent_info->al_mac,&p,MAC_ADDR_LEN);

    /* Only in case of valid msg type which is for all cases of Agent Update, send msg_type as well.
            This is not sent for agent onboard */
    /* IPC Packet - Msg Type */
    if(msg_type == CMDU_TYPE_AP_AUTOCONFIGURATION_WSC || msg_type == CMDU_TYPE_TOPOLOGY_RESPONSE)
        _I2B(&msg_type, &p);

    char mac_str[MAX_MAC_STRING_LEN];
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, "MAP_IPC_TAG_NOTIFY_ALE_UPDATE IPC  - %s " , MAC_AS_STR(agent_info->upstream_remote_iface_mac, mac_str));

    /* IPC Packet - Data - agent interface mac . Incase of local agent it is same as al mac*/
    if (strstr(agent_info->iface_name, "lo") != NULL)
        _InB(agent_info->al_mac,&p,MAC_ADDR_LEN);
    else
        _InB(agent_info->upstream_local_iface_mac,&p,MAC_ADDR_LEN);

    /*IPC Packet - Data - Interface type */
    _I2B(&interface_type, &p);

    /*IPC Packet - Data - Length of manufacturer name*/
    _I1B(&manufacturer_len, &p);

    /*IPC Packet - Data - manufacturer name*/
    _InB(agent_info->manufacturer_name, &p, manufacturer_len);

    /*IPC Packet - Data - Parent Interface mac */
    if(interface_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET)
        _InB(parent_mac,&p,MAC_ADDR_LEN);
    else
        _InB(agent_info->upstream_remote_iface_mac,&p,MAC_ADDR_LEN);

    /* IPC Packet - Data - sta count*/   
    _I1B(&sta_count, &p);

    /* IPC Packet - Data - radio count */
    _I1B(&agent_info->num_radios, &p);
    
    for(radio_index = 0; radio_index < agent_info->num_radios; radio_index++) 
    {
        radio_node = agent_info->radio_list[radio_index];
        
        if(radio_node) {

            if(radio_node->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
            {
                radio_type = MAP_IPC_RADIO_TYPE_2G;
            }
            else if(radio_node->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ)
            {
                radio_type = MAP_IPC_RADIO_TYPE_5G;
            }
            /* IPC Packet - Data - Radio ID */
            _InB(radio_node->radio_id,&p,MAC_ADDR_LEN);
            _I1B(&radio_type,&p);
                    
            /* IPC Packet - Data - bss count */
            _I1B(&radio_node->num_bss, &p);
            
            for (bss_index = 0;bss_index < radio_node->num_bss; bss_index++ , bss_type= 0) 
            {	               
                _InB(radio_node->bss_list[bss_index]->bssid,&p,MAC_ADDR_LEN);

                if( (radio_node->bss_list[bss_index]->type & MAP_BACKHAUL_BSS) && (radio_node->bss_list[bss_index]->type & MAP_FRONTHAUL_BSS)) {
                    bss_type = MAP_IPC_BSS_TYPE_BOTH;
                }
                else if (radio_node->bss_list[bss_index]->type & MAP_FRONTHAUL_BSS) {
                    bss_type = MAP_IPC_BSS_TYPE_FRONTHAUL;
                }
                else if (radio_node->bss_list[bss_index]->type & MAP_BACKHAUL_BSS) {
                    bss_type = MAP_IPC_BSS_TYPE_BACKHAUL;
                }

                _I1B(&bss_type,&p);
            }
        }
    }  

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(agent_data_len + EVENT_TYPE_LENGTH);
    /* This sends STA CONNECT events for same stations for both agent onboard and update and hence not used.
    Instead For stations connected during onboard, client cappability query must be triggered in which case STA connect
    events will be automatically sent. This will be taken care as part of topology hardening - TBD*/
    #if MULTIPLE_STA_CONNECT
    if(sta_count > 0)
        map_mgmt_send_multiple_sta_connect(agent_info,sta_count);
    #endif
}

static int map_mgmt_send_vendor_specific_tlv(struct vendorSpecificTLV *vendor_specific_tlv, uint8_t *src_mac)
{
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    uint16_t data_len = 0;
    uint8_t event = 0;
    uint8_t registered = 0;
    uint16_t message_type = CMDU_TYPE_VENDOR_SPECIFIC;

    if(vendor_specific_tlv)
    {
        /* Validate the vendor data OUID */
        registered = is_vendor_OUI_registered(vendor_specific_tlv->vendorOUI);

        if(!registered)
        return MAP_IPC_ERR_INVALID_PARAM;

        event = MAP_IPC_TAG_NOTIFY_1905_DATA;
        data_len = VENDOR_MSG_DATA_LENGTH + vendor_specific_tlv->m_nr;

        /* Fill the IPC Socket Buffer with the data */

        /* IPC Packet - Event Tag */
        _I1B(&event, &p);

        /* IPC Packet - Event Length */
        _I2B(&data_len, &p);

        /* IPC Packet - Data - Message Type */

        _I2B(&message_type, &p);

        /* IPC Packet - Data - TLV Type*/

        _I1B(&vendor_specific_tlv->tlv_type, &p);

        /* IPC Packet - Data - Agent MAC */

        _InB(src_mac, &p, MAC_ADDR_LEN);

        /* IPC Packet - Data - Length of vendor data */

        _I2B(&vendor_specific_tlv->m_nr, &p);

        /* IPC Packet - Data - Vendor Data */

        _InB(vendor_specific_tlv->m, &p, vendor_specific_tlv->m_nr);

        platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
        map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);
    }

    return MAP_IPC_SUCCESS;

}
static int map_mgmt_send_vendor_specific_data(struct CMDU* cmdu)
{
    struct vendorSpecificTLV *vendor_specific_tlv = NULL;
    uint8_t *tlv = NULL;


    for ( uint8_t i = 0; NULL != (tlv = cmdu->list_of_TLVs[i]) ; i++ )  
    {
        switch (*tlv)
        {
            case TLV_TYPE_VENDOR_SPECIFIC:
            {
                vendor_specific_tlv = (struct vendorSpecificTLV*) tlv;
                map_mgmt_send_vendor_specific_tlv(vendor_specific_tlv,cmdu->cmdu_stream.src_mac_addr);
                break;
            }
            default:
            {
                platform_log(MAP_VENDOR_IPC,LOG_DEBUG,"TODO TLV (%d) type inside CMDU\n", (uint8_t)(*tlv));
                break;
            }
        }
    }

    return MAP_IPC_SUCCESS;
}

static int map_mgmt_send_1905_ack(struct CMDU* cmdu)
{
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    uint16_t data_len = 0;
    uint8_t event = 0;
    uint16_t message_type = CMDU_TYPE_MAP_ACK;
    uint8_t tlv_type = TLV_TYPE_END_OF_MESSAGE;
    uint16_t vendor_msg_len = 0;

    event = MAP_IPC_TAG_NOTIFY_1905_DATA;
    data_len = VENDOR_MSG_DATA_LENGTH ;

    /* Fill the IPC Socket Buffer with the data */

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&data_len, &p);

    /* IPC Packet - Data - Message Type */

    _I2B(&message_type, &p);

    /* IPC Packet - Data - TLV Type*/

    _I1B(&tlv_type, &p);

    /* IPC Packet - Data - Agent MAC */

    _InB(cmdu->cmdu_stream.src_mac_addr, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - Length of vendor data */

    _I2B(&vendor_msg_len, &p);

    /* Ignoring the vendor data for the 1905 ACK */

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);

    return MAP_IPC_SUCCESS;
        
}

static void map_mgmt_send_sta_metrics_data(void)
{
    map_sta_info_t *sta = NULL;
    const char *key     = NULL;
    uint8_t *event_len_mem = NULL;
    uint8_t sta_count = 0;

    uint8_t event = MAP_IPC_TAG_NOTIFY_STA_METRICS;
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;
    uint16_t data_len = 1 ;/*Length initially is 1 byte for sta count alone */
    map_sta_link_metrics_t* link_metrics;
    uint32_t datarate = 0;
    uint8_t rssi = 0;

    if(!is_valid_datamodel())
    {
        platform_log(MAP_VENDOR_IPC,LOG_INFO, " %s Data model NULL \n", __func__);
        return;
    }
    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length - Fill later will actual data */
    event_len_mem = p;
    _I2B(&data_len, &p);

    /* IPC Packet - Station count - fill later with actual data. Memory pointer not
        stored as event length continuation  can be used*/
    _I1B(&sta_count, &p);

    foreach_hash_node(key) {
        filter_sta(key, sta);
        if(sta && sta->traffic_stats && sta->metrics) {

            platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Sta Present \n", __func__);

            /* IPC Packet - STA MAC */
            _InB(sta->mac, &p, MAC_ADDR_LEN);

            link_metrics = first_object(sta->metrics);

            if (link_metrics != NULL) {
                /* IPC Packet - Signal Strength */
                rssi = link_metrics->rssi;
                _I1B(&rssi,&p);

                /* IPC Packet - DL datalink rate */
                datarate = link_metrics->dl_mac_datarate * 1000 ; /* Mbps -> Kbps */
                _I4B(&datarate ,&p);

                /* IPC Packet - UL datalink rate */
                datarate = link_metrics->ul_mac_datarate * 1000 ; /* Mbps -> Kbps */
                _I4B(&datarate ,&p);
            }
            else { /* Send values for metrics as zero */
                /* IPC Packet - Signal Strength */
                rssi = 0;
                _I1B(&rssi ,&p);

                datarate = 0;
                /* IPC Packet - UL datalink rate */
                _I4B(&datarate ,&p);

                /* IPC Packet - UL datalink rate */
                _I4B(&datarate ,&p);
            }

            /* IPC Packet - Bytes Sent */
            _I4B(&sta->traffic_stats->txbytes,&p);

            /* IPC Packet - Bytes Received */
            _I4B(&sta->traffic_stats->rxbytes,&p);

            /* IPC Packet - Packets Sent */
            _I4B(&sta->traffic_stats->txpkts,&p);

            /* IPC Packet - Packets Received */
            _I4B(&sta->traffic_stats->rxpkts,&p);
        
            /* IPC Packet - Tx Packets Error */
            _I4B(&sta->traffic_stats->txpkterrors,&p);

            /* IPC Packet - RetransmissionCount */
            _I4B(&sta->traffic_stats->retransmission_cnt,&p);
            sta_count++;

            platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Sta count - %d Packet Rcvd %d\n", __func__,sta_count, sta->traffic_stats->rxpkts);

        }
    }
        
    if(sta_count)
    {
        /* Update with correct event length now */
        data_len += (sta_count * STA_METRICS_DATA_LENGTH);
        _I2B(&data_len, &event_len_mem);
        /* Update sta count as well */
        _I1B(&sta_count, &event_len_mem);
        /* Send the data  */
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
        map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);
    }

}



/* Send agent onboard data to daemon */
static int map_controller_mgmt_ipc_send_agent_onboard(void *data)
{
    map_ale_info_t* agent_info = NULL;

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s \n", __func__);

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    agent_info = (map_ale_info_t *)data;
    uint8_t event = MAP_IPC_TAG_NOTIFY_ALE_ONBOARD;

    /* Send agent Data , here msg_type will be ignored*/
    map_mgmt_send_agent_data(event,agent_info, 0);

    return MAP_IPC_SUCCESS;
}

/* Send agent offoard data to daemon */
static int map_controller_mgmt_ipc_send_agent_offboard(void *data)
{
    uint16_t agent_data_len = MAC_ADDR_LEN;
    map_ale_info_t* agent_info = NULL;

    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    agent_info = (map_ale_info_t *)data;
    uint8_t event = MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD;

    /* Fill the IPC Socket Buffer with the data */

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&agent_data_len, &p);

    /* IPC Packet - Data - ale_mac */
    _InB(agent_info->al_mac,&p,MAC_ADDR_LEN);

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(agent_data_len + EVENT_TYPE_LENGTH);

    return MAP_IPC_SUCCESS;

}

static int map_controller_mgmt_ipc_send_agent_update(void *data)
{
    map_ipc_agent_data *agent_data = NULL; 
    map_ale_info_t* ale_info = NULL;

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    agent_data = (map_ipc_agent_data *)data;
    ale_info = (map_ale_info_t *)agent_data->ale_info;
   
    uint8_t event = MAP_IPC_TAG_NOTIFY_ALE_UPDATE;

    /* Send agent Data */
    map_mgmt_send_agent_data(event,ale_info,agent_data->msg_type);

    return MAP_IPC_SUCCESS;
}

static int map_controller_mgmt_ipc_send_1905_data(void *data)
{
    /* Input parameter validation */
    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    struct CMDU *cmdu = (struct CMDU*)data;

    uintptr_t msg_id = cmdu->message_id;

    /* Check if the mgmt ipc has already registered for this message type first */
    uint8_t registered = is_messagetype_registered(cmdu->message_type);

    if(!registered)
        return MAP_IPC_ERR_INVALID_PARAM;

    switch(cmdu->message_type)
    {
        case CMDU_TYPE_VENDOR_SPECIFIC:
            /* Send the vendor specific data */
            map_mgmt_send_vendor_specific_data(cmdu);
            break;

        case CMDU_TYPE_MAP_ACK:
            /* Send the 1905 ACK as its identified as ACK for a message sent by daemon
                    But if multiple vendor messages are sent, there is no way to identify which ACK maps
                    to which message - TBD*/
            map_mgmt_send_1905_ack(cmdu);
            /* Once the ack is sent, remove the mid from the list*/
            remove_object(gmap_mgmt_ipc.message_id_list, (void*)msg_id, compare_message_id);
            break;

        default:
            platform_log(MAP_VENDOR_IPC,LOG_INFO, " %s Not a Valid Message type to send \n", __func__);
            break;
    }

    return MAP_IPC_SUCCESS;
}

static int map_controller_mgmt_ipc_send_sta_connect(void *data)
{
    map_sta_info_t *sta = NULL;
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    uint16_t data_len = 0;
    uint8_t sta_count = 1, event = 0;

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    sta = (map_sta_info_t*)data;

    event = MAP_IPC_TAG_NOTIFY_STA_CONNECT;
    data_len = STA_CONNECT_DATA_LENGTH;

    /* Fill the IPC Socket Buffer with the data */

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&data_len, &p);

    /* IPC Packet - Data - Agent MAC */
    _InB(sta->bss->radio->ale->al_mac, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - No of stations */
    _I1B(&sta_count, &p);

    /* IPC Packet - Data - STA MAC */
    _InB(sta->mac, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - BSSID */
    _InB(sta->bss->bssid, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - Supported Std */
    _I1B(&sta->sta_caps.supported_standard, &p);

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);

    return MAP_IPC_SUCCESS;
}

static int map_controller_mgmt_ipc_send_sta_disconnect(void *data)
{
    map_sta_info_t *sta = NULL;
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    uint16_t data_len = 0;
    uint8_t sta_count = 1, event = 0;

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    sta = (map_sta_info_t*)data;

    event = MAP_IPC_TAG_NOTIFY_STA_DISCONNECT;
    data_len = STA_DISCONNECT_DATA_LENGTH;

    /* Fill the IPC Socket Buffer with the data */

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&data_len, &p);

    /* IPC Packet - Data - Agent MAC */
    _InB(sta->bss->radio->ale->al_mac, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - No of stations */
    _I1B(&sta_count, &p);

    /* IPC Packet - Data - STA MAC */
    _InB(sta->mac, &p, MAC_ADDR_LEN);

    /* IPC Packet - Data - BSSID */
    _InB(sta->bss->bssid, &p, MAC_ADDR_LEN);

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);

    return MAP_IPC_SUCCESS;
}

static int map_controller_mgmt_ipc_send_ap_metrics(void *data)
{
    map_ipc_agent_metric *agent_metric_info = NULL;
    uint8_t index = 0;
 
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s \n", __func__);

    uint8_t *p = gmap_mgmt_ipc.sock_buffer;

    if(data == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    agent_metric_info = (map_ipc_agent_metric *)data;
    uint8_t event = MAP_IPC_TAG_NOTIFY_AP_METRICS;
    uint8_t agent_count = agent_metric_info->agent_count;
    uint16_t agent_data_len = (SINGLE_AGENT_METRICS_DATA_LENGTH * agent_count) + 1 /* No of agents */;

    /* Fill the IPC Socket Buffer with the data */

    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&agent_data_len, &p);

    /* IPC Packet - Agent Count*/
    _I1B(&agent_count, &p);

    for(index = 0 ; index < agent_count; index ++)
    {
        /* IPC Packet - Data - ale_mac */
        _InB(agent_metric_info->agent_table[index].agent_mac,&p,MAC_ADDR_LEN);

        /* IPC Packet - Phy Rate */
        _I2B(&agent_metric_info->agent_table[index].phyrate, &p);

        /* IPC Packet - RSSI*/
        _I1B(&agent_metric_info->agent_table[index].rssi, &p);
    }

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Send Data \n", __func__);
    if(agent_count != 0)
    {
        map_mgmt_ipc_socket_send(agent_data_len + EVENT_TYPE_LENGTH);
    }

    return MAP_IPC_SUCCESS;
}
static int map_controller_mgmt_ipc_send_sta_metrics(void *data)
{
    /* No data is needed , so no imput parameters check*/
    map_mgmt_send_sta_metrics_data();
    return MAP_IPC_SUCCESS;
}

static int map_controller_mgmt_ipc_send_mcast_completed(void *data)
{
    uint8_t *p = gmap_mgmt_ipc.sock_buffer;
    uint16_t data_len = 0;
    uint8_t event = MAP_IPC_TAG_NOTIFY_MCAST_STATUS;
    uint8_t status = 1;
    uint8_t no_of_agents_not_rcvd = 0;
    uint8_t index = 0;
    uint16_t received_uuid = 0;

    /* If an MCAST is already in progress, we send the new UUID as parameter, else we send NULL as data.
            For MCAST already in progress the status is Failure with 0 agents*/

    if(data != NULL)
    {
        received_uuid = *((uint16_t *)data);
    }
    else
    {
        no_of_agents_not_rcvd = list_get_size(MCAST_NO_ACK_MSG_LIST);
        if(no_of_agents_not_rcvd == 0)
        {
            status = 2;
        }
        received_uuid = gmap_mgmt_ipc.mcast_msg_info.uuid;
    }

    data_len = MCAST_COMPLETED_LENGTH + (no_of_agents_not_rcvd * MAC_ADDR_LEN);

    /* Fill the IPC Socket Buffer with the data */
    /* IPC Packet - Event Tag */
    _I1B(&event, &p);

    /* IPC Packet - Event Length */
    _I2B(&data_len, &p);

     /* IPC Packet - UUID */
    _I2B(&received_uuid, &p);

    /* IPC Packet - Status */
    _I1B(&status, &p);

    /* IPC Packet - no_of_agents */
    _I1B(&no_of_agents_not_rcvd, &p);

    /* IPC Packet - Data - Agent MAC */
    for(index = 0; index < no_of_agents_not_rcvd ; index++)
    {
        uint8_t* ale_mac = pop_object(MCAST_NO_ACK_MSG_LIST);
        if(ale_mac)
        {
            _InB(ale_mac, &p, MAC_ADDR_LEN);
            free(ale_mac);
        }
    }
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG," %s MCAST Status - %d, No of Agents not rcvd- %d \n",__func__, status, no_of_agents_not_rcvd);

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s MCAST Send Data \n", __func__);
    map_mgmt_ipc_socket_send(data_len + EVENT_TYPE_LENGTH);

    return MAP_IPC_SUCCESS;
}

/** @brief This will setup sockets for vendor daemon IPC.
 *
 *  This will take care of setting up sockets for
 *  communication with vendor daemon
 *  
 *  @param loop the global controller loop context
 *  @param data the output pointer in which the socket descriptor of vendor daemon is updated
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_init_mgmt_ipc(uv_loop_t *loop)
{
    struct sockaddr_un sock_path_addr;
    int16_t interval = atoi(map_controller_env_mgmt_ipc_report_interval);

    gmap_mgmt_ipc.ctrlr_loop = loop;
    /* Initialize the vendor socket fd. This is only updated in accept and hence should not
    contain garbage value that can be used until then */
    gmap_mgmt_ipc.client_fd = -1;
    gmap_mgmt_ipc.server_fd = -1;

    /* Initialize the array list for storing mcast msg info */
    MCAST_MSG_LIST = new_array_list(eListTypeDefault);
    if(NULL == MCAST_MSG_LIST)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Failed to create mcast message id list\n",__func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    /* Initialize the array list for storing no ack mcast msg info */
    MCAST_NO_ACK_MSG_LIST = new_array_list(eListTypeDefault);
    if(NULL == MCAST_NO_ACK_MSG_LIST)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Failed to create no ack mcast message id list\n",__func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    /* Initialize the array list for storing message id */
    gmap_mgmt_ipc.message_id_list = new_array_list(eListTypeDefault);
    if(!gmap_mgmt_ipc.message_id_list)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Failed to message id list\n",__func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    //create a socket
    if ((gmap_mgmt_ipc.server_fd=socket(MAP_IPC_SOCKET_TYPE, SOCK_SEQPACKET, 0)) == -1)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Socket Create Failed \n", __func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Socket Created \n", __func__);

    // zero out the structure
    memset((char *) &sock_path_addr, 0, sizeof(sock_path_addr));

    sock_path_addr.sun_family = MAP_IPC_SOCKET_TYPE;
    memset(sock_path_addr.sun_path,0,MAX_SOCK_PATH);
    strncpy(sock_path_addr.sun_path + 1, MAP_IPC_PATH_NAME, MAX_SOCK_PATH);
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s Client socket path:%s \n", __func__,sock_path_addr.sun_path + 1);

    //bind socket to file
    if( bind(gmap_mgmt_ipc.server_fd , (const struct sockaddr *)&sock_path_addr, ABSTRACT_SUN_LEN(&sock_path_addr)) == -1)
    {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Socket Bind Failed \n", __func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    if (listen(gmap_mgmt_ipc.server_fd, MAX_CLIENTS) < 0) {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Socket Listen Failed \n", __func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    /* Start server socket poll now for new client connections*/
    map_mgmt_ipc_poll(true);

    /* Register the timer call back that will send Metrics data
       Do I want to do it here or after client connects and clean it up after every disconnect ?? - TBD*/
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s IPC Metrics Interval - %d \n", __func__,interval);
    if( map_timer_register_callback(interval, mgmt_ipc_report_timer , NULL , mgmt_ipc_report_timer_callback) < 0) {
        platform_log(MAP_VENDOR_IPC,LOG_ERR, " %s Timer Callback registeration failed\n", __func__);
        return MAP_IPC_ERR_INVALID_PARAM;
    }

    return MAP_IPC_SUCCESS;
}

/** @brief This will send data to daemon via socket IPC.
 *
 *  This will take care of sending required data to the mgmnt daemon via sockets
 *  
 *  @param cmd the type of event to data
 *  @param data the data required to populate and send the data
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_mgmt_ipc_send(map_ipc_tags cmd,void *data)
{
    uint8_t index = get_map_ipc_event_index(cmd);

    if(index == -1 || map_ipc_evnt_table[index].registered == 0 || gmap_mgmt_ipc.client_fd == -1)
        return MAP_IPC_ERR_INVALID_PARAM;

    map_ipc_evnt_table[index].ipc_event_handler(data);

    return MAP_IPC_SUCCESS;
}

/** @brief This will update the message id for which we expect a ACK.
 *
 *  This will update the message id for which we expect a ACK that controller has to send to mgmt IPC
 *  
 *  @param mid the message id for which ACK is expected
 *  @return The status code 0-success, -ve for failure
 */
int map_controller_mgmt_ipc_update_message_id(uint16_t mid)
{
    uintptr_t msg_id = mid;

    if(gmap_mgmt_ipc.client_fd == -1 || gmap_mgmt_ipc.message_id_list == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    push_object(gmap_mgmt_ipc.message_id_list,(void *)msg_id);

    return MAP_IPC_SUCCESS;
}

/** @brief This checks if ACK is expected for the message id
 *
 *  This checks if we expect a ACK for a message id
 *  
 *  @param mid the message id for which ACK is expected
 *  @return 1- true 0-false
 */
uint8_t map_controller_mgmt_ipc_is_pending_ack(uint16_t mid)
{
    uintptr_t msg_id = mid;
    uint8_t ret = 0;

    /* Input validation - If no client socket or if message list is NULL */
    if(gmap_mgmt_ipc.client_fd == -1 || gmap_mgmt_ipc.message_id_list == NULL)
        return ret;

    void * obj = find_object(gmap_mgmt_ipc.message_id_list, (void*)msg_id, compare_message_id);

    /* Using numbers for object. Wondering if message id will ever be 0 */
    if(obj)
    {
        platform_log(MAP_VENDOR_IPC,LOG_DEBUG, " %s YES \n", __func__);
        ret = 1;
    }

    return ret;
}

/** @brief This sends an Agent Update event to VE IPC
 *
 *  
 *  @param msg_type the message type that triggers the update
 *  @param map_ale_info_t * the ALE for which update is to be sent
 *  @return 0 success
 */
int32_t map_controller_send_agent_update(uint16_t msg_type, map_ale_info_t *ale_info)
{
    
#ifdef MAP_MGMT_IPC
    char mac_str[MAX_MAC_STRING_LEN];

    if(ale_info == NULL)
        return MAP_IPC_ERR_INVALID_PARAM;

    map_ipc_agent_data agent_ipc_data;
    agent_ipc_data.msg_type = msg_type;
    agent_ipc_data.ale_info = (void *)ale_info;
    platform_log(MAP_VENDOR_IPC,LOG_DEBUG, "%s ALE - %s, Msg type - %d " , __func__,MAC_AS_STR(ale_info->al_mac, mac_str),msg_type);
    map_controller_mgmt_ipc_send(MAP_IPC_TAG_NOTIFY_ALE_UPDATE,(void *)&agent_ipc_data);
#endif
    return MAP_IPC_SUCCESS;
}

