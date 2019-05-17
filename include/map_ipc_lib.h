/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef _MAP_IPC_LIB_H_
#define _MAP_IPC_LIB_H_

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include "map_common_defines.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

#define MAP_IPC_SOCKET_TYPE			AF_UNIX
#define MAP_IPC_USE_ABSTRACT_PATH	1			/* an abstract socket address is distinguished (from a
												pathname socket) by the fact that sun_path[0] is a null byte
											  ('\0').  The socket's address in this namespace is given by the
											  additional bytes in sun_path that are covered by the specified
											  length of the address structure.  (Null bytes in the name have no
											  special significance.)  The name has no connection with filesystem
											  pathnames.  When the address of an abstract socket is returned,
											  the returned addrlen is greater than sizeof(sa_family_t) (i.e.,
											  greater than 2), and the name of the socket is contained in the
											  first (addrlen - sizeof(sa_family_t)) bytes of sun_path.*/
											  
#define MAP_IPC_PATH_NAME			"map_mgmt_ipc"
// Version of SUN_LEN() for paths in abstract namespace.
// Only take the used part of the 'sun_path' field into account.
// Otherwise the trailing \0 bytes will also be part of the address,
// which gives funny output in /proc/net/unix.
// Assumes there's a 'path_len' variable containing the strlen of the path.
// The + 1 is for the leading \0.
#define ABSTRACT_SUN_LEN(ptr) ((socklen_t) offsetof(struct sockaddr_un,sun_path) \
                               + 1 + strlen(MAP_IPC_PATH_NAME))


/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/

typedef char map_ipc_mac[MAC_ADDR_LEN];

typedef enum
{
    MAP_IPC_RADIO_TYPE_2G = 0x01,
    MAP_IPC_RADIO_TYPE_5G,
    MAP_IPC_RADIO_TYPE_MAX
}map_ipc_radio_type;

typedef enum
{
    MAP_IPC_BSS_TYPE_FRONTHAUL = 0x01,
    MAP_IPC_BSS_TYPE_BACKHAUL,
    MAP_IPC_BSS_TYPE_BOTH
}map_ipc_bss_type;

typedef enum
{
    MAP_IPC_TAG_FIRST                 ,           // Dummy not really used
    MAP_IPC_TAG_EVNT_REG	      ,			//< refer map_ipc_event_reg
    MAP_IPC_TAG_NOTIFY_ALE_ONBOARD    ,			//< refer map_ipc_agent_onboard
    MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD   ,			//< refer map_ipc_agent_offboard
    MAP_IPC_TAG_NOTIFY_ALE_UPDATE     ,			//< TBD
    MAP_IPC_TAG_NOTIFY_STA_CONNECT    ,			//< refer map_ipc_sta_connect
    MAP_IPC_TAG_NOTIFY_STA_DISCONNECT ,				//< TBD
    MAP_IPC_TAG_NOTIFY_1905_DATA      ,				//< TBD
    MAP_IPC_TAG_NOTIFY_STA_METRICS    ,			//< TBD
    MAP_IPC_TAG_NOTIFY_AP_METRICS     ,				//< TBD
    MAP_IPC_TAG_WRITE_1905_VE	      ,				//< map_ipc_write_1905_ve
    MAP_IPC_TAG_NOTIFY_MCAST_STATUS            ,           //TBD
    MAP_IPC_TAG_LAST 		      ,
}map_ipc_tags;


/// IPC packet format:
///		* the complete packet is in contiguous memory (including map_ipc_packet.data 
///	
///	
typedef struct 
{
    uint8_t	tag;
    uint16_t	len;
    void	*data;
}map_ipc_packet;

/* Vendor ext to Controller communcation */


typedef struct
{
    uint8_t			event_type;			/// <Event type, must be part of the map_ipc_tags. Particualrly MAP_IPC_TAG_NOTIFY_xxxx_yyyy
    uint32_t		event_data;			/// <event data is optional parameter for a given event type.
											///		incase of optional - callee has to still fill 0xffffffff
											///		it is must to provide data for MAP_IPC_TAG_NOTIFY_1905_DATA. The expected data format for MAP_IPC_TAG_NOTIFY_1905_DATA
											///		a) first byte is message Type (This is does not allow one to register for MAP messages (0x8000) unless we use some formula
											///		b) 2nd to 4th byte is TLV value. 
											///		 e.g to register for 1905 vendor extensio for a ouid 24F128 then event_data = (0x4 << 24) | (0x24F128 < 8)

}map_ipc_event_table;

typedef struct
{
    uint8_t		event_count;			/// <number of interested events
    map_ipc_event_table event_table[0];    /// Event table 

}map_ipc_event_reg;

typedef struct 
{
    uint16_t	uuid;	                //unique ID sent from VE daemon
    uint8_t 	oui_id[3];
    map_ipc_mac	ale_mac;					///< incase if this message has to be transmitted to each ALE, from bottom to up (ie DFS) then 
											///		callee has to pass the 0xff for all octect of the ale_mac. 
    uint16_t	len;						///< length of the data
    uint8_t	*data;						///< data

}map_ipc_write_1905_ve;

/* Controller to Vendor ext communcation */
typedef struct
{
    uint8_t            bssid[MAC_ADDR_LEN];
    uint8_t            type; /* FH,BH or BOTH*/
}map_ipc_bss_table;

typedef struct
{
    uint8_t            radio_type; /// Refer map_ipc_radio_type
    uint8_t            radioid[MAC_ADDR_LEN];
    uint8_t            bss_count;
    map_ipc_bss_table  bss_table[0];
}map_ipc_radio_table;



typedef struct
{
    map_ipc_mac		ale_mac;
    map_ipc_mac		interface_mac;
    uint16_t            interface_type; /*Based on refer table 6-12 of 1905.1 specification */
    uint8_t		manufacturer_name[MAX_MANUFACTURER_NAME_LEN];
    map_ipc_mac		parent;
    uint8_t		sta_count;
    uint8_t		radio_count;
    map_ipc_radio_table radio_table[0];
}map_ipc_agent_onboard;

typedef struct
{
    map_ipc_mac		ale_mac;
}map_ipc_agent_offboard;

typedef struct
{
    map_ipc_mac sta_mac;
    map_ipc_mac	bssid;
    uint8_t	oper_std;					//< refer STD_80211_xxx of map_common_defines.h

}map_ipc_sta_table;

typedef struct
{
    map_ipc_mac		ale_mac;
    uint8_t		sta_count;
    map_ipc_sta_table	sta_table[0];
}map_ipc_sta_connect;

typedef struct
{
    map_ipc_mac		ale_mac;
    uint8_t		sta_count;
    map_ipc_sta_table	sta_table[0]; /*oper_std is not needed for disconnect */
}map_ipc_sta_disconnect;

typedef struct
{
    map_ipc_mac agent_mac;
    uint16_t	phyrate;
    uint8_t	rssi;
}map_ipc_agent_metric_table;

typedef struct
{
    uint8_t		agent_count;
    map_ipc_agent_metric_table	agent_table[1]; /* Minimum one agent, for rest do an malloc if needed*/
}map_ipc_agent_metric;


typedef struct
{
    map_ipc_mac al_mac;
}map_ipc_mcast_table;

typedef struct
{
    uint16_t    uuid;
    uint8_t     status;
    uint8_t		agent_count;
    map_ipc_mcast_table	mcast_ale_table[0];
}map_ipc_mcast_complete;


typedef enum map_ipc_return_value_s
{
    MAP_IPC_SUCCESS = 0,
    MAP_IPC_ERR_INVALID_PARAM = -0X600,
    MAP_IPC_ERR_INVALID_HANDLE,	
}map_ipc_ret_val;

#endif
