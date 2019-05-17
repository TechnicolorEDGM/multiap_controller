/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <lua.h>                                /* Always include this when calling Lua */
#include <lauxlib.h>                            /* Always include this when calling Lua */
#include <lualib.h>                             /* Prototype for luaL_openlibs(), */
                                                /*   always include this when calling Lua */

#include <stdlib.h>                             /* For function exit() */
#include <stdio.h>                              /* For input/output */
#include <libubus.h>
#include <sys/un.h>
//#include <platform_ubus.h>
#include "map_ipc_lib.h"
#include <uv.h>

#define MAX_SOCK_PATH 32
#define MAX_MODE_LEN 4
#define SOCK_PATH "map_mgmt_ipc"
#define MAC_ADDR_LEN 6
// Version of SUN_LEN() for paths in abstract namespace.
// Only take the used part of the 'sun_path' field into account.
// Otherwise the trailing \0 bytes will also be part of the address,
// which gives funny output in /proc/net/unix.
// Assumes there's a 'path_len' variable containing the strlen of the path.
// The + 1 is for the leading \0.
#define ABSTRACT_SUN_LEN(ptr) ((socklen_t) offsetof(struct sockaddr_un,sun_path) \
                               + 1 + strlen(SOCK_PATH))


int sockfd = 0;
uv_loop_t *loop;

typedef unsigned char INT8U;
typedef unsigned short int INT16U;
typedef unsigned int INT32U;

#define REBOOT 1

#if 0
char *vendor_data = "Testing Vendor Specific";
#else
#if REBOOT
unsigned char vendor_data[1024] = "";
#else
char *vendor_data = "{\"proto\":\"2\",\"write\":\"1\",\"user\":\"\",\"id\":\"16C6A287\",\"chsum\":\"7316a61036380167bbb5ba1f1f8c2158\",\"woffset\":\"60\",\"pwd\":\"\",\"url\":\"http:\/\/192.168.1.1\/fwimg\/WE410443B-TA_2.02.50_01_aldk_uImage_web\",\"FwInfo\":{\"md\":\"WE410443B-TA\",\"subver\":\"01\",\"hwver\":\"WE410443B-TA-01\",\"mver\":\"2.02.48\"},\"dwindows\":\"300\"}";
#endif
#endif

unsigned char buffer[2048] = {0};

void msg_parse(unsigned char *buf);

static inline void _E1B(INT8U **packet_ppointer, INT8U *memory_pointer)
{
    *memory_pointer     = **packet_ppointer;
    (*packet_ppointer) += 1;
}
static inline void _I1B(INT8U *memory_pointer, INT8U **packet_ppointer)
{
    **packet_ppointer   = *memory_pointer;
    (*packet_ppointer) += 1;
}

// Extract/insert 2 bytes
//
static inline void _E2B(INT8U **packet_ppointer, INT16U *memory_pointer)
{
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
}
static inline void _I2B(INT16U *memory_pointer, INT8U **packet_ppointer)
{
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
}

// Extract/insert 4 bytes
//
static inline void _E4B(INT8U **packet_ppointer, INT32U *memory_pointer)
{
    *(((INT8U *)memory_pointer)+3)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+2)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+1)  = **packet_ppointer; (*packet_ppointer)++;
    *(((INT8U *)memory_pointer)+0)  = **packet_ppointer; (*packet_ppointer)++;
}
static inline void _I4B(INT32U *memory_pointer, INT8U **packet_ppointer)
{
    **packet_ppointer = *(((INT8U *)memory_pointer)+3); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((INT8U *)memory_pointer)+0); (*packet_ppointer)++;
}

// Extract/insert N bytes (ignore endianess)
//
static inline void _EnB(INT8U **packet_ppointer, void *memory_pointer, INT32U n)
{
    memcpy(memory_pointer, *packet_ppointer, n);
    (*packet_ppointer) += n;
}
static inline void _InB(void *memory_pointer, INT8U **packet_ppointer, INT32U n)
{
    memcpy(*packet_ppointer, memory_pointer, n);
    (*packet_ppointer) += n;
}


map_ipc_event_table map_ipc_evnt_table[] = {
	{MAP_IPC_TAG_NOTIFY_ALE_ONBOARD, 0xFFFFFFFF}, /* event data is nil */
	{MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD, 0xFFFFFFFF}, /* event data is nil */
	{MAP_IPC_TAG_NOTIFY_ALE_UPDATE, 0xFFFFFFFF}, /* event data is nil */
	{MAP_IPC_TAG_NOTIFY_STA_CONNECT, 0xFFFFFFFF}, /* event data is nil */
	{MAP_IPC_TAG_NOTIFY_STA_DISCONNECT, 0xFFFFFFFF}, /* event data is nil */
	{MAP_IPC_TAG_NOTIFY_1905_DATA, ((0x4 << 24) | (0x24F128))}, /* event data is string that consist of "TLV type" & "TLV Data".
										For eg, to register Vendor Ext TLV, callee has to pass "0x0004", "oui_id" */
	{MAP_IPC_TAG_WRITE_1905_VE, 0xFFFFFFFF},/* event data is nil */
	{MAP_IPC_TAG_NOTIFY_STA_METRICS, 0xFFFFFFFF},/* event data is nil */
	{MAP_IPC_TAG_NOTIFY_AP_METRICS, 0xFFFFFFFF},/* event data is nil */
	{MAP_IPC_TAG_NOTIFY_MCAST_STATUS, 0xFFFFFFFF},/* event data is nil */
};

int get_mac_from_string(char * value, uint8_t *mac)
{
	if(MAC_ADDR_LEN== sscanf(value, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
		return 1;
	return 0;
}

void print_mac(uint8_t *mac_addr)
{
	printf("MAC %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx \n",
										mac_addr[0], mac_addr[1],
										mac_addr[2], mac_addr[3],
		                                mac_addr[4], mac_addr[5]);
}

void parse_agent_offboard(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char mac[6];
	unsigned char *p = buff;

	/* Parse the Event Length */
	_E2B(&p, &event_len);
	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);

	return;
}
void parse_agent_onboard(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char mac[6];
	unsigned char sta_count = 0;
	unsigned char radio_count = 0;
	unsigned char bss_count = 0;
	int i = 0, j=0;
	unsigned char *p = buff;
	unsigned char type;
	unsigned short int if_type = 0xFFFF;

	unsigned char manu_len = 0;
	unsigned char manu[65] = {0};

	/* Parse the Event Length */
	_E2B(&p, &event_len);
	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);

	_EnB(&p, mac, 6);
	printf("Interface Mac ");
	print_mac(mac);

	_E2B(&p, &if_type);
	printf("Interface Type - %d \n", if_type);

	_E1B(&p, &manu_len);
	printf("Manu Len - %d \n", manu_len);

	_EnB(&p, manu, manu_len);

	printf("Manufacturer string %s \n", manu);

	_EnB(&p, mac, 6);
	printf("Parent ");
	print_mac(mac);


	_E1B(&p,&sta_count);
	printf("STA Count - %d \n", sta_count);
	_E1B(&p,&radio_count);
	printf("Radio Count - %d \n", radio_count);


	for(i = 0; i< radio_count; i++)
	{

		printf("Radio %d ", i);
		_EnB(&p, mac, 6);
		_E1B(&p, &type);
		printf( "type %d ",type);


		print_mac(mac);
		_E1B(&p,&bss_count);
		printf("BSS Count - %d \n", bss_count);
		for(j = 0; j< bss_count; j++)
		{
			_EnB(&p, mac, 6);
			printf("BSS %d ", j);
			print_mac(mac);
		}
	}

	sleep(10);
	send_vendor_specific();
	//send_unicast_vendor_specific();
	//send_vendor_specific();

	return;
}

void parse_agent_update(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char mac[6];
	unsigned char sta_count = 0;
	unsigned char radio_count = 0;
	unsigned char bss_count = 0;
	int i = 0, j=0;
	unsigned char *p = buff;
	unsigned char type;
	unsigned short int if_type = 0xFFFF;

	unsigned char manu_len = 0;
	unsigned char manu[65] = {0};

	/* Parse the Event Length */
	_E2B(&p, &event_len);
	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);

	_EnB(&p, mac, 6);
	printf("Interface Mac ");
	print_mac(mac);

	_E2B(&p, &if_type);
	printf("Interface Type - %d \n", if_type);

	_E1B(&p, &manu_len);
	printf("Manu Len - %d \n", manu_len);

	_EnB(&p, manu, manu_len);

	printf("Manufacturer string %s \n", manu);

	_EnB(&p, mac, 6);
	printf("Parent ");
	print_mac(mac);


	_E1B(&p,&sta_count);
	printf("STA Count - %d \n", sta_count);
	_E1B(&p,&radio_count);
	printf("Radio Count - %d \n", radio_count);


	for(i = 0; i< radio_count; i++)
	{

		printf("Radio %d ", i);
		_EnB(&p, mac, 6);
		_E1B(&p, &type);
		printf( "type %d ",type);


		print_mac(mac);
		_E1B(&p,&bss_count);
		printf("BSS Count - %d \n", bss_count);
		for(j = 0; j< bss_count; j++)
		{
			_EnB(&p, mac, 6);
			printf("BSS %d ", j);
			print_mac(mac);
		}
	}

	return;
}

void parse_1905_data(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned short int msg_type = 0;
	unsigned char type = 0;
		unsigned char mac[6];
		unsigned char * vendor_str;
		unsigned char *p = buff;
	unsigned short int vendor_type = 0;
	unsigned int vendor_length = 0;


	printf("PARSING VENDOR \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);

	_E2B(&p, &msg_type);
	printf("MSG Type - %d \n", msg_type);

	_E1B(&p, &type);
	printf("TLV Type - %d \n", type);

	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);


	if(msg_type == 0x4)
	{
	_E2B(&p, &event_len);
	printf("Data Len - %d \n", event_len);

	vendor_str = (unsigned char *) malloc(event_len);
	_EnB(&p, vendor_str , event_len);

#if 1
		_E2B(&vendor_str, &vendor_type);
		_E4B(&vendor_str, &vendor_length);
#else

#endif

		printf(" VENDOR STR TYPE %d LEN %d \n" , vendor_type,vendor_length);
	}
	return;
}

void parse_sta_connect(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char sta_no = 0;
	unsigned char mac[6];
	unsigned char *p = buff;
	unsigned char std = 0xF;
	int i = 0;

	printf("PARSING STA CONNECT \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);

	printf("Data Len - %d \n", event_len );


	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);


	_E1B(&p, &sta_no);
	printf("No of stations - %d \n",sta_no);


	for(i =0 ; i< sta_no; i++)
	{
		printf("Station %d Details : \n", i+1);
		_EnB(&p, mac, 6);
		printf("STA MAC ");
		print_mac(mac);
		_EnB(&p, mac, 6);
		printf("BSSID ");
		print_mac(mac);
		_E1B(&p, &std);
		printf("STD %d \n", std);

	}
	return;
}

void parse_sta_disconnect(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char sta_no = 0;
	unsigned char mac[6];
	unsigned char *p = buff;
	unsigned char std = 0xF;
	int i = 0;


	printf("PARSING STA DISCONNECT \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);
	printf("Data Len - %d \n", event_len);

	_EnB(&p, mac, 6);
	printf("Agent ");
	print_mac(mac);

	_E1B(&p, &sta_no);
	printf("No of stations - %d \n",sta_no);

	for(i =0 ; i< sta_no; i++)
	{
		printf("Station %d Details : \n", i+1);
		_EnB(&p, mac, 6);
		printf("STA MAC ");
		print_mac(mac);
		_EnB(&p, mac, 6);
		printf("BSSID ");
		print_mac(mac);
	}
	return;
}

void parse_sta_metrics(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char sta_no = 0;
	unsigned char mac[6];
	unsigned char *p = buff;
	unsigned int info = 0;
	char rssi = 0;
	int i = 0;


	printf("PARSING STA METRICS \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);
	printf("Data Len - %d \n", event_len);

	_E1B(&p, &sta_no);
	printf("No of stations - %d \n",sta_no);

	for(i =0 ; i< sta_no; i++)
	{
		printf("Station %d Details : \n", i+1);
		_EnB(&p, mac, 6);
		printf("STA MAC ");
		print_mac(mac);

		_E1B(&p,&rssi);
		printf("Signal Strength - %d\n", rssi);
		_E4B(&p,&info);
		printf("UL Datarate - %d\n", info);
		_E4B(&p,&info);
		printf("DL Datarate - %d\n", info);
		_E4B(&p,&info);
		printf("RX Bytes - %d\n", info);
		_E4B(&p,&info);
		printf("TX Bytes - %d\n", info);
		_E4B(&p,&info);
		printf("TX Packets - %d\n", info);
		_E4B(&p,&info);
		printf("TX Packet errors - %d\n", info);
		_E4B(&p,&info);
		printf("Retransmission count - %d\n", info);
	}
	return;
}


void parse_ap_metrics(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char agent_no = 0;
	unsigned char mac[6];
	unsigned char *p = buff;
	unsigned int phyrate = 0;
	char rssi = 0;
	int i = 0;


	printf("PARSING AP METRICS \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);
	printf("Data Len - %d \n", event_len);

	_E1B(&p, &agent_no);
	printf("No of stations - %d \n",agent_no);

	for(i =0 ; i< agent_no; i++)
	{
		printf("Agent %d Details : \n", i+1);
		_EnB(&p, mac, 6);
		printf("Agent MAC ");
		print_mac(mac);

		_E2B(&p,&phyrate);
		printf("PHYRATE - %d\n", phyrate);

		_E1B(&p,&rssi);
		printf("Signal Strength - %d\n", rssi);
	}
	return;
}

void parse_mcast_completed(unsigned char *buff)
{
	unsigned short int event_len = 0;
	unsigned char agent_no = 0;
	unsigned char status = 0;

	unsigned char mac[6];
	unsigned char *p = buff;
	unsigned short int uuid = 0;
	int i;


	printf("PARSING MCAST \n");
	/* Parse the Event Length */
	_E2B(&p, &event_len);
	printf("Data Len - %d \n", event_len);

	_E2B(&p, &uuid);
	printf("UUID - %d \n", uuid);

	_E1B(&p, &status);
	printf("Status of MCAST - %d \n",status);

	_E1B(&p, &agent_no);
	printf("No of agents - %d \n",agent_no);

	for(i =0 ; i< agent_no; i++)
	{
		printf("Agent %d Details : \n", i+1);
		_EnB(&p, mac, 6);
		printf("Agent MAC ");
		print_mac(mac);
	}
	return;
}
void msg_parse(unsigned char *buff)
{
#if 0
   	printf("%s\n",buffer );
#else
	unsigned char event_tag = 0;
	unsigned char *p = buff;

	/* First parse the event tag */
	_E1B(&p, &event_tag);

	printf(" Event Received - %d \n", event_tag);

	switch(event_tag)
	{
		case MAP_IPC_TAG_NOTIFY_ALE_ONBOARD:
			parse_agent_onboard(p);
			break;

		case MAP_IPC_TAG_NOTIFY_ALE_OFFBOARD:
			parse_agent_offboard(p);
			break;

		case MAP_IPC_TAG_NOTIFY_ALE_UPDATE:
			parse_agent_update(p);
			break;

		case MAP_IPC_TAG_NOTIFY_1905_DATA:
			parse_1905_data(p);
			break;

		case MAP_IPC_TAG_NOTIFY_STA_CONNECT:
			parse_sta_connect(p);
			break;

		case MAP_IPC_TAG_NOTIFY_STA_DISCONNECT:
			parse_sta_disconnect(p);
			break;

		case MAP_IPC_TAG_NOTIFY_STA_METRICS:
			parse_sta_metrics(p);
			break;

		case MAP_IPC_TAG_NOTIFY_AP_METRICS:
			parse_ap_metrics(p);
			break;

		case MAP_IPC_TAG_NOTIFY_MCAST_STATUS:
			parse_mcast_completed(p);
			break;

		default:
			break;
	}

#endif
    return;
}

void send_event_register()
{
	int i;
	int *p = (char *)buffer;
	int len = (10 * sizeof(map_ipc_event_table));
	map_ipc_event_reg *event = (map_ipc_event_reg *)malloc(sizeof(map_ipc_event_reg) + len);
	map_ipc_packet ipc_pkt = {0};
	event->event_count = 10;
	memcpy(event->event_table, map_ipc_evnt_table,len);
	ipc_pkt.tag = MAP_IPC_TAG_EVNT_REG;
	printf("SIZE of STRUCT - %d \n",sizeof(map_ipc_event_table));
	ipc_pkt.len = sizeof(map_ipc_event_reg) + (event->event_count * sizeof(map_ipc_event_table));
	printf("SIZE of IPC - %d \n",ipc_pkt.len);
	_I1B(&ipc_pkt.tag,&p);
	printf("Frst level \n");
	_I2B(&ipc_pkt.len,&p);
	_I1B(&event->event_count,&p);
	for(i=0; i< event->event_count; i++)
	{
		_I1B(&event->event_table[i].event_type,&p);
		_I4B(&event->event_table[i].event_data,&p);
	}

	printf("Send Data\n");
	send(sockfd , buffer , 2048 , 0 );
	free(event);

}
void send_vendor_specific()
{
	char *mac1 = "A6:91:B1:53:2C:3F";
	char *mac2 = "44:fe:3b:56:bd:ea";
	char *mcastmac = "01:80:c2:00:00:13";
	int len = 0, i;
	map_ipc_write_1905_ve vendor_buff = {0};
	map_ipc_packet ipc_pkt = {0};
	int *p = (char *)buffer;
	unsigned char num_agents = 1;
	unsigned short int code = 3;
	unsigned int total_len = 0;
	unsigned short int uuid = 99;


	memset(p,0,2048);

	vendor_buff.oui_id[0] = 0x24;
	vendor_buff.oui_id[1] = 0xF1;
	vendor_buff.oui_id[2] = 0x28;

	#if 0
	for(i=0; i< 1023; i++)
		vendor_data[i] = 'a';

	vendor_data[1023] = '\0';

	vendor_buff.len = 1024;
	#else
	//vendor_buff.len = strlen(vendor_data);
	#if REBOOT
	vendor_buff.len = 6;
	vendor_data[1] = 7 /*reboot */;
	vendor_data[2] = 0;
	#else
	vendor_buff.len = strlen(vendor_data);
	total_len = vendor_buff.len+ 6;
	#endif
	#endif
	//vendor_buff.data = malloc(vendor_buff.len+1);
	//vendor_buff.data = vendor_data;
	printf("SEND VENDOR DATA of len %d - %s \n",vendor_buff.len,vendor_data );

	ipc_pkt.tag = MAP_IPC_TAG_WRITE_1905_VE;
	ipc_pkt.len = (sizeof(vendor_buff) + vendor_buff.len+1) * 1;
	printf(" SIZE OF VENDOR IPC SENT%d \n", ipc_pkt.len);
	_I1B(&ipc_pkt.tag,&p);
	printf("Frst level \n");
	_I2B(&ipc_pkt.len,&p);
	_I2B(&uuid,&p);
	_InB(vendor_buff.oui_id, &p, 3);
	_I1B(&num_agents,&p);
	#if REBOOT
	#if 0
	get_mac_from_string(mac1,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#endif
	get_mac_from_string(mcastmac,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#else

	get_mac_from_string(mac2,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&total_len, &p);
	_I2B(&code, &p);
	_I4B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#endif
	send(sockfd , buffer , 2048 , 0 );

	printf("Sent Vendor \n");
}

void send_unicast_vendor_specific()
{
	char *mac1 = "a6:91:b1:67:f3:69";
	char *mac2 = "44:fe:3b:56:bd:ea";
	char *mcastmac = "01:80:c2:00:00:13";
	int len = 0, i;
	map_ipc_write_1905_ve vendor_buff = {0};
	map_ipc_packet ipc_pkt = {0};
	int *p = (char *)buffer;
	unsigned char num_agents = 2;
	unsigned short int code = 3;
	unsigned int total_len = 0;
	unsigned short int uuid = 100;


	memset(p,0,2048);

	vendor_buff.oui_id[0] = 0x24;
	vendor_buff.oui_id[1] = 0xF1;
	vendor_buff.oui_id[2] = 0x28;

	#if 0
	for(i=0; i< 1023; i++)
		vendor_data[i] = 'a';

	vendor_data[1023] = '\0';

	vendor_buff.len = 1024;
	#else
	//vendor_buff.len = strlen(vendor_data);
	#if REBOOT
	vendor_buff.len = 6;
	vendor_data[1] = 7 /*reboot */;
	vendor_data[2] = 0;
	#else
	vendor_buff.len = strlen(vendor_data);
	total_len = vendor_buff.len+ 6;
	#endif
	#endif
	//vendor_buff.data = malloc(vendor_buff.len+1);
	//vendor_buff.data = vendor_data;
	printf("SEND VENDOR DATA of len %d - %s \n",vendor_buff.len,vendor_data );

	ipc_pkt.tag = MAP_IPC_TAG_WRITE_1905_VE;
	ipc_pkt.len = (sizeof(vendor_buff) + vendor_buff.len+1) * 2;
	printf(" SIZE OF VENDOR IPC SENT%d \n", ipc_pkt.len);
	_I1B(&ipc_pkt.tag,&p);
	printf("Frst level \n");
	_I2B(&ipc_pkt.len,&p);
	_I2B(&uuid,&p);
	_InB(vendor_buff.oui_id, &p, 3);
	_I1B(&num_agents,&p);
	#if REBOOT
	#if 1
	get_mac_from_string(mac1,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	get_mac_from_string(mac2,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#else
	get_mac_from_string(mcastmac,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#endif
	#else

	get_mac_from_string(mac2,vendor_buff.ale_mac);
	print_mac(vendor_buff.ale_mac);
	_InB(vendor_buff.ale_mac, &p, 6);
	_I2B(&total_len, &p);
	_I2B(&code, &p);
	_I4B(&vendor_buff.len, &p);
	_InB(vendor_data, &p, vendor_buff.len);
	#endif
	send(sockfd , buffer , 2048 , 0 );

	printf("Sent Vendor \n");
}
void uvpoll_read_cb (uv_poll_t* handle, int status, int events)
{
    if((status < 0) || (events & UV_DISCONNECT))
    {
        printf("DISCONNECT \n");
        uv_poll_stop(handle);
    }
    else if (events & UV_READABLE) {
		int valread;
        printf("READ DATA \n");
        valread = read( sockfd , buffer, 1024);
		msg_parse(buffer);
//    	send_vendor_specific();
    	#if 0
    	uv_poll_stop(handle);
		uv_loop_close(loop);
		free(loop);
		exit(EXIT_SUCCESS);
		#endif
    }
    return;
}

int main(void)
{
    struct sockaddr_un test;
    uv_poll_t uvpoll_handle;
     char *hello = "Hello from client";
    loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    int err ;

    printf("UV LOOP INIT \n");

	//create a socket
	if ((sockfd=socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1)
	{
		 exit(EXIT_FAILURE);
	}

	printf("SOCKET CREATED\n");
	// zero out the structure
	memset((char *) &test, 0, sizeof(test));

	test.sun_family = AF_UNIX;
	memset(test.sun_path,0,MAX_SOCK_PATH);
	strncpy(test.sun_path + 1, SOCK_PATH, MAX_SOCK_PATH);
	printf("Client socket path:%s",test.sun_path + 1);


    printf("Client Socket Path:%s",test.sun_path);


 	//if (connect(sockfd, (struct sockaddr_un *)&test, sizeof(test)) < 0)
 	do
 	{
		err = connect(sockfd, (struct sockaddr_un *)&test, ABSTRACT_SUN_LEN(&test));
	}while((err < 0) && (errno == 111));

	#if 0
	if (err < 0)
	{
		printf("EXIT CONNECT %d\n",err);
		printf("socket() failed with errno=%d (%s)\n", errno, strerror(errno));
	    exit(EXIT_FAILURE);
    }
	#endif
	printf("SOCKET CONNECT \n");

	//sleep(5);

	#if 0
	send(sockfd , hello , strlen(hello) , 0 );
	#else
	send_event_register();

	//sleep(10);

	//send_vendor_specific();

	#endif
	uv_poll_init(loop, &uvpoll_handle, sockfd);
	uv_poll_start(&uvpoll_handle, (UV_READABLE|UV_DISCONNECT), uvpoll_read_cb);


    uv_run(loop, UV_RUN_DEFAULT);


	printf("LOOP CLOSING\n");

	uv_loop_close(loop);
	free(loop);


   printf("RETURN");
    return 0;
}
