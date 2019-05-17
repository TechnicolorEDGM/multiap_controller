/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_controller.h"
#include "multiap_controller_callbacks.h"
#include "multiap_controller_utils.h"
#include "multiap_controller_onboarding_handler.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "multiap_controller_cli_event_handler.h"
#include "multiap_controller_ext_roaming_engine.h"
#include "multiap_controller_mgmt_ipc.h"
#include "multiap_controller_topology_tree_builder.h"



#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(OPENWRT) && defined(__GLIBC__)
#include <malloc.h>
#endif
#include "monitor_task.h"

#define MGMT_CMDLINE_UBUS "ubus"
#define MGMT_CMDLINE_SOCK "sock"

uv_loop_t *loop;
#ifdef OPENWRT
static uv_signal_t uv_sigint;
static uv_signal_t uv_sigterm;
#ifdef __GLIBC__
static uv_signal_t uv_sigusr1;
#endif /* __GLIBC__ */
#endif /* OPENWRT */

unsigned int grun_daemon=0;

static int parse_controller_options(int argc, char *argv[]);
static void print_usage();
static inline void Err_Argument();

plfrm_config pltfrm_config;
handle_1905_t handle_1905;

// TODO: Move this API and the platform config API to Controller utils
map_cfg* get_controller_config() {
    return &pltfrm_config.map_config;
}

#ifdef EXT_ROAMING_ENGINE
map_controller_ext_roaming_engine_cbs_t g_map_controller_ext_roaming_engine_cbs;
#endif /* EXT_ROAMING_ENGINE */

#ifdef OPENWRT
static void uv_sigint_term_handler(uv_signal_t *handle, int signum)
{
    uv_stop(loop);
}

#ifdef __GLIBC__
/* Register SIGUSR1 to dump malloc info */
static void uv_sigusr1_handler(uv_signal_t *handle, int signum)
{
    FILE *fp;
    char  fname[128];

    extern const char *__progname;

    snprintf(fname, sizeof(fname), "/tmp/%s.malloc_info", __progname);

    fp = fopen(fname, "w");
    if (fp) {
        malloc_info(0, fp);
        fclose(fp);
    }
}
#endif /* __GLIBC__ */
#endif /* OPENWRT */

// TODO:: Do not call the exit from here. Let the daemon handle it 
int map_controller_init(int argc, char *argv[])
{
    parse_controller_options(argc,argv);
    do
    {
        if(platform_init(&pltfrm_config)) {
            Err_Argument();
        }

    #ifndef OPENWRT
        init_signal_handling();
    #endif

        loop = malloc(sizeof(uv_loop_t));
        uv_loop_init(loop);

    #ifdef OPENWRT
        uv_signal_init(loop, &uv_sigint);
        uv_signal_start(&uv_sigint, uv_sigint_term_handler, SIGINT);
        uv_signal_init(loop, &uv_sigterm);
        uv_signal_start(&uv_sigterm, uv_sigint_term_handler, SIGTERM);
    #ifdef __GLIBC__
        /* Register SIGUSR1 to dump malloc info */
        uv_signal_init(loop, &uv_sigusr1);
        uv_signal_start(&uv_sigusr1, uv_sigusr1_handler, SIGUSR1);
    #endif /* __GLIBC__ */
    #endif /* OPENWRT */


        if(init_map_datamodel() == -1) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " Failed to initialize the controller data model.\n");
            exit(EXIT_FAILURE);
        }
        if(init_controller_topology_tree() == -1)
        {
            platform_log(MAP_CONTROLLER,LOG_ERR, " init_controller_topology_tree  failed.\n");
            exit(EXIT_FAILURE);
        }
        if (map_init_timer_handler(loop , TIMER_FREQUENCY_ONE_SEC) != 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " map_init_timer_handler Failed.\n");
            exit(EXIT_FAILURE);
        }

#ifdef MAP_MGMT_IPC
        if(map_controller_init_mgmt_ipc(loop) == -1) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " Failed to initialize the Vendor IPC\n");
            /* AT this point I do not want to the controller to block because of vendor daemon */
            //exit(EXIT_FAILURE);
        }
#endif
        if(init_map_retry_handler() == -1 ) {
            platform_log(MAP_CONTROLLER,LOG_ERR, " init_map_retry_handler Failed.\n");
            exit(EXIT_FAILURE);
        }
        if(init_agent_onboarding_handler())
        {
            platform_log(MAP_CONTROLLER,LOG_ERR, " init_agent_onboarding_handler  failed.\n");
            exit(EXIT_FAILURE);
        }
        if(init_map_controller_callback() != 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "init_map_controller_callback failed.\n");
            exit(EXIT_FAILURE);
        }
        if(init_cli_event_handler(loop) < 0) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "init_cli_event_handler failed.\n");
            exit(EXIT_FAILURE);
        }

#ifdef EXT_ROAMING_ENGINE
        if (map_controller_ext_roaming_engine_init(loop, &g_map_controller_ext_roaming_engine_cbs)) {
            platform_log(MAP_CONTROLLER,LOG_ERR, "map_controller_ext_roaming_engine_init\n");
            exit(EXIT_FAILURE);
        }
#endif /* EXT_ROAMING_ENGINE */

        return 0;
    } while (0);
}

// Main UV loop
void map_controller_run() {    
    uv_run(loop, UV_RUN_DEFAULT);
}

// TODO::
// Each init of the corresponding module should also have a 
// cleanup API which should be called during exit.
void map_controller_cleanup() {

    // Cleanup the timer
    cleanup_timer_handler();

    MAP_CONTROLLER_EXT_ROAMING_ENGINE_DEINIT();

#ifdef OPENWRT
    uv_signal_stop(&uv_sigint);
    uv_signal_stop(&uv_sigterm);
#ifdef __GLIBC__
    uv_signal_stop(&uv_sigusr1);
#endif /* __GLIBC__ */
#endif /* OPENWRT */

    // Close the UV loop
    uv_loop_close(loop);
    free(loop);

    exit(EXIT_SUCCESS);
}

static int parse_controller_options(int argc, char *argv[]) {
    int opt = 0;
    int num_subargs = 0;

    while( (opt = getopt( argc, argv, "sdf:m:l:" ))!= -1 )
    {
        switch( opt )
        {
            case 'f':
                if( strlen(optarg) > PATH_NAME_MAX )
                    Err_Argument();
                else
                    pltfrm_config.config_file = optarg;
                break;
            case 'm':
                optind--;
                for( ;optind < argc && *argv[optind] != '-'; optind++)
                {
                    if(strcmp(MGMT_CMDLINE_UBUS, argv[optind])== 0)
                    {
                        pltfrm_config.map_config.multiap_opts.is_mgmt_ubus=1;
                        num_subargs+=1;
                        break;
                    }
                    else if(strcmp(MGMT_CMDLINE_SOCK, argv[optind])== 0)
                    {
                        pltfrm_config.map_config.multiap_opts.is_mgmt_sock=1;
                        num_subargs+=1;
                    }
                    else
                    {
                        if(pltfrm_config.map_config.multiap_opts.is_mgmt_sock)
                        {
                            if(strlen(argv[optind]) < SOCK_NAME_LEN_MAX)
                                pltfrm_config.mgmt_sock_name=argv[optind];
                            else
                                num_subargs=0;
                        }   
                    }

                }
                if(num_subargs ==0 || num_subargs >1)
                    Err_Argument();
                break;
            case 's':
                pltfrm_config.log_output = log_stdout;
                break;
            case 'd':
                grun_daemon = 1;
                break;
            case 'h':
            case '?':
            default:
                print_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    pltfrm_config.map_config.version = CONTROLLER_VERSION;

    return 0;
}

static inline void Err_Argument()
{
    printf("\n Invalid Arguments");
    print_usage();
    exit(EXIT_FAILURE);
}

static void print_usage()
{
    printf("\n ------MultiAP Controller Daemon-------");
    printf("\n -f   option to provide non default config file with path");
    printf("\n -m   to enable managemnt interface to debugging ");
    printf("\n      <ubus> for ubus based");
    printf("\n      <sock> for socket based followed by <name> of the socket"); 
    printf("\n -d   option to put error logs in console rather than syslog");   
    printf("\n -l   option to Mention log level for Debugging");
    printf("\n      <1>Only Critical errors and Exceptions");
    printf("\n      <2>Info Logs with <1>");
    printf("\n      <3>Debug Logs with <1> and <2>");
    printf("\n      <4>Noise Level Logs with packet dumps (Dont use this unless required)");

}

