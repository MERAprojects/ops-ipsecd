/*
 *Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 *All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

/**********************************
*System Includes
**********************************/
#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>


/**********************************
*Local Includes
**********************************/
#include "UnixctlCommandsUtils.h"
#include "UnixctlCommands.h"

extern  "C" {
#include <command-line.h>
#include <compiler.h>
#include <daemon.h>
#include <util.h>
}

UnixctlCommandsUtils* UnixctlCommandsUtils::unixctlcmds = nullptr;

UnixctlCommandsUtils::UnixctlCommandsUtils()
{
}

void UnixctlCommandsUtils::usage()
{
     printf("%s: OpenSwitch ipsecd daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:/var/run/openvswitch/db.sock\").\n",
           program_name, program_name);
    daemon_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
    exit(EXIT_SUCCESS);
}

void UnixctlCommandsUtils::parse_options()
{
    enum {
        OPT_UNIXCTL=UCHAR_MAX + 1,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, nullptr, 'h'},
        {"unixctl",     required_argument, nullptr, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        {nullptr, 0, nullptr, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(*argc, argv, short_options, long_options, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();
            break;

        case OPT_UNIXCTL:
            unixctl_pathp = optarg;
            break;

        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    *argc -= optind;
    argv += optind;

    if  (*argc == 0)
    {
        /*TODO show the path of the socket on which ovsdb-server
        * is listening if it's required with ovs_rundir function
        */
        //printf("unix:/var/run/openvswitch/db.sock\n");
    }
    else
    {
        printf("at most one non-option argument accepted; "
                   "use --help for usage\n");
    }
} /* parse_options() */

void UnixctlCommandsUtils::ipsecd_unixctl_exit(struct unixctl_conn *conn,
        int argc_c OVS_UNUSED, const char *argv_c[] OVS_UNUSED,
        void *this_copy)
{
    UnixctlCommandsUtils *self = static_cast<UnixctlCommandsUtils*> (this_copy);
    self->is_ucc_running = false;
    std::string message = "\n ops-ipsecd daemon is shutting down now... \n";
    unixctl_command_reply(conn, message.c_str());
}

void UnixctlCommandsUtils::ipsecd_unixctl_connection(struct unixctl_conn *conn,
        int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
        void *auxListener = nullptr)
{
    /**
    * Message to talk with the unixctl.ctl server
    */
    std::string message = "";
    ipsec_ret result = ipsec_ret::OK;

    result = ipsecd_ucc_create_connection(argc, argv, message);
    if (result == ipsec_ret::OK)
    {
        unixctl_command_reply(conn, message.c_str());
    }
    else
    {
        message.assign("Transaction error, " \
            "please check your input arguments and try again, " \
            "Error " + std::to_string(static_cast<int>(result)) +  " \n");
        unixctl_command_reply_error(conn, message.c_str());
    }
}

void UnixctlCommandsUtils::ipsecd_unixctl_debug(struct unixctl_conn* conn,
        int argc OVS_UNUSED, const char* argv[] OVS_UNUSED,
        void *auxListener = nullptr)
{
    /**
    * Message to talk with the unixctl.ctl server
    */
    std::string message = "";
    ipsec_ret result = ipsec_ret::OK;

    result = ipsecd_ucc_debug(argc, argv, message);
    if (result == ipsec_ret::OK)
    {
        unixctl_command_reply(conn, message.c_str());
    }
    else
    {
        message.assign("Input Error, (use ipsecd/help) " \
            "please check your input arguments and try again\n");
        unixctl_command_reply_error(conn, message.c_str());
    }
}

void UnixctlCommandsUtils::ipsecd_unixctl_help(struct unixctl_conn* conn,
        int argc OVS_UNUSED, const char* argv[] OVS_UNUSED,
        void *auxListener = nullptr)
{
    /**
    * Message to talk with the unixctl.ctl server
    */
    std::string message = "";
    ipsec_ret result = ipsec_ret::OK;

    result = ipsecd_ucc_help(argc, argv, message);
    if (result == ipsec_ret::OK)
    {
        unixctl_command_reply(conn, message.c_str());
    }
    else
    {
        message.assign("Input Error" \
            " help command takes no arguments\n");
        unixctl_command_reply_error(conn, message.c_str());
    }
}

bool UnixctlCommandsUtils::uccIsRunning()
{
    return is_ucc_running;
}

void UnixctlCommandsUtils::set_unixclt_server(int argc_c,
        char *argv_c[], char *pathp=nullptr)
{
    argc = &argc_c;
    argv = &argv_c[0];
    unixctl_pathp = pathp;
    init_unixctl();
}

void UnixctlCommandsUtils::init_unixctl()
{
    int ret;
    set_program_name (argv[0]);
    proctitle_init(*argc, (char **)argv);
    parse_options();
    daemonize_start();
    /*Create unixctl server*/
    ret = unixctl_server_create(unixctl_pathp, &appctl);
    if (ret)
    {
        exit(EXIT_FAILURE);
    }
    register_commands();
}

void UnixctlCommandsUtils::destroy_unixctl()
{
    unixctl_server_destroy(appctl);
}

void UnixctlCommandsUtils::run_unixctl()
{
    unixctl_server_run(appctl);
}

void UnixctlCommandsUtils::wait_unixctl()
{
    unixctl_server_wait(appctl);
}

void UnixctlCommandsUtils::register_commands()
{

    /*Register the ovs-appctl 'ipsecd/exit' command for ops-ipsecd daemon */
    unixctl_command_register("ipsecd/exit","",0,0,
        UnixctlCommandsUtils::ipsecd_unixctl_exit, static_cast<void*>(this));
    /**
    * Register the ovs-appctl 'ipsecd/connection' command
    * for ops-ipsecd daemon
    */
    unixctl_command_register("ipsecd/connection",
            "Create a new ipsecd connection",2,27,
            UnixctlCommandsUtils::ipsecd_unixctl_connection, nullptr);

    /**
    * Register the ovs-appctl 'ipsecd/debug' command
    * for ops-ipsecd daemon
    */
    unixctl_command_register("ipsecd/debug",
            "Enable/disable Debugger Mode for ops-ipsecd",1,1,
            UnixctlCommandsUtils::ipsecd_unixctl_debug, nullptr);
    /**
    * Register the ovs-appctl 'ipsecd/help' command
    * for ops-ipsecd daemon
    */
    unixctl_command_register("ipsecd/help",
            "Show usage for all ops-ipsecd commands", 0, 0,
            UnixctlCommandsUtils::ipsecd_unixctl_help, nullptr);
}
