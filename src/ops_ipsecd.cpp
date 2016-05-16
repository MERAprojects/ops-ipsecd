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
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <unistd.h>
#include <string.h>

/**********************************
*Local Includes
**********************************/
#include "ViciAPI.h"
#include "MapFile.h"
#include "DebugMode.h"
#include "IKEViciAPI.h"
#include "ConfigQueue.h"
#include "SystemCalls.h"
#include "Orchestrator.h"
#include "StatPublisher.h"
#include "LibmnlWrapper.h"
#include "IPsecNetlinkAPI.h"
#include "ViciStreamParser.h"

/**
* Global variable set to true while the program is running
* it will be set to false when it receives a signal to terminate.
*/
static bool g_IsRunning = true;

/**********************************
*Function Defs
**********************************/

/**
* Callback for when the process receives a signal to terminate.
* It will let the rest of the process know that it is terminating.
* @param signum The signal that was sent to the process.
*/
static void ipsecd_on_sigint ( int signum )
{
    g_IsRunning = false;
}

/**
* Sets the callback for signals received to terminate program.
*/
static void ipsecd_signal_set_mask()
{
    struct sigaction sa;

    //Register callback to stop running
    sa.sa_handler = ipsecd_on_sigint;
    sigfillset ( &sa.sa_mask );
    sa.sa_flags = 0;
    sigaction ( SIGINT, &sa, NULL );
}

int main( int argc, const char* argv[] )
{
    /////////////////////////
    //Set Signal
    ipsecd_signal_set_mask();

    /////////////////////////
    //Create Wrappers & APIs
    SystemCalls systemCalls;
    LibmnlWrapper mnl_wrapper;
    ViciAPI vici_api;
    MapFile mapFile(systemCalls);
    ViciStreamParser vici_stream_parser(vici_api);
    IKEViciAPI ikeViciApi(vici_api, vici_stream_parser, mapFile);
    IPsecNetlinkAPI ipsec_netlink(mnl_wrapper);

    /////////////////////////
    //Create Worker Classes
    ConfigQueue config_queue(ikeViciApi, ipsec_netlink);
    StatPublisher stat_pub(ikeViciApi, ipsec_netlink);

    /////////////////////////
    //Create Orchestrator Control Class
    Orchestrator ipsec_orchest(ikeViciApi, config_queue, stat_pub);

    /////////////////////////
    //Initialize Orchestrator
    if (ipsec_orchest.initialize() != ipsec_ret::OK)
    {
        exit(EXIT_FAILURE);
    }

    /////////////////////////
    //Create Debug Class
    DebugMode* debugger = DebugMode::createInst(
            ikeViciApi, ipsec_netlink, argc, (char **) argv);

    while(g_IsRunning && debugger->uccIsRunning())
    {
        debugger->ucc_run();
        usleep(250 * 1000);
        debugger->ucc_wait();
    }
    debugger->ucc_destroy();

    return EXIT_SUCCESS;
}
