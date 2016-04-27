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

#ifndef DEBUG_MODE_H
#define DEBUG_MODE_H

/**********************************
*System Includes
**********************************/
#include <iostream>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IKEViciAPI.h"
#include "UnixctlCommandsUtils.h"

/**
* Utilities for debugger mode
*/
class DebugMode
{
    public:
        /**
        * Create  a new DebugMode instance
        *
        * @param ikeviciApi Reference to the main IKEViciAPI object
        *
        * @param argc Number of arguments taken from the command line
        *
        * @param argv Arguments taken from the command line
        *
        * @return DebugMode instance
        */
        static DebugMode *createInst(IKEViciAPI& ikeviciApi, int argc,
                char **argv)
        {
            if (m_debugger == NULL)
            {
                m_debugger = new DebugMode(ikeviciApi, argc, argv);
            }
            return m_debugger;
        }

        /**
        * Get the static DebugMode instance. This function must be used only
        * when createIns has been called before
        */
         static DebugMode *getInst()
        {
            return m_debugger;
        }

        /**
        * Get the current state for Debugger mode
        */
        bool isEnable(void);

        /**
        * Enable/disable debug Mode for UCC
        *
        * @param state The new state for Debugger mode
        */
        void set_Enable(bool state);

        /**
        * Methods ucc_run, ucc_wait and ucc_destroy are controlled by
        * unixctl_api. If something went wrong at the moment to create, run
        * or destroy the  unixctl server the current thread is aborted
        */

        /**
        * Run the queue request from unixctl server
        */
        void ucc_run(void);

        /**
        * Wait an answer from unixctl server
        */
        void ucc_wait(void);

        /**
        * Destroy current unixctl server
        */
        void ucc_destroy(void);

        /**
        * Get connection stats from IKEViciAPI object
        */
        ipsec_ret get_connection_stats(const std::string& conn_name,
                ipsec_ike_connection_stats& stats);
        /**
        * Start a connection created before
        */
        ipsec_ret start_connection(const std::string& conn_name,
                uint32_t timeout_ms);
        /**
        * Stop a connection created before
        */
        ipsec_ret stop_connection(const std::string& conn_name,
                uint32_t timeout_ms);

        /**
        * Delete a connection created before
        */
        ipsec_ret delete_connection(const std::string& conn_name);

        /**
        * Create a new connection
        */
        ipsec_ret create_connection(const ipsec_ike_connection& conn);

        /**
        * Load credential to memory
        */
        ipsec_ret load_credential(const ipsec_credential& cred);

        /**
        * Get the current state for UCC
        */
         bool uccIsRunning();
    private:
        /**
        * Number of arguments taken from main function and used  on unixctl
        * constructor
        */
        int argc_d = 0;

        /**
        * Arguments taken from main function and used  on unixctl constructor
        */
        char **argv_d = nullptr;

        /**
        * The only one instance for this class
        */
        static DebugMode* m_debugger;

        /**
        * Current state for debugger mode
        */
        bool d_enable = false;

        /*
        * Path where the requested details are going to be saved
        */
        std::string path_to_file = "";

        /**
        * Unixctl object for UCC
        */
        UnixctlCommandsUtils *m_unixcmds = UCC;

        /**
        * Reference to IKEViciAPI object
        */
        IKEViciAPI& m_ikeviciApi;

        /**
        * Removed Copy Constructor
        */
        DebugMode(const DebugMode& orig) = delete;

        /**
        * Deleted default constructor
        */
        DebugMode() = delete;

        /**
        * Constructor
        *
        * @param ikeviciApi Reference to IKEViciAPI main object
        *
        * @param argc Number of arguments taken from the command line
        *
        * @param argv Arguments taken from the command line
        */
        DebugMode(IKEViciAPI& ikeviciApi, int argc, char **argv);
};

#endif /*DEBUG_MODE_H*/
