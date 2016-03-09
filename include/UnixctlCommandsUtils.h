/*
 *  (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

#ifndef __UNIXCTL_COMMANDS_UTILS__
#define __UNIXCTL_COMMANDS_UTILS__

/**********************************
*Includes
**********************************/

extern  "C" {
#include <unixctl.h>
}

#define UCC UnixctlCommandsUtils::getInst()

/**
 * Unixctl commands and utils for ops-ipsecd
 */
class UnixctlCommandsUtils
{
    public:
         /**
        * Get a static UnixctlCommandsUtils instance
        */
         static UnixctlCommandsUtils *getInst()
        {
            if (unixctlcmds == nullptr)
            {
                unixctlcmds = new UnixctlCommandsUtils();
            }
            return unixctlcmds;
        }

        /**
        * Method to parse options from command line
        */
        void parse_options();

        /**
        * Method to perform initialization to the unixctl server
        */
        void init_unixctl();

        /**
        * Execute unixctl server after init_unixctl method has been called
        */
        void run_unixctl();

        /**
        * Wait for an answer from unixctl server
        */
        void wait_unixctl();

        /**
        * Destroy the current unixctl sever after deamon shutdown
        */
        void destroy_unixctl();

        /**
        * Set the values for the instance returned by getInst() method
        *
        * @param argc_c Number of arguments taken from the command line
        *
        * @param argv_c Arguments taken from the command line
        *
        * @param pathp Path for the new unixctl server
        */
        void set_unixclt_server(int argc_c, char *argv_c[], char *pathp);

        /**
        * Add commands to ovs-appctl. In order to do register a new command
        * a handle must be created as a private static  member
        */
        void register_commands();

        /**
        * Show the usage for this daemon
        */
         void usage();

        /**
        * Method to get the current state for UCC
        */
        bool uccIsRunning();

    private:
        int *argc = nullptr;
        char *unixctl_pathp = nullptr;
        char **argv = nullptr;
        struct unixctl_server *appctl = nullptr;

        /**
        * Variable to control the interaction between ops-ipsecd and
        * UCC. This variable is changed when ipsecd/exit command is called
        */
        bool is_ucc_running = true;

        /**
        * The only one instance for this class
        */
        static UnixctlCommandsUtils* unixctlcmds;

        /*Private constructor*/
        UnixctlCommandsUtils();

        /**
        * Handle used by unixctl when ipsecd/exit is called
        */
        static void ipsecd_unixctl_exit(struct unixctl_conn* conn, int argc_c,
                const char* argv_c[], void *this_copy);
        /**
        * Handle used by unixctl when ipsecd/connection is called
        */
        static void ipsecd_unixctl_connection(struct unixctl_conn* conn,
                int argc_c, const char* argv_c[], void *auxListener);
        /**
        * Handle used by unixctl when ipsecd/debug is called
        */
        static void ipsecd_unixctl_debug(struct unixctl_conn* conn,
                int argc_c, const char* argv_c[], void *auxListener);
        /**
        * Handle used by unixctl when ipsecd/help is called
        */
        static void ipsecd_unixctl_help(struct unixctl_conn* conn,
                int argc_c, const char* argv_c[], void *auxListener);
};
#endif /*__UNIXCTL_COMMANDS_UTILS*/
