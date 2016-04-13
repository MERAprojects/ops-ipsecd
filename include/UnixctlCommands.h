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

#ifndef __UNIXCTL_COMMANDS__
#define __UNIXCTL_COMMANDS__

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
* Create a new connection when ipsecd/connection is called
*/
ipsec_ret ipsecd_ucc_create_connection(int argc, const char **argv,
        std::string &message);

/**
* Show a detailed usage for every single command registered by ops-ipsecd
*/
ipsec_ret ipsecd_ucc_help(int argc, const char **argv, std::string &message);

/**
* Enable or disable Debugger mode for ops-ipsecd
*/
ipsec_ret ipsecd_ucc_debug (int argc, const char **argv, std::string &message);

/**
* Add, delete and get a SA
*/
ipsec_ret ipsecd_ucc_sa(int argc, const char **argv, std::string &message);

/**
* Add, delete and get a SP
*/
ipsec_ret ipsecd_ucc_sp(int argc, const char **argv, std::string &message);

#endif /*__UNIXCTL_COMMANDS__*/
