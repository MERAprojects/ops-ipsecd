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

#ifndef OPS_IPSECD_VICI_DEFS_H
#define OPS_IPSECD_VICI_DEFS_H

/**********************************
*System Includes
**********************************/
#include <cstdint>

/**********************************
*Defines
**********************************/

/**
 * Refer to https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
 * VICI Control String in macros so no one will make an error in a typo and
 * have a difficult bug later on
 */

#define IPSEC_VICI_LOAD_CONN        "load-conn"
#define IPSEC_VICI_LOCAL_ADDRS      "local_addrs"
#define IPSEC_VICI_REMOTE_ADDRS     "remote_addrs"
#define IPSEC_VICI_VERSION          "version"
#define IPSEC_VICI_CHILDREN         "children"
#define IPSEC_VICI_MODE             "mode"
#define IPSEC_VICI_LOCAL_TS         "local_ts"
#define IPSEC_VICI_REMOTE_TS        "remote_ts"
#define IPSEC_VICI_ESP_PROPOSALS    "esp_proposals"
#define IPSEC_VICI_AH_PROPOSALS     "ah_proposals"
#define IPSEC_VICI_PROPOSALS        "proposals"
#define IPSEC_VICI_LOCAL            "local"
#define IPSEC_VICI_REMOTE           "remote"
#define IPSEC_VICI_ID               "id"
#define IPSEC_VICI_AUTH             "auth"
#define IPSEC_VICI_SUCCESS          "success"
#define IPSEC_VICI_ERRMSG           "errmsg"
#define IPSEC_VICI_UNLOAD_CONN      "unload-conn"
#define IPSEC_VICI_NAME             "name"
#define IPSEC_VICI_INITIATE         "initiate"
#define IPSEC_VICI_CHILD            "child"
#define IPSEC_VICI_TIMEOUT          "timeout"
#define IPSEC_VICI_INIT_LIMITS      "init-limits"
#define IPSEC_VICI_LOG_LEVEL        "loglevel"
#define IPSEC_VICI_LOAD_KEY         "load-key"
#define IPSEC_VICI_LOAD_SHARED      "load-shared"
#define IPSEC_VICI_TYPE             "type"
#define IPSEC_VICI_DATA             "data"
#define IPSEC_VICI_OWNERS           "owners"
#define IPSEC_VICI_TERMINATE        "terminate"
#define IPSEC_VICI_IKE              "ike"
#define IPSEC_VICI_LIST_SA_EVENT    "list-sa"


/**********************************
*Enums
**********************************/

enum class ViciItemType : uint32_t
{
    Section,
    List,
    Value
};

#endif /* OPS_IPSECD_VICI_DEFS_H */