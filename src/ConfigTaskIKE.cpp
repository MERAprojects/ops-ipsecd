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

/**********************************
*Local Includes
**********************************/
#include "ConfigTaskIKE.h"

/**********************************
*Function Declarations
**********************************/
ConfigTaskIKE::ConfigTaskIKE(ipsec_config_action config_action,
                             const ipsec_ike_connection& ike_connection)
    : ConfigTask(ipsec_type::ike, config_action)
    , m_ike_connection(ike_connection)
{
}

ConfigTaskIKE::~ConfigTaskIKE()
{
}
