/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/**********************************
* System Includes
**********************************/
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>

/**********************************
* Local Includes
***********************************/
#include "IPsecVty.h"
#include "IPsecVtyIsaKmp.h"

IPsecVtyIsaKmp::IPsecVtyIsaKmp(IPsecVty &ipsec_pol)
    : m_ipsec_pol(ipsec_pol)
{

}

IPsecVtyIsaKmp::~IPsecVtyIsaKmp()
{

}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_version_set(
        const ipsec_ike_version ike_version)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_hash_set(const ipsec_integrity hash)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_encryption_set(
                const ipsec_cipher encryption)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_group_set(
                const ipsec_diffie_group group)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_authentication_set(
                const ipsec_authby authby)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_localid_set(const std::string& local_id)
{
    return ipsec_ret::OK;
}

ipsec_ret IPsecVtyIsaKmp::vty_isakmp_remoteid_set(const std::string& remote_id)
{
    return ipsec_ret::OK;
}
