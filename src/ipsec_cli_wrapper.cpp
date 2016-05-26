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
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

/**********************************
* Local Includes
***********************************/
#include "IPsecVty.h"
#include "IPsecVtyIsaKmp.h"
#include "ops-ipsecd.h"
#include "ipsec_cli_wrapper.h"


extern "C" {

static vty_ipsec_ret_t vty_get_ret(ipsec_ret ret_value);


vty_ipsec_ret_t vty_policy_create(void **ipsec_pol)
{
    IPsecVty *o_ipsec_pol = nullptr;

    o_ipsec_pol = new IPsecVty();

    if (o_ipsec_pol == nullptr) {
        *ipsec_pol = nullptr;
        return VTY_ALLOC_FAILED;
    }

    *ipsec_pol = ((void *)o_ipsec_pol);
    return VTY_OK;
}

vty_ipsec_ret_t vty_policy_id_set(const void *ipsec_pol, const char *pol_id)
{
    IPsecVty *o_ipsec_pol = nullptr;
    ipsec_ret result = ipsec_ret::ERR;

    if (ipsec_pol == nullptr || pol_id == nullptr) {
        return VTY_NULL_PARAMETERS;
    }
    else {
        o_ipsec_pol = (IPsecVty *)ipsec_pol;
        result = o_ipsec_pol->vty_policy_id_set(pol_id);
        return vty_get_ret(result);
    }
}

vty_ipsec_ret_t vty_policy_id_get(const void *ipsec_pol, const char ** pol_id)
{
    IPsecVty *o_ipsec_pol = nullptr;
    std::string str_pol_id = "";
    ipsec_ret result = ipsec_ret::ERR;

    if (ipsec_pol == nullptr || pol_id == nullptr) {
        return VTY_NULL_PARAMETERS;
    }
    else {
        o_ipsec_pol = (IPsecVty *)ipsec_pol;
        result = o_ipsec_pol->vty_policy_id_get(str_pol_id);
        if (result == ipsec_ret::OK) {
            *pol_id = strndup(str_pol_id.c_str(),
                              str_pol_id.length() + 1);
        }
        else {
            *pol_id = nullptr;
        }
    }
    return vty_get_ret(result);
}


vty_ipsec_ret_t vty_policy_desc_set(const void *ipsec_pol, const char * desc)
{
    IPsecVty *o_ipsec_pol = nullptr;
    std::string str_desc = "";
    ipsec_ret result = ipsec_ret::ERR;

    if (ipsec_pol == nullptr || desc == nullptr) {
        return VTY_NULL_PARAMETERS;
    }
    else {
        o_ipsec_pol = (IPsecVty *)ipsec_pol;
        str_desc = std::string(desc);
        result = o_ipsec_pol->vty_policy_desc_set(str_desc);
    }
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_mode_set(const void *ipsec_pol, const vty_ipsec_value_t pol_mode)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVty *o_ipsec_pol = nullptr;
    ipsec_mode pm = ipsec_mode::transport;

    if (ipsec_pol == nullptr) {
        return VTY_NULL_PARAMETERS;
    }

    switch(pol_mode) {
        case VTY_IPSEC_MODE_TUNNEL:
            pm = ipsec_mode::tunnel;
            break;
        case VTY_IPSEC_MODE_TRASPORT:
        default:
            pm = ipsec_mode::transport;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    result = o_ipsec_pol->vty_policy_mode_set(pm);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_esp_hash_set(const void *ipsec_pol, const vty_ipsec_value_t hash)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVty *o_ipsec_pol = nullptr;
    ipsec_integrity hash_int = ipsec_integrity::none;

    if (ipsec_pol == nullptr) {
        return VTY_NULL_PARAMETERS;
    }

    switch(hash) {
        case VTY_IPSEC_INT_SHA1:
            hash_int = ipsec_integrity::sha1;
            break;
        case VTY_IPSEC_INT_SHA256:
            hash_int = ipsec_integrity::sha256;
            break;
        case VTY_IPSEC_INT_SHA512:
            hash_int = ipsec_integrity::sha512;
            break;
        case VTY_IPSEC_NONE:
        default:
            hash_int = ipsec_integrity::none;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    result = o_ipsec_pol->vty_policy_esp_hash_set(hash_int);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_esp_encrypt_set(const void *ipsec_pol, const vty_ipsec_value_t encryption)
{
    ipsec_ret result = ipsec_ret::ERR;
    ipsec_cipher enc = ipsec_cipher::cipher_none;
    IPsecVty *o_ipsec_pol = nullptr;

    if (ipsec_pol == nullptr) {
        return VTY_NULL_PARAMETERS;
    }

    switch(encryption) {
        case VTY_IPSEC_CIPHER_AES:
            enc = ipsec_cipher::cipher_aes;
            break;
        case VTY_IPSEC_CIPHER_AES256:
            enc = ipsec_cipher::cipher_aes256;
            break;
        default:
            enc = ipsec_cipher::cipher_none;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    result = o_ipsec_pol->vty_policy_esp_encrypt_set(enc);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_enable(const void *ipsec_pol)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVty *o_ipsec_pol = nullptr;

    if (ipsec_pol == nullptr) {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    result = o_ipsec_pol->vty_policy_enable();
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_disable(const void *ipsec_pol)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVty *o_ipsec_pol = nullptr;

    if (ipsec_pol == nullptr) {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    result = o_ipsec_pol->vty_policy_disable();
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_policy_destroy(void **ipsec_pol)
{
    IPsecVty *o_ipsec_pol = nullptr;

    if (ipsec_pol != nullptr) {
        o_ipsec_pol = (IPsecVty *)(*ipsec_pol);
        DeleteMem(o_ipsec_pol);
        *ipsec_pol = nullptr;
        return VTY_OK;
    }
    else {
        return VTY_NULL_PARAMETERS;
    }
}

vty_ipsec_ret_t vty_isakmp_create(const void *ipsec_pol, void **isakmp)
{
    IPsecVty *o_ipsec_pol = nullptr;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;

    if (ipsec_pol == nullptr || isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_pol = (IPsecVty *)ipsec_pol;
    o_ipsec_isakmp = new IPsecVtyIsaKmp(*o_ipsec_pol);

    if (o_ipsec_isakmp == nullptr) {
        *isakmp = nullptr;
        return VTY_ALLOC_FAILED;
    }

    *isakmp = (void *)o_ipsec_isakmp;
    return VTY_OK;
}

vty_ipsec_ret_t vty_isakmp_version_set(const void *isakmp,
                                       const vty_ipsec_value_t ike_version)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    ipsec_ike_version ikev = ipsec_ike_version::v1v2;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    switch(ike_version) {
        case VTY_IPSEC_IKE_V1:
            ikev = ipsec_ike_version::v1;
            break;
        case VTY_IPSEC_IKE_V2:
            ikev = ipsec_ike_version::v2;
            break;
        case VTY_IPSEC_IKE_V1V2:
        default:
            ikev = ipsec_ike_version::v1v2;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    result = o_ipsec_isakmp->vty_isakmp_version_set(ikev);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_hash_set(const void *isakmp,
                                    const vty_ipsec_value_t hash)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    ipsec_integrity ha = ipsec_integrity::none;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    switch(hash) {
        case VTY_IPSEC_INT_SHA1:
            ha = ipsec_integrity::sha1;
            break;
        case VTY_IPSEC_INT_MD5:
            ha = ipsec_integrity::md5;
            break;
        default:
            ha = ipsec_integrity::none;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    result = o_ipsec_isakmp->vty_isakmp_hash_set(ha);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_encryption_set(const void *isakmp,
                                          const vty_ipsec_value_t encryption)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    ipsec_cipher enc = ipsec_cipher::cipher_none;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    switch(encryption) {
        case VTY_IPSEC_CIPHER_AES:
            enc = ipsec_cipher::cipher_aes;
            break;
        case VTY_IPSEC_CIPHER_AES256:
            enc = ipsec_cipher::cipher_aes256;
            break;
        default:
            enc = ipsec_cipher::cipher_none;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    result = o_ipsec_isakmp->vty_isakmp_encryption_set(enc);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_authentication_set(const void *isakmp,
                                              const vty_ipsec_value_t auth)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    ipsec_authby authby = ipsec_authby::psk;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    switch(auth) {
        case VTY_IPSEC_AUTHBY_PUBKEY:
            authby = ipsec_authby::pubkey;
            break;
        case VTY_IPSEC_AUTHBY_PSK:
        default:
            authby = ipsec_authby::psk;
            break;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    result = o_ipsec_isakmp->vty_isakmp_authentication_set(authby);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_group_set(const void *isakmp,
                                     const vty_ipsec_value_t group)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    ipsec_diffie_group grp = ipsec_diffie_group::group_none;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    switch(group) {
        case VTY_IPSEC_DIFFIE_GROUP2:
            grp = ipsec_diffie_group::group_2;
            break;
        case VTY_IPSEC_DIFFIE_GROUP14:
            grp = ipsec_diffie_group::group_14;
            break;
        case VTY_IPSEC_NONE:
        default:
            grp = ipsec_diffie_group::group_none;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    result = o_ipsec_isakmp->vty_isakmp_group_set(grp);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_localid_set(const void *isakmp,
                                       const char *local_id)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    std::string str_id = "";

    if (isakmp == nullptr || local_id == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    str_id = std::string(local_id);
    result = o_ipsec_isakmp->vty_isakmp_localid_set(str_id);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_remoteid_set(const void *isakmp,
                                        const char *remote_id)
{
    ipsec_ret result = ipsec_ret::ERR;
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;
    std::string str_id = "";

    if (isakmp == nullptr || remote_id == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)isakmp;
    str_id = std::string(remote_id);
    result = o_ipsec_isakmp->vty_isakmp_localid_set(str_id);
    return vty_get_ret(result);
}

vty_ipsec_ret_t vty_isakmp_destroy(void **isakmp)
{
    IPsecVtyIsaKmp *o_ipsec_isakmp = nullptr;

    if (isakmp == nullptr)
    {
        return VTY_NULL_PARAMETERS;
    }

    o_ipsec_isakmp = (IPsecVtyIsaKmp *)(*isakmp);
    DeleteMem(o_ipsec_isakmp);
    *isakmp = nullptr;

    return VTY_OK;
}

static vty_ipsec_ret_t vty_get_ret(ipsec_ret ret_value)
{
    switch (ret_value) {
        case ipsec_ret::MODIFY_FAILED:
            return VTY_MODIFY_FAILED;
        case ipsec_ret::ADD_FAILED:
            return VTY_ADD_FAILED;
        case ipsec_ret::DELETE_FAILED:
            return VTY_REMOVE_FAILED;
        case ipsec_ret::NOT_FOUND:
            return VTY_NOT_FOUND;
        case ipsec_ret::ALLOC_FAILED:
            return VTY_ALLOC_FAILED;
        case ipsec_ret::NULL_PARAMETERS:
            return VTY_NULL_PARAMETERS;
        case ipsec_ret::EMPTY_STRING:
            return VTY_EMPTY_STRING;
        case ipsec_ret::OK:
            return VTY_OK;
        case ipsec_ret::ERR:
        default:
            return VTY_ERROR;
    }
}
}
