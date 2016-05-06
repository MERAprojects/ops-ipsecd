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
#include <error_notify_msg.h>

/**********************************
*Local Includes
**********************************/
#include "ops_ipsecd_helper.h"

/**********************************
*Local Decls
**********************************/

namespace ipsecd_helper
{
    const char* cipher_to_str(ipsec_cipher cipher)
    {
        switch(cipher)
        {
            case ipsec_cipher::cipher_aes:
                return "aes";

            case ipsec_cipher::cipher_aes256:
                return "aes256";

            case ipsec_cipher::cipher_3des:
                return "3des";

            default:
                return "";
        }
    }

    const char* integrity_to_str(ipsec_integrity integrity)
    {
        switch(integrity)
        {
            case ipsec_integrity::sha1:
                return "sha1";

            case ipsec_integrity::sha256:
                return "sha256";

            case ipsec_integrity::sha512:
                return "sha512";

            case ipsec_integrity::md5:
                return "md5";

            default:
                return "";
        }
    }

    const char* group_to_str(ipsec_diffie_group group)
    {
        switch(group)
        {
            case ipsec_diffie_group::group_2:
                return "modp1024";

            case ipsec_diffie_group::group_14:
                return "modp2048";

            default:
                return "";
        }
    }

    const char* authby_to_str(ipsec_authby auth_by)
    {
        switch(auth_by)
        {
            case ipsec_authby::pubkey:
                return "pubkey";

            case ipsec_authby::psk:
                return "psk";

            default:
                return "";
        }
    }

    const char* ike_version_to_str(ipsec_ike_version version)
    {
        switch(version)
        {
            case ipsec_ike_version::v1:
                return "1";

            case ipsec_ike_version::v2:
                return "2";

            case ipsec_ike_version::v1v2:
                return "0";

            default:
                return "";
        }
    }

    const char* mode_to_str(ipsec_mode mode)
    {
        switch(mode)
        {
            case ipsec_mode::transport:
                return "Transport";

            case ipsec_mode::tunnel:
                return "Tunnel";

            default:
                return "";
        }
    }

    const char* cred_to_str(ipsec_credential_type cred)
    {
        switch(cred)
        {
            case ipsec_credential_type::psk:
                return "ike";

            case ipsec_credential_type::rsa:
                return "rsa";

            default:
                return "";
        }
    }

    std::string cipher_integrity_group_to_str(ipsec_cipher cipher,
                                              ipsec_integrity integrity,
                                              ipsec_diffie_group group)
    {
        bool append = false;
        std::string result = "";

        if(cipher != ipsec_cipher::cipher_none)
        {
            result = cipher_to_str(cipher);

            append = true;
        }

        if(integrity != ipsec_integrity::none)
        {
            if(append)
            {
                result += "-";
            }

            result += integrity_to_str(integrity);

            append = true;
        }

        if(group != ipsec_diffie_group::group_none)
        {
            if(append)
            {
                result += "-";
            }

            result += group_to_str(group);
        }

        return result;
    }

    ipsec_state ike_state_to_ipsec_state(const std::string ike_state)
    {
        if(ike_state.compare("ESTABLISHED") == 0)
        {
            return ipsec_state::establish;
        }
        else if(ike_state.compare("INSTALLED") == 0)
        {
            return ipsec_state::installed;
        }
        else if(ike_state.compare("CONNECTING") == 0)
        {
            return ipsec_state::connecting;
        }
        else if(ike_state.compare("REKEYING") == 0)
        {
            return ipsec_state::rekeying;
        }
        else if(ike_state.compare("DELETING") == 0)
        {
            return ipsec_state::deleting;
        }
        else if(ike_state.compare("DESTROYING") == 0)
        {
            return ipsec_state::destroying;
        }
        else if(ike_state.compare("PASSIVE") == 0)
        {
            return ipsec_state::passive;
        }
        else if(ike_state.compare("CREATED") == 0)
        {
            return ipsec_state::created;
        }
        else if(ike_state.compare("ROUTED") == 0)
        {
            return ipsec_state::routed;
        }
        else if(ike_state.compare("INSTALLING") == 0)
        {
            return ipsec_state::installing;
        }
        else if(ike_state.compare("UPDATING") == 0)
        {
            return ipsec_state::updating;
        }
        else if(ike_state.compare("REKEYED") == 0)
        {
            return ipsec_state::rekeyed;
        }
        else if(ike_state.compare("RETRYING") == 0)
        {
            return ipsec_state::retrying;
        }

        return ipsec_state::config_error;
    }

    bool char_to_hex(char alpha, uint8_t& hex)
    {
        static const uint8_t hexArr[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                                          0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };


        int32_t pos = 0;
        alpha = tolower(alpha);

        if(alpha >= 48 && alpha <= 102)
        {
            if(alpha >= 97)
            {
                pos = (int32_t)alpha - 87;
            }
            else if(alpha <= 57)
            {
                pos = (int32_t)alpha - 48;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        hex = hexArr[pos];

        return true;
    }

    void str_to_key(const std::string& str, char* key, uint32_t key_len)
    {
        if(str.size() < 2 || key == nullptr || key_len == 0)
        {
            return;
        }

        memset(key, 0, key_len * sizeof(uint8_t));

        uint32_t size = str.size();
        for(uint32_t i = 0, j = 0; i < size && (i+1) < size && j < key_len; i+=2)
        {
            uint8_t key1 = 0;
            uint8_t key2 = 0;

            if(!char_to_hex(str[i], key1) ||
               !char_to_hex(str[i+1], key2))
            {
                continue;
            }

            key[j] = (key1 << 4) | key2;
            j++;
        }
    }

    std::string key_to_str(const char* key, uint32_t keyLen)
    {
        static const char hex[]= "0123456789abcdef";

        if(key == NULL || keyLen == 0)
        {
            return "";
        }

        std::string buffer = "";

        for(uint32_t i = 0; i < keyLen; i++)
        {

            buffer.push_back(hex[ (key[i] >> 4) & 0x0F]);
            buffer.push_back(hex[ (key[i]) & 0x0F]);
        }

        return buffer;
    }

    ipsec_error_event ss_error_to_ipsec_error_event(int error)
    {
        switch(error)
        {
            case ERROR_NOTIFY_LOCAL_AUTH_FAILED:
                return ipsec_error_event::local_auth_failed;

            case ERROR_NOTIFY_PEER_AUTH_FAILED:
                return ipsec_error_event::peer_auth_failed;

            case ERROR_NOTIFY_PARSE_ERROR_HEADER:
            case ERROR_NOTIFY_PARSE_ERROR_BODY:
                return ipsec_error_event::parse_error;

            case ERROR_NOTIFY_RETRANSMIT_SEND_TIMEOUT:
                return ipsec_error_event::retransmit_timeout;

            case ERROR_NOTIFY_HALF_OPEN_TIMEOUT:
                return ipsec_error_event::half_open_timeout;

            case ERROR_NOTIFY_PROPOSAL_MISMATCH_IKE:
                return ipsec_error_event::proposal_mismatch_ike;

            case ERROR_NOTIFY_PROPOSAL_MISMATCH_CHILD:
                return ipsec_error_event::proposal_mismatch_sa;

            case ERROR_NOTIFY_TS_MISMATCH:
                return ipsec_error_event::ts_mismatch;

            case ERROR_NOTIFY_INSTALL_CHILD_SA_FAILED:
                return ipsec_error_event::adding_sa_failed;

            case ERROR_NOTIFY_INSTALL_CHILD_POLICY_FAILED:
                return ipsec_error_event::adding_sp_failed;

            case ERROR_NOTIFY_AUTHORIZATION_FAILED:
                return ipsec_error_event::auth_failed;

            case ERROR_NOTIFY_CERT_EXPIRED:
                return ipsec_error_event::cert_expired;

            case ERROR_NOTIFY_CERT_REVOKED:
                return ipsec_error_event::cert_revoked;

            case ERROR_NOTIFY_NO_ISSUER_CERT:
                return ipsec_error_event::no_issuer_cert;

            case ERROR_NOTIFY_RADIUS_NOT_RESPONDING:
                return ipsec_error_event::radius_conn_error;

            case ERROR_NOTIFY_UNIQUE_REPLACE:
            case ERROR_NOTIFY_UNIQUE_KEEP:
            case ERROR_NOTIFY_VIP_FAILURE:
            default:
                return ipsec_error_event::misc;
        }
    }
}