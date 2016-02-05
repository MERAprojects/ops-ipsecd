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

            append = true;
        }

        return result;
    }

    ipsec_state ike_state_to_ipsec_state(const std::string ike_state)
    {
        if(ike_state.compare("ESTABLISHED") == 0)
        {
            return ipsec_state::establish;
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

        return ipsec_state::config_error;
    }
}