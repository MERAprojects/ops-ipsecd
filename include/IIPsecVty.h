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

#ifndef IIPSEC_VTY_H
#define IIPSEC_VTY_H
/**********************************
*System Includes
**********************************/
#include <string>
#include "vtysh/vtysh_ovsdb_config.h"
/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**********************************
*Class Decl
**********************************/

class IIPsecVty {
    public:
        /**
         * Default Constructor
         */
        IIPsecVty() {}

        /**
         * Default Destructor
         */
        ~IIPsecVty() {}

        /**
         * Set id for new policy
         *
         * @param pol_id IPsec policy ID
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_id_set(const string pol_id) = 0;

        /**
         * Set id for new policy
         *
         * @param pol_id IPsec policy ID
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_id_get(string& pol_id) = 0;

        /**
         * Set description for IPsec policy
         *
         * @param pol_desc IPsec policy description
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_desc_set(const string pol_desc) = 0;

        /**
         * Set IPsec mode (tunnel|transport)
         *
         * @param pol_mode IPsec mode
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_mode_set(const ipsec_mode pol_mode) = 0;

        /**
         * Set configuration hash for IPsec ESP
         *
         * @param hash Hash type to use
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_esp_hash_set(
                const ipsec_integrity hash) = 0;

        /**
         * Set encryption for IPsec ESP
         *
         * @param encryption Cipher for ESP
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_esp_encrypt_set(
                const ipsec_cipher encryption) = 0;

        /**
         * Enable IPsec policy
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_enable() = 0;

        /**
         * Disable IPsec policy
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_policy_disable() = 0;

}

#endif
