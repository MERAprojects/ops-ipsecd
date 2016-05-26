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

#ifndef IIPSEC_VTY_ISAKMP_H
#define IIPSEC_VTY_ISAKMP_H
/**********************************
*System Includes
**********************************/
#include <string>
/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IIPsecVty.h"

/**********************************
*Class Decl
**********************************/

class IIPsecVtyIsaKmp
{
    public:

        /**
         * Constructor with Ipsec policy
         */
        IIPsecVtyIsaKmp() {}

        /**
         * Default destructor
         */
        virtual ~IIPsecVtyIsaKmp() {}

        /**
         * Set IKE version
         *
         * @param ike_version IKE version to use
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_version_set(
                const ipsec_ike_version ike_version) = 0;

        /**
         * Set hash for IKE
         *
         * @param hash IKE hash
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_hash_set(const ipsec_integrity hash) = 0;

        /**
         * Set encryption for IKE
         *
         * @param encryption Encryption used for IKE
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_encryption_set(
                const ipsec_cipher encryption) = 0;

        /**
         * Set authentication method
         *
         * @param authby Authentication method for IKE
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_authentication_set(
                const ipsec_authby authby) = 0;

        /**
         * Set Diffie Group to use with IKE
         *
         * @param group Diffie Group to use with IKE
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_group_set(
                const ipsec_diffie_group group) = 0;

        /**
         * Set local ID for IKE
         *
         * @param local_id Local ID used by policy
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_localid_set(const std::string& local_id) = 0;

        /**
         * Set remote ID for IKE
         *
         * @param remote_id Remote ID used by policy
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret vty_isakmp_remoteid_set(const std::string& remote_id) = 0;
};

#endif
