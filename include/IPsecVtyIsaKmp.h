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

#ifndef IPSEC_VTY_ISAKMP_H
#define IPSEC_VTY_ISAKMP_H
/**********************************
*System Includes
**********************************/
#include <string>
/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IIPsecVty.h"
#include "IIPsecVtyIsaKmp.h"

/**********************************
*Class Decl
**********************************/
class IPsecVtyIsaKmp: public IIPsecVtyIsaKmp
{
    public:

        /**
         * Removed Copy Constructor
         */
        IPsecVtyIsaKmp(const IPsecVtyIsaKmp& orig) = delete;

    protected:
    //TODO: Add attributes
        IIPsecVty& m_ipsec_pol;
    public:
        /**
         * Default constructor
         *
         * @param IPsecPol Existing IPsec policy
         */
        IPsecVtyIsaKmp(IPsecVty &ipsec_pol);

        /**
         * Default destructor
         */
        ~IPsecVtyIsaKmp();

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_version_set
         */
        ipsec_ret vty_isakmp_version_set(
                const ipsec_ike_version ike_version) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_hash_set
         */
        ipsec_ret vty_isakmp_hash_set(const ipsec_integrity hash) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_encryption_set
         */
        ipsec_ret vty_isakmp_encryption_set(
                const ipsec_cipher encryption) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_authentication_set
         */
        ipsec_ret vty_isakmp_authentication_set(
                const ipsec_authby authby) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_group_set
         */
        ipsec_ret vty_isakmp_group_set(
                const ipsec_diffie_group group) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_localid_set
         */
        ipsec_ret vty_isakmp_localid_set(const std::string& local_id) override;

        /**
         * @copydoc IIPsecVtyIsaKmp::vty_isakmp_remoteid_set
         */
        ipsec_ret vty_isakmp_remoteid_set(const std::string& remote_id) override;

        //TODO: define a Getter method
};
#endif
