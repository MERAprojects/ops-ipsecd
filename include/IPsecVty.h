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

#ifndef IPSEC_VTY_H
#define IPSEC_VTY_H
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
class IPsecVty: public IIPsecVty
{
    /**
     * Removed Copy Constructor
     */
    IPsecVty(const IPsecVty& orig) = delete;

    protected:
    //TODO: Add attributes
    public:
        /**
         * Default constructor
         */
        IPsecVty();

        /**
         * Default destructor
         */
        ~IPsecVty();

        /**
         * @copydoc IIPsecVty::vty_policy_id_set
         */
        ipsec_ret vty_policy_id_set(const std::string& pol_id) override;

        /**
         * @copydoc IIPsecVty::vty_policy_id_get
         */
        ipsec_ret vty_policy_id_get(const std::string& pol_id) override;

        /**
         * @copydoc IIPsecVty::vty_policy_desc_set
         */
        ipsec_ret vty_policy_desc_set(const std::string& pol_desc) override;

        /**
         * @copydoc IIPsecVty::vty_policy_mode_set
         */
        ipsec_ret vty_policy_mode_set(const ipsec_mode pol_mode) override;

        /**
         * @copydoc IIPsecVty::vty_policy_esp_hash_set
         */
        ipsec_ret vty_policy_esp_hash_set(const ipsec_integrity hash)
            override;

        /**
         * @copydoc IIPsecVty::vty_policy_esp_config
         */
        ipsec_ret vty_policy_esp_encrypt_set(const ipsec_cipher encryption)
            override;

        /**
         * @copydoc IIPsecVty::vty_policy_enable
         */
        ipsec_ret vty_policy_enable() override;

        /**
         * @copydoc IIPsecVty::vty_policy_disable
         */
        ipsec_ret vty_policy_disable() override;

        //TODO: define a Getter method
};
#endif
