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

#ifndef CONFIGTASKIKE_H
#define CONFIGTASKIKE_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ConfigTask.h"

/**
 * Class for Configuration Task of an IKE
 */
class ConfigTaskIKE : public ConfigTask
{
    private:

        /**
         * IPsec IKE Connection
         */
        ipsec_ike_connection m_ike_connection;

    public:

        /**
         * Default Constructor
         *
         * @param config_action Configuration Action
         *
         * @param ike_connection IPsec IKE Connection
         */
        ConfigTaskIKE(ipsec_config_action config_action,
                      const ipsec_ike_connection& ike_connection);

        /**
         * Default Destructor
         */
        virtual ~ConfigTaskIKE();

        /**
         * Gets IPsec IKE Connection
         */
        inline const ipsec_ike_connection& get_ike_connection() const
        {
            return m_ike_connection;
        }
};

#endif