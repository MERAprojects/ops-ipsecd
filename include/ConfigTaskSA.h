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

#ifndef CONFIGTASKSA_H
#define CONFIGTASKSA_H

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
 * Class for Configuration Task of a SA
 */
class ConfigTaskSA : public ConfigTask
{
    private:

        /**
         * IPsec SA
         */
        ipsec_sa m_sa;

    public:

        /**
         * Default Constructor
         *
         * @param config_action Configuration Action
         *
         * @param sa IPsec SA
         */
        ConfigTaskSA(ipsec_config_action config_action,
                     const ipsec_sa& sa);

        /**
         * Default Destructor
         */
        virtual ~ConfigTaskSA();

        /**
         * Gets IPsec SA
         */
        inline const ipsec_sa& get_sa() const
        {
            return m_sa;
        }
};

#endif