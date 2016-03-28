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

#ifndef CONFIGTASK_H
#define CONFIGTASK_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Class for a Configuration Task
 */
class ConfigTask
{
    private:

        /**
         * Type of IPSec Connection
         */
        ipsec_type m_type = ipsec_type::ike;

        /**
         * Type of Configuration Type
         */
        ipsec_config_action m_config_action = ipsec_config_action::add;

    public:

        /**
         * Default Constructor
         */
        ConfigTask();

        /**
         * Default Constructor
         *
         * @param type IPsec Connection Type
         *
         * @param config_action Configuration Action
         */
        ConfigTask(ipsec_type type, ipsec_config_action config_action);

        /**
         * Default Destructor
         */
        virtual ~ConfigTask();

        /**
         * Get the Type of IPsec Connection
         */
        inline ipsec_type get_type() const
        {
            return m_type;
        }

        /**
         * Get the action for the Configuration Task
         */
        inline ipsec_config_action get_config_action() const
        {
            return m_config_action;
        }

};

#endif /* CONFIGQUEUE_H */