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

#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

/**********************************
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**********************************
*Forward Decl
**********************************/
class IIKEAPI;
class IIPsecAPI;
class IConfigQueue;
class IStatPublisher;

class Orchestrator
{
        /**
         * Removed Copy Constructor
         */
        Orchestrator(const Orchestrator& orig) = delete;

    protected:

        /**
         * IKE API Interface
         * */
        IIKEAPI& m_ike_api;

        /**
         * Config Queue Interface
         */
        IConfigQueue& m_config_queue;

        /**
         * Stat Publisher Interface
         */
        IStatPublisher& m_stats_publisher;

        /**
         * Determines if the class was successfully initialized
         */
        bool m_is_ready = false;

    public:
        /**
         * Orchestrator Constructor
         *
         * @param ike_api IKE API interface
         *
         * @param ipsec_api IPsec API Interface
         *
         * @param config_queue Config Queue Interface
         *
         * @param stats_publisher Stats Publisher Interface
         */
        Orchestrator(IIKEAPI& ike_api, IConfigQueue& config_queue,
                     IStatPublisher& stats_publisher);

        /**
         * Initialize main method for ops-ipsecd
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret initialize();

        /**
         * Default Destructor
         */
         ~Orchestrator();
};
#endif /*ORCHESTRATOR_H*/
