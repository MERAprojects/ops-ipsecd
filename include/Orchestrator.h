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

class Orchestrator
{
        /**
         * Removed Copy Constructor
         */
        Orchestrator(const Orchestrator& orig) = delete;

    protected:
        /**
         * IKEViciApi object reference
         * */
        IIKEAPI& m_ikeapi;

    public:
        /**
         * Orchestrator Constructor
         *
         * @param ikeapi IKE Vici API main Object
         */
        Orchestrator(IIKEAPI& ikeapi);

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
