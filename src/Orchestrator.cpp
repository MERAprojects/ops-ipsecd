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
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "IIKEAPI.h"
#include "Orchestrator.h"
#include "IConfigQueue.h"

Orchestrator::Orchestrator(IIKEAPI& ike_api,
                           IConfigQueue& config_queue)
    : m_ike_api(ike_api)
    , m_config_queue(config_queue)
{
}

Orchestrator::~Orchestrator()
{
    m_config_queue.stop_thread();
}

ipsec_ret Orchestrator::initialize()
{
    if(m_is_ready)
    {
        return ipsec_ret::OK;
    }

    ipsec_ret result = ipsec_ret::OK;

    ///////////////////////////////
    //Initialize the IKE Api
    result = m_ike_api.initialize();
    if (result != ipsec_ret::OK)
    {
        return result;
    }

    ///////////////////////////////
    //Start Config Queue Thread
    result = m_config_queue.start_thread();
    if (result != ipsec_ret::OK)
    {
        return result;
    }

    m_is_ready = true;

    return result;
}
