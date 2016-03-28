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

#ifndef CONFIGQUEUE_H
#define CONFIGQUEUE_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IConfigQueue.h"

/**
 * Base Interface Class for Configuration Queue
 */
class ConfigQueue : public IConfigQueue
{
    protected:

        /**
         * IKE API Interface
         */
        IIKEAPI& m_ike_api;

    public:

        /**
         * Default Constructor
         *
         * @param ike_api IKE API Interface
         */
        ConfigQueue(IIKEAPI& ike_api);

        /**
         * Default Destructor
         */
        virtual ~ConfigQueue();

};

#endif /* CONFIGQUEUE_H */