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

#ifndef IVICISTREAMPARSER_H
#define IVICISTREAMPARSER_H

/**********************************
*System Includes
**********************************/

extern "C"
{
#include <libvici.h>
}

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Vici Stream Callback Parser Interface
 */
class IViciStreamParser
{
    public:

        /**
         * Default Constructor
         */
        IViciStreamParser() {}

        /**
         * Default Destructor
         */
        virtual ~IViciStreamParser() {}

        /**
         * Gets the current parse status
         *
         * @return Parse Status
         */
        virtual ipsec_ret get_parse_status() const = 0;

        /**
         * Gets a Vici Section filled with the response of the requested event.
         *
         * @return  Vici Event Response
         */
        virtual const ViciSection& get_vici_answer() const = 0;

        /**
         * Registers an Event Callback. When the event is triggered the
         * callback will parse the answer.
         *
         * @param conn Vici Connection
         * @param name Name of the Event
         *
         * @return OK if the event callback was registered, otherwise an error
         * code is returned
         */
        virtual ipsec_ret register_stream_cb(vici_conn_t* conn,
                                             const std::string& name) = 0;

        /**
         * Unregisters the callback if an event has been registered.
         */
        virtual void unregister_stream_cb() = 0;
};

#endif /* IVICISTREAMPARSER_H */