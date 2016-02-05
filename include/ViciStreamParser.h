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

#ifndef VICISTREAMPARSER_H
#define VICISTREAMPARSER_H

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
#include "ViciSection.h"
#include "IViciStreamParser.h"

/**********************************
*Forward Declarations
**********************************/
class IViciAPI;

/**
 * Vici Stream Callback Parser
 */
class ViciStreamParser : public IViciStreamParser
{
    protected:

        /**
         * Callback method to parse a Vici Section.
         * As defined in vici_parse_section_cb_t
         */
        static int parse_section(void* user, vici_res_t* res, char* name);

        /**
         * Callback method to parse a Vici Key Value.
         * As defined in vici_parse_value_cb_t
         */
        static int parse_key_value(void* user, vici_res_t* res, char* name,
                                   void* value, int len);

        /**
         * Callback method to parse a Vici List Item.
         * As defined in vici_parse_value_cb_t
         */
        static int parse_list_item(void* user, vici_res_t* res, char* name,
                                   void* value, int len);

        /**
         * Callback method for a Vici Event.
         * As defined in vici_event_cb_t
         */
        static void event_cb(void* user, char* name, vici_res_t* res);

        /**
         * Current Parse Status for the event
         */
        ipsec_ret m_parse_status = ipsec_ret::NOT_PARSE;

        /**
         * Name of the Event that was registered
         */
        std::string m_event_registered = "";

        /**
         * Vici Connection for the registered event
         */
        vici_conn_t* m_conn_registered = nullptr;

        /**
         * Top Level Vici Section use to save the event response
         */
        ViciSection m_vici_section;

        /**
         * Vici API Layer
         */
        IViciAPI& m_vici_api;

    public:

        /**
         * Constructor
         *
         * @param vici_api VICI API Layer
         */
        ViciStreamParser(IViciAPI& vici_api);

        /**
         * Default Destructor
         */
        virtual ~ViciStreamParser();

        /**
         * @copydoc IViciStreamParser::get_parse_status
         */
        inline ipsec_ret get_parse_status() const override
        {
            return m_parse_status;
        }

        /**
         * @copydoc IViciStreamParser::get_vici_answer
         */
        inline const ViciSection& get_vici_answer() const override
        {
            return m_vici_section;
        }

        /**
         * @copydoc IViciStreamParser::register_stream_cb
         */
        ipsec_ret register_stream_cb(vici_conn_t* conn,
                                     const std::string& name) override;

        /**
         * @copydoc IViciStreamParser::unregister_stream_cb
         */
        void unregister_stream_cb() override;

        /**
         * Struct to hold multiple fields for Callback Data User Parameter
         */
        struct DataCB
        {
            /**
             * Current Vici Section for the Callback
             */
            ViciSection* m_section = nullptr;

            /**
             * Vici API Layer
             */
            IViciAPI* m_vici_api = nullptr;
        };
};

#endif /* VICISTREAMPARSER_H */