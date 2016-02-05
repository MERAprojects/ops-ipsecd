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

#ifndef IKEVICIAPI_H
#define IKEVICIAPI_H

/**********************************
*System Includes
**********************************/
#include <string>

extern "C"
{
#include <libvici.h>
}

/**********************************
*Local Includes
**********************************/
#include "IIKEAPI.h"
#include "ops-ipsecd.h"
#include "ViciStreamParser.h"

/**********************************
*Forward Decl
**********************************/
class IViciAPI;

/**
 * IKE strongSWAN Daemon VICI API
 */
class IKEViciAPI : public IIKEAPI
{
    /**
     * Removed Copy Constructor
     */
    IKEViciAPI(const IKEViciAPI& orig) = delete;

    protected:

        /**
         * VICI Connection to charon (strongSWAN) Daemon
         */
        vici_conn_t* m_vici_connection = nullptr;

        /**
         * Determines if the API has been initialize and is ready to be used
         */
        bool m_is_ready = false;

        /**
         * VICI API Layer
         */
        IViciAPI& m_vici_api;

        /**
         * Vici Event Stream Response Parser
         */
        IViciStreamParser& m_vici_stream_parser;

        /**
         * @copydoc IIKEAPI::deinitialize
         */
        void deinitialize() override;

    public:

        /**
         * IKE Vici API Constructor
         *
         * @param vici_api Vici API Layer Object
         *
         * @param viciParser Vici Event Stream Response Parser
         */
        IKEViciAPI(IViciAPI& vici_api, IViciStreamParser& viciParser);

        /**
         * Default Destructor
         */
        virtual ~IKEViciAPI();

        /**
         * @copydoc IIKEAPI::initialize
         */
        ipsec_ret initialize() override;

        /**
         * @copydoc IIKEAPI::create_connection
         */
        ipsec_ret create_connection(const ipsec_ike_connection& conn) override;

        /**
         * @copydoc IIKEAPI::delete_connection
         */
        ipsec_ret delete_connection(const std::string& conn_name) override;

        /**
         * @copydoc IIKEAPI::start_connection
         */
        ipsec_ret start_connection(const std::string& conn_name,
                                   uint32_t timeout_ms) override;

        /**
         * @copydoc IIKEAPI::stop_connection
         */
        ipsec_ret stop_connection(const std::string& conn_name,
                                  uint32_t timeout_ms) override;

        /**
         * @copydoc IIKEAPI::load_credential
         */
        ipsec_ret load_credential(const ipsec_credential& cred) override;

        /**
         * @copydoc IIKEAPI::get_connection_stats
         */
        ipsec_ret get_connection_stats(const std::string& conn_name,
                                       ipsec_ike_connection_stats& stats);
};

#endif /* IKEVICIAPI_H */