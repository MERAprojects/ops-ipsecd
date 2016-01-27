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

#ifndef IIKEAPI_H
#define IIKEAPI_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Base Interface Class for IKE Daemon API
 */
class IIKEAPI
{
    protected:

        /**
         * Deinitializes the connection to the API
         */
        virtual void deinitialize() = 0;

    public:

        /**
         * Default Constructor
         */
        IIKEAPI() {}

        /**
         * Default Destructor
         */
        virtual ~IIKEAPI() {}

        /**
         * Initializes the the API and gets it ready for use
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret initialize() = 0;

        /**
         * Creates a Connection in the IKE Daemon
         *
         * @param conn Connection to create
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret create_connection(const ipsec_ike_connection& conn)
                                            = 0;

        /**
         * Deletes a Connection from the IKE Daemon
         *
         * @param conn_name Name of the Connection to delete
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret delete_connection(const std::string& conn_name) = 0;

        /**
         * Starts a IKE/IPsec Connection
         *
         * @param conn_name Name of the connection to initiate
         *
         * @param timeout_ms Timeout in milliseconds to wait for the connection
         * to establish
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret start_connection(const std::string& conn_name,
                                           uint32_t timeout_ms) = 0;

        /**
         * Stops a IKE/IPsec Connection
         *
         * @param conn_name Name of the connection to terminate
         *
         * @param timeout_ms Timeout in milliseconds to wait for the connection
         * to terminate
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret stop_connection(const std::string& conn_name,
                                          uint32_t timeout_ms) = 0;

        /**
         * Load a PSK/RSA Credential to the IKE Daemon
         *
         * @param cred Credential values to load
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret load_credential(const ipsec_credential& cred) = 0;
};

#endif /* IIKEAPI_H */