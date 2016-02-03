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

#ifndef VICIAPI_H
#define VICIAPI_H

/**********************************
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "IViciAPI.h"

/**
 * Implementation of LibVICI API Layer
 */
class ViciAPI : public IViciAPI
{
    /**
     * Removed Copy Constructor
     */
    ViciAPI(const ViciAPI& orig) = delete;

    public:

        /**
         * Default Constructor
         */
        ViciAPI();

        /**
         * Default Destructor
         */
        virtual ~ViciAPI();

        /**
         * @copydoc IViciAPI::init
         */
        void init() override;

        /**
         * @copydoc IViciAPI::deinit
         */
        void deinit() override;

        /**
         * @copydoc IViciAPI::connect
         */
        vici_conn_t* connect(const char *uri) override;

        /**
         * @copydoc IViciAPI::disconnect
         */
        void disconnect(vici_conn_t *conn) override;

        /**
         * @copydoc IViciAPI::begin
         */
        vici_req_t* begin(const char *name) override;

        /**
         * @copydoc IViciAPI::add_key_value_str
         */
        void add_key_value_str(vici_req_t *req, const char *key,
                               const std::string& value) override;

        /**
         * @copydoc IViciAPI::add_key_value_uint
         */
        void add_key_value_uint(vici_req_t *req, const char *key,
                                uint32_t value) override;

        /**
         * @copydoc IViciAPI::add_key_value
         */
        void add_key_value(vici_req_t *req, const char *key,
                           const void* data, uint32_t len) override;

        /**
         * @copydoc IViciAPI::submit
         */
        vici_res_t* submit(vici_req_t *req, vici_conn_t *conn) override;

        /**
         * @copydoc IViciAPI::find_str
         */
        const char* find_str(vici_res_t *res, const char *def,
                             const char *fmt) override;

        /**
         * @copydoc IViciAPI::free_res
         */
        void free_res(vici_res_t *res) override;

        /**
         * @copydoc IViciAPI::begin_section
         */
        void begin_section(vici_req_t *req, const char *name) override;

        /**
         * @copydoc IViciAPI::begin_list
         */
        void begin_list(vici_req_t *req, const char *name) override;

        /**
         * @copydoc IViciAPI::add_list_item
         */
        void add_list_item(vici_req_t *req, const std::string& item) override;

        /**
         * @copydoc IViciAPI::end_list
         */
        void end_list(vici_req_t *req) override;

        /**
         * @copydoc IViciAPI::end_section
         */
        void end_section(vici_req_t *req) override;

        /**
         * @copydoc IViciAPI::free_req
         */
        void free_req(vici_req_t *req) override;

        /**
         * @copydoc IViciAPI::register_cb
         */
        int register_cb(vici_conn_t *conn, const char *name,
                        vici_event_cb_t cb, void *user) override;

        /**
         * @copydoc IViciAPI::parse_cb
         */
        int parse_cb(vici_res_t *res, vici_parse_section_cb_t section,
                     vici_parse_value_cb_t kv, vici_parse_value_cb_t li,
                     void *user) override;
};

#endif /* VICIAPI_H */