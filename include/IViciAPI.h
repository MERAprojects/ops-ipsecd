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

#ifndef IVICIAPI_H
#define IVICIAPI_H

/**********************************
*System Includes
**********************************/
#include <string>
#include <stdint.h>

extern "C"
{
#include <libvici.h>
}

/**
 * Base Interface class for Vici API Layer, primarily use for
 * mocking for unit tests
 */
class IViciAPI
{
    public:

        /**
         * Default Constructor
         */
        IViciAPI() {}

        /**
         * Default Destructor
         */
        virtual ~IViciAPI() {}

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_init
         */
        virtual void init() = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_deinit
         */
        virtual void deinit() = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_connect
         */
        virtual vici_conn_t* connect(const char *uri) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_disconnect
         */
        virtual void disconnect(vici_conn_t *conn) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_begin
         */
        virtual vici_req_t* begin(const char *name) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_add_key_value_str
         */
        virtual void add_key_value_str(vici_req_t *req, const char *key,
                                       const std::string& value) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_add_key_value_uint
         */
        virtual void add_key_value_uint(vici_req_t *req, const char *key,
                                        uint32_t value) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_add_key_value
         */
        virtual void add_key_value(vici_req_t *req, const char *key,
                                   const void* data, uint32_t len) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_submit
         */
        virtual vici_res_t* submit(vici_req_t *req, vici_conn_t *conn) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_find_str
         */
        virtual const char* find_str(vici_res_t *res, const char *def,
                                     const char *fmt) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_free_res
         */
        virtual void free_res(vici_res_t *res) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_begin_section
         */
        virtual void begin_section(vici_req_t *req, const char *name) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_begin_list
         */
        virtual void begin_list(vici_req_t *req, const char *name) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_add_list_item
         */
        virtual void add_list_item(vici_req_t *req,
                                   const std::string& item) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_end_list
         */
        virtual void end_list(vici_req_t *req) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_end_section
         */
        virtual void end_section(vici_req_t *req) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_free_req
         */
        virtual void free_req(vici_req_t *req) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_register
         */
        virtual int register_cb(vici_conn_t *conn, const char *name,
                                vici_event_cb_t cb, void *user) = 0;

        /**
         * Refer to https://fossies.org/dox/strongswan-5.3.5/group__vici.html
         * vici_parse_cb
         */
        virtual int parse_cb(vici_res_t *res, vici_parse_section_cb_t section,
                             vici_parse_value_cb_t kv, vici_parse_value_cb_t li,
                             void *user) = 0;
};

#endif /* IVICIAPI_H */