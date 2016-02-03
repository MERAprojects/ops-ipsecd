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
*Local Includes
**********************************/
#include "ViciAPI.h"

ViciAPI::ViciAPI() {
}

ViciAPI::~ViciAPI() {
}

void ViciAPI::init()
{
    vici_init();
}

void ViciAPI::deinit()
{
    vici_deinit();
}

vici_conn_t* ViciAPI::connect(const char *uri)
{
    return vici_connect((char*)uri);
}

void ViciAPI::disconnect(vici_conn_t *conn)
{
    vici_disconnect(conn);
}

vici_req_t* ViciAPI::begin(const char *name)
{
    return vici_begin((char*)name);
}

void ViciAPI::add_key_value_str(vici_req_t *req, const char *key,
                                const std::string& value)
{
    vici_add_key_valuef(req, (char*)key, (char*)"%s", value.c_str());
}

void ViciAPI::add_key_value_uint(vici_req_t *req, const char *key,
                                 uint32_t value)
{
    vici_add_key_valuef(req, (char*)key, (char*)"%u", value);
}

void ViciAPI::add_key_value(vici_req_t *req, const char *key,
                           const void* data, uint32_t len)
{
    vici_add_key_value(req, (char*)key, (void*)data, len);
}

vici_res_t* ViciAPI::submit(vici_req_t *req, vici_conn_t *conn)
{
    return vici_submit(req, conn);
}

const char* ViciAPI::find_str(vici_res_t *res, const char *def, const char *fmt)
{
    return vici_find_str(res, (char*)def, (char*)fmt);
}

void ViciAPI::free_res(vici_res_t *res)
{
    vici_free_res(res);
}

void ViciAPI::begin_section(vici_req_t *req, const char *name)
{
    vici_begin_section(req, (char*)name);
}

void ViciAPI::begin_list(vici_req_t *req, const char *name)
{
    vici_begin_list(req, (char*)name);
}

void ViciAPI::add_list_item(vici_req_t *req,
                            const std::string& item)
{
    vici_add_list_itemf(req, (char*)item.c_str());
}

void ViciAPI::end_list(vici_req_t *req)
{
    vici_end_list(req);
}

void ViciAPI::end_section(vici_req_t *req)
{
    vici_end_section(req);
}

void ViciAPI::free_req(vici_req_t *req)
{
    vici_free_req(req);
}

int ViciAPI::register_cb(vici_conn_t *conn, const char *name,
                         vici_event_cb_t cb, void *user)
{
    return vici_register(conn, (char*)name, cb, user);
}

int ViciAPI::parse_cb(vici_res_t *res, vici_parse_section_cb_t section,
                      vici_parse_value_cb_t kv, vici_parse_value_cb_t li,
                      void *user)
{
    return vici_parse_cb(res, section, kv, li, user);
}