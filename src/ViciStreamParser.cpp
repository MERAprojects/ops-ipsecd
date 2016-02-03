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
#include "IViciAPI.h"
#include "ViciList.h"
#include "ViciValue.h"
#include "ViciSection.h"
#include "ViciStreamParser.h"

/**********************************
*Local Includes
**********************************/

ViciStreamParser::ViciStreamParser(IViciAPI& vici_api)
    : m_vici_api(vici_api)
{
}

ViciStreamParser::~ViciStreamParser()
{
    unregister_stream_cb();
}

int ViciStreamParser::parse_section(void* user, vici_res_t* res, char* name)
{
    DataCB* data_cb = reinterpret_cast<DataCB*>(user);
    if(data_cb == nullptr)
    {
        return -1;
    }

    ViciSection* section = data_cb->m_section;
    ViciSection* subSection = new ViciSection();
    subSection->set_name(name);
    section->set_item(name, subSection);

    data_cb->m_section = subSection;

    return data_cb->m_vici_api->parse_cb(res,
                                         ViciStreamParser::parse_section,
                                         ViciStreamParser::parse_key_value,
                                         ViciStreamParser::parse_list_item,
                                         data_cb);
}

int ViciStreamParser::parse_key_value(void* user, vici_res_t* res, char* name,
                                      void* value, int len)
{
    DataCB* data_cb = reinterpret_cast<DataCB*>(user);
    if(data_cb == nullptr)
    {
        return -1;
    }

    ViciSection* section = data_cb->m_section;
    ViciValue* itemValue = new ViciValue();
    std::string valueStr = "";
    valueStr.append((char*)value, len);

    itemValue->set_value(valueStr);

    section->set_item(name, itemValue);

    return data_cb->m_vici_api->parse_cb(res,
                                         ViciStreamParser::parse_section,
                                         ViciStreamParser::parse_key_value,
                                         ViciStreamParser::parse_list_item,
                                         data_cb);
}

int ViciStreamParser::parse_list_item(void* user, vici_res_t* res, char* name,
                                      void* value, int len)
{
    DataCB* data_cb = reinterpret_cast<DataCB*>(user);
    if(data_cb == nullptr)
    {
        return -1;
    }

    ViciSection* section = data_cb->m_section;
    ViciList* list = reinterpret_cast<ViciList*>(section->get_item(name));
    if(list == nullptr)
    {
        list = new ViciList();
        section->set_item(name, list);
    }

    std::string valueStr = "";
    valueStr.append((char*)value, len);

    list->add_value(valueStr);

    return data_cb->m_vici_api->parse_cb(res,
                                         ViciStreamParser::parse_section,
                                         ViciStreamParser::parse_key_value,
                                         ViciStreamParser::parse_list_item,
                                         data_cb);
}

void ViciStreamParser::event_cb(void* user, char* name, vici_res_t* res)
{
    ViciStreamParser* parser = reinterpret_cast<ViciStreamParser*>(user);
    if(parser == nullptr)
    {
        return;
    }

    DataCB data_cb;
    data_cb.m_section = &parser->m_vici_section;
    data_cb.m_vici_api = &parser->m_vici_api;

    parser->m_vici_section.set_name(name);

    if( parser->m_vici_api.parse_cb(res,
                                    ViciStreamParser::parse_section,
                                    ViciStreamParser::parse_key_value,
                                    ViciStreamParser::parse_list_item,
                                    &data_cb) != 0)
    {
        parser->m_parse_status = ipsec_ret::PARSE_ERR;
    }
    else
    {
        parser->m_parse_status = ipsec_ret::OK;
    }
}

ipsec_ret ViciStreamParser::register_stream_cb(vici_conn_t* conn,
                                               const std::string& name)
{
    if(conn == nullptr)
    {
        return ipsec_ret::NULL_PARAMETERS;
    }

    if(name.empty())
    {
        return ipsec_ret::EMPTY_STRING;
    }

    if(m_conn_registered != nullptr)
    {
        unregister_stream_cb();
    }

    m_parse_status = ipsec_ret::NOT_PARSE;
    m_vici_section.clear();

    if(m_vici_api.register_cb(conn, name.c_str(), ViciStreamParser::event_cb,
                              this) != 0)
    {
        return ipsec_ret::REGISTER_FAILED;
    }

    m_event_registered = name;
    m_conn_registered = conn;

    return ipsec_ret::OK;
}

void ViciStreamParser::unregister_stream_cb()
{
    if(m_conn_registered == nullptr)
    {
        return;
    }

    m_vici_api.register_cb(m_conn_registered,
                           m_event_registered.c_str(), nullptr, nullptr);

    m_event_registered.clear();
    m_conn_registered = nullptr;
}
