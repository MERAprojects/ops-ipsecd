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
#include <cstring>

/**********************************
*Local Includes
**********************************/
#include "IViciAPI.h"
#include "ViciList.h"
#include "ViciValue.h"
#include "IKEViciAPI.h"
#include "ViciSection.h"
#include "ops_ipsecd_helper.h"
#include "ops_ipsecd_vici_defs.h"

/**********************************
*Function Declarations
**********************************/

IKEViciAPI::IKEViciAPI(IViciAPI& vici_api, IViciStreamParser& viciParser)
    : m_vici_api(vici_api)
    , m_vici_stream_parser(viciParser)
{
}

IKEViciAPI::~IKEViciAPI()
{
    deinitialize();
}

void IKEViciAPI::deinitialize()
{
    if(!m_is_ready)
    {
        return;
    }

    if(m_vici_connection != nullptr)
    {
        m_vici_api.disconnect(m_vici_connection);
        m_vici_connection = nullptr;
    }

    m_vici_api.deinit();

    m_is_ready = false;
}

ipsec_ret IKEViciAPI::initialize()
{
    if(m_is_ready)
    {
        return ipsec_ret::OK;
    }

    m_vici_api.init();

    m_vici_connection = m_vici_api.connect(nullptr);
    if(m_vici_connection == nullptr)
    {
        m_vici_api.deinit();

        return ipsec_ret::SOCKET_OPEN_FAILED;
    }

    m_is_ready = true;

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::create_connection(const ipsec_ike_connection& conn)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    std::string sa_prop = "";
    std::string ike_prop = "";

    sa_prop = ipsecd_helper::cipher_integrity_group_to_str(
                                                conn.m_child_sa.m_cipher,
                                                conn.m_child_sa.m_integrity,
                                                conn.m_child_sa.m_diffie_group);

    ike_prop = ipsecd_helper::cipher_integrity_group_to_str(
                                                conn.m_cipher,
                                                conn.m_integrity,
                                                conn.m_diffie_group);

    vici_req_t* req = nullptr;
    vici_res_t* res = nullptr;

    //
    //Fill in the message to execute the command as in
    //https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
    //

    req = m_vici_api.begin(IPSEC_VICI_LOAD_CONN);

    m_vici_api.begin_section(req, conn.m_name.c_str());

    m_vici_api.begin_list(req, IPSEC_VICI_LOCAL_ADDRS);
    m_vici_api.add_list_item(req, conn.m_local_ip);
    m_vici_api.end_list(req); //End IPSEC_VICI_LOCAL_ADDRS

    m_vici_api.begin_list(req, IPSEC_VICI_REMOTE_ADDRS);
    m_vici_api.add_list_item(req, conn.m_remote_ip);
    m_vici_api.end_list(req); //End IPSEC_VICI_REMOTE_ADDRS

    m_vici_api.begin_list(req, IPSEC_VICI_PROPOSALS);
    m_vici_api.add_list_item(req, ike_prop);
    m_vici_api.end_list(req); //End IPSEC_VICI_PROPOSALS

    m_vici_api.add_key_value_str(req, IPSEC_VICI_VERSION,
                         ipsecd_helper::ike_version_to_str(conn.m_ike_version));

    m_vici_api.begin_section(req, IPSEC_VICI_CHILDREN);
    m_vici_api.begin_section(req, conn.m_name.c_str());

    m_vici_api.add_key_value_str(req, IPSEC_VICI_MODE,
                            ipsecd_helper::mode_to_str(conn.m_child_sa.m_mode));

    m_vici_api.begin_list(req, IPSEC_VICI_LOCAL_TS);
    m_vici_api.add_list_item(req, "dynamic");
    m_vici_api.end_list(req); //End IPSEC_VICI_LOCAL_TS

    m_vici_api.begin_list(req, IPSEC_VICI_REMOTE_TS);
    m_vici_api.add_list_item(req, "dynamic");
    m_vici_api.end_list(req); //End IPSEC_VICI_REMOTE_TS

    if(conn.m_child_sa.m_auth_method == ipsec_auth_method::ah)
    {
        m_vici_api.begin_list(req, IPSEC_VICI_AH_PROPOSALS);
        m_vici_api.add_list_item(req, sa_prop);
        m_vici_api.end_list(req); //End IPSEC_VICI_AH_PROPOSALS
    }
    else
    {
        m_vici_api.begin_list(req, IPSEC_VICI_ESP_PROPOSALS);
        m_vici_api.add_list_item(req, sa_prop);
        m_vici_api.end_list(req); //End IPSEC_VICI_ESP_PROPOSALS
    }

    m_vici_api.end_section(req); //End <Child Name>
    m_vici_api.end_section(req); //End IPSEC_VICI_CHILDREN


    m_vici_api.begin_section(req, IPSEC_VICI_LOCAL);
    m_vici_api.add_key_value_str(req, IPSEC_VICI_ID,
                             conn.m_local_peer.m_id);
    m_vici_api.add_key_value_str(req, IPSEC_VICI_AUTH,
                     ipsecd_helper::authby_to_str(conn.m_local_peer.m_auth_by));

    if(conn.m_local_peer.m_auth_by == ipsec_authby::pubkey)
    {
        m_vici_api.free_req(req);
        return ipsec_ret::ERR;
    }

    m_vici_api.end_section(req); //End IPSEC_VICI_LOCAL


    m_vici_api.begin_section(req, IPSEC_VICI_REMOTE);
    m_vici_api.add_key_value_str(req, IPSEC_VICI_ID,
                             conn.m_remote_peer.m_id);
    m_vici_api.add_key_value_str(req, IPSEC_VICI_AUTH,
                    ipsecd_helper::authby_to_str(conn.m_remote_peer.m_auth_by));

    if(conn.m_remote_peer.m_auth_by == ipsec_authby::pubkey)
    {
        m_vici_api.free_req(req);
        return ipsec_ret::ERR;
    }

    m_vici_api.end_section(req); //End IPSEC_VICI_REMOTE

    m_vici_api.end_section(req); //End <Connection Name>

    res = m_vici_api.submit(req, m_vici_connection);
    if (res != nullptr)
    {
        const char* success = m_vici_api.find_str(res, "", IPSEC_VICI_SUCCESS);

        if(strcmp(success, "yes") != 0)
        {
            //TODO: Add log
            //printf("error: %s\n", vici_find_str(res, "", IPSEC_VICI_ERRMSG));

            m_vici_api.free_res(res);

            return ipsec_ret::ADD_FAILED;
        }

        m_vici_api.free_res(res);
    }
    else
    {
        return ipsec_ret::ERR;
    }

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::delete_connection(const std::string& conn_name)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    if(conn_name.empty())
    {
        return ipsec_ret::EMPTY_STRING;
    }

    vici_req_t* req = nullptr;
    vici_res_t* res = nullptr;

    req = m_vici_api.begin(IPSEC_VICI_UNLOAD_CONN);

    m_vici_api.add_key_value_str(req, IPSEC_VICI_NAME, conn_name);

    res = m_vici_api.submit(req, m_vici_connection);
    if (res != nullptr)
    {
        const char* success = m_vici_api.find_str(res, "", IPSEC_VICI_SUCCESS);

        if(strcmp(success, "yes") != 0)
        {
            //TODO: Add log
            //printf("error: %s\n", vici_find_str(res, "", IPSEC_VICI_ERRMSG));

            m_vici_api.free_res(res);

            return ipsec_ret::DELETE_FAILED;
        }

        m_vici_api.free_res(res);
    }
    else
    {
        return ipsec_ret::ERR;
    }

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::start_connection(const std::string& conn_name,
                                       uint32_t timeout_ms)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    if(conn_name.empty())
    {
        return ipsec_ret::EMPTY_STRING;
    }

    vici_req_t *req = nullptr;
    vici_res_t *res = nullptr;

    //
    //Fill in the message to execute the command as in
    //https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
    //

    req = m_vici_api.begin(IPSEC_VICI_INITIATE);

    m_vici_api.add_key_value_str(req, IPSEC_VICI_CHILD, conn_name);
    m_vici_api.add_key_value_uint(req, IPSEC_VICI_TIMEOUT, timeout_ms);
    m_vici_api.add_key_value_uint(req, IPSEC_VICI_INIT_LIMITS, 1);
    m_vici_api.add_key_value_uint(req, IPSEC_VICI_LOG_LEVEL, 0);

    res = m_vici_api.submit(req, m_vici_connection);
    if (res != nullptr)
    {
        const char* success = m_vici_api.find_str(res, "", IPSEC_VICI_SUCCESS);

        if(strcmp(success, "yes") != 0)
        {
            //TODO: Add error to log
            //printf("error: %s\n", vici_find_str(res, "", IPSEC_VICI_ERRMSG));

            m_vici_api.free_res(res);

            return ipsec_ret::START_FAILED;
        }

        m_vici_api.free_res(res);
    }
    else
    {
        return ipsec_ret::ERR;
    }

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::stop_connection(const std::string& conn_name,
                                      uint32_t timeout_ms)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    if(conn_name.empty())
    {
        return ipsec_ret::EMPTY_STRING;
    }

    vici_req_t *req = nullptr;
    vici_res_t *res = nullptr;

    //
    //Fill in the message to execute the command as in
    //https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
    //

    req = m_vici_api.begin(IPSEC_VICI_TERMINATE);

    m_vici_api.add_key_value_str(req, IPSEC_VICI_IKE, conn_name);
    m_vici_api.add_key_value_uint(req, IPSEC_VICI_TIMEOUT, timeout_ms);
    m_vici_api.add_key_value_uint(req, IPSEC_VICI_LOG_LEVEL, 0);

    res = m_vici_api.submit(req, m_vici_connection);
    if (res != nullptr)
    {
        const char* success = m_vici_api.find_str(res, "", IPSEC_VICI_SUCCESS);

        if(strcmp(success, "yes") != 0)
        {
            //TODO: Add log error
            //printf("error: %s\n", vici_find_str(res, "", IPSEC_VICI_ERRMSG));

            m_vici_api.free_res(res);

            return ipsec_ret::STOP_FAILED;
        }

        m_vici_api.free_res(res);
    }
    else
    {
        return ipsec_ret::ERR;
    }

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::load_credential(const ipsec_credential& cred)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    vici_req_t* req = nullptr;
    vici_res_t* res = nullptr;

    //
    //Fill in the message to execute the command as in
    //https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
    //

    if(cred.m_cred_type == ipsec_credential_type::psk)
    {
        req = m_vici_api.begin(IPSEC_VICI_LOAD_SHARED);

        m_vici_api.add_key_value_str(req, IPSEC_VICI_DATA,
                                     cred.m_psk);

        //TODO: Missing Owners
    }
    else
    {
        req = m_vici_api.begin(IPSEC_VICI_LOAD_KEY);

        m_vici_api.add_key_value(req, IPSEC_VICI_DATA,
                                 cred.m_rsa.m_data,
                                 cred.m_rsa.m_len);
    }

    m_vici_api.add_key_value_str(req, IPSEC_VICI_TYPE,
                                 ipsecd_helper::cred_to_str(cred.m_cred_type));

    res = m_vici_api.submit(req, m_vici_connection);
    if (res != nullptr)
    {
        const char* success = m_vici_api.find_str(res, "", IPSEC_VICI_SUCCESS);

        if(strcmp(success, "yes") != 0)
        {
            //TODO: add log
            //printf("error: %s\n", m_vici_api.find_str(res, "", IPSEC_VICI_ERRMSG));

            m_vici_api.free_res(res);

            return ipsec_ret::ADD_FAILED;
        }

        m_vici_api.free_res(res);
    }
    else
    {
        return ipsec_ret::ERR;
    }

    return ipsec_ret::OK;
}

ipsec_ret IKEViciAPI::get_connection_stats(const std::string& conn_name,
                                           ipsec_ike_connection_stats& stats)
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    vici_req_t* req = nullptr;
    vici_res_t* res = nullptr;

    //
    //Fill in the message to execute the command as in
    //https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
    //

    if(m_vici_stream_parser.register_stream_cb(m_vici_connection,
                                    IPSEC_VICI_LIST_SA_EVENT) != ipsec_ret::OK)
    {
        return ipsec_ret::REGISTER_FAILED;
    }

    req = m_vici_api.begin(IPSEC_VICI_LIST_SAS);
    m_vici_api.add_key_value_str(req, IPSEC_VICI_IKE, conn_name);

    res = m_vici_api.submit(req, m_vici_connection);
    if (res == nullptr)
    {
        m_vici_stream_parser.unregister_stream_cb();
        return ipsec_ret::ERR;
    }

    m_vici_api.free_res(res);
    m_vici_stream_parser.unregister_stream_cb();

    if(m_vici_stream_parser.get_parse_status() != ipsec_ret::OK)
    {
        return m_vici_stream_parser.get_parse_status();
    }

    const ViciSection& answer = m_vici_stream_parser.get_vici_answer();

    ViciSection* section = answer.get_item_type<ViciSection>(conn_name);
    if(section == nullptr)
    {
        return ipsec_ret::NOT_FOUND;
    }

    ViciValue* value = nullptr;
    stats = ipsec_ike_connection_stats();

    stats.m_conn_name = conn_name;

    //Main IKE Section
    value = section->get_item_type<ViciValue>(IPSEC_VICI_ESTABLISHED_KEY);
    if(value != nullptr)
    {
        stats.m_establish_secs = std::stoul(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_REKEY_TIME_KEY);
    if(value != nullptr)
    {
        stats.m_rekey_time = std::stoul(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_INIT_SPI_KEY);
    if(value != nullptr)
    {
        stats.m_initiator_spi = std::stoull(value->get_value(), nullptr, 16);
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_RESP_SPI_KEY);
    if(value != nullptr)
    {
        stats.m_responder_spi = std::stoull(value->get_value(), nullptr, 16);
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_STATE_KEY);
    if(value != nullptr)
    {
        stats.m_conn_state =
                ipsecd_helper::ike_state_to_ipsec_state(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    //Child SA Section
    section = section->get_item_type<ViciSection>(IPSEC_VICI_CHILD_SAS_KEY);
    if(section == nullptr)
    {
        return ipsec_ret::PARSE_ERR;
    }

    section = section->get_item_type<ViciSection>(conn_name);
    if(section == nullptr)
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_LIFE_TIME_KEY);
    if(value != nullptr)
    {
        stats.m_sa_lifetime = std::stoul(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_REKEY_TIME_KEY);
    if(value != nullptr)
    {
        stats.m_sa_rekey = std::stoul(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_BYTES_IN_KEY);
    if(value != nullptr)
    {
        stats.m_bytes_in = std::stoull(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_BYTES_OUT_KEY);
    if(value != nullptr)
    {
        stats.m_bytes_out = std::stoull(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_PACKETS_IN_KEY);
    if(value != nullptr)
    {
        stats.m_packets_in = std::stoull(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_PACKETS_OUT_KEY);
    if(value != nullptr)
    {
        stats.m_packets_out = std::stoull(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_SPI_IN_KEY);
    if(value != nullptr)
    {
        stats.m_sa_spi_in = std::stoull(value->get_value(), nullptr, 16);
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_SPI_OUT_KEY);
    if(value != nullptr)
    {
        stats.m_sa_spi_out = std::stoull(value->get_value(), nullptr, 16);
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    value = section->get_item_type<ViciValue>(IPSEC_VICI_STATE_KEY);
    if(value != nullptr)
    {
        stats.m_sa_state =
                ipsecd_helper::ike_state_to_ipsec_state(value->get_value());
    }
    else
    {
        return ipsec_ret::PARSE_ERR;
    }

    return ipsec_ret::OK;
}