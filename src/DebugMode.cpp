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
#include <iostream>

/**********************************
*Local Includes
**********************************/
#include "DebugMode.h"

/**
* Initialize static member
*/
DebugMode *DebugMode::m_debugger = nullptr;

DebugMode::DebugMode(IKEViciAPI& ikeviciApi, IPsecNetlinkAPI& ipsecNetlink,
        IPsecOvsdb& ipsec_ovsdb, int argc, char **argv)
        : m_ikeviciApi(ikeviciApi), m_ipsecNetlink(ipsecNetlink),
        m_ipsec_ovsdb(ipsec_ovsdb)
{
    argc_d = argc;
    argv_d = &argv[0];
    m_unixcmds->set_unixclt_server(argc_d,(char **)argv_d, NULL);
}

bool DebugMode::isEnable()
{
    return d_enable;
}

bool DebugMode::uccIsRunning()
{
    return m_unixcmds->uccIsRunning();
}

void DebugMode::set_Enable(bool state)
{
    d_enable = state;
}

void DebugMode::ucc_run()
{
    m_unixcmds->run_unixctl();
}

void DebugMode::ucc_wait()
{
    m_unixcmds->wait_unixctl();
}

void DebugMode::ucc_destroy()
{
    m_unixcmds->destroy_unixctl();
}

ipsec_ret DebugMode::create_connection(const ipsec_ike_connection& conn)
{
    return m_ikeviciApi.create_connection(conn);
}

ipsec_ret DebugMode::stop_connection(const std::string& conn_name,
        uint32_t timeout_ms)
{
    return m_ikeviciApi.stop_connection(conn_name, timeout_ms);
}

ipsec_ret DebugMode::delete_connection(const std::string& conn_name)
{
    return m_ikeviciApi.delete_connection(conn_name);
}

ipsec_ret DebugMode::start_connection(const std::string& conn_name,
        uint32_t timeout_ms)
{
    return m_ikeviciApi.start_connection(conn_name, timeout_ms);
}

ipsec_ret DebugMode::get_connection_stats(const std::string& conn_name,
        ipsec_ike_connection_stats& stats)
{
    return m_ikeviciApi.get_connection_stats(conn_name, stats);
}

ipsec_ret DebugMode::load_credential(const ipsec_credential& cred)
{
    return m_ikeviciApi.load_credential(cred);
}

ipsec_ret DebugMode::add_sa(const ipsec_sa& sa)
{
    ipsec_ret result =  ipsec_ret::ERR;
    result = m_ipsecNetlink.add_sa(sa);
    if(result != ipsec_ret::OK)
    {
        return result;
    }
    return  m_ipsec_ovsdb.ipsec_manual_sa_insert_row(sa);
}

ipsec_ret  DebugMode::get_sa(uint32_t spi, ipsec_sa& sa)
{
    //m_ipsecNetlink.get_sa(spi, sa);
    return m_ipsec_ovsdb.ipsec_manual_sa_get_row(spi, sa);
}

ipsec_ret  DebugMode::del_sa(const ipsec_sa_id& id)
{
    ipsec_ret result = ipsec_ret::ERR;
    result = m_ipsecNetlink.del_sa(id);
    if(result != ipsec_ret::OK)
    {
        return result;
    }
    return m_ipsec_ovsdb.ipsec_manual_sa_delete_row(id);
}

ipsec_ret  DebugMode::add_sp(const ipsec_sp& sp)
{
    ipsec_ret result = ipsec_ret::ERR;
    result = m_ipsecNetlink.add_sp(sp);
    if(result != ipsec_ret::OK)
    {
        return result;
    }
    return m_ipsec_ovsdb.ipsec_manual_sp_insert_row(sp);
}

ipsec_ret  DebugMode::get_sp(const ipsec_sp_id& sp_id, ipsec_sp& sp)
{
    //m_ipsecNetlink.get_sp(sp_id, sp);
    return m_ipsec_ovsdb.ipsec_manual_sp_get_row(sp_id.m_dir,
            sp_id.m_selector, sp);
}

ipsec_ret  DebugMode::del_sp(const ipsec_sp_id& sp_id)
{
    ipsec_ret result = ipsec_ret::ERR;
    result = m_ipsecNetlink.del_sp(sp_id);
    if(result != ipsec_ret::OK)
    {
        return result;
    }
    return m_ipsec_ovsdb.ipsec_manual_sp_delete_row(
            sp_id.m_dir, sp_id.m_selector);
}
