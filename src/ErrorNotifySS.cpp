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
#include <string>
#include <sstream>
#include <sys/un.h>
#include <arpa/inet.h>

/**********************************
*Local Includes
**********************************/
#include "ErrorNotifySS.h"
#include "ops_ipsecd_helper.h"

/**********************************
*Function Declarations
**********************************/
ErrorNotifySS::ErrorNotifySS(ISystemCalls& system_calls, IErrorListener& error_listener)
    : m_system_calls(system_calls)
    , m_error_listener(error_listener)
{
}

ErrorNotifySS::~ErrorNotifySS()
{
    cleanup();
}

void ErrorNotifySS::cleanup(bool join_thread)
{
    m_is_running = false;

    if(join_thread && m_error_thread.joinable())
    {
        m_error_thread.join();
    }

    m_is_ready = false;

    if(m_conn != 0)
    {
        m_system_calls.s_close(m_conn);
        m_conn = 0;
    }
}

ipsec_ret ErrorNotifySS::initialize()
{
    if(m_is_ready)
    {
        return ipsec_ret::OK;
    }

    int len = 0;
    int ret = 0;
    struct sockaddr_un unix_socket = { 0 };

    ///////////////
    //Set Socket Properties
    unix_socket.sun_family = AF_UNIX;
    strncpy(unix_socket.sun_path, ERROR_NOTIFY_SOCKET, 108);

    len = strlen(unix_socket.sun_path) + sizeof(unix_socket.sun_family);

    ///////////////
    //Create Socket
    m_conn = m_system_calls.s_socket(unix_socket.sun_family, SOCK_STREAM, 0);
    if(m_conn < 0)
    {
        return ipsec_ret::SOCKET_CREATE_FAILED;
    }

    ret = m_system_calls.s_connect(m_conn, (struct sockaddr*)&unix_socket, len);
    if(ret < 0)
    {
        return ipsec_ret::SOCKET_CONNECT_FAILED;
    }

    m_is_running = true;
    m_is_ready = true;

    m_error_thread = std::thread(&ErrorNotifySS::run_error_receiver, this);

    return ipsec_ret::OK;
}

ipsec_ret ErrorNotifySS::run_error_receiver()
{
    if(!m_is_ready)
    {
        return ipsec_ret::NOT_READY;
    }

    if(!m_is_running)
    {
        return ipsec_ret::NOT_RUNNING;
    }

    error_notify_msg_t msg;
    const ssize_t size = sizeof(error_notify_msg_t);
    uint8_t* pos = nullptr;
    ssize_t total = 0;
    ssize_t len = 0;

    while(m_is_running)
    {
        total = 0;
        pos = (uint8_t*)&msg;

        while(total < size)
        {
            len = m_system_calls.s_read(m_conn, pos, size - total);
            if(len < 0)
            {
                //TODO: Log error: strerror(errno)

                cleanup();

                return ipsec_ret::ERR;
            }

            total += len;
            pos += len;
        }

        if(!m_is_running || len < size)
        {
            continue;
        }

        process_error(msg);
    }

    return ipsec_ret::OK;
}

void ErrorNotifySS::process_error(const error_notify_msg_t& msg)
{
    ipsec_error err;
    std::stringstream ss;

    err.m_connection = msg.name;

    if(strlen(msg.id) != 0)
    {
        ss << "Peer '" << msg.id << "'";
    }
    else
    {
        ss << "Peer";
    }

    ss << " with connection name '" << msg.name << "'";

    if(strlen(msg.ip) != 0)
    {
        ss << " and address of '" << msg.ip << "'";
    }

    ss << " encountered an error";

    err.m_msg = ss.str();

    err.m_error = msg.str;

    err.m_error_event = ipsecd_helper::ss_error_to_ipsec_error_event(msg.type);

    m_error_listener.error_event(err);
}
