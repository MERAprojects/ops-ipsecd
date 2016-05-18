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
#include "IIKEAPI.h"
#include "StatPublisher.h"
#include "IIPsecAPI.h"

/**********************************
*Function Declarations
**********************************/
StatPublisher::StatPublisher(IIKEAPI& ike_api, IIPsecAPI& ipsec_api)
    : m_ike_api(ike_api)
    , m_ipsec_api(ipsec_api)
{
}

StatPublisher::~StatPublisher()
{
    stop_thread();
}

ipsec_ret StatPublisher::start_thread()
{
    std::lock_guard<std::mutex> lock(m_publisher_mutex);

    if(m_is_running)
    {
        return ipsec_ret::IS_RUNNING;
    }

    m_is_running = true;

    m_publisher_thread = std::thread(&StatPublisher::run_publisher, this);

    return ipsec_ret::OK;
}

ipsec_ret StatPublisher::stop_thread()
{
    std::lock_guard<std::mutex> lock(m_publisher_mutex);

    if(!m_is_running)
    {
        return ipsec_ret::NOT_RUNNING;
    }

    m_is_running = false;

    if(m_publisher_thread.joinable())
    {
        m_publisher_thread.join();
    }

    return ipsec_ret::OK;
}

void StatPublisher::run_publisher()
{
    while(m_is_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        ++m_current_ticks;

        if((m_current_ticks / 4) < m_publish_time_sec)
        {
            continue;
        }

        m_current_ticks = 0;

        std::lock_guard<std::mutex> lock(m_publisher_list_mutex);

        for(auto stat_id : m_pub_list)
        {
            if(publish_stat(stat_id) != ipsec_ret::OK)
            {
                //TODO: add log
            }
        }
    }
}

ipsec_ret StatPublisher::publish_stat(const ipsec_stat_pub& stat_ipsec)
{
    switch(stat_ipsec.m_type)
    {
        case ipsec_type::sa:
            {
                ipsec_sa sa;

                if(m_ipsec_api.get_sa(stat_ipsec.m_sa_spi, sa) != ipsec_ret::OK)
                {
                    return ipsec_ret::ERR;
                }

                //TODO: publish to OVSDB
            }
            break;

        case ipsec_type::sp:
            {
                ipsec_sp sp;

                if(m_ipsec_api.get_sp(stat_ipsec.m_sp_id, sp) != ipsec_ret::OK)
                {
                    return ipsec_ret::ERR;
                }

                //TODO: publish to OVSDB
            }
            break;

        case ipsec_type::ike:
            {
                ipsec_ike_connection_stats ike_stats;

                if (m_ike_api.get_connection_stats(stat_ipsec.m_ike_name,
                                                  ike_stats) != ipsec_ret::OK)
                {
                    return ipsec_ret::ERR;
                }

                //TODO: publish to OVSDB
            }
            break;

        default:
            return ipsec_ret::ERR;
    };

    return ipsec_ret::OK;
}

ipsec_ret StatPublisher::add_ipsec_stat(const ipsec_stat_pub& stat_ipsec)
{
    std::lock_guard<std::mutex> lock(m_publisher_list_mutex);

    m_pub_list.push_back(stat_ipsec);

    return ipsec_ret::OK;
}

ipsec_ret StatPublisher::remove_ipsec_stat(const ipsec_stat_pub& stat_ipsec)
{
    std::lock_guard<std::mutex> lock(m_publisher_list_mutex);

    m_pub_list.remove(stat_ipsec);

    return ipsec_ret::OK;
}
