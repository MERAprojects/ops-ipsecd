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
#include "ConfigQueue.h"

/**********************************
*Function Declarations
**********************************/
ConfigQueue::ConfigQueue(IIKEAPI& ike_api)
    : m_ike_api(ike_api)
{
}

ConfigQueue::~ConfigQueue()
{
}

void ConfigQueue::run_config_dispatcher()
{
    ConfigTask task;

    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(m_config_queue_mutex);

            m_task_conditional.wait(
                lock, [this]{return !m_task_queue.empty() || !m_is_running; });

            if (!m_is_running)
            {
                    break;
            }

            task = m_task_queue.front();

            m_task_queue.pop();
        }

        run_config_task(task);
    }
}

ipsec_ret ConfigQueue::start_thread()
{
    std::lock_guard<std::mutex> lock(m_config_task_mutex);

    if(m_is_running)
    {
        return ipsec_ret::IS_RUNNING;
    }

    m_is_running = true;

    m_config_thread = std::thread(&ConfigQueue::run_config_dispatcher, this);

    return ipsec_ret::OK;
}

ipsec_ret ConfigQueue::stop_thread()
{
    std::lock_guard<std::mutex> lock(m_config_task_mutex);

    if (!m_is_running)
    {
        return ipsec_ret::NOT_RUNNING;
    }

    m_is_running = false;

    m_task_conditional.notify_all();

    if(m_config_thread.joinable())
    {
        m_config_thread.join();
    }

    return ipsec_ret::OK;
}

void ConfigQueue::run_config_task(const ConfigTask& task)
{
}

void ConfigQueue::add_task(const ConfigTask& task)
{
    {
        std::lock_guard<std::mutex> lock(m_config_queue_mutex);

        m_task_queue.push(task);
    }

    m_task_conditional.notify_one();
}
