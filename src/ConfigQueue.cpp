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
#include "IIPsecAPI.h"
#include "ConfigTask.h"
#include "ConfigQueue.h"
#include "ConfigTaskSA.h"
#include "ConfigTaskSP.h"
#include "ConfigTaskCA.h"
#include "ConfigTaskIKE.h"

/**********************************
*Function Declarations
**********************************/
ConfigQueue::ConfigQueue(IIKEAPI& ike_api, IIPsecAPI& ipsec_api)
    : m_ike_api(ike_api)
    , m_ipsec_api(ipsec_api)
{
}

ConfigQueue::~ConfigQueue()
{
    stop_thread();

    clean();
}

void ConfigQueue::clean()
{
    std::lock_guard<std::mutex> lock(m_config_queue_mutex);

    while(!m_task_queue.empty())
    {
        ConfigTask* task = m_task_queue.front();

        m_task_queue.pop();

        DeleteMem(task);
    }
}

void ConfigQueue::run_config_dispatcher()
{
    ConfigTask* task = nullptr;

    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(m_config_queue_mutex);

            m_task_conditional.wait(
                lock, [this]{return !m_task_queue.empty() || !m_is_running; });

            if (m_task_queue.empty() && !m_is_running)
            {
                break;
            }

            task = m_task_queue.front();

            m_task_queue.pop();
        }

        run_config_task(task);

        DeleteMem(task);
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

void ConfigQueue::run_config_task(const ConfigTask* task)
{
    switch(task->get_type())
    {
        case ipsec_type::sa:
            {
                const ConfigTaskSA* sa_task =
                        dynamic_cast<const ConfigTaskSA*>(task);
                sa_config_task(sa_task);
            }
            break;

        case ipsec_type::sp:
            {
                const ConfigTaskSP* sp_task =
                        dynamic_cast<const ConfigTaskSP*>(task);
                sp_config_task(sp_task);
            }
            break;

        case ipsec_type::ike:
            {
                const ConfigTaskIKE* ike_task =
                        dynamic_cast<const ConfigTaskIKE*>(task);
                ike_config_task(ike_task);
            }
            break;

        case ipsec_type::ca:
            {
                const ConfigTaskCA* ca_task =
                        dynamic_cast<const ConfigTaskCA*>(task);
                ca_config_task(ca_task);
            }
            break;

        default:
            //TODO: Add Log
            break;
    }
}

void ConfigQueue::ike_config_task(const ConfigTaskIKE* task)
{
    if(task == nullptr)
    {
        //TODO: Add log

        return;
    }

    ipsec_ret ret = ipsec_ret::OK;

    switch(task->get_config_action())
    {
        case ipsec_config_action::add:
        case ipsec_config_action::modify:

            ret = m_ike_api.create_connection(task->get_ike_connection());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        case ipsec_config_action::remove:

            ret = m_ike_api.delete_connection(task->get_ike_connection().m_name);

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }

            break;

        default:
            //TODO: Add Log
            break;
    }
}

void ConfigQueue::ca_config_task(const ConfigTaskCA* task)
{
    if(task == nullptr)
    {
        //TODO: Add log

        return;
    }

    ipsec_ret ret = ipsec_ret::OK;

    switch(task->get_config_action())
    {
        case ipsec_config_action::add:
        case ipsec_config_action::modify:

            ret = m_ike_api.load_authority(task->get_ca());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
            }

            break;

        case ipsec_config_action::remove:

            ret = m_ike_api.unload_authority(task->get_ca().m_name);

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
            }

            break;

        default:
            //TODO: Add Log
            break;
    }
}

void ConfigQueue::sa_config_task(const ConfigTaskSA* task)
{
    if(task == nullptr)
    {
        //TODO: Add log

        return;
    }

    ipsec_ret ret = ipsec_ret::OK;

    switch(task->get_config_action())
    {
        case ipsec_config_action::add:

            ret = m_ipsec_api.add_sa(task->get_sa());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        case ipsec_config_action::modify:

            ret = m_ipsec_api.modify_sa(task->get_sa());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        case ipsec_config_action::remove:

            ret = m_ipsec_api.del_sa(task->get_sa().m_id);

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        default:
            //TODO: Add Log
            break;
    }
}

void ConfigQueue::sp_config_task(const ConfigTaskSP* task)
{
    if(task == nullptr)
    {
        //TODO: Add log

        return;
    }

    ipsec_ret ret = ipsec_ret::OK;

    switch(task->get_config_action())
    {
        case ipsec_config_action::add:

            ret = m_ipsec_api.add_sp(task->get_sp());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        case ipsec_config_action::modify:

            ret = m_ipsec_api.modify_sp(task->get_sp());

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        case ipsec_config_action::remove:

            ret = m_ipsec_api.del_sp(task->get_sp().m_id);

            if(ret != ipsec_ret::OK)
            {
                //TODO: add log
                //TODO: Send Status to OVSDB
            }
            else
            {
                //TODO: Send Status to OVSDB
            }

            break;

        default:
            //TODO: Add Log
            break;
    }
}

ipsec_ret ConfigQueue::add_task(ConfigTask* task)
{
    if(task == nullptr)
    {
        return ipsec_ret::NULL_PARAMETERS;
    }

    {
        std::lock_guard<std::mutex> lock(m_config_queue_mutex);

        m_task_queue.push(task);
    }

    m_task_conditional.notify_one();

    return ipsec_ret::OK;
}
