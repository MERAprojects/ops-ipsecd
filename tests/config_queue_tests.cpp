/*
 *  (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

/**********************************
*System Includes
**********************************/
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gtest/gtest.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ConfigTask.h"
#include "ConfigQueue.h"
#include "ConfigTaskSA.h"
#include "ConfigTaskSP.h"
#include "ConfigTaskCA.h"
#include "ConfigTaskIKE.h"
#include "mocks/mock_IIKEAPI.h"
#include "mocks/mock_IIPsecAPI.h"

/**********************************
*Using
**********************************/
using ::testing::_;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Test;
using ::testing::StrEq;
using ::testing::IsNull;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::SetArgPointee;

class ConfigQueue_EnO : public ConfigQueue
{
    public:
        ConfigQueue_EnO(IIKEAPI& ike_api, IIPsecAPI& ipsec_api)
            : ConfigQueue(ike_api, ipsec_api)
        {
        }

        std::queue<ConfigTask*>& get_task_queue()
        {
            return m_task_queue;
        }

        void call_clean()
        {
            clean();
        }

        bool get_is_running() const
        {
            return m_is_running;
        }

        void set_is_running(bool value)
        {
            m_is_running = value;
        }
};

class ConfigQueueTestSuite : public Test
{
    public:

        MockIIKEAPI m_ike_api;
        MockIIPsecAPI m_ipsec_api;
        ConfigQueue_EnO m_config_queue;

        ConfigQueueTestSuite()
            : m_config_queue(m_ike_api, m_ipsec_api)
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
            m_config_queue.stop_thread();
            m_config_queue.call_clean();
        }
};

/**
 * Objective: Verify that clean will erase the queue objects
 **/
TEST_F(ConfigQueueTestSuite, TestClean)
{
    EXPECT_FALSE(m_config_queue.get_is_running());

    std::queue<ConfigTask*>& confQueue = m_config_queue.get_task_queue();

    EXPECT_EQ(confQueue.size(), 0);

    ConfigTaskIKE* ikeTask = new ConfigTaskIKE(ipsec_config_action::add,
                                               ipsec_ike_connection());

    ConfigTaskCA* caTask = new ConfigTaskCA(ipsec_config_action::add,
                                               ipsec_ca());

    EXPECT_EQ(m_config_queue.add_task(ikeTask), ipsec_ret::OK);
    EXPECT_EQ(confQueue.size(), 1);
    EXPECT_EQ(m_config_queue.add_task(caTask), ipsec_ret::OK);
    EXPECT_EQ(confQueue.size(), 2);

    m_config_queue.call_clean();

    EXPECT_EQ(confQueue.size(), 0);
}

/**
 * Objective: Verify that a ConfigTask Object can be added to the queue
 **/
TEST_F(ConfigQueueTestSuite, TestAddTask)
{
    EXPECT_FALSE(m_config_queue.get_is_running());

    std::queue<ConfigTask*>& confQueue = m_config_queue.get_task_queue();

    EXPECT_EQ(confQueue.size(), 0);

    ipsec_ike_connection ike_conn;
    ike_conn.m_cipher = ipsec_cipher::cipher_aes256;
    ike_conn.m_ike_version = ipsec_ike_version::v1v2;
    ike_conn.m_local_ip = "local";

    ConfigTaskIKE* ikeTask = new ConfigTaskIKE(ipsec_config_action::remove,
                                               ike_conn);

    EXPECT_EQ(m_config_queue.add_task(ikeTask), ipsec_ret::OK);
    EXPECT_EQ(confQueue.size(), 1);

    ConfigTaskIKE* ikeTaskRet = dynamic_cast<ConfigTaskIKE*>(confQueue.front());

    ASSERT_NE(ikeTaskRet, nullptr);

    EXPECT_EQ(ikeTask->get_config_action(), ikeTaskRet->get_config_action());
    EXPECT_EQ(ikeTask->get_type(), ikeTaskRet->get_type());

    const ipsec_ike_connection& ike_conn_ret = ikeTaskRet->get_ike_connection();

    EXPECT_EQ(ike_conn.m_cipher, ike_conn_ret.m_cipher);
    EXPECT_EQ(ike_conn.m_ike_version, ike_conn_ret.m_ike_version);
    EXPECT_EQ(ike_conn.m_local_ip.compare(ike_conn_ret.m_local_ip), 0);
}

/**
 * Objective: Verify that a ConfigTask Object can't be added to the queue
 * if it is null
 **/
TEST_F(ConfigQueueTestSuite, TestAddTaskNull)
{
    EXPECT_FALSE(m_config_queue.get_is_running());

    std::queue<ConfigTask*>& confQueue = m_config_queue.get_task_queue();

    EXPECT_EQ(confQueue.size(), 0);

    ConfigTaskIKE* ikeTask = nullptr;

    EXPECT_EQ(m_config_queue.add_task(ikeTask), ipsec_ret::NULL_PARAMETERS);

    EXPECT_EQ(confQueue.size(), 0);
}

/**
 * Objective: Verify that dispatcher thread can be started
 **/
TEST_F(ConfigQueueTestSuite, TestStartThread)
{
    EXPECT_FALSE(m_config_queue.get_is_running());
    EXPECT_EQ(m_config_queue.get_task_queue().size(), 0);

    EXPECT_EQ(m_config_queue.start_thread(), ipsec_ret::OK);

    EXPECT_TRUE(m_config_queue.get_is_running());
}

/**
 * Objective: Verify that dispatcher thread will not be started if it is already
 * running
 **/
TEST_F(ConfigQueueTestSuite, TestStartThreadRunning)
{
    EXPECT_FALSE(m_config_queue.get_is_running());
    EXPECT_EQ(m_config_queue.get_task_queue().size(), 0);

    m_config_queue.set_is_running(true);

    EXPECT_EQ(m_config_queue.start_thread(), ipsec_ret::IS_RUNNING);

    EXPECT_TRUE(m_config_queue.get_is_running());

    m_config_queue.set_is_running(false);
}

/**
 * Objective: Verify that dispatcher thread can be stop
 **/
TEST_F(ConfigQueueTestSuite, TestStopThread)
{
    EXPECT_FALSE(m_config_queue.get_is_running());
    EXPECT_EQ(m_config_queue.get_task_queue().size(), 0);

    m_config_queue.set_is_running(true);

    EXPECT_EQ(m_config_queue.stop_thread(), ipsec_ret::OK);

    EXPECT_FALSE(m_config_queue.get_is_running());
}

/**
 * Objective: Verify that dispatcher thread will return error if it tries to
 * stop an already running thread
 **/
TEST_F(ConfigQueueTestSuite, TestStopThreadNotRunning)
{
    EXPECT_FALSE(m_config_queue.get_is_running());
    EXPECT_EQ(m_config_queue.get_task_queue().size(), 0);

    EXPECT_EQ(m_config_queue.stop_thread(), ipsec_ret::NOT_RUNNING);

    EXPECT_FALSE(m_config_queue.get_is_running());
}
