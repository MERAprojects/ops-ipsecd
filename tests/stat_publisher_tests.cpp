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
#include <gtest/gtest.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "StatPublisher.h"
#include "mocks/mock_IIKEAPI.h"

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

class StatPublisher_EnO : public StatPublisher
{
    public:

        StatPublisher_EnO(IIKEAPI& ike_api)
            : StatPublisher(ike_api)
        {
        }

        std::list<ipsec_stat_pub>& get_pub_list()
        {
            return m_pub_list;
        }

        std::thread& get_publisher_thread()
        {
            return m_publisher_thread;
        }

        void set_is_running(bool value)
        {
            m_is_running = value;
        }

        bool get_is_running()
        {
            return m_is_running;
        }

        uint32_t get_publish_time_sec()
        {
            return m_publish_time_sec;
        }

        void call_run_publisher()
        {
            run_publisher();
        }

        ipsec_ret call_publish_stat(const ipsec_stat_pub& stat_ipsec)
        {
            return publish_stat(stat_ipsec);
        }
};

class StatPublisherTestSuite : public Test
{
    public:

        MockIIKEAPI m_ike_api;
        StatPublisher_EnO m_StatPublisher;

        StatPublisherTestSuite()
            : m_StatPublisher(m_ike_api)
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
            std::list<ipsec_stat_pub>& list_stats = m_StatPublisher.get_pub_list();
            list_stats.clear();

            m_StatPublisher.stop_thread();
        }
};

/**
 * Objective: Verify that the Thread can be started
 **/
TEST_F(StatPublisherTestSuite, StartThread)
{
    std::list<ipsec_stat_pub>& list_stats = m_StatPublisher.get_pub_list();
    list_stats.clear();

    m_StatPublisher.set_is_running(false);

    EXPECT_EQ(m_StatPublisher.start_thread(), ipsec_ret::OK);
    EXPECT_TRUE(m_StatPublisher.get_is_running());
}

/**
 * Objective: Verify that the Thread will not be started again if it is
 * running
 **/
TEST_F(StatPublisherTestSuite, StartThreadRunning)
{
    m_StatPublisher.set_is_running(true);

    EXPECT_EQ(m_StatPublisher.start_thread(), ipsec_ret::IS_RUNNING);
    EXPECT_TRUE(m_StatPublisher.get_is_running());
}

/**
 * Objective: Verify that the Thread can be stop
 **/
TEST_F(StatPublisherTestSuite, StopThread)
{
    m_StatPublisher.set_is_running(true);

    EXPECT_EQ(m_StatPublisher.stop_thread(), ipsec_ret::OK);
    EXPECT_FALSE(m_StatPublisher.get_is_running());
}

/**
 * Objective: Verify that the Thread will not be stop again if it is not
 * running
 **/
TEST_F(StatPublisherTestSuite, StopThreadNotRunning)
{
    m_StatPublisher.set_is_running(false);

    EXPECT_EQ(m_StatPublisher.stop_thread(), ipsec_ret::NOT_RUNNING);
    EXPECT_FALSE(m_StatPublisher.get_is_running());
}

/**
 * Objective: Verify that the an IPsec Connection can be added to the publisher
 **/
TEST_F(StatPublisherTestSuite, AddIPsecStatPub)
{
    const std::list<ipsec_stat_pub>& list_stats = m_StatPublisher.get_pub_list();

    EXPECT_EQ(list_stats.size(), 0);

    ipsec_stat_pub stat_ipsec;
    stat_ipsec.m_type = ipsec_type::ike;
    stat_ipsec.m_ike_name = "IKEConn";

    EXPECT_EQ(m_StatPublisher.add_ipsec_stat(stat_ipsec), ipsec_ret::OK);

    EXPECT_EQ(list_stats.size(), 1);
}

/**
 * Objective: Verify that the an IPsec Connection can be removed from
 * the publisher
 **/
TEST_F(StatPublisherTestSuite, RemoveIPsecStatPub)
{
    const std::list<ipsec_stat_pub>& list_stats = m_StatPublisher.get_pub_list();

    ipsec_stat_pub stat_ipsec;
    stat_ipsec.m_type = ipsec_type::ike;
    stat_ipsec.m_ike_name = "IKEConn";

    m_StatPublisher.add_ipsec_stat(stat_ipsec);

    EXPECT_EQ(list_stats.size(), 1);

    EXPECT_EQ(m_StatPublisher.remove_ipsec_stat(stat_ipsec), ipsec_ret::OK);

    EXPECT_EQ(list_stats.size(), 0);
}
