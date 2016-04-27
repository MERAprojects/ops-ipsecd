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
#include <gtest/gtest.h>

/**********************************
*Local Includes
**********************************/
#include "IPsecNetlinkAPI.h"
#include "ops_ipsecd_helper.h"
#include "mocks/mock_ILibmnlWrapper.h"

/**********************************
*Using
**********************************/
using ::testing::_;
using ::testing::An;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Test;
using ::testing::ByRef;
using ::testing::StrEq;
using ::testing::Return;
using ::testing::Invoke;
using ::testing::NotNull;
using ::testing::ReturnRef;
using ::testing::InSequence;

class FakeCalls
{
    public:

        int32_t cb_run(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
                       mnl_cb_t cb_data, void* data)
        {
            if(data == nullptr)
            {
                return -1;
            }

            IPsecNetlinkAPI::CB_Data* userdata = (IPsecNetlinkAPI::CB_Data*)data;

            ipsec_sa* sa = (ipsec_sa*)userdata->user_data;

            sa->m_id.m_addr_family = AF_INET;

            return 0;
        }
};

class IPsecNetlinkAPI_EnO : public IPsecNetlinkAPI
{
    public:

        IPsecNetlinkAPI_EnO(ILibmnlWrapper& mnl_wrapper)
            : IPsecNetlinkAPI(mnl_wrapper)
        {
        }

        ipsec_ret call_create_socket(struct mnl_socket** nl_socket,
                                     uint32_t groups)
        {
            return create_socket(nl_socket, groups);
        }
};

class IPsecNetlinkAPITestSuite : public Test
{
    public:

        MockILibmnlWrapper m_mnl_wrapper;
        IPsecNetlinkAPI_EnO m_netlink_api;

        IPsecNetlinkAPITestSuite()
            : m_netlink_api(m_mnl_wrapper)
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
        }

        void set_create_socket_ok_expectation(uint32_t groups)
        {
            InSequence seq;

            struct mnl_socket* tempNL = (struct mnl_socket*)0x900;

            EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
                    .WillOnce(Return(tempNL));

            EXPECT_CALL(m_mnl_wrapper, socket_bind(Eq(tempNL), Eq(groups),
                                                   Eq(MNL_SOCKET_AUTOPID)))
                    .WillOnce(Return(1));
        }

        void fill_ipsec_sa(ipsec_sa& sa)
        {
            sa.m_id.m_addr_family = AF_INET;
            sa.m_id.m_protocol = 50;
            sa.m_id.m_spi = 0x1234;

            sa.m_id.m_src_ip.m_ipv4 = inet_addr("10.100.1.1");
            sa.m_id.m_dst_ip.m_ipv4 = inet_addr("10.100.1.2");

            sa.m_mode = ipsec_mode::transport;
            sa.m_req_id = 0x100;
            sa.m_flags = 0;
            sa.m_stats.m_replay_window = 32;

            sa.m_selector.m_src_addr.m_ipv4 = inet_addr("10.100.0.0");
            sa.m_selector.m_dst_addr.m_ipv4 = inet_addr("10.200.0.0");
            sa.m_selector.m_addr_family = AF_INET;
            sa.m_selector.m_src_mask = 24;
            sa.m_selector.m_dst_mask = 24;

            sa.m_crypt_set = true;
            sa.m_crypt.m_name = "aes";
            sa.m_crypt.m_key = "11112222333344445555666677778888";

            sa.m_auth_set = true;
            sa.m_auth.m_name = "sha1";
            sa.m_auth.m_key = "11112222333344445555666677778888";
        }

        void set_expect_ipsec_sa(const struct nlmsghdr& nlh,
                                 const struct xfrm_usersa_info& xfrm_sa,
                                 const ipsec_sa& sa,
                                 uint16_t flags)
        {
            EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_NEWSA);
            EXPECT_EQ(nlh.nlmsg_flags, flags);
            EXPECT_NE(nlh.nlmsg_seq, 0);

            EXPECT_EQ(xfrm_sa.family, sa.m_id.m_addr_family);
            EXPECT_EQ(xfrm_sa.id.proto, sa.m_id.m_protocol);
            EXPECT_EQ(xfrm_sa.id.spi, htonl(sa.m_id.m_spi));
            EXPECT_EQ(memcmp(&xfrm_sa.id.daddr, &sa.m_id.m_dst_ip, IP_ADDRESS_LENGTH), 0);
            EXPECT_EQ(memcmp(&xfrm_sa.saddr, &sa.m_id.m_src_ip, IP_ADDRESS_LENGTH), 0);

            EXPECT_EQ(xfrm_sa.mode, (uint8_t)sa.m_mode);
            EXPECT_EQ(xfrm_sa.reqid, sa.m_req_id);
            EXPECT_EQ(xfrm_sa.flags, sa.m_flags);
            EXPECT_EQ(xfrm_sa.replay_window, sa.m_stats.m_replay_window);

            EXPECT_EQ(memcmp(&xfrm_sa.sel.saddr, &sa.m_selector.m_src_addr, IP_ADDRESS_LENGTH), 0);
            EXPECT_EQ(memcmp(&xfrm_sa.sel.daddr, &sa.m_selector.m_dst_addr, IP_ADDRESS_LENGTH), 0);
            EXPECT_EQ(xfrm_sa.sel.family, sa.m_selector.m_addr_family);
            EXPECT_EQ(xfrm_sa.sel.prefixlen_s, sa.m_selector.m_src_mask);
            EXPECT_EQ(xfrm_sa.sel.prefixlen_d, sa.m_selector.m_dst_mask);

            EXPECT_EQ(xfrm_sa.lft.soft_byte_limit, XFRM_INF);
            EXPECT_EQ(xfrm_sa.lft.hard_byte_limit, XFRM_INF);

            EXPECT_EQ(xfrm_sa.lft.soft_packet_limit, XFRM_INF);
            EXPECT_EQ(xfrm_sa.lft.hard_packet_limit, XFRM_INF);

            EXPECT_EQ(xfrm_sa.lft.hard_add_expires_seconds, 0);
            EXPECT_EQ(xfrm_sa.lft.soft_add_expires_seconds, 0);

            EXPECT_EQ(xfrm_sa.lft.hard_use_expires_seconds, 0);
            EXPECT_EQ(xfrm_sa.lft.soft_use_expires_seconds, 0);
        }
};

/**
 * Objective: Verify that create socket will be able to connect to Netlink
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateSocket)
{
    struct mnl_socket* nl_socket = nullptr;
    struct mnl_socket* tempNL = (struct mnl_socket*)0x900;
    uint32_t groups = 456;

    set_create_socket_ok_expectation(groups);

    EXPECT_EQ(m_netlink_api.call_create_socket(&nl_socket, groups),
              ipsec_ret::OK);

    EXPECT_EQ(nl_socket, tempNL);
}

/**
 * Objective: Verify that create socket will return correct error if the socket
 * can't be open
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateSocketOpenFailed)
{
    struct mnl_socket* nl_socket = nullptr;
    uint32_t groups = 456;

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(nullptr));

    EXPECT_EQ(m_netlink_api.call_create_socket(&nl_socket, groups),
              ipsec_ret::SOCKET_OPEN_FAILED);

    EXPECT_EQ(nl_socket, nullptr);
}

/**
 * Objective: Verify that create socket will return correct error if the socket
 * can't be bind
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateSocketBindFailed)
{
    struct mnl_socket* nl_socket = nullptr;
    struct mnl_socket* tempNL = (struct mnl_socket*)0x900;
    uint32_t groups = 456;

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(tempNL));

    EXPECT_CALL(m_mnl_wrapper, socket_bind(Eq(tempNL), Eq(groups),
                                           Eq(MNL_SOCKET_AUTOPID)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(Eq(tempNL)));

    EXPECT_EQ(m_netlink_api.call_create_socket(&nl_socket, groups),
              ipsec_ret::SOCKET_BIND_FAILED);

    EXPECT_EQ(nl_socket, nullptr);
}