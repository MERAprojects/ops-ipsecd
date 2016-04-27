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

        int32_t cb_run_not_found(const void* buf, size_t numbytes, uint32_t seq,
                uint32_t portid, mnl_cb_t cb_data, void* data)
        {
            if(data == nullptr)
            {
                return -1;
            }

            IPsecNetlinkAPI::CB_Data* userdata = (IPsecNetlinkAPI::CB_Data*)data;

            ipsec_sa* sa = (ipsec_sa*)userdata->user_data;

            sa->m_id.m_addr_family = 0;

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

/**
 * Objective: Verify that add sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSA)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct xfrm_usersa_info* p_xfrm_sa = &xfrm_sa;
    struct nlmsgerr err;
    struct nlmsgerr* p_err = &err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    ipsec_sa sa;

    ///////////////////////////////////////

    err.error = 0;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(p_xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(p_nlh)))
            .WillOnce(Return(p_err));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::OK);

    ///////////////////////////////////////

    set_expect_ipsec_sa(nlh, xfrm_sa, sa, flags);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSAPutHeaderFails)
{
    ipsec_sa sa;

    ///////////////////////////////////////
    fill_ipsec_sa(sa);

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSAPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    fill_ipsec_sa(sa);

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSACreateSocketFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct xfrm_usersa_info* p_xfrm_sa = &xfrm_sa;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(p_xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::SOCKET_CREATE_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSASocketSendToFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct xfrm_usersa_info* p_xfrm_sa = &xfrm_sa;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(p_xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::SOCKET_SEND_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSASocketReceiveToFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct xfrm_usersa_info* p_xfrm_sa = &xfrm_sa;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(p_xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::SOCKET_RECV_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateAddSAErrorInMsg)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct xfrm_usersa_info* p_xfrm_sa = &xfrm_sa;
    struct nlmsgerr err;
    struct nlmsgerr* p_err = &err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    ipsec_sa sa;

    ///////////////////////////////////////

    err.error = -1;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(p_xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(p_nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(p_nlh)))
            .WillOnce(Return(p_err));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::ADD_FAILED);

    ///////////////////////////////////////

    EXPECT_EQ(-err.error, errno);

    set_expect_ipsec_sa(nlh, xfrm_sa, sa, flags);
}

/**
 * Objective: Verify that get sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSA)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_id xfrm_said;
    struct xfrm_usersa_id* p_xfrm_said = &xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    uint32_t pid = 200;
    ssize_t socketRet = 100;
    FakeCalls fakeCalls;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, cb_run(_, _, _, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::cb_run));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(p_xfrm_said));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(pid));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(socketRet));

    EXPECT_CALL(m_mnl_wrapper, cb_run(NotNull(), Eq(socketRet), _, Eq(pid),
                                      NotNull(), NotNull()));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::OK);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_GETSA);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSAPutHeaderFails)
{
    ipsec_sa sa;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSAPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSASocketCreateFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_id xfrm_said;
    struct xfrm_usersa_id* p_xfrm_said = &xfrm_said;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(p_xfrm_said));

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::SOCKET_CREATE_FAILED);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSASocketSendFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_id xfrm_said;
    struct xfrm_usersa_id* p_xfrm_said = &xfrm_said;
    uint32_t pid = 200;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(p_xfrm_said));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(pid));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::SOCKET_SEND_FAILED);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSASocketRevcFailed)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_id xfrm_said;
    struct xfrm_usersa_id* p_xfrm_said = &xfrm_said;
    uint32_t pid = 200;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(p_xfrm_said));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(pid));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::NOT_FOUND);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestCreateGetSANotFound)
{
    struct nlmsghdr nlh;
    struct nlmsghdr* p_nlh = &nlh;
    struct xfrm_usersa_id xfrm_said;
    struct xfrm_usersa_id* p_xfrm_said = &xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    uint32_t pid = 200;
    ssize_t socketRet = 100;
    FakeCalls fakeCalls;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, cb_run(_, _, _, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::cb_run_not_found));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(p_nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(p_nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(p_xfrm_said));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(pid));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(p_nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Ne(0)))
            .WillOnce(Return(socketRet));

    EXPECT_CALL(m_mnl_wrapper, cb_run(NotNull(), Eq(socketRet), _, Eq(pid),
                                      NotNull(), NotNull()));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::NOT_FOUND);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_GETSA);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);
}
