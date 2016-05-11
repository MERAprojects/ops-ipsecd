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

        struct xfrm_user_tmpl m_tmpl;

        int32_t cb_run_sa(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
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

        int32_t cb_run_sp(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
                       mnl_cb_t cb_data, void* data)
        {
            if(data == nullptr)
            {
                return -1;
            }

            IPsecNetlinkAPI::CB_Data* userdata = (IPsecNetlinkAPI::CB_Data*)data;

            ipsec_sp* sp = (ipsec_sp*)userdata->user_data;

            sp->m_index = 1;

            return 0;
        }

        int attr_parse_payload_sa(const void* payload, size_t payload_len,
                                       mnl_attr_cb_t cb, void* data)
        {
            if(payload == nullptr || data == nullptr)
            {
                return -1;
            }

            IPsecNetlinkAPI::CB_Data* userdata = (IPsecNetlinkAPI::CB_Data*)data;

            struct nlattr** nl_attrs = (struct nlattr**)userdata->user_data;

            nl_attrs[XFRMA_ALG_CRYPT] = (struct nlattr*)0x100;
            nl_attrs[XFRMA_ALG_AUTH] = (struct nlattr*)0x200;

            return 0;
        }

        int attr_parse_payload_sp(const void* payload, size_t payload_len,
                                       mnl_attr_cb_t cb, void* data)
        {
            if(payload == nullptr || data == nullptr)
            {
                return -1;
            }

            IPsecNetlinkAPI::CB_Data* userdata = (IPsecNetlinkAPI::CB_Data*)data;

            struct nlattr** nl_attrs = (struct nlattr**)userdata->user_data;

            nl_attrs[XFRMA_TMPL] = (struct nlattr*)0x100;

            return 0;
        }

        void attr_put(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data)
        {
            if(data == nullptr)
            {
                return;
            }

            memcpy(&m_tmpl, data, sizeof(xfrm_user_tmpl));
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

        mnl_cb_t addr_mnl_parse_xfrm_sa()
        {
            return mnl_parse_xfrm_sa;
        }

        int call_parse_nested_attr(const struct nlattr* nl_attr, void* data)
        {
            return parse_nested_attr(nl_attr, data);
        }

        int call_mnl_parse_xfrm_sa(const struct nlmsghdr* nlh, void* data)
        {
            return mnl_parse_xfrm_sa(nlh, data);
        }

        mnl_attr_cb_t addr_parse_nested_attr()
        {
            return parse_nested_attr;
        }

        mnl_cb_t addr_mnl_parse_xfrm_sp()
        {
            return mnl_parse_xfrm_sp;
        }

        int call_mnl_parse_xfrm_sp(const struct nlmsghdr* nlh, void* data)
        {
            return mnl_parse_xfrm_sp(nlh, data);
        }

        ipsec_ret call_send_msg(struct nlmsghdr* nlh, char* buffer, size_t buffer_len)
        {
            return send_msg(nlh, buffer, buffer_len);
        }

        ipsec_ret call_send_receive_msg(struct nlmsghdr* nlh, char* buffer,
                                        size_t buffer_len, void* sa_sp_data,
                                        mnl_cb_t callback, uint32_t seq)
        {
            return send_receive_msg(nlh, buffer, buffer_len, sa_sp_data,
                                    callback, seq);
        }

        ipsec_ret call_insert_sp(const ipsec_sp& sp, bool adding)
        {
            return insert_sp(sp, adding);
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
            sa.m_replay_window = 32;

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
            EXPECT_EQ(xfrm_sa.replay_window, sa.m_replay_window);

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

        void fill_ipsec_sp(ipsec_sp& sp)
        {
            sp.m_action = ipsec_action::allow;
            sp.m_index = 1024;
            sp.m_priority = 2556;

            sp.m_id.m_dir = ipsec_direction::inbound;

            sp.m_id.m_selector.m_addr_family = AF_INET;
            sp.m_id.m_selector.m_src_addr.m_ipv4 = inet_addr("10.100.1.0");
            sp.m_id.m_selector.m_src_mask = 24;
            sp.m_id.m_selector.m_dst_addr.m_ipv4 = inet_addr("10.100.2.0");
            sp.m_id.m_selector.m_dst_mask = 24;

            ipsec_tmpl tmpl;
            tmpl.m_addr_family = AF_INET;
            tmpl.m_src_ip.m_ipv4 = inet_addr("10.100.1.1");;
            tmpl.m_dst_ip.m_ipv4 = inet_addr("10.100.2.1");;
            tmpl.m_mode = ipsec_mode::tunnel;
            tmpl.m_protocol = 50;
            tmpl.m_req_id = 0x100;

            sp.m_template_lists.push_back(tmpl);
        }

        void set_expect_ipsec_sp(const struct nlmsghdr& nlh,
                                 const struct xfrm_userpolicy_info& xfrm_sp,
                                 const ipsec_sp& sp,
                                 uint16_t flags,
                                 const struct xfrm_user_tmpl& tmplArr)
        {
            EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_NEWPOLICY);
            EXPECT_EQ(nlh.nlmsg_flags, flags);
            EXPECT_NE(nlh.nlmsg_seq, 0);

            EXPECT_EQ((ipsec_action)xfrm_sp.action, sp.m_action);
            EXPECT_EQ(xfrm_sp.index, sp.m_index);
            EXPECT_EQ(xfrm_sp.priority, sp.m_priority);

            EXPECT_EQ((ipsec_direction)xfrm_sp.dir, sp.m_id.m_dir);

            EXPECT_EQ(xfrm_sp.sel.family, sp.m_id.m_selector.m_addr_family);
            EXPECT_EQ(memcmp(&xfrm_sp.sel.saddr, &sp.m_id.m_selector.m_src_addr, IP_ADDRESS_LENGTH), 0);
            EXPECT_EQ(memcmp(&xfrm_sp.sel.daddr, &sp.m_id.m_selector.m_dst_addr, IP_ADDRESS_LENGTH), 0);
            EXPECT_EQ(xfrm_sp.sel.prefixlen_s, sp.m_id.m_selector.m_src_mask);
            EXPECT_EQ(xfrm_sp.sel.prefixlen_d, sp.m_id.m_selector.m_dst_mask);

            EXPECT_EQ(xfrm_sp.lft.soft_byte_limit, XFRM_INF);
            EXPECT_EQ(xfrm_sp.lft.hard_byte_limit, XFRM_INF);

            EXPECT_EQ(xfrm_sp.lft.soft_packet_limit, XFRM_INF);
            EXPECT_EQ(xfrm_sp.lft.hard_packet_limit, XFRM_INF);

            EXPECT_EQ(xfrm_sp.lft.hard_add_expires_seconds, 0);
            EXPECT_EQ(xfrm_sp.lft.soft_add_expires_seconds, 0);

            EXPECT_EQ(xfrm_sp.lft.hard_use_expires_seconds, 0);
            EXPECT_EQ(xfrm_sp.lft.soft_use_expires_seconds, 0);


            EXPECT_EQ(memcmp(&tmplArr.saddr, &sp.m_template_lists[0].m_src_ip, IP_ADDRESS_LENGTH), 0);

            EXPECT_EQ(tmplArr.id.proto, sp.m_template_lists[0].m_protocol);
            EXPECT_EQ(memcmp(&tmplArr.id.daddr, &sp.m_template_lists[0].m_dst_ip, IP_ADDRESS_LENGTH), 0);

            EXPECT_EQ(tmplArr.family, sp.m_template_lists[0].m_addr_family);
            EXPECT_EQ((ipsec_mode)tmplArr.mode, sp.m_template_lists[0].m_mode);

            EXPECT_EQ(tmplArr.reqid, sp.m_template_lists[0].m_req_id);

            EXPECT_EQ(tmplArr.ealgos, (~(uint32_t)0));
            EXPECT_EQ(tmplArr.aalgos, (~(uint32_t)0));
            EXPECT_EQ(tmplArr.calgos, (~(uint32_t)0));
            EXPECT_EQ(tmplArr.id.spi, 0);
        }

        void set_send_msg_err_expectation(const struct nlmsghdr& nlh,
                                          struct nlmsgerr& err)
        {
            EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
                    .WillOnce(Return(0));

            EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Eq(MNL_SOCKET_BUFFER_SIZE)))
                    .WillOnce(Return(0));

            EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

            EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
                    .WillOnce(Return(&err));
        }

        void set_send_recive_msg_expectation_ok(const struct nlmsghdr& nlh,
                                                mnl_cb_t callback)
        {
            uint32_t socketRet = 100;
            uint32_t pid = 200;

            set_create_socket_ok_expectation(0);

            EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
                    .WillOnce(Return(pid));

            EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
                    .WillOnce(Return(1));

            EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Eq(MNL_SOCKET_BUFFER_SIZE)))
                    .WillOnce(Return(socketRet));

            EXPECT_CALL(m_mnl_wrapper, cb_run(NotNull(), Eq(socketRet), _, Eq(pid),
                                    Eq(callback), NotNull()));

            EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));
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
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessage)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsgerr err;

    ///////////////////////////////////////

    err.error = 0;

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, buf, sizeof(buf)),
              ipsec_ret::OK);
}

/**
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessageNullParameters)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(nullptr, buf, sizeof(buf)),
              ipsec_ret::NULL_PARAMETERS);

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, nullptr, sizeof(buf)),
              ipsec_ret::NULL_PARAMETERS);
}

/**
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessageCreateSocketFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, buf, sizeof(buf)),
              ipsec_ret::SOCKET_CREATE_FAILED);
}

/**
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessageSocketSendToFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, buf, sizeof(buf)),
              ipsec_ret::SOCKET_SEND_FAILED);
}

/**
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessageSocketReceiveToFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Eq(MNL_SOCKET_BUFFER_SIZE)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, buf, sizeof(buf)),
              ipsec_ret::SOCKET_RECV_FAILED);
}

/**
 * Objective: Verify that add Send Message will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSendMessageErrorInMsg)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsgerr err;

    ///////////////////////////////////////

    err.error = 10;

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_msg(&nlh, buf, sizeof(buf)),
              ipsec_ret::ERR);

    ///////////////////////////////////////

    EXPECT_EQ(-err.error, errno);
}

/**
 * Objective: Verify that get Send Message Receive will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSendMessageReceive)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 10;
    ipsec_sa sa;

    ///////////////////////////////////////

    set_send_recive_msg_expectation_ok(nlh,
                                       m_netlink_api.addr_mnl_parse_xfrm_sa());

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, buf, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::OK);
}

/**
 * Objective: Verify that get Send Message Receive will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSendMessageReceiveNullParameters)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 10;
    ipsec_sa sa;

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(nullptr, buf, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::NULL_PARAMETERS);

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, nullptr, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::NULL_PARAMETERS);

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, buf, sizeof(buf), nullptr,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::NULL_PARAMETERS);
}

/**
 * Objective: Verify that get Send Message Receive will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSendMessageReceiveSocketCreateFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 10;
    ipsec_sa sa;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, socket_open(Eq(NETLINK_XFRM)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, buf, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::SOCKET_CREATE_FAILED);
}

/**
 * Objective: Verify that get Send Message Receive will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSendMessageReceiveSocketSendFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 10;
    ipsec_sa sa;

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(0));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, buf, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::SOCKET_SEND_FAILED);
}

/**
 * Objective: Verify that get Send Message Receive will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSendMessageReceiveSocketRevcFailed)
{
    struct nlmsghdr nlh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 10;
    ipsec_sa sa;

    ///////////////////////////////////////

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Eq(MNL_SOCKET_BUFFER_SIZE)))
            .WillOnce(Return(-1));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_send_receive_msg(&nlh, buf, sizeof(buf), &sa,
                                m_netlink_api.addr_mnl_parse_xfrm_sa(), seq),
              ipsec_ret::SOCKET_RECV_FAILED);
}

/**
 * Objective: Verify that add sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSA)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct nlmsgerr err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
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
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(&xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::OK);

    ///////////////////////////////////////

    set_expect_ipsec_sa(nlh, xfrm_sa, sa, flags);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSAPutHeaderFails)
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
TEST_F(IPsecNetlinkAPITestSuite, TestAddSAPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    fill_ipsec_sa(sa);

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that add sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSAAddFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct nlmsgerr err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    ipsec_sa sa;

    ///////////////////////////////////////

    err.error = 1;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_info))))
            .WillOnce(Return(&xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                   NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                   NotNull()));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sa(sa), ipsec_ret::ADD_FAILED);

    ///////////////////////////////////////

    set_expect_ipsec_sa(nlh, xfrm_sa, sa, flags);
}

/**
 * Objective: Verify that get sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSA)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_id xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    FakeCalls fakeCalls;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, cb_run(_, _, _, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::cb_run_sa));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(&xfrm_said));

    set_send_recive_msg_expectation_ok(nlh,
                                       m_netlink_api.addr_mnl_parse_xfrm_sa());

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
TEST_F(IPsecNetlinkAPITestSuite, TestGetSAPutHeaderFails)
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
TEST_F(IPsecNetlinkAPITestSuite, TestGetSAPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that get sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSANotFound)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_id xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    ipsec_sa sa;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(&xfrm_said));

    set_send_recive_msg_expectation_ok(nlh,
                                       m_netlink_api.addr_mnl_parse_xfrm_sa());

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sa(0x100, sa), ipsec_ret::NOT_FOUND);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_GETSA);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);
}

/**
 * Objective: Verify that delete sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSA)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_id xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    struct nlmsgerr err;
    ipsec_sa_id said;

    ///////////////////////////////////////

    said.m_addr_family = AF_INET;
    said.m_dst_ip.m_ipv4 = inet_addr("10.100.1.1");
    said.m_protocol = 50;
    said.m_spi = 0x200;

    err.error = 0;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(&xfrm_said));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sa(said), ipsec_ret::OK);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_DELSA);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);

    EXPECT_EQ(xfrm_said.family, said.m_addr_family);
    EXPECT_EQ(xfrm_said.proto, said.m_protocol);
    EXPECT_EQ(xfrm_said.spi, htonl(said.m_spi));
    EXPECT_EQ(memcmp(&xfrm_said.daddr, &said.m_dst_ip, IP_ADDRESS_LENGTH), 0);
}

/**
 * Objective: Verify that delete sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSAPutHeaderFails)
{
    ipsec_sa_id said;

    ///////////////////////////////////////

    said.m_addr_family = AF_INET;
    said.m_dst_ip.m_ipv4 = inet_addr("10.100.1.1");
    said.m_protocol = 50;
    said.m_spi = 0x200;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sa(said), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that delete sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSAPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sa_id said;

    ///////////////////////////////////////

    said.m_addr_family = AF_INET;
    said.m_dst_ip.m_ipv4 = inet_addr("10.100.1.1");
    said.m_protocol = 50;
    said.m_spi = 0x200;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sa(said), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that delete sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSADeleteFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_id xfrm_said;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    struct nlmsgerr err;
    ipsec_sa_id said;

    ///////////////////////////////////////

    said.m_addr_family = AF_INET;
    said.m_dst_ip.m_ipv4 = inet_addr("10.100.1.1");
    said.m_protocol = 50;
    said.m_spi = 0x200;

    err.error = -1;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_usersa_id))))
            .WillOnce(Return(&xfrm_said));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sa(said), ipsec_ret::DELETE_FAILED);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_DELSA);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);

    EXPECT_EQ(xfrm_said.family, said.m_addr_family);
    EXPECT_EQ(xfrm_said.proto, said.m_protocol);
    EXPECT_EQ(xfrm_said.spi, htonl(said.m_spi));
    EXPECT_EQ(memcmp(&xfrm_said.daddr, &said.m_dst_ip, IP_ADDRESS_LENGTH), 0);
}

/**
 * Objective: Verify that modify sa will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestModifySA)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct nlmsgerr err;
    ipsec_sa sa;

    struct xfrm_usersa_id xfrm_said;

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

    {
        InSequence s;

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
                .WillOnce(Return(&nlh));

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                       Eq(sizeof(struct xfrm_usersa_id))))
                .WillOnce(Return(&xfrm_said));

        set_create_socket_ok_expectation(0);

        set_send_msg_err_expectation(nlh, err);

        //##########

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
                .WillOnce(Return(&nlh));

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                       Eq(sizeof(struct xfrm_usersa_info))))
                .WillOnce(Return(&xfrm_sa));

        EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                       NotNull()));

        EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                       NotNull()));

        set_create_socket_ok_expectation(0);

        set_send_msg_err_expectation(nlh, err);
    }

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.modify_sa(sa), ipsec_ret::OK);
}

/**
 * Objective: Verify that Modify SA attributes will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestModifySAAddFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_usersa_info xfrm_sa;
    struct nlmsgerr err;
    struct nlmsgerr err_add;
    ipsec_sa sa;

    struct xfrm_usersa_id xfrm_said;

    ///////////////////////////////////////

    err.error = 0;
    err_add.error = 10;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sa(sa);

    uint32_t xfrmCryptAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
    uint32_t xfrmCryptAlgoSize = sizeof(struct xfrm_algo) + xfrmCryptAlgoKeySize;

    uint32_t xfrmAuthAlgoKeySize = (sa.m_auth.m_key.size() / 2);
    uint32_t xfrmAuthAlgoSize = sizeof(struct xfrm_algo) + xfrmAuthAlgoKeySize;

    ///////////////////////////////////////

    {
        InSequence s;

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
                .WillOnce(Return(&nlh));

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                       Eq(sizeof(struct xfrm_usersa_id))))
                .WillOnce(Return(&xfrm_said));

        set_create_socket_ok_expectation(0);

        set_send_msg_err_expectation(nlh, err);

        //##########

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
                .WillOnce(Return(&nlh));

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                       Eq(sizeof(struct xfrm_usersa_info))))
                .WillOnce(Return(&xfrm_sa));

        EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_CRYPT), xfrmCryptAlgoSize,
                                       NotNull()));

        EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_ALG_AUTH), xfrmAuthAlgoSize,
                                       NotNull()));

        set_create_socket_ok_expectation(0);

        set_send_msg_err_expectation(nlh, err_add);
    }

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.modify_sa(sa), ipsec_ret::ADD_FAILED);
}

/**
 * Objective: Verify that Modify SA attributes will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestModifySADeleteFailed)
{
    struct nlmsghdr nlh;
    struct nlmsgerr err;
    ipsec_sa sa;

    struct xfrm_usersa_id xfrm_said;

    ///////////////////////////////////////

    err.error = 10;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    {
        InSequence s;

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
                .WillOnce(Return(&nlh));

        EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                       Eq(sizeof(struct xfrm_usersa_id))))
                .WillOnce(Return(&xfrm_said));

        set_create_socket_ok_expectation(0);

        set_send_msg_err_expectation(nlh, err);
    }

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.modify_sa(sa), ipsec_ret::DELETE_FAILED);
}

/**
 * Objective: Verify that parse nested attributes will work as intended
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseNestedAttr)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlattr nl_attr;
    struct nlattr* nl_attrs[10] = { 0 };
    uint32_t idx = 1;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = nl_attrs;

    nl_attr.nla_len = 111;
    nl_attr.nla_type = 222;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, attr_get_type(Eq(&nl_attr)))
            .WillOnce(Return(idx));

    EXPECT_CALL(m_mnl_wrapper, attr_type_valid(Eq(&nl_attr),
                                   Eq(XFRMA_MAX)))
            .WillOnce(Return(1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_parse_nested_attr(&nl_attr, &cbdata), MNL_CB_OK);

    ///////////////////////////////////////

    EXPECT_EQ(nl_attrs[idx]->nla_len, nl_attr.nla_len);
    EXPECT_EQ(nl_attrs[idx]->nla_type, nl_attr.nla_type);
}

/**
 * Objective: Verify that parse nested attributes will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseNestedAttrDataNull)
{
    EXPECT_EQ(m_netlink_api.call_parse_nested_attr(nullptr, nullptr), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse nested attributes will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseNestedAttrNotValid)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlattr nl_attr;
    struct nlattr* nl_attrs[10] = { 0 };
    uint32_t idx = 1;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = nl_attrs;

    nl_attr.nla_len = 111;
    nl_attr.nla_type = 222;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, attr_get_type(Eq(&nl_attr)))
            .WillOnce(Return(idx));

    EXPECT_CALL(m_mnl_wrapper, attr_type_valid(Eq(&nl_attr),
                                   Eq(XFRMA_MAX)))
            .WillOnce(Return(-1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_parse_nested_attr(&nl_attr, &cbdata), MNL_CB_OK);

    ///////////////////////////////////////

    EXPECT_EQ(nl_attrs[idx], nullptr);
}

/**
 * Objective: Verify that parse xfrm sa will work as intended
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSA)
{
    FakeCalls fakeCalls;
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sa sa;
    struct xfrm_usersa_info xfrm_sa[2] = { 0 };
    struct nlattr* nl_attr_crypt = (struct nlattr*)0x100;
    struct nlattr* nl_attr_auth = (struct nlattr*)0x200;
    struct xfrm_algo* xfrm_crypt = nullptr;
    struct xfrm_algo* xfrm_auth = nullptr;
    uint32_t xfrm_algo_size = sizeof(struct xfrm_algo) + 16;

    uint8_t key1[] = {0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
                      0x66, 0x66, 0x77, 0x77, 0x88, 0x88};
    std::string str_key1 = "11112222333344445555666677778888";

    uint8_t key2[] = {0x00, 0x00, 0x99, 0x99, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
                      0x66, 0x66, 0x77, 0x77, 0x88, 0x88};
    std::string str_key2 = "00009999333344445555666677778888";

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sa;

    xfrm_sa[0].family = AF_INET;
    xfrm_sa[0].flags = 1;
    xfrm_sa[0].mode = 1;
    xfrm_sa[0].replay_window = 32;
    xfrm_sa[0].reqid = 0x222;

    xfrm_sa[0].saddr.a4 = inet_addr("10.100.0.1");

    xfrm_sa[0].id.daddr.a4 = inet_addr("10.100.0.2");
    xfrm_sa[0].id.proto = 50;
    xfrm_sa[0].id.spi = htonl(0x111);

    xfrm_sa[0].curlft.add_time = 900;
    xfrm_sa[0].curlft.use_time = 800;
    xfrm_sa[0].curlft.packets = 700;
    xfrm_sa[0].curlft.bytes = 600;

    xfrm_sa[0].stats.integrity_failed = 10;
    xfrm_sa[0].stats.replay = 20;
    xfrm_sa[0].stats.replay_window = 30;

    xfrm_sa[0].sel.saddr.a4 = inet_addr("192.168.1.0");
    xfrm_sa[0].sel.daddr.a4 = inet_addr("192.168.2.0");
    xfrm_sa[0].sel.family = AF_INET;
    xfrm_sa[0].sel.prefixlen_s = 24;
    xfrm_sa[0].sel.prefixlen_d = 24;

    nlh.nlmsg_len = sizeof(struct xfrm_usersa_info);
    nlh.nlmsg_type = XFRM_MSG_GETSA;

    xfrm_crypt = (struct xfrm_algo*)new uint8_t[xfrm_algo_size];
    memset(xfrm_crypt, 0, xfrm_algo_size);
    strncpy(xfrm_crypt->alg_name, "aes", IPSEC_MAX_ALGO_NAME_LEN);
    memcpy(xfrm_crypt->alg_key, key1, 16);
    xfrm_crypt->alg_key_len = 16 * 8;

    xfrm_auth = (struct xfrm_algo*)new uint8_t[xfrm_algo_size];
    memset(xfrm_auth, 0, xfrm_algo_size);
    strncpy(xfrm_auth->alg_name, "sha1", IPSEC_MAX_ALGO_NAME_LEN);
    memcpy(xfrm_auth->alg_key, key2, 16);
    xfrm_auth->alg_key_len = 16 * 8;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, attr_parse_payload(_, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::attr_parse_payload_sa));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sa[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_get_payload(Eq(nl_attr_crypt)))
            .WillOnce(Return(xfrm_crypt));

    EXPECT_CALL(m_mnl_wrapper, attr_get_payload(Eq(nl_attr_auth)))
            .WillOnce(Return(xfrm_auth));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(&nlh, &cbdata), MNL_CB_OK);

    ///////////////////////////////////////

    EXPECT_TRUE(sa.m_crypt_set);
    EXPECT_EQ(sa.m_crypt.m_name.compare(xfrm_crypt->alg_name), 0);
    EXPECT_EQ(sa.m_crypt.m_key.compare(str_key1), 0);

    EXPECT_TRUE(sa.m_auth_set);
    EXPECT_EQ(sa.m_auth.m_name.compare(xfrm_auth->alg_name), 0);
    EXPECT_EQ(sa.m_auth.m_key.compare(str_key2), 0);

    EXPECT_EQ(sa.m_id.m_addr_family, xfrm_sa[0].family);
    EXPECT_EQ(sa.m_flags, xfrm_sa[0].flags);
    EXPECT_EQ(sa.m_mode, (ipsec_mode)xfrm_sa[0].mode);
    EXPECT_EQ(sa.m_replay_window, xfrm_sa[0].replay_window);
    EXPECT_EQ(sa.m_req_id, xfrm_sa[0].reqid);

    EXPECT_EQ(memcmp(&sa.m_id.m_src_ip, &xfrm_sa[0].saddr, IP_ADDRESS_LENGTH), 0);

    EXPECT_EQ(memcmp(&sa.m_id.m_dst_ip, &xfrm_sa[0].id.daddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(sa.m_id.m_protocol, xfrm_sa[0].id.proto);
    EXPECT_EQ(htonl(sa.m_id.m_spi), xfrm_sa[0].id.spi);

    EXPECT_EQ(sa.m_lifetime_current.m_add_time, xfrm_sa[0].curlft.add_time);
    EXPECT_EQ(sa.m_lifetime_current.m_use_time, xfrm_sa[0].curlft.use_time);
    EXPECT_EQ(sa.m_lifetime_current.m_packets, xfrm_sa[0].curlft.packets);
    EXPECT_EQ(sa.m_lifetime_current.m_bytes, xfrm_sa[0].curlft.bytes);

    EXPECT_EQ(sa.m_stats.m_integrity_failed, xfrm_sa[0].stats.integrity_failed);
    EXPECT_EQ(sa.m_stats.m_replay, xfrm_sa[0].stats.replay);;
    EXPECT_EQ(sa.m_stats.m_replay_window, xfrm_sa[0].stats.replay_window);;

    EXPECT_EQ(memcmp(&sa.m_selector.m_src_addr, &xfrm_sa[0].sel.saddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&sa.m_selector.m_dst_addr, &xfrm_sa[0].sel.daddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(sa.m_selector.m_addr_family, xfrm_sa[0].sel.family);
    EXPECT_EQ(sa.m_selector.m_src_mask, xfrm_sa[0].sel.prefixlen_s);
    EXPECT_EQ(sa.m_selector.m_dst_mask, xfrm_sa[0].sel.prefixlen_d);

    DeleteMemArr(xfrm_crypt);
    DeleteMemArr(xfrm_auth);
}

/**
 * Objective: Verify that parse xfrm sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSADataNull)
{
    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(nullptr, nullptr), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSAMsgTypeIncorrect)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sa;

    nlh.nlmsg_len = sizeof(struct xfrm_usersa_info);
    nlh.nlmsg_type = XFRM_MSG_ALLOCSPI;

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSAPayloadNull)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sa sa;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sa;

    nlh.nlmsg_len = sizeof(struct xfrm_usersa_info);
    nlh.nlmsg_type = XFRM_MSG_GETSA;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSAParsePayloadFailed)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sa sa;
    struct xfrm_usersa_info xfrm_sa[2] = { 0 };

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sa;

    nlh.nlmsg_len = sizeof(struct xfrm_usersa_info);
    nlh.nlmsg_type = XFRM_MSG_GETSA;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sa[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()))
            .WillOnce(Return(-1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sa will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSANullObjectParseSA)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    struct xfrm_usersa_info xfrm_sa[2] = { 0 };

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = nullptr;

    nlh.nlmsg_len = sizeof(struct xfrm_usersa_info);
    nlh.nlmsg_type = XFRM_MSG_GETSA;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(xfrm_sa));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sa[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()))
            .WillOnce(Return(1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sa(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that insert sp will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestInsertSP)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_info xfrm_sp;
    struct nlmsgerr err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    ipsec_sp sp;
    uint32_t tmpl_size = 0;
    FakeCalls fakeCalls;

    ///////////////////////////////////////

    err.error = 0;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sp(sp);

    tmpl_size = sizeof(struct xfrm_user_tmpl) * sp.m_template_lists.size();

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, attr_put(_, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::attr_put));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_info))))
            .WillOnce(Return(&xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_TMPL), Eq(tmpl_size), NotNull()));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_insert_sp(sp, true), ipsec_ret::OK);

    ///////////////////////////////////////

    set_expect_ipsec_sp(nlh, xfrm_sp, sp, flags, fakeCalls.m_tmpl);
}

/**
 * Objective: Verify that insert sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestInsertSPPutHeaderFails)
{
    ipsec_sp sp;

    ///////////////////////////////////////
    fill_ipsec_sp(sp);

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_insert_sp(sp, true), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that insert sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestInsertInsertPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sp sp;

    ///////////////////////////////////////

    fill_ipsec_sp(sp);

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_info))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_insert_sp(sp, true), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that add sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestAddSPAddFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_info xfrm_sp;
    struct nlmsgerr err;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    ipsec_sp sp;
    uint32_t tmpl_size = 0;
    FakeCalls fakeCalls;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sp(sp);

    tmpl_size = sizeof(struct xfrm_user_tmpl) * sp.m_template_lists.size();

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, attr_put(_, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::attr_put));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_info))))
            .WillOnce(Return(&xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_TMPL), Eq(tmpl_size), NotNull()));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.add_sp(sp), ipsec_ret::ADD_FAILED);

    ///////////////////////////////////////

    set_expect_ipsec_sp(nlh, xfrm_sp, sp, flags, fakeCalls.m_tmpl);
}

/**
 * Objective: Verify that modify sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestModifySPModifyFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_info xfrm_sp;
    struct nlmsgerr err;
    ipsec_sp sp;
    uint32_t tmpl_size = 0;
    FakeCalls fakeCalls;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;
    fill_ipsec_sp(sp);

    tmpl_size = sizeof(struct xfrm_user_tmpl) * sp.m_template_lists.size();

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, attr_put(_, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::attr_put));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_info))))
            .WillOnce(Return(&xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_put(Eq(&nlh), Eq(XFRMA_TMPL), Eq(tmpl_size), NotNull()));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.modify_sp(sp), ipsec_ret::MODIFY_FAILED);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_UPDPOLICY);
}

/**
 * Objective: Verify that get sp will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSP)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_id xfrm_spid;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    uint32_t pid = 200;
    ssize_t socketRet = 100;
    FakeCalls fakeCalls;
    ipsec_sp_id sp_id;
    ipsec_sp sp;

    ///////////////////////////////////////

    sp_id.m_dir = ipsec_direction::inbound;
    sp_id.m_selector.m_addr_family = AF_INET;
    sp_id.m_selector.m_src_addr.m_ipv4 = inet_addr("10.100.1.0");
    sp_id.m_selector.m_dst_addr.m_ipv4 = inet_addr("10.100.2.0");
    sp_id.m_selector.m_src_mask = 24;
    sp_id.m_selector.m_dst_mask = 24;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, cb_run(_, _, _, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::cb_run_sp));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(&xfrm_spid));

    set_create_socket_ok_expectation(0);

    EXPECT_CALL(m_mnl_wrapper, socket_get_portid(NotNull()))
            .WillOnce(Return(pid));

    EXPECT_CALL(m_mnl_wrapper, socket_sendto(NotNull(), Eq(&nlh), Eq(nlh.nlmsg_len)))
            .WillOnce(Return(1));

    EXPECT_CALL(m_mnl_wrapper, socket_recvfrom(NotNull(), NotNull(), Eq(MNL_SOCKET_BUFFER_SIZE)))
            .WillOnce(Return(socketRet));

    EXPECT_CALL(m_mnl_wrapper, cb_run(NotNull(), Eq(socketRet), _, Eq(pid),
                            Eq(m_netlink_api.addr_mnl_parse_xfrm_sp()), NotNull()));

    EXPECT_CALL(m_mnl_wrapper, socket_close(NotNull()));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sp(sp_id, sp), ipsec_ret::OK);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_GETPOLICY);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);

    EXPECT_EQ((ipsec_direction)xfrm_spid.dir, sp_id.m_dir);
    EXPECT_EQ(xfrm_spid.sel.family, sp_id.m_selector.m_addr_family);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.saddr, &sp_id.m_selector.m_src_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.daddr, &sp_id.m_selector.m_dst_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_s, sp_id.m_selector.m_src_mask);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_d, sp_id.m_selector.m_dst_mask);
}

/**
 * Objective: Verify that get sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSPPutHeaderFails)
{
    ipsec_sp sp;
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sp(sp_id, sp), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that get sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSPPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sp sp;
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sp(sp_id, sp), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that get sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestGetSPNotFound)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_id xfrm_spid;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    ipsec_sp_id sp_id;
    ipsec_sp sp;

    ///////////////////////////////////////

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////
    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(&xfrm_spid));

    set_send_recive_msg_expectation_ok(nlh,
                                       m_netlink_api.addr_mnl_parse_xfrm_sp());

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.get_sp(sp_id, sp), ipsec_ret::NOT_FOUND);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_GETPOLICY);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);
}

/**
 * Objective: Verify that delete sP will call the correct methods
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSP)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_id xfrm_spid;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    struct nlmsgerr err;
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    err.error = 0;

    sp_id.m_dir = ipsec_direction::inbound;
    sp_id.m_selector.m_addr_family = AF_INET;
    sp_id.m_selector.m_src_addr.m_ipv4 = inet_addr("10.100.1.0");
    sp_id.m_selector.m_dst_addr.m_ipv4 = inet_addr("10.100.2.0");
    sp_id.m_selector.m_src_mask = 24;
    sp_id.m_selector.m_dst_mask = 24;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(&xfrm_spid));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sp(sp_id), ipsec_ret::OK);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_DELPOLICY);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);

    EXPECT_EQ((ipsec_direction)xfrm_spid.dir, sp_id.m_dir);
    EXPECT_EQ(xfrm_spid.sel.family, sp_id.m_selector.m_addr_family);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.saddr, &sp_id.m_selector.m_src_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.daddr, &sp_id.m_selector.m_dst_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_s, sp_id.m_selector.m_src_mask);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_d, sp_id.m_selector.m_dst_mask);
}

/**
 * Objective: Verify that delete sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSPPutHeaderFails)
{
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sp(sp_id), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that delete sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSPPutExtraHeaderFails)
{
    struct nlmsghdr nlh;
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sp(sp_id), ipsec_ret::ALLOC_FAILED);
}

/**
 * Objective: Verify that delete sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestDelSPDeleteFailed)
{
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_id xfrm_spid;
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    struct nlmsgerr err;
    ipsec_sp_id sp_id;

    ///////////////////////////////////////

    err.error = 1;

    sp_id.m_dir = ipsec_direction::inbound;
    sp_id.m_selector.m_addr_family = AF_INET;
    sp_id.m_selector.m_src_addr.m_ipv4 = inet_addr("10.100.1.0");
    sp_id.m_selector.m_dst_addr.m_ipv4 = inet_addr("10.100.2.0");
    sp_id.m_selector.m_src_mask = 24;
    sp_id.m_selector.m_dst_mask = 24;

    nlh.nlmsg_seq = 0;
    nlh.nlmsg_len = 100;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_header(NotNull()))
            .WillOnce(Return(&nlh));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_put_extra_header(Eq(&nlh),
                                   Eq(sizeof(struct xfrm_userpolicy_id))))
            .WillOnce(Return(&xfrm_spid));

    set_create_socket_ok_expectation(0);

    set_send_msg_err_expectation(nlh, err);

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.del_sp(sp_id), ipsec_ret::DELETE_FAILED);

    ///////////////////////////////////////

    EXPECT_EQ(nlh.nlmsg_type, XFRM_MSG_DELPOLICY);
    EXPECT_EQ(nlh.nlmsg_flags, flags);
    EXPECT_NE(nlh.nlmsg_seq, 0);

    EXPECT_EQ((ipsec_direction)xfrm_spid.dir, sp_id.m_dir);
    EXPECT_EQ(xfrm_spid.sel.family, sp_id.m_selector.m_addr_family);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.saddr, &sp_id.m_selector.m_src_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&xfrm_spid.sel.daddr, &sp_id.m_selector.m_dst_addr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_s, sp_id.m_selector.m_src_mask);
    EXPECT_EQ(xfrm_spid.sel.prefixlen_d, sp_id.m_selector.m_dst_mask);
}

/**
 * Objective: Verify that parse xfrm sp will work as intended
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSP)
{
    FakeCalls fakeCalls;
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sp sp;
    struct xfrm_userpolicy_info xfrm_sp[2] = { 0 };
    struct nlattr* nl_attr_tmpl = (struct nlattr*)0x100;
    struct xfrm_user_tmpl xfrm_tmpl;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sp;

    xfrm_sp[0].action = (uint8_t)ipsec_action::block;
    xfrm_sp[0].dir = (uint8_t)ipsec_direction::outbound;
    xfrm_sp[0].index = 1230;
    xfrm_sp[0].priority = 9876;

    xfrm_sp[0].sel.family = AF_INET;
    xfrm_sp[0].sel.saddr.a4 = inet_addr("10.100.1.0");
    xfrm_sp[0].sel.daddr.a4 = inet_addr("10.100.1.0");
    xfrm_sp[0].sel.prefixlen_s = 24;
    xfrm_sp[0].sel.prefixlen_d = 24;
    xfrm_sp[0].sel.proto = 50;

    xfrm_tmpl.family = AF_INET;
    xfrm_tmpl.id.proto = 50;
    xfrm_tmpl.mode = (uint8_t)ipsec_mode::tunnel;
    xfrm_tmpl.reqid = 0x100;
    xfrm_tmpl.id.daddr.a4 = inet_addr("10.100.1.1");
    xfrm_tmpl.saddr.a4 = inet_addr("10.100.1.2");

    nlh.nlmsg_len = sizeof(struct xfrm_userpolicy_info);
    nlh.nlmsg_type = XFRM_MSG_GETPOLICY;

    ///////////////////////////////////////

    ON_CALL(m_mnl_wrapper, attr_parse_payload(_, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::attr_parse_payload_sp));

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(&xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sp[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()));

    EXPECT_CALL(m_mnl_wrapper, attr_get_payload(Eq(nl_attr_tmpl)))
            .WillOnce(Return(&xfrm_tmpl));

    EXPECT_CALL(m_mnl_wrapper, attr_get_len(Eq(nl_attr_tmpl)))
            .WillOnce(Return(sizeof(struct xfrm_user_tmpl)));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(&nlh, &cbdata), MNL_CB_OK);

    ///////////////////////////////////////

    EXPECT_EQ(sp.m_action, (ipsec_action)xfrm_sp[0].action);
    EXPECT_EQ(sp.m_id.m_dir, (ipsec_direction)xfrm_sp[0].dir);
    EXPECT_EQ(sp.m_index, xfrm_sp[0].index);
    EXPECT_EQ(sp.m_priority, xfrm_sp[0].priority);

    EXPECT_EQ(sp.m_id.m_selector.m_addr_family, xfrm_sp[0].sel.family);
    EXPECT_EQ(memcmp(&sp.m_id.m_selector.m_src_addr, &xfrm_sp[0].sel.saddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&sp.m_id.m_selector.m_dst_addr, &xfrm_sp[0].sel.daddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(sp.m_id.m_selector.m_src_mask, xfrm_sp[0].sel.prefixlen_s);
    EXPECT_EQ(sp.m_id.m_selector.m_dst_mask, xfrm_sp[0].sel.prefixlen_d);

    ASSERT_EQ(sp.m_template_lists.size(), 1);

    const ipsec_tmpl& tmpl = sp.m_template_lists[0];
    EXPECT_EQ(tmpl.m_addr_family, xfrm_tmpl.family);
    EXPECT_EQ(tmpl.m_protocol, xfrm_tmpl.id.proto);
    EXPECT_EQ(tmpl.m_mode, (ipsec_mode)xfrm_tmpl.mode);
    EXPECT_EQ(tmpl.m_req_id, xfrm_tmpl.reqid);
    EXPECT_EQ(memcmp(&tmpl.m_src_ip, &xfrm_tmpl.saddr, IP_ADDRESS_LENGTH), 0);
    EXPECT_EQ(memcmp(&tmpl.m_dst_ip, &xfrm_tmpl.id.daddr, IP_ADDRESS_LENGTH), 0);
}

/**
 * Objective: Verify that parse xfrm sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSPDataNull)
{
    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(nullptr, nullptr), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSPMsgTypeIncorrect)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sp sp;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sp;

    nlh.nlmsg_len = sizeof(struct xfrm_userpolicy_info);
    nlh.nlmsg_type = XFRM_MSG_ALLOCSPI;

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSPPayloadNull)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sp sp;

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sp;

    nlh.nlmsg_len = sizeof(struct xfrm_userpolicy_info);
    nlh.nlmsg_type = XFRM_MSG_GETPOLICY;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(nullptr));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSPParsePayloadFailed)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    ipsec_sp sp;
    struct xfrm_userpolicy_info xfrm_sp[2] = { 0 };

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = &sp;

    nlh.nlmsg_len = sizeof(struct xfrm_userpolicy_info);
    nlh.nlmsg_type = XFRM_MSG_GETPOLICY;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sp[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()))
            .WillOnce(Return(-1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(&nlh, &cbdata), MNL_CB_ERROR);
}

/**
 * Objective: Verify that parse xfrm sp will return the correct error
 **/
TEST_F(IPsecNetlinkAPITestSuite, TestParseXFRMSPNullObjectParseSP)
{
    IPsecNetlinkAPI::CB_Data cbdata;
    struct nlmsghdr nlh;
    struct xfrm_userpolicy_info xfrm_sp[2] = { 0 };

    ///////////////////////////////////////

    cbdata.m_netlink_api = &m_netlink_api;
    cbdata.user_data = nullptr;

    nlh.nlmsg_len = sizeof(struct xfrm_userpolicy_info);
    nlh.nlmsg_type = XFRM_MSG_GETPOLICY;

    ///////////////////////////////////////

    EXPECT_CALL(m_mnl_wrapper, nlmsg_get_payload(Eq(&nlh)))
            .WillOnce(Return(xfrm_sp));

    EXPECT_CALL(m_mnl_wrapper, attr_parse_payload(Eq(&xfrm_sp[1]), Eq(0),
                            Eq(m_netlink_api.addr_parse_nested_attr()), NotNull()))
            .WillOnce(Return(1));

    ///////////////////////////////////////

    EXPECT_EQ(m_netlink_api.call_mnl_parse_xfrm_sp(&nlh, &cbdata), MNL_CB_ERROR);
}
