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

extern "C"
{
#include <libvici.h>
}

/**********************************
*Local Includes
**********************************/
#include "IViciAPI.h"
#include "IKEViciAPI.h"
#include "mock_IViciAPI.h"
#include "ops_ipsecd_helper.h"
#include "ops_ipsecd_vici_defs.h"

/**********************************
*Using
**********************************/
using ::testing::An;
using ::testing::Eq;
using ::testing::Test;
using ::testing::StrEq;
using ::testing::Return;
using ::testing::InSequence;

class IKEViciAPI_EnO : public IKEViciAPI
{
    public:

        IKEViciAPI_EnO(IViciAPI& vici_api)
            : IKEViciAPI(vici_api)
        {
        }

        void reset()
        {
            m_is_ready = false;
        }

        void set_is_ready(bool value)
        {
            m_vici_connection = nullptr;
            m_is_ready = value;
        }

        bool get_is_ready()
        {
            return m_is_ready;
        }

        void set_vici_connection(vici_conn_t* value)
        {
            m_vici_connection = value;
        }

        vici_conn_t* get_vici_connection()
        {
            return m_vici_connection;
        }

        void call_deinitialize()
        {
            deinitialize();
        }
};

class IKEViciAPITestSuite : public Test
{
    public:

        MockIViciAPI m_vici_api;
        IKEViciAPI_EnO m_ike_vici_api;

        IKEViciAPITestSuite()
            : m_ike_vici_api(m_vici_api)
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
            m_ike_vici_api.reset();
        }

        /**
         * Create Basic IKE Connection Object to use in the tests
         */
        ipsec_ike_connection CreateConnectionObject()
        {
            ipsec_ike_connection conn;

            conn.m_name                     = "TestConn";

            conn.m_addr_family              = AF_INET;
            conn.m_local_ip                 = "10.1.2.1";
            conn.m_remote_ip                = "10.1.2.2";
            conn.m_ike_version              = ipsec_ike_version::v2;

            conn.m_cipher                   = ipsec_cipher::cipher_aes;
            conn.m_integrity                = ipsec_integrity::sha1;
            conn.m_diffie_group             = ipsec_diffie_group::group_2;

            conn.m_local_peer.m_id          = "Local_ID";
            conn.m_local_peer.m_auth_by     = ipsec_authby::psk;
            conn.m_local_peer.m_cert        = "";

            conn.m_remote_peer.m_id         = "Remote_ID";
            conn.m_remote_peer.m_auth_by    = ipsec_authby::psk;
            conn.m_remote_peer.m_cert       = "";

            conn.m_child_sa.m_cipher        = ipsec_cipher::cipher_aes;
            conn.m_child_sa.m_integrity     = ipsec_integrity::sha1;
            conn.m_child_sa.m_diffie_group  = ipsec_diffie_group::group_2;
            conn.m_child_sa.m_mode          = ipsec_mode::transport;
            conn.m_child_sa.m_auth_method   = ipsec_auth_method::esp;

            return conn;
        }

        /**
         * Set Basic Expectations for the Create Connections tests to use. To
         * not have to repeat code
         *
         * @param conn IKE Connection Object
         *
         * @param reqTest VICI Request Object (Faked)
         */
        void SetCreateConnectionExpectation(const ipsec_ike_connection& conn,
                                            vici_req_t* reqTest)
        {
            std::string sa_prop = ipsecd_helper::cipher_integrity_group_to_str(
                                                        conn.m_child_sa.m_cipher,
                                                        conn.m_child_sa.m_integrity,
                                                        conn.m_child_sa.m_diffie_group);

            std::string ike_prop = ipsecd_helper::cipher_integrity_group_to_str(
                                                        conn.m_cipher,
                                                        conn.m_integrity,
                                                        conn.m_diffie_group);

            {
                /**
                 * Using InSequence here will force the test to make sure all
                 * the functions are expected to be called in the following
                 * sequence, because of how the message is created if functions
                 * where to be moved the call can fail.
                 */
                InSequence s;

                EXPECT_CALL(m_vici_api, begin_section(Eq(reqTest), StrEq(conn.m_name)));

                EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                            StrEq(IPSEC_VICI_LOCAL_ADDRS)));
                EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                            StrEq(conn.m_local_ip)));
                EXPECT_CALL(m_vici_api,
                            end_list(Eq(reqTest))); //End IPSEC_VICI_LOCAL_ADDRS

                EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                            StrEq(IPSEC_VICI_REMOTE_ADDRS)));
                EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                            StrEq(conn.m_remote_ip)));
                EXPECT_CALL(m_vici_api,
                            end_list(Eq(reqTest))); //End IPSEC_VICI_REMOTE_ADDRS

                EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                            StrEq(IPSEC_VICI_PROPOSALS)));
                EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                            StrEq(ike_prop)));
                EXPECT_CALL(m_vici_api,
                            end_list(Eq(reqTest))); //End IPSEC_VICI_PROPOSALS

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_VERSION),
                            StrEq(ipsecd_helper::ike_version_to_str(conn.m_ike_version))
                            ));

                EXPECT_CALL(m_vici_api, begin_section(Eq(reqTest),
                            StrEq(IPSEC_VICI_CHILDREN)));
                EXPECT_CALL(m_vici_api, begin_section(Eq(reqTest), StrEq(conn.m_name)));

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_MODE),
                            StrEq(ipsecd_helper::mode_to_str(conn.m_child_sa.m_mode))
                            ));

                EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                            StrEq(IPSEC_VICI_LOCAL_TS)));
                EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                            StrEq("dynamic")));
                EXPECT_CALL(m_vici_api,
                            end_list(Eq(reqTest))); //End IPSEC_VICI_LOCAL_TS

                EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                            StrEq(IPSEC_VICI_REMOTE_TS)));
                EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                            StrEq("dynamic")));
                EXPECT_CALL(m_vici_api,
                            end_list(Eq(reqTest))); //End IPSEC_VICI_REMOTE_TS


                if(conn.m_child_sa.m_auth_method == ipsec_auth_method::ah)
                {
                    EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                                StrEq(IPSEC_VICI_AH_PROPOSALS)));
                    EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                                StrEq(sa_prop)));
                    EXPECT_CALL(m_vici_api,
                                end_list(Eq(reqTest))); //End IPSEC_VICI_AH_PROPOSALS
                }
                else
                {
                    EXPECT_CALL(m_vici_api, begin_list(Eq(reqTest),
                                StrEq(IPSEC_VICI_ESP_PROPOSALS)));
                    EXPECT_CALL(m_vici_api, add_list_item(Eq(reqTest),
                                StrEq(sa_prop)));
                    EXPECT_CALL(m_vici_api,
                                end_list(Eq(reqTest))); //End IPSEC_VICI_ESP_PROPOSALS
                }

                EXPECT_CALL(m_vici_api, end_section(Eq(reqTest))); //End <Child Name>
                EXPECT_CALL(m_vici_api, end_section(Eq(reqTest))); //End IPSEC_VICI_CHILDREN

                EXPECT_CALL(m_vici_api, begin_section(Eq(reqTest),
                            StrEq(IPSEC_VICI_LOCAL)));

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_ID),
                            StrEq(conn.m_local_peer.m_id)
                            ));

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_AUTH),
                            StrEq(ipsecd_helper::authby_to_str(conn.m_local_peer.m_auth_by))
                            ));

                if(conn.m_local_peer.m_auth_by == ipsec_authby::pubkey)
                {
                    EXPECT_CALL(m_vici_api, free_req(reqTest));

                    EXPECT_EQ(m_ike_vici_api.create_connection(conn),
                              ipsec_ret::ERR);

                    return;
                }

                EXPECT_CALL(m_vici_api, end_section(Eq(reqTest))); //End IPSEC_VICI_LOCAL


                EXPECT_CALL(m_vici_api, begin_section(Eq(reqTest),
                            StrEq(IPSEC_VICI_REMOTE)));

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_ID),
                            StrEq(conn.m_remote_peer.m_id)
                            ));

                EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                            StrEq(IPSEC_VICI_AUTH),
                            StrEq(ipsecd_helper::authby_to_str(conn.m_remote_peer.m_auth_by))
                            ));

                if(conn.m_remote_peer.m_auth_by == ipsec_authby::pubkey)
                {
                    EXPECT_CALL(m_vici_api, free_req(reqTest));

                    EXPECT_EQ(m_ike_vici_api.create_connection(conn),
                              ipsec_ret::ERR);

                    return;
                }

                EXPECT_CALL(m_vici_api, end_section(Eq(reqTest))); //End IPSEC_VICI_REMOTE

                EXPECT_CALL(m_vici_api, end_section(Eq(reqTest))); //End <Connection Name>
            }
        }
};

/**
 * Objective: Verify that initialize sets up all the member fields
 **/
TEST_F(IKEViciAPITestSuite, TestInitialize)
{
    vici_conn_t* empty_conn = (vici_conn_t*)0x100;

    EXPECT_FALSE(m_ike_vici_api.get_is_ready());

    EXPECT_CALL(m_vici_api, init());

    EXPECT_CALL(m_vici_api, connect(Eq(nullptr))).WillOnce(Return(empty_conn));

    EXPECT_EQ(m_ike_vici_api.initialize(), ipsec_ret::OK);

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), empty_conn);
    EXPECT_TRUE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify that initialize returns error if connection can't be
 * establish with VICI Socket
 **/
TEST_F(IKEViciAPITestSuite, TestInitializeConnectFailed)
{
    EXPECT_FALSE(m_ike_vici_api.get_is_ready());

    EXPECT_CALL(m_vici_api, init());

    EXPECT_CALL(m_vici_api, connect(Eq(nullptr))).WillOnce(Return(nullptr));

    EXPECT_CALL(m_vici_api, deinit());

    EXPECT_EQ(m_ike_vici_api.initialize(), ipsec_ret::SOCKET_OPEN_FAILED);

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), nullptr);

    EXPECT_FALSE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify that initialize returns ok is Is Ready variables
 * is already set to true.
 **/
TEST_F(IKEViciAPITestSuite, TestInitializeReadyIsTrue)
{
    m_ike_vici_api.set_is_ready(true);

    EXPECT_EQ(m_ike_vici_api.initialize(), ipsec_ret::OK);

    EXPECT_TRUE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify Create Connection will not work if Is Ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionIsReadyFalse)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn;

    EXPECT_EQ(m_ike_vici_api.create_connection(conn), ipsec_ret::NOT_READY);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection (ESP + PSK) can be created.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionESP_LocalRemotePSK)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::esp;
    conn.m_local_peer.m_auth_by = ipsec_authby::psk;
    conn.m_remote_peer.m_auth_by = ipsec_authby::psk;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                .WillOnce(Return(resTest));

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest),
                StrEq(""), StrEq(IPSEC_VICI_SUCCESS)))
                .WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.create_connection(conn), ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection (AH + PSK) can be created.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionAH_LocalRemotePSK)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::ah;
    conn.m_local_peer.m_auth_by = ipsec_authby::psk;
    conn.m_remote_peer.m_auth_by = ipsec_authby::psk;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                .WillOnce(Return(resTest));

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest),
                StrEq(""), StrEq(IPSEC_VICI_SUCCESS)))
                .WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.create_connection(conn), ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a submit fails to create a connection
 * then the appropriate errors will be set.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionSubmitFailed)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::ah;
    conn.m_local_peer.m_auth_by = ipsec_authby::psk;
    conn.m_remote_peer.m_auth_by = ipsec_authby::psk;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                .WillOnce(Return(nullptr));

    EXPECT_EQ(m_ike_vici_api.create_connection(conn), ipsec_ret::ERR);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a connection can't be added
 * then the appropriate errors will be set.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionAddFailed)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::ah;
    conn.m_local_peer.m_auth_by = ipsec_authby::psk;
    conn.m_remote_peer.m_auth_by = ipsec_authby::psk;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                .WillOnce(Return(resTest));

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest),
                StrEq(""), StrEq(IPSEC_VICI_SUCCESS)))
                .WillOnce(Return("no"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.create_connection(conn), ipsec_ret::ADD_FAILED);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection (ESP + Local PubKey) can't be created
 * at this time.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionESP_LocalPubKey)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::esp;
    conn.m_local_peer.m_auth_by = ipsec_authby::pubkey;
    conn.m_remote_peer.m_auth_by = ipsec_authby::psk;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection (ESP + Remote PubKey) can't be created
 * at this time.
 **/
TEST_F(IKEViciAPITestSuite, TestCreateConnectionESP_RemotePubKey)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    ipsec_ike_connection conn = CreateConnectionObject();
    conn.m_child_sa.m_auth_method = ipsec_auth_method::esp;
    conn.m_local_peer.m_auth_by = ipsec_authby::psk;
    conn.m_remote_peer.m_auth_by = ipsec_authby::pubkey;

    EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_CONN)))
                .WillOnce(Return(reqTest));

    SetCreateConnectionExpectation(conn, reqTest);

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that deinitialize clears up all the member fields
 **/
TEST_F(IKEViciAPITestSuite, TestDeinitialize)
{
    vici_conn_t* connViciTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(connViciTest);

    EXPECT_CALL(m_vici_api, disconnect(Eq(connViciTest)));

    EXPECT_CALL(m_vici_api, deinit());

    m_ike_vici_api.call_deinitialize();

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), nullptr);
    EXPECT_FALSE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify that deinitialize clears up all the member fields
 * if Vici Connection is null, it will not try to disconnect
 **/
TEST_F(IKEViciAPITestSuite, TestDeinitializeViciConnNULL)
{
    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(nullptr);

    EXPECT_CALL(m_vici_api, deinit());

    m_ike_vici_api.call_deinitialize();

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), nullptr);
    EXPECT_FALSE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify that deinitialize does not do anything
 * if is ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestDeinitializeIsReadyFalse)
{
    vici_conn_t* connViciTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(connViciTest);

    m_ike_vici_api.call_deinitialize();

    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), connViciTest);
    EXPECT_FALSE(m_ike_vici_api.get_is_ready());
}

/**
 * Objective: Verify Delete Connection will not work if Is Ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestDeleteConnectionIsReadyFalse)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.delete_connection("TestConn"),
              ipsec_ret::NOT_READY);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if an empty string is pass as a name an error is
 * returned
 **/
TEST_F(IKEViciAPITestSuite, TestDeleteConnectionEmptyName)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.delete_connection(""),
              ipsec_ret::EMPTY_STRING);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection can be deleted
 **/
TEST_F(IKEViciAPITestSuite, TestDeleteConnection)
{
    std::string connName = "TestConn";
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_UNLOAD_CONN)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_NAME),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.delete_connection(connName),
              ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a submit delete connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestDeleteConnectionSubmitFailed)
{
    std::string connName = "TestConn";
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_UNLOAD_CONN)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_NAME),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(nullptr));
    }

    EXPECT_EQ(m_ike_vici_api.delete_connection(connName),
              ipsec_ret::ERR);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a delete connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestDeleteConnectionDeleteFails)
{
    std::string connName = "TestConn";
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_UNLOAD_CONN)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_NAME),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("no"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.delete_connection(connName),
              ipsec_ret::DELETE_FAILED);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify Start Connection will not work if Is Ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestStartConnectionIsReadyFalse)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.start_connection("TestConn", 100),
              ipsec_ret::NOT_READY);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if an empty string is pass as a name an error is
 * returned
 **/
TEST_F(IKEViciAPITestSuite, TestStartConnectionEmptyName)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.start_connection("", 100),
              ipsec_ret::EMPTY_STRING);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection can be started
 **/
TEST_F(IKEViciAPITestSuite, TestStartConnection)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_INITIATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_CHILD),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_INIT_LIMITS),
                                              Eq(1)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.start_connection(connName, timeout),
              ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a submit start connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestStartConnectionSubmitFailed)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_INITIATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_CHILD),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_INIT_LIMITS),
                                              Eq(1)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(nullptr));
    }

    EXPECT_EQ(m_ike_vici_api.start_connection(connName, timeout),
              ipsec_ret::ERR);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a start connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestStartConnectionStartFails)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_INITIATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_CHILD),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_INIT_LIMITS),
                                              Eq(1)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("no"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.start_connection(connName, timeout),
              ipsec_ret::START_FAILED);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify Stop Connection will not work if Is Ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestStopConnectionIsReadyFalse)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.stop_connection("TestConn", 100),
              ipsec_ret::NOT_READY);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if an empty string is pass as a name an error is
 * returned
 **/
TEST_F(IKEViciAPITestSuite, TestStopConnectionEmptyName)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.stop_connection("", 100),
              ipsec_ret::EMPTY_STRING);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that a connection can be stop
 **/
TEST_F(IKEViciAPITestSuite, TestStopConnection)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_TERMINATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_IKE),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.stop_connection(connName, timeout),
              ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a submit stop connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestStopConnectionSubmitFailed)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_TERMINATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_IKE),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(nullptr));
    }

    EXPECT_EQ(m_ike_vici_api.stop_connection(connName, timeout),
              ipsec_ret::ERR);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify that if a stop connection fails
 * an error will be return
 **/
TEST_F(IKEViciAPITestSuite, TestStopConnectionStopFails)
{
    std::string connName = "TestConn";
    uint32_t timeout = 100;
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_TERMINATE)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_IKE),
                                              StrEq(connName)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_TIMEOUT),
                                              Eq(timeout)));

        EXPECT_CALL(m_vici_api, add_key_value_uint(Eq(reqTest),
                                              StrEq(IPSEC_VICI_LOG_LEVEL),
                                              Eq(0)));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("no"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.stop_connection(connName, timeout),
              ipsec_ret::STOP_FAILED);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify Load Credential will not work if Is Ready is false
 **/
TEST_F(IKEViciAPITestSuite, TestLoadCredentialIsReadyFalse)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    ipsec_credential cred;

    m_ike_vici_api.set_is_ready(false);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    EXPECT_EQ(m_ike_vici_api.load_credential(cred),
              ipsec_ret::NOT_READY);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify Load Credential will add a PSK Credential
 **/
TEST_F(IKEViciAPITestSuite, TestLoadCredentialPSK)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    ipsec_credential cred;
    cred.m_cred_type    = ipsec_credential_type::psk;
    cred.m_psk          = "TestPSK";

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_SHARED)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                                              StrEq(IPSEC_VICI_DATA),
                                              StrEq(cred.m_psk)));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                        StrEq(IPSEC_VICI_TYPE),
                        StrEq(ipsecd_helper::cred_to_str(cred.m_cred_type))));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.load_credential(cred),
              ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify Load Credential will add a RSA Credential
 **/
TEST_F(IKEViciAPITestSuite, TestLoadCredentialRSA)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    ipsec_credential cred;
    cred.m_cred_type    = ipsec_credential_type::rsa;
    cred.m_rsa.m_data   = (uint8_t*)0x400;
    cred.m_rsa.m_len    = 100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_KEY)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value(Eq(reqTest),
                                              StrEq(IPSEC_VICI_DATA),
                                              Eq(cred.m_rsa.m_data),
                                              Eq(cred.m_rsa.m_len)));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                        StrEq(IPSEC_VICI_TYPE),
                        StrEq(ipsecd_helper::cred_to_str(cred.m_cred_type))));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("yes"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.load_credential(cred),
              ipsec_ret::OK);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify if Submit fails that an error will be set by
 * Load Credential
 **/
TEST_F(IKEViciAPITestSuite, TestLoadCredentialSubmitFails)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;

    ipsec_credential cred;
    cred.m_cred_type    = ipsec_credential_type::rsa;
    cred.m_rsa.m_data   = (uint8_t*)0x400;
    cred.m_rsa.m_len    = 100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_KEY)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value(Eq(reqTest),
                                              StrEq(IPSEC_VICI_DATA),
                                              Eq(cred.m_rsa.m_data),
                                              Eq(cred.m_rsa.m_len)));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                        StrEq(IPSEC_VICI_TYPE),
                        StrEq(ipsecd_helper::cred_to_str(cred.m_cred_type))));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(nullptr));
    }

    EXPECT_EQ(m_ike_vici_api.load_credential(cred),
              ipsec_ret::ERR);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}

/**
 * Objective: Verify if the Load Credential can not upload the
 * credential an error will be set
 **/
TEST_F(IKEViciAPITestSuite, TestLoadCredentialLoadFails)
{
    vici_conn_t* viciConnTest = (vici_conn_t*)0x100;
    vici_req_t* reqTest = (vici_req_t*)0x200;
    vici_res_t* resTest = (vici_res_t*)0x300;

    ipsec_credential cred;
    cred.m_cred_type    = ipsec_credential_type::rsa;
    cred.m_rsa.m_data   = (uint8_t*)0x400;
    cred.m_rsa.m_len    = 100;

    m_ike_vici_api.set_is_ready(true);
    m_ike_vici_api.set_vici_connection(viciConnTest);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, begin(StrEq(IPSEC_VICI_LOAD_KEY)))
                    .WillOnce(Return(reqTest));

        EXPECT_CALL(m_vici_api, add_key_value(Eq(reqTest),
                                              StrEq(IPSEC_VICI_DATA),
                                              Eq(cred.m_rsa.m_data),
                                              Eq(cred.m_rsa.m_len)));

        EXPECT_CALL(m_vici_api, add_key_value_str(Eq(reqTest),
                        StrEq(IPSEC_VICI_TYPE),
                        StrEq(ipsecd_helper::cred_to_str(cred.m_cred_type))));

        EXPECT_CALL(m_vici_api, submit(Eq(reqTest), Eq(viciConnTest)))
                    .WillOnce(Return(resTest));
    }

    EXPECT_CALL(m_vici_api, find_str(Eq(resTest), StrEq(""),
                StrEq(IPSEC_VICI_SUCCESS))).WillOnce(Return("no"));

    EXPECT_CALL(m_vici_api, free_res(Eq(resTest)));

    EXPECT_EQ(m_ike_vici_api.load_credential(cred),
              ipsec_ret::ADD_FAILED);
    EXPECT_EQ(m_ike_vici_api.get_vici_connection(), viciConnTest);
}
