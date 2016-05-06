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
#include <error_notify_msg.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ops_ipsecd_helper.h"

/**********************************
*Using
**********************************/
using ::testing::Test;

class IPsecdHelperTestSuite : public Test
{
    public:

        IPsecdHelperTestSuite()
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
        }
};

/**
 * Objective: Verify that Cipher to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestCipherToStr)
{
    EXPECT_STREQ(ipsecd_helper::cipher_to_str(ipsec_cipher::cipher_aes),
                 "aes");

    EXPECT_STREQ(ipsecd_helper::cipher_to_str(ipsec_cipher::cipher_aes256),
                 "aes256");

    EXPECT_STREQ(ipsecd_helper::cipher_to_str(ipsec_cipher::cipher_3des),
                 "3des");

    EXPECT_STREQ(ipsecd_helper::cipher_to_str(ipsec_cipher::cipher_none),
                 "");
}

/**
 * Objective: Verify that Integrity to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestIntegrityToStr)
{
    EXPECT_STREQ(ipsecd_helper::integrity_to_str(ipsec_integrity::sha1),
                 "sha1");

    EXPECT_STREQ(ipsecd_helper::integrity_to_str(ipsec_integrity::sha256),
                 "sha256");

    EXPECT_STREQ(ipsecd_helper::integrity_to_str(ipsec_integrity::sha512),
                 "sha512");

    EXPECT_STREQ(ipsecd_helper::integrity_to_str(ipsec_integrity::md5),
                 "md5");

    EXPECT_STREQ(ipsecd_helper::integrity_to_str(ipsec_integrity::none),
                 "");
}

/**
 * Objective: Verify that Diffie Group to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestDiffieGroupToStr)
{
    EXPECT_STREQ(ipsecd_helper::group_to_str(ipsec_diffie_group::group_2),
                 "modp1024");

    EXPECT_STREQ(ipsecd_helper::group_to_str(ipsec_diffie_group::group_14),
                 "modp2048");

    EXPECT_STREQ(ipsecd_helper::group_to_str(ipsec_diffie_group::group_none),
                 "");
}

/**
 * Objective: Verify that AuthBy to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestAuthByToStr)
{
    EXPECT_STREQ(ipsecd_helper::authby_to_str(ipsec_authby::pubkey),
                 "pubkey");

    EXPECT_STREQ(ipsecd_helper::authby_to_str(ipsec_authby::psk),
                 "psk");

    EXPECT_STREQ(ipsecd_helper::authby_to_str((ipsec_authby)-1),
                 "");
}

/**
 * Objective: Verify that IKE Version to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestIKEVersionToStr)
{
    EXPECT_STREQ(ipsecd_helper::ike_version_to_str(ipsec_ike_version::v1),
                 "1");

    EXPECT_STREQ(ipsecd_helper::ike_version_to_str(ipsec_ike_version::v2),
                 "2");

    EXPECT_STREQ(ipsecd_helper::ike_version_to_str(ipsec_ike_version::v1v2),
                 "0");

    EXPECT_STREQ(ipsecd_helper::ike_version_to_str((ipsec_ike_version)-1),
                 "");
}

/**
 * Objective: Verify that Mode to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestModeToStr)
{
    EXPECT_STREQ(ipsecd_helper::mode_to_str(ipsec_mode::transport),
                 "Transport");

    EXPECT_STREQ(ipsecd_helper::mode_to_str(ipsec_mode::tunnel),
                 "Tunnel");

    EXPECT_STREQ(ipsecd_helper::mode_to_str((ipsec_mode)-1),
                 "");
}

/**
 * Objective: Verify that Credential to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestCredToStr)
{
    EXPECT_STREQ(ipsecd_helper::cred_to_str(ipsec_credential_type::psk),
                 "ike");

    EXPECT_STREQ(ipsecd_helper::cred_to_str(ipsec_credential_type::rsa),
                 "rsa");

    EXPECT_STREQ(ipsecd_helper::cred_to_str((ipsec_credential_type)-1),
                 "");
}

/**
 * Objective: Verify that Cipher Integrity Group
 * to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestCipherIntegrityGroupToStr)
{
    std::string res = "";

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_none,
                    ipsec_integrity::none,
                    ipsec_diffie_group::group_none);
    EXPECT_EQ(res.compare(""), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_aes,
                    ipsec_integrity::none,
                    ipsec_diffie_group::group_none);
    EXPECT_EQ(res.compare("aes"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_none,
                    ipsec_integrity::md5,
                    ipsec_diffie_group::group_none);
    EXPECT_EQ(res.compare("md5"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_none,
                    ipsec_integrity::none,
                    ipsec_diffie_group::group_14);
    EXPECT_EQ(res.compare("modp2048"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_aes,
                    ipsec_integrity::md5,
                    ipsec_diffie_group::group_none);
    EXPECT_EQ(res.compare("aes-md5"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_aes,
                    ipsec_integrity::none,
                    ipsec_diffie_group::group_14);
    EXPECT_EQ(res.compare("aes-modp2048"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_none,
                    ipsec_integrity::md5,
                    ipsec_diffie_group::group_14);
    EXPECT_EQ(res.compare("md5-modp2048"), 0);

    res = ipsecd_helper::cipher_integrity_group_to_str(
                    ipsec_cipher::cipher_aes,
                    ipsec_integrity::md5,
                    ipsec_diffie_group::group_14);
    EXPECT_EQ(res.compare("aes-md5-modp2048"), 0);
}

/**
 * Objective: Verify that IKE State to String will return the correct
 * ipsec state
 **/
TEST_F(IPsecdHelperTestSuite, TestIKEStateToString)
{
    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("ESTABLISHED"),
              ipsec_state::establish);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("CONNECTING"),
              ipsec_state::connecting);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("REKEYING"),
              ipsec_state::rekeying);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("DELETING"),
              ipsec_state::deleting);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("DESTROYING"),
              ipsec_state::destroying);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("PASSIVE"),
              ipsec_state::passive);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("CREATED"),
              ipsec_state::created);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("ROUTED"),
              ipsec_state::routed);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("INSTALLING"),
              ipsec_state::installing);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("INSTALLED"),
              ipsec_state::installed);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("UPDATING"),
              ipsec_state::updating);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("REKEYED"),
              ipsec_state::rekeyed);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("RETRYING"),
              ipsec_state::retrying);

    EXPECT_EQ(ipsecd_helper::ike_state_to_ipsec_state("BLaH"),
              ipsec_state::config_error);
}

/**
 * Objective: Verify that Char to Hex Value
 **/
TEST_F(IPsecdHelperTestSuite, TestCharToHex)
{
    uint8_t hex1 = 255;
    uint8_t hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex(102, hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex(48, hex1));

    EXPECT_TRUE(ipsecd_helper::char_to_hex(97, hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex(57, hex1));

    EXPECT_FALSE(ipsecd_helper::char_to_hex(103, hex1));
    EXPECT_FALSE(ipsecd_helper::char_to_hex(47, hex1));

    EXPECT_FALSE(ipsecd_helper::char_to_hex(96, hex1));
    EXPECT_FALSE(ipsecd_helper::char_to_hex(58, hex1));
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('A', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('a', hex2));
    EXPECT_EQ(hex1, 0xa);
    EXPECT_EQ(hex2, 0xa);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('B', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('b', hex2));
    EXPECT_EQ(hex1, 0xb);
    EXPECT_EQ(hex2, 0xb);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('C', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('c', hex2));
    EXPECT_EQ(hex1, 0xc);
    EXPECT_EQ(hex2, 0xc);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('D', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('d', hex2));
    EXPECT_EQ(hex1, 0xd);
    EXPECT_EQ(hex2, 0xd);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('E', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('e', hex2));
    EXPECT_EQ(hex1, 0xe);
    EXPECT_EQ(hex2, 0xe);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('F', hex1));
    EXPECT_TRUE(ipsecd_helper::char_to_hex('f', hex2));
    EXPECT_EQ(hex1, 0xf);
    EXPECT_EQ(hex2, 0xf);
    hex1 = 255;
    hex2 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('0', hex1));
    EXPECT_EQ(hex1, 0x0);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('1', hex1));
    EXPECT_EQ(hex1, 0x1);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('2', hex1));
    EXPECT_EQ(hex1, 0x2);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('3', hex1));
    EXPECT_EQ(hex1, 0x3);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('4', hex1));
    EXPECT_EQ(hex1, 0x4);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('5', hex1));
    EXPECT_EQ(hex1, 0x5);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('6', hex1));
    EXPECT_EQ(hex1, 0x6);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('7', hex1));
    EXPECT_EQ(hex1, 0x7);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('8', hex1));
    EXPECT_EQ(hex1, 0x8);
    hex1 = 255;

    EXPECT_TRUE(ipsecd_helper::char_to_hex('9', hex1));
    EXPECT_EQ(hex1, 0x9);
    hex1 = 255;
}

/**
 * Objective: Verify that Str to Hex will convert a string of hexadecimals to
 * a byte array
 **/
TEST_F(IPsecdHelperTestSuite, TestStrToHex)
{
    std::string wrong_str_1 = "AABBCC_USIAA";
    std::string wrong_str_2 = "A";
    std::string right_str = "AABBCCDDEEFF00112233445566778899";
    uint8_t base_test_arr[16] = { 0 };
    uint8_t test_arr[16] = { 0 };
    uint8_t arr_hex[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                          0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    uint8_t wrong_arr_hex[] = { 0xAA, 0xBB, 0xCC, 0xAA };

    ipsecd_helper::str_to_key(wrong_str_2, (char*)test_arr, 16);
    EXPECT_EQ(memcmp(test_arr, base_test_arr, 16), 0);

    ipsecd_helper::str_to_key(wrong_str_2, nullptr, 16);
    EXPECT_EQ(memcmp(test_arr, base_test_arr, 16), 0);

    ipsecd_helper::str_to_key(wrong_str_2, (char*)test_arr, 0);
    EXPECT_EQ(memcmp(test_arr, base_test_arr, 16), 0);

    ipsecd_helper::str_to_key(wrong_str_1, (char*)test_arr, 4);
    EXPECT_EQ(memcmp(test_arr, wrong_arr_hex, 4), 0);

    ipsecd_helper::str_to_key(right_str, (char*)test_arr, 16);
    EXPECT_EQ(memcmp(test_arr, arr_hex, 16), 0);
}

/**
 * Objective: Verify that Key(Hex) to Str will convert a byte array to string
 **/
TEST_F(IPsecdHelperTestSuite, TestKeyToStr)
{
    std::string ret = "123";
    std::string right_str = "aabbccddeeff00112233445566778899";
    uint8_t arr_hex[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                          0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };

    ret = ipsecd_helper::key_to_str(nullptr, 16);
    EXPECT_TRUE(ret.empty());
    ret = "123";

    ret = ipsecd_helper::key_to_str((char*)arr_hex, 0);
    EXPECT_TRUE(ret.empty());

    ret = ipsecd_helper::key_to_str((char*)arr_hex, 16);
    EXPECT_EQ(ret.compare(right_str), 0);
}

/**
 * Objective: Verify that Cipher to String will return the correct strings
 **/
TEST_F(IPsecdHelperTestSuite, TestSSErrorToIPsecErrorEvent)
{
    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_LOCAL_AUTH_FAILED),
                 ipsec_error_event::local_auth_failed);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_PEER_AUTH_FAILED),
                 ipsec_error_event::peer_auth_failed);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_PARSE_ERROR_HEADER),
                 ipsec_error_event::parse_error);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_PARSE_ERROR_BODY),
                 ipsec_error_event::parse_error);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_RETRANSMIT_SEND_TIMEOUT),
                 ipsec_error_event::retransmit_timeout);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_HALF_OPEN_TIMEOUT),
                 ipsec_error_event::half_open_timeout);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_PROPOSAL_MISMATCH_IKE),
                 ipsec_error_event::proposal_mismatch_ike);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_PROPOSAL_MISMATCH_CHILD),
                 ipsec_error_event::proposal_mismatch_sa);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_TS_MISMATCH),
                 ipsec_error_event::ts_mismatch);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_INSTALL_CHILD_SA_FAILED),
                 ipsec_error_event::adding_sa_failed);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_INSTALL_CHILD_POLICY_FAILED),
                 ipsec_error_event::adding_sp_failed);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_AUTHORIZATION_FAILED),
                 ipsec_error_event::auth_failed);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_CERT_EXPIRED),
                 ipsec_error_event::cert_expired);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_CERT_REVOKED),
                 ipsec_error_event::cert_revoked);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_NO_ISSUER_CERT),
                 ipsec_error_event::no_issuer_cert);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_RADIUS_NOT_RESPONDING),
                 ipsec_error_event::radius_conn_error);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_UNIQUE_REPLACE),
                 ipsec_error_event::misc);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_UNIQUE_KEEP),
                 ipsec_error_event::misc);

    EXPECT_EQ(ipsecd_helper::ss_error_to_ipsec_error_event(ERROR_NOTIFY_VIP_FAILURE),
                 ipsec_error_event::misc);
}
