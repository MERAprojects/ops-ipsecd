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
