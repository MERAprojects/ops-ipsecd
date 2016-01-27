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

#ifndef OPS_IPSECD_H_
#define OPS_IPSECD_H_

/**********************************
*System Includes
**********************************/
#include <string>
#include <stdint.h>
#include <arpa/inet.h>

/**********************************
*Defines
**********************************/

/**
 * Maximum lenght of a IPv6 Address
 */
#define IP_ADDRESS_LENGTH           16

/**********************************
*Enums
**********************************/

/**
 * Return Codes for functions
 */
enum class ipsec_ret : int32_t
{
    ERR = -10000,
    SOCKET_OPEN_FAILED,
    SOCKET_BIND_FAILED,
    SOCKET_CREATE_FAILED,
    SOCKET_SEND_FAILED,
    SOCKET_RECV_FAILED,
    ALLOC_FAILED,
    ADD_FAILED,
    DELETE_FAILED,
    START_FAILED,
    STOP_FAILED,
    INVALID_API,
    NULL_PARAMETERS,
    NULL_OBJECT,
    NOT_FOUND,
    INVALID_SIZE,
    NOT_READY,
    EMPTY_STRING,

    //Add Errors before this line
    OK = 0
};

enum class ipsec_ike_version : uint32_t
{
    v1 = 0,
    v2,
    v1v2
};

enum class ipsec_authby : uint32_t
{
    pubkey = 0,
    psk
};

enum class ipsec_cipher : uint32_t
{
    cipher_none = 0,
    cipher_aes,
    cipher_aes256,
    cipher_3des
};

enum class ipsec_integrity : uint32_t
{
    none = 0,
    sha1,
    sha256,
    sha512,
    md5
};

enum class ipsec_diffie_group : uint32_t
{
    group_none = 0,
    group_2,
    group_14
};

enum class ipsec_auth_method : uint32_t
{
    ah = 0,
    esp
};

enum class ipsec_mode : uint32_t
{
    transport = 0,
    tunnel
};

enum class ipsec_credential_type : uint32_t
{
    psk = 0,
    rsa
};

/**********************************
*Unions
**********************************/

/**
 * Union of IPv4 and IPv6 address types.
 * It's required for both kernel and user space code, so it needs to remain at this position
 * on the header file
 **/
typedef union
{
    in_addr_t m_ipv4;
    struct in6_addr m_ipv6;
    uint8_t m_raw[IP_ADDRESS_LENGTH];
} ip_addr_t;

/**********************************
*Structs
**********************************/

/**
 * IPsec Peer Config Values
 */
struct ipsec_peer
{
    /**
     * ID of an Peer can be a string or the certificate
     * "C=CH, O=Linux strongSwan, CN=moon.strongswan.org"
     */
    std::string m_id        = "";

    /**
     * How is the Peer going to authenticate
     */
    ipsec_authby m_auth_by  = ipsec_authby::psk;

    /**
     * Loaded Certificate in memory
     */
    std::string m_cert      = "";
};

/**
 * Child SA Config Values
 */
struct ipsec_child_sa
{
    /**
     * Cipher the Child SA is going to use
     */
    ipsec_cipher m_cipher               = ipsec_cipher::cipher_none;

    /**
     * Integrity the Child SA is going to use
     */
    ipsec_integrity m_integrity         = ipsec_integrity::none;

    /**
     * Diffie Group the Child SA is going to use
     */
    ipsec_diffie_group m_diffie_group   = ipsec_diffie_group::group_none;

    /**
     * IPsec Mode the Child SA is going to use
     */
    ipsec_mode m_mode                   = ipsec_mode::transport;

    /**
     * Authentication Method the Child SA is going to use
     */
    ipsec_auth_method m_auth_method     = ipsec_auth_method::esp;
};

/**
 * IKE Connection Config Values
 */
struct ipsec_ike_connection
{
    /**
     * Name of the Connection
     */
    std::string m_name                  = "";

    /**
     * Address Family of the connection
     */
    uint16_t m_addr_family              = 0;

    /**
     * Local End-point for the connection
     */
    std::string m_local_ip              = "";

    /**
     * Remote End-point for the connection
     */
    std::string m_remote_ip             = "";

    /**
     * IKE Version the connection will use to establish itself
     */
    ipsec_ike_version m_ike_version     = ipsec_ike_version::v1v2;

    /**
     * Cipher the IKE Connection will use
     */
    ipsec_cipher m_cipher               = ipsec_cipher::cipher_none;

    /**
     * Integrity the IKE Connection will use
     */
    ipsec_integrity m_integrity         = ipsec_integrity::none;

    /**
     * Diffie Group the IKE Connection will use
     */
    ipsec_diffie_group m_diffie_group   = ipsec_diffie_group::group_none;

    /**
     * Local Peer Config Options
     */
    ipsec_peer m_local_peer;

    /**
     * Remote Peer Config Options
     */
    ipsec_peer m_remote_peer;

    /**
     * Child SA Config Options for the IKE Connection
     */
    ipsec_child_sa m_child_sa;
};

/**
 * IPsec Credentials Config Values
 */
struct ipsec_credential
{
    /**
     * Type of Credential
     */
    ipsec_credential_type m_cred_type   = ipsec_credential_type::psk;

    /**
     * Pre-shared Key Value
     */
    std::string m_psk                   = "";
    //TODO: Missing Owners

    /**
     * RSA loaded in memory
     */
    struct
    {
        uint8_t* m_data                 = nullptr;
        uint32_t m_len                  = 0;
    } m_rsa;
};

#endif