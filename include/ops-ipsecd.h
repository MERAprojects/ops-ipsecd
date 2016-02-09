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
    NOT_PARSE,
    PARSE_ERR,
    REGISTER_FAILED,

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

enum class ipsec_state : int32_t
{
    /**
     * Error in the Configuration, it was not able to be set
     */
    config_error = -10000,

    /////////////////////

    /**
     * Configuration was accepted, but not applied yet
     */
    config_ok = 0,

    /**
     * Connection has been created, but not yet establish
     */
    created,

    /**
     * Connection is trying to connect
     */
    connecting,

    /**
     * IKE Connection is not been managed by IKE Daemon(strongSWAN)
     */
    passive,

    /**
     * Connection is renewing its keys
     */
    rekeying,

    /**
     * Deleting the connection information (in progress)
     */
    deleting,

    /**
     * Destroyed the connection
     */
    destroying,

    /**
     * SPD installed but no SAD Entries
     */
    routed,

    /**
     * Trying to install the policies into the kernel
     */
    installing,

    /**
     * Updating connection with new information
     */
    updating,

    /**
     * Connections has changed its keys
     */
    rekeyed,

    /**
     * Retrying to connect
     */
    retrying,

    /**
     * SA or SP policies has been installed in the kernel
     */
    installed,

    /**
     * Connections has been establish
     */
    establish
};

enum class ipsec_direction : uint32_t
{
    outbound = 0,
    inbound,
    forward
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
    uint16_t m_addr_family              = AF_INET;

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

/**
 * IPsec IKE Connection Statistics Values
 */
struct ipsec_ike_connection_stats
{
    /**
     * Name of the Connection
     */
    std::string m_conn_name = "";

    /**
     * Seconds since been establish
     */
    uint32_t m_establish_secs = 0;

    /**
     * Initiator SPI/Cookie
     */
    uint64_t m_initiator_spi = 0;

    /**
     * Responder SPI/Cookie
     */
    uint64_t m_responder_spi = 0;

    /**
     * Seconds till IKE connection re-keys
     */
    uint32_t m_rekey_time = 0;

    /**
     * State of the IKE Connection
     */
    ipsec_state m_conn_state = ipsec_state::config_error;

    /**
     * Seconds before SA expires
     */
    uint32_t m_sa_lifetime = 0;

    /**
     * Seconds before SA re-keys
     */
    uint32_t m_sa_rekey = 0;

    /**
     * Number of input bytes processed
     */
    uint64_t m_bytes_in = 0;

    /**
     * Number of output bytes processed
     */
    uint64_t m_bytes_out = 0;

    /**
     * Number of input packets processed
     */
    uint64_t m_packets_in = 0;

    /**
     * Number of output packets processed
     */
    uint64_t m_packets_out = 0;

    /**
     * State of the SA
     */
    ipsec_state m_sa_state = ipsec_state::config_error;

    /**
     * Inbound SA SPI
     */
    uint32_t m_sa_spi_in = 0;

    /**
     * Outbound SA SPI
     */
    uint32_t m_sa_spi_out = 0;
};

/**
 * IPsec current lifetime Values
 */
struct ipsec_lifetime_current
{
    /**
     * Date added in epoch
     */
    uint64_t m_add_time = 0;

    /**
     * Date used in epoch
     */
    uint64_t m_use_time = 0;

    /**
     * Amount of bytes processed
     */
    uint64_t m_bytes;

    /**
     * Amount of packets processed
     */
    uint64_t m_packets;
};

struct ipsec_selector
{
    /**
     * Address Family of the Selector
     */
    uint16_t m_addr_family = AF_INET;

    /**
     * IP Source Address Range
     */
    ip_addr_t m_src_addr = { 0 };

    /**
     * Source Address Mask
     */
    uint8_t m_src_mask = 0;

    /**
     * IP Destination Address Range
     */
    ip_addr_t m_dst_addr = { 0 };

    /**
     * Destination Address Mask
     */
    uint8_t m_dst_mask = 0;
};

/**
 * SP ID
 */
struct ipsec_sp_id
{
    /**
     * Direction of the packets for the the Policy
     */
    ipsec_direction m_dir;

    /**
     * Selector for the SP
     */
    ipsec_selector m_selector;
};

/**
 * Statistic information for the SA
 */
struct ipsec_sa_stats
{
    /**
     * SPI used in SA
     */
    uint32_t m_spi = 0;

    /**
     * Size of the replay-window
     */
    uint32_t m_replay_window = 0;

    /**
     * Number of replays
     */
    uint32_t m_replay = 0;

    /**
     * Number of failed integrity checks
     */
    uint32_t m_integrity_failed = 0;

    /**
     * Lifetime stats of the SA
     */
    ipsec_lifetime_current m_life_stats;
};

/**
 * Statistic information for the SP
 */
struct ipsec_sp_stats
{
    /**
     * ID of the SP
     */
    ipsec_sp_id m_id;

    /**
     * Lifetime stats of the SP
     */
    ipsec_lifetime_current m_life_stats;
};

#endif