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

/**********************************
*System Includes
**********************************/
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/xfrm.h>

/**********************************
*Local Includes
**********************************/
#include "IPsecNetlinkAPI.h"
#include "ops_ipsecd_helper.h"

/**********************************
*Function Declarations
**********************************/
IPsecNetlinkAPI::IPsecNetlinkAPI(ILibmnlWrapper& mnl_wrapper)
    : m_mnl_wrapper(mnl_wrapper)
{
}

IPsecNetlinkAPI::~IPsecNetlinkAPI()
{
}

ipsec_ret IPsecNetlinkAPI::create_socket(struct mnl_socket** nl_socket,
                                         uint32_t groups)
{
    int32_t ret = 0;

    ///////////////////////////////////////
    //Create and open Socket
    struct mnl_socket* tempNL = m_mnl_wrapper.socket_open(NETLINK_XFRM);
    if (tempNL == nullptr)
    {
        return ipsec_ret::SOCKET_OPEN_FAILED;
    }

    ///////////////////////////////////////
    //Bind Socket to Netlink
    ret = m_mnl_wrapper.socket_bind(tempNL, groups, MNL_SOCKET_AUTOPID);
    if (ret < 0)
    {
        m_mnl_wrapper.socket_close(tempNL);

        return ipsec_ret::SOCKET_BIND_FAILED;
    }

    ///////////////////////////////////////
    //Finish
    *nl_socket = tempNL;

    return ipsec_ret::OK;
}

ipsec_ret IPsecNetlinkAPI::add_sa(const ipsec_sa& sa)
{
    struct mnl_socket* nl_socket = nullptr;
    struct nlmsghdr* nlh = nullptr;
    struct xfrm_usersa_info* xfrm_sa = nullptr;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    nlh = m_mnl_wrapper.nlmsg_put_header(buf);
    if(nlh == nullptr)
    {
        return ipsec_ret::ALLOC_FAILED;
    }

    nlh->nlmsg_type     = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags    = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq      = time(nullptr);

    xfrm_sa = (struct xfrm_usersa_info*)m_mnl_wrapper.nlmsg_put_extra_header(nlh,
                                                 sizeof(struct xfrm_usersa_info));
    if(xfrm_sa == nullptr)
    {
        return ipsec_ret::ALLOC_FAILED;
    }
    memset(xfrm_sa, 0, sizeof(struct xfrm_usersa_info));

    ///////////////////////////////////////
    //Set XFRM SA ID
    xfrm_sa->family     = sa.m_id.m_addr_family;
    xfrm_sa->id.proto   = sa.m_id.m_protocol;
    xfrm_sa->id.spi     = htonl(sa.m_id.m_spi);
    memcpy(&xfrm_sa->id.daddr, &sa.m_id.m_dst_ip, IP_ADDRESS_LENGTH);
    memcpy(&xfrm_sa->saddr, &sa.m_id.m_src_ip, IP_ADDRESS_LENGTH);

    ///////////////////////////////////////
    //Set XFRM SA Base
    xfrm_sa->mode       = (uint8_t)sa.m_mode;
    xfrm_sa->reqid      = sa.m_req_id;
    xfrm_sa->flags      = sa.m_flags;
    xfrm_sa->replay_window  = 255;

    ///////////////////////////////////////
    //Set XFRM SA Selector
    memcpy(&xfrm_sa->sel.saddr, &sa.m_selector.m_src_addr, IP_ADDRESS_LENGTH);
    memcpy(&xfrm_sa->sel.daddr, &sa.m_selector.m_dst_addr, IP_ADDRESS_LENGTH);
    xfrm_sa->sel.family      = sa.m_selector.m_addr_family;
    xfrm_sa->sel.prefixlen_s = sa.m_selector.m_src_mask;
    xfrm_sa->sel.prefixlen_d = sa.m_selector.m_dst_mask;

    ///////////////////////////////////////
    //Set XFRM SA Lifetime Defaults
    xfrm_sa->lft.soft_byte_limit            = XFRM_INF;
    xfrm_sa->lft.hard_byte_limit            = XFRM_INF;

    xfrm_sa->lft.soft_packet_limit          = XFRM_INF;
    xfrm_sa->lft.hard_packet_limit          = XFRM_INF;

    xfrm_sa->lft.hard_add_expires_seconds   = 0;
    xfrm_sa->lft.soft_add_expires_seconds   = 0;

    xfrm_sa->lft.hard_use_expires_seconds   = 0;
    xfrm_sa->lft.soft_use_expires_seconds   = 0;

    ///////////////////////////////////////
    //Set XFRM SA Lifetime Defaults
    if(sa.m_crypt_set)
    {
        uint32_t xfrmAlgoKeySize = (sa.m_crypt.m_key.size() / 2);
        uint32_t xfrmAlgoSize = sizeof(struct xfrm_algo) + xfrmAlgoKeySize;

        struct xfrm_algo* xfrm_crypt = (struct xfrm_algo*)malloc(xfrmAlgoSize);

        memset(xfrm_crypt, 0, xfrmAlgoSize);

        ///////////////////////////////////////
        //Set Encryption Name
        strncpy(xfrm_crypt->alg_name, sa.m_crypt.m_name.c_str(),
                IPSEC_MAX_ALGO_NAME_LEN);

        ///////////////////////////////////////
        //Convert String Key to Byte Array
        ipsecd_helper::str_to_key(sa.m_crypt.m_key, xfrm_crypt->alg_key,
                                  xfrmAlgoKeySize);

        ///////////////////////////////////////
        //Set Key Size in Bits
        xfrm_crypt->alg_key_len = xfrmAlgoKeySize * 8;

        ///////////////////////////////////////
        //Set Attribute to Netlink
        m_mnl_wrapper.attr_put(nlh, XFRMA_ALG_CRYPT, xfrmAlgoSize, xfrm_crypt);

        ///////////////////////////////////////
        //Free the memory
        free(xfrm_crypt);
    }

    ///////////////////////////////////////
    //Set XFRM SA Lifetime Defaults
    if(sa.m_auth_set)
    {
        uint32_t xfrmAlgoKeySize = (sa.m_auth.m_key.size() / 2);
        uint32_t xfrmAlgoSize = sizeof(struct xfrm_algo) + xfrmAlgoKeySize;

        struct xfrm_algo* xfrm_auth = (struct xfrm_algo*)malloc(xfrmAlgoSize);

        memset(xfrm_auth, 0, xfrmAlgoSize);

        ///////////////////////////////////////
        //Set Auth Name
        strncpy(xfrm_auth->alg_name, sa.m_auth.m_name.c_str(),
                IPSEC_MAX_ALGO_NAME_LEN);

        ///////////////////////////////////////
        //Convert String Key to Byte Array
        ipsecd_helper::str_to_key(sa.m_auth.m_key, xfrm_auth->alg_key,
                                  xfrmAlgoKeySize);

        ///////////////////////////////////////
        //Set Key Size in Bits
        xfrm_auth->alg_key_len = xfrmAlgoKeySize * 8;

        ///////////////////////////////////////
        //Set Attribute to Netlink
        m_mnl_wrapper.attr_put(nlh, XFRMA_ALG_AUTH, xfrmAlgoSize, xfrm_auth);

        ///////////////////////////////////////
        //Free the memory
        free(xfrm_auth);
    }

    ///////////////////////////////////////
    //Get Socket
    if(create_socket(&nl_socket, 0) != ipsec_ret::OK)
    {
        return ipsec_ret::SOCKET_CREATE_FAILED;
    }

    ///////////////////////////////////////
    //Send Request and Listen for ACK
    if (m_mnl_wrapper.socket_sendto(nl_socket, nlh, nlh->nlmsg_len) < 0)
    {
        m_mnl_wrapper.socket_close(nl_socket);

        return ipsec_ret::SOCKET_SEND_FAILED;
    }


    if(m_mnl_wrapper.socket_recvfrom(nl_socket, buf, sizeof(buf)) < 0)
    {
        m_mnl_wrapper.socket_close(nl_socket);

        return ipsec_ret::SOCKET_RECV_FAILED;
    }

    m_mnl_wrapper.socket_close(nl_socket);

    ///////////////////////////////////////
    //Check if Netlink returned any errors
    const struct nlmsgerr* err =
                   (const struct nlmsgerr*)m_mnl_wrapper.nlmsg_get_payload(nlh);
    if(err->error != 0)
    {
        errno = -err->error;
        return ipsec_ret::ADD_FAILED;
    }

    ///////////////////////////////////////
    //Finish
    return ipsec_ret::OK;
}

ipsec_ret IPsecNetlinkAPI::get_sa(uint32_t spi, ipsec_sa& sa)
{
    struct mnl_socket* nl_socket = NULL;
    struct nlmsghdr* nlh = NULL;
    struct xfrm_usersa_id* xfrm_said = NULL;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = 0;
    uint32_t pid = 0;

    nlh = m_mnl_wrapper.nlmsg_put_header(buf);
    if(nlh == NULL)
    {
        return ipsec_ret::ALLOC_FAILED;
    }

    nlh->nlmsg_type = XFRM_MSG_GETSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);

    xfrm_said =
         (struct xfrm_usersa_id*)m_mnl_wrapper.nlmsg_put_extra_header(nlh,
                                                 sizeof(struct xfrm_usersa_id));
    if(xfrm_said == nullptr)
    {
        return ipsec_ret::ALLOC_FAILED;
    }
    memset(xfrm_said, 0, sizeof(struct xfrm_usersa_id));

    ///////////////////////////////////////
    //Get Socket
    if(create_socket(&nl_socket, 0) != ipsec_ret::OK)
    {
        return ipsec_ret::SOCKET_CREATE_FAILED;
    }

    ///////////////////////////////////////
    //Set XFRM SA SPI
    xfrm_said->spi     = htonl(spi);

    ///////////////////////////////////////
    //Get Socket Port ID
    pid = m_mnl_wrapper.socket_get_portid(nl_socket);

    ///////////////////////////////////////
    //Clean SA
    sa = ipsec_sa();

    ///////////////////////////////////////
    //Send Request
    ssize_t socketRet = m_mnl_wrapper.socket_sendto(nl_socket, nlh, nlh->nlmsg_len);
    if(socketRet <= 0)
    {
        ///////////////////////////////////////
        //Close Socket and return error
        m_mnl_wrapper.socket_close(nl_socket);

        return ipsec_ret::SOCKET_SEND_FAILED;
    }

    socketRet = m_mnl_wrapper.socket_recvfrom(nl_socket, buf, sizeof(buf));
    if(socketRet > 0)
    {
        CB_Data data;

        data.m_netlink_api = this;
        data.user_data = &sa;

        socketRet = m_mnl_wrapper.cb_run(buf, socketRet, seq, pid,
                                         mnl_parse_xfrm_sa, &data);
        if (socketRet <= MNL_CB_STOP)
        {
            //TODO: Log error
        }
    }

    ///////////////////////////////////////
    //Close Socket
    m_mnl_wrapper.socket_close(nl_socket);

    ///////////////////////////////////////
    //If Address Family was not set, SA was not found
    if(sa.m_id.m_addr_family == 0)
    {
        return ipsec_ret::NOT_FOUND;
    }

    return ipsec_ret::OK;
}

int IPsecNetlinkAPI::parse_nested_attr(const struct nlattr* nl_attr, void* data)
{
    if(data == nullptr)
    {
        return MNL_CB_ERROR;
    }

    CB_Data* cbData = (CB_Data*)data;
    ILibmnlWrapper& mnl_wrapper = cbData->m_netlink_api->m_mnl_wrapper;

    const struct nlattr** nl_attrs = (const struct nlattr**)cbData->user_data;

    uint16_t type = mnl_wrapper.attr_get_type(nl_attr);

    ///////////////////////////////////////
    //Check if Attribute Type is valid, if it is not skip it
    if (mnl_wrapper.attr_type_valid(nl_attr, XFRMA_MAX) < 0)
    {
        return MNL_CB_OK;
    }

    ///////////////////////////////////////
    //Finish
    nl_attrs[type] = nl_attr;

    return MNL_CB_OK;
}

int IPsecNetlinkAPI::mnl_parse_xfrm_sa(const struct nlmsghdr* nlh, void* data)
{
    if(data == nullptr)
    {
        return MNL_CB_ERROR;
    }

    CB_Data* cbData = (CB_Data*)data;
    ILibmnlWrapper& mnl_wrapper = cbData->m_netlink_api->m_mnl_wrapper;
    ipsec_sa* sa = (ipsec_sa*)cbData->user_data;

    if(nlh->nlmsg_type != XFRM_MSG_NEWSA &&
       nlh->nlmsg_type != XFRM_MSG_DELSA &&
       nlh->nlmsg_type != XFRM_MSG_GETSA &&
       nlh->nlmsg_type != XFRM_MSG_UPDSA)
    {
        return MNL_CB_ERROR;
    }

    if(data == NULL)
    {
        return MNL_CB_ERROR;
    }

    ///////////////////////////////////////
    //Get Payload
    uint8_t* payload = (uint8_t*)mnl_wrapper.nlmsg_get_payload(nlh);
    size_t payloadLen = nlh->nlmsg_len - sizeof(struct xfrm_usersa_info);

    ///////////////////////////////////////
    //Retrieve XFRM SA Info
    struct xfrm_usersa_info* xfrm_sa = (struct xfrm_usersa_info*)payload;
    if(xfrm_sa == NULL)
    {
        return MNL_CB_ERROR;
    }

    ///////////////////////////////////////
    //Advance Payload Pointer to start of Attributes
    payload += sizeof(struct xfrm_usersa_info);

    ///////////////////////////////////////
    //Netlink Attributes
    struct nlattr* nlAttrs[XFRMA_MAX + 1] = { 0 };

    ///////////////////////////////////////
    //Parse the Netlink Conntrack Attributes
    CB_Data user_data;
    user_data.m_netlink_api = cbData->m_netlink_api;
    user_data.user_data = nlAttrs;
    if(mnl_wrapper.attr_parse_payload(payload, payloadLen,
                                      parse_nested_attr, &user_data) < 0)
    {
        return MNL_CB_ERROR;
    }

    if(cbData->m_netlink_api->parse_xfrm_sa(xfrm_sa, nlAttrs, sa) != ipsec_ret::OK)
    {
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

ipsec_ret IPsecNetlinkAPI::parse_xfrm_sa(struct xfrm_usersa_info* xfrm_sa,
                                       struct nlattr** nl_attrs, ipsec_sa* sa)
{
    if(xfrm_sa == nullptr || nl_attrs == nullptr || sa == nullptr)
    {
        return ipsec_ret::NULL_PARAMETERS;
    }

    ///////////////////////////////////////
    //Fill in base SA Information
    *sa = ipsec_sa();

    sa->m_id.m_addr_family   = xfrm_sa->family;
    sa->m_id.m_spi           = ntohl(xfrm_sa->id.spi);
    sa->m_id.m_protocol      = xfrm_sa->id.proto;
    memcpy(&sa->m_id.m_dst_ip, &xfrm_sa->saddr, IP_ADDRESS_LENGTH);
    memcpy(&sa->m_id.m_dst_ip, &xfrm_sa->id.daddr, IP_ADDRESS_LENGTH);
    sa->m_mode               = (ipsec_mode)xfrm_sa->mode;
    sa->m_req_id             = xfrm_sa->reqid;
    sa->m_flags              = xfrm_sa->flags;

    memcpy(&sa->m_selector.m_src_addr, &xfrm_sa->sel.saddr, IP_ADDRESS_LENGTH);
    memcpy(&sa->m_selector.m_dst_addr, &xfrm_sa->sel.daddr, IP_ADDRESS_LENGTH);
    sa->m_selector.m_addr_family     = xfrm_sa->sel.family;
    sa->m_selector.m_src_mask        = xfrm_sa->sel.prefixlen_s;
    sa->m_selector.m_dst_mask        = xfrm_sa->sel.prefixlen_d;

    sa->m_lifetime_current.m_add_time   = xfrm_sa->curlft.add_time;
    sa->m_lifetime_current.m_use_time   = xfrm_sa->curlft.use_time;
    sa->m_lifetime_current.m_bytes      = xfrm_sa->curlft.bytes;
    sa->m_lifetime_current.m_packets    = xfrm_sa->curlft.packets;

    sa->m_stats.m_replay_window     = xfrm_sa->stats.replay_window;
    sa->m_stats.m_integrity_failed  = xfrm_sa->stats.integrity_failed;
    sa->m_stats.m_replay            = xfrm_sa->stats.replay;

    ///////////////////////////////////////
    //Fill in SA with attributes
    if(nl_attrs[XFRMA_ALG_CRYPT] != NULL)
    {
        sa->m_crypt_set = true;

        struct xfrm_algo* xfrm_crypt =
                (struct xfrm_algo*)m_mnl_wrapper.attr_get_payload(nl_attrs[XFRMA_ALG_CRYPT]);

        uint32_t key_size = (xfrm_crypt->alg_key_len / 8);

        sa->m_crypt.m_key = ipsecd_helper::key_to_str(xfrm_crypt->alg_key, key_size);

        sa->m_crypt.m_name = std::string(xfrm_crypt->alg_name);
    }

    if(nl_attrs[XFRMA_ALG_AUTH] != NULL)
    {
        sa->m_auth_set = true;

        struct xfrm_algo* xfrm_auth =
                (struct xfrm_algo*)m_mnl_wrapper.attr_get_payload(nl_attrs[XFRMA_ALG_AUTH]);

        uint32_t key_size = (xfrm_auth->alg_key_len / 8) * 2;

        sa->m_auth.m_key = ipsecd_helper::key_to_str(xfrm_auth->alg_key, key_size);

        sa->m_auth.m_name = std::string(xfrm_auth->alg_name);
    }

    return ipsec_ret::OK;
}
