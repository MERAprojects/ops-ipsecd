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
