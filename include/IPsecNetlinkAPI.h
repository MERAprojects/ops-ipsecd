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

#ifndef IIPSECNETLINKAPI_H
#define IIPSECNETLINKAPI_H

/**********************************
*System Includes
**********************************/
#include <string>
#include <linux/xfrm.h>

/**********************************
*Local Includes
**********************************/
#include "IIPsecAPI.h"
#include "ILibmnlWrapper.h"

/**********************************
*Defines
**********************************/

#define IPSEC_NETLINK_CB_DATA_MAGIC     0xAECDFFAA

/**********************************
*Forward Decl
**********************************/

/**
 * Base Interface Class for Configuration Queue
 */
class IPsecNetlinkAPI : public IIPsecAPI
{
    protected:

        /**
         * Libmnl API Interface
         */
        ILibmnlWrapper& m_mnl_wrapper;

        /**
         * Create the Netlink Socket
         *
         * @param nl_socket mnl socket to be created
         *
         * @param groups Groups to bind the socket to
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret create_socket(struct mnl_socket** nl_socket, uint32_t groups);

        /**
         * Sends the message to Netlink and waits for ACK
         *
         * @param nlh Netlink Header
         *
         * @param buffer Buffer use for Netlink
         *
         * @param buffer_len Buffer length
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret send_msg(struct nlmsghdr* nlh, char* buffer, size_t buffer_len);

        /**
         * Sends the message to Netlink and waits for data to be received and
         * sends it to be parsed
         *
         * @param nlh Netlink Header
         *
         * @param buffer Buffer use for Netlink
         *
         * @param buffer_len Buffer length
         *
         * @param sa_sp_data SA or SP struct use to save data
         *
         * @param callback Callback Function that will parse the data
         *
         * @param seq Sequence number of Netlink packet
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret send_receive_msg(struct nlmsghdr* nlh, char* buffer,
                                   size_t buffer_len, void* sa_sp_data,
                                   mnl_cb_t callback, uint32_t seq);

        /**
         * Parses the XFRM SA structure and saves it into a ipsec_sa structure
         *
         * @param xfrm_sa SA to parse
         *
         * @param nl_attrs Attributes the XFRM struct contains
         *
         * @param sa SA struct to save data
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret parse_xfrm_sa(struct xfrm_usersa_info* xfrm_sa,
                                struct nlattr** nl_attrs, ipsec_sa* sa);

        /**
         * Parses the XFRM SP structure and saves it into a ipsec_sp structure
         *
         * @param xfrm_sp SP to parse
         *
         * @param nl_attrs Attributes the XFRM struct contains
         *
         * @param sp SP struct to save data
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret parse_xfrm_sp(struct xfrm_userpolicy_info* xfrm_sp,
                                struct nlattr** nl_attrs, ipsec_sp* sp);

        /**
         * Fills the xfrm_sp structure with the information from ipsec_sp
         *
         * @param sp SP information use to convert to XFRM
         *
         * @param xfrm_sp XFRM struct to fill
         *
         * @param nlh Netlink Message Header
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret set_xfrm_sp(const ipsec_sp& sp,
                              struct xfrm_userpolicy_info* xfrm_sp,
                              struct nlmsghdr* nlh);

        /**
         * Generic Function to add or modify an SP
         *
         * @param sp SP to insert
         *
         * @param adding True when adding, false when modifying
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        ipsec_ret insert_sp(const ipsec_sp& sp, bool adding);

        /**
         * MNL Callback when parsing attributes
         */
        static int parse_nested_attr(const struct nlattr* nl_attr, void* data);

        /**
         * MNL Parser for XFRM SA Message
         */
        static int mnl_parse_xfrm_sa(const struct nlmsghdr* nlh, void* data);

        /**
         * MNL Parser for XFRM SP Message
         */
        static int mnl_parse_xfrm_sp(const struct nlmsghdr* nlh, void* data);

    public:

        /**
         * Structure use to pass Data to the MNL Callbacks
         */
        struct CB_Data
        {
            const uint32_t m_magic = IPSEC_NETLINK_CB_DATA_MAGIC;
            IPsecNetlinkAPI* m_netlink_api = nullptr;
            void* user_data = nullptr;
        };

        /**
         * Default Constructor
         *
         * @param mnl_wrapper Libmnl API Interface
         */
        IPsecNetlinkAPI(ILibmnlWrapper& mnl_wrapper);

        /**
         * Default Destructor
         */
        virtual ~IPsecNetlinkAPI();

        /**
         * @copydoc IPsecAPI::add_sa
         */
        ipsec_ret add_sa(const ipsec_sa& sa) override;

        /**
         * @copydoc IPsecAPI::modify_sa
         */
        ipsec_ret modify_sa(const ipsec_sa& sa) override;


        /**
         * @copydoc IPsecAPI::get_sa
         */
        ipsec_ret get_sa(uint32_t spi, ipsec_sa& sa) override;

        /**
         * @copydoc IPsecAPI::del_sa
         */
        ipsec_ret del_sa(const ipsec_sa_id& id) override;

        /**
         * @copydoc IPsecAPI::add_sp
         */
        ipsec_ret add_sp(const ipsec_sp& sp) override;

        /**
         * @copydoc IPsecAPI::modify_sp
         */
        ipsec_ret modify_sp(const ipsec_sp& sp) override;

        /**
         * @copydoc IPsecAPI::get_sp
         */
        ipsec_ret get_sp(const ipsec_sp_id& sp_id, ipsec_sp& sp) override;

        /**
         * @copydoc IPsecAPI::del_sp
         */
        ipsec_ret del_sp(const ipsec_sp_id& sp_id) override;

};

#endif /* IIPSECNETLINKAPI_H */