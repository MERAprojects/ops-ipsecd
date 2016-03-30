/*
* Copyright (C) 2014 Hewlett-Packard Development Company, L.P.
* All Rights Reserved.
*
* The contents of this software are proprietary and confidential to the
* Hewlett-Packard Development Company, L.P.  No part of this program
* may be photocopied, reproduced, or translated into another
* programming language without prior written consent of the
* Hewlett-Packard Development Company, L.P.
*/

#ifndef _LIBMNL_WRAPPER_H
#define _LIBMNL_WRAPPER_H

/**********************************
*System Includes
**********************************/
#include <stdint.h>
#include <libmnl/libmnl.h>

/**********************************
* Local Includes
***********************************/
#include "ILibmnlWrapper.h"

/**********************************
*Forward Decl
**********************************/

/**********************************
*Typedef
**********************************/

/**********************************
*Class Decl
**********************************/

/**
 * MNL Library Wrapper
 */
class LibmnlWrapper : public ILibmnlWrapper
{
    public:

        /**
         * Default Constructor
         */
        LibmnlWrapper();

        /**
         * Default Destructor
         */
        virtual ~LibmnlWrapper();

        /**
         * @copydoc ILibmnlWrapper::socket_open
         */
        struct mnl_socket* socket_open(int32_t bus) override;

        /**
         * @copydoc ILibmnlWrapper::socket_close
         */
        int32_t socket_close(struct mnl_socket* nl) override;

        /**
         * @copydoc ILibmnlWrapper::socket_bind
         */
        int32_t socket_bind(struct mnl_socket* nl, uint32_t groups, pid_t pid) override;

        /**
         * @copydoc ILibmnlWrapper::nlmsg_put_header
         */
        struct nlmsghdr* nlmsg_put_header(char* buf) override;

        /**
         * @copydoc ILibmnlWrapper::nlmsg_put_extra_header
         */
        void* nlmsg_put_extra_header(struct nlmsghdr* nlh, size_t size) override;

        /**
         * @copydoc ILibmnlWrapper::socket_get_portid
         */
        uint32_t socket_get_portid(const struct mnl_socket* nl) override;

        /**
         * @copydoc ILibmnlWrapper::socket_sendto
         */
        ssize_t socket_sendto(const struct mnl_socket* nl, const void* buf, size_t len) override;

        /**
         * @copydoc ILibmnlWrapper::socket_recvfrom
         */
        ssize_t socket_recvfrom(const struct mnl_socket* nl, void* buf, size_t bufsiz) override;

        /**
         * @copydoc ILibmnlWrapper::nlmsg_get_payload
         */
        void* nlmsg_get_payload(const struct nlmsghdr* nlh) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_payload
         */
        void* attr_get_payload(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_type
         */
        uint16_t attr_get_type(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_len
         */
        uint16_t attr_get_len(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_type_valid
         */
        int32_t attr_type_valid(const struct nlattr* attr, uint16_t max) override;

        /**
         * @copydoc ILibmnlWrapper::attr_validate
         */
        int32_t attr_validate(const struct nlattr* attr, enum mnl_attr_data_type type) override;

        /**
         * @copydoc ILibmnlWrapper::attr_validate2
         */
        int32_t attr_validate2(const struct nlattr* attr, enum mnl_attr_data_type type,
                               size_t exp_len) override;

        /**
         * @copydoc ILibmnlWrapper::attr_parse_payload
         */
        int32_t attr_parse_payload(const void* payload, size_t payload_len,
                                   mnl_attr_cb_t cb, void* data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_parse_nested
         */
        int32_t attr_parse_nested(const struct nlattr* nested, mnl_attr_cb_t cb, void* data) override;

        /**
         * @copydoc ILibmnlWrapper::cb_run
         */
        int32_t cb_run(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
                               mnl_cb_t cb_data, void* data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_nest_start
         */
        struct nlattr* attr_nest_start(struct nlmsghdr* nlh, uint16_t type) override;

        /**
         * @copydoc ILibmnlWrapper::attr_nest_end
         */
        void attr_nest_end(struct nlmsghdr* nlh, struct nlattr* start) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_u8
         */
        uint8_t attr_get_u8(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_u16
         */
        uint16_t attr_get_u16(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_u32
         */
        uint32_t attr_get_u32(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_get_u64
         */
        uint64_t attr_get_u64(const struct nlattr* attr) override;

        /**
         * @copydoc ILibmnlWrapper::attr_put
         */
        void attr_put(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_put_u8
         */
        void attr_put_u8(struct nlmsghdr* nlh, uint16_t type, uint8_t data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_put_u16
         */
        void attr_put_u16(struct nlmsghdr* nlh, uint16_t type, uint16_t data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_put_u32
         */
        void attr_put_u32(struct nlmsghdr* nlh, uint16_t type, uint32_t data) override;

        /**
         * @copydoc ILibmnlWrapper::attr_put_u64
         */
        void attr_put_u64(struct nlmsghdr* nlh, uint16_t type, uint64_t data) override;
};

#endif	/* LIBMNLWRAPPER_H */
