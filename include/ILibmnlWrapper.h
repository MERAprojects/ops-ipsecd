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

#ifndef _ILIBMNL_WRAPPER_H
#define _ILIBMNL_WRAPPER_H

/**********************************
*System Includes
**********************************/
#include <stdint.h>
#include <libmnl/libmnl.h>

/**********************************
* Local Includes
***********************************/

/**********************************
*Forward Decl
**********************************/

/**********************************
*Typedef
**********************************/

/**********************************
*Struct Decl
**********************************/

/**********************************
*Class Decl
**********************************/

/**
 * MNL Library Wrapper Interface
 */
class ILibmnlWrapper
{
    public:

        /**
         * Default Constructor
         */
        ILibmnlWrapper() {}

        /**
         * Default Destructor
         */
        virtual ~ILibmnlWrapper() {}

        /**
         * Open a netlink socket.
         *
         * @param bus The netlink socket bus ID (see NETLINK_* constants).
         *
         * @return Pointer to the mnl_socket structure, if error -1 and errno is set.
         */
        virtual struct mnl_socket* socket_open(int32_t bus) = 0;

        /**
         * Close a given netlink socket.
         *
         * @param nl Netlink socket obtained via socket_open().
         *
         * @return On success 0, otherwise -1 and errno is set.
         */
        virtual int32_t socket_close(struct mnl_socket* nl) = 0;

        /**
         * Bind netlink socket.
         * <p>
         * You can use MNL_SOCKET_AUTOPID which is 0 for automatic port ID selection.
         *
         * @param nl Netlink socket obtained via socket_open().
         * @param groups The group of message you're interested in.
         * @param pid The port ID you want to use (use zero for automatic selection).
         *
         * @return On success 0, -1 on error and errno is set.
         */
        virtual int32_t socket_bind(struct mnl_socket* nl, uint32_t groups, pid_t pid) = 0;

        /**
         * Reserve and prepare room for Netlink header.
         * <p>
         * This function sets to zero the room that is required to put the Netlink header in
         * the memory buffer passed as parameter. This function also initializes the nlmsg_len
         * field to the size of the Netlink header.
         *
         * @param buf Memory already allocated to store the Netlink header.
         *
         * @return Pointer to the Netlink header structure, if error NULL.
         */
        virtual struct nlmsghdr* nlmsg_put_header(char* buf) = 0;

        /**
         * Reserve and Prepare room for an extra header.
         * <p>
         * This function sets to zero the room that is required to put the extra header
         * after the initial Netlink header. This function also increases the nlmsg_len field.
         * You have to invoke nlmsg_put_header() before you call this function.
         *
         * @param nlh
         * @param size
         *
         * @return Pointer to the extra header, if error NULL
         */
        virtual void* nlmsg_put_extra_header(struct nlmsghdr* nlh, size_t size) = 0;

        /**
         * Obtain Netlink PortID from netlink socket.
         * <p>
         * It's a common mistake to assume that this PortID equals the process ID which is not
         * always true. This is the case if you open more than one socket that is binded to the
         * same Netlink subsystem from the same process.
         *
         * @param nl Netlink socket obtained via socket_open().

         *
         * @return Netlink PortID of a given netlink socket.
         */
        virtual uint32_t socket_get_portid(const struct mnl_socket* nl) = 0;

        /**
         * Send a netlink message of a certain size.
         *
         * @param nl Netlink socket obtained via socket_open().
         * @param buf Buffer containing the netlink message to be sent
         * @param len Number of bytes in the buffer that you want to send
         *
         * @return The number of bytes sent, -1 if error and errno is set.
         */
        virtual ssize_t socket_sendto(const struct mnl_socket* nl, const void* buf, size_t len) = 0;

        /**
         * Receive a netlink message.
         * <p>
         * If errno is set to ENOSPC, it means that the buffer that you have passed to store the
         * netlink message is too small, so you have received a truncated message. To avoid this,
         * you have to allocate a buffer of MNL_SOCKET_BUFFER_SIZE (which is 8KB,
         * see linux/netlink.h for more information). Using this buffer size ensures that your
         * buffer is big enough to store the netlink message without truncating it.
         *
         * @param nl Netlink socket obtained via socket_open().
         * @param buf Buffer that you want to use to store the netlink message.
         * @param bufzie Size of the buffer passed to store the netlink message.
         *
         * @return On error -1 and errno is set, 0 on success.
         */
        virtual ssize_t socket_recvfrom(const struct mnl_socket* nl, void* buf, size_t bufsiz) = 0;

        /**
         * Get a pointer to the payload of the netlink message.
         *
         * @param nlh Pointer to a netlink header.
         *
         * @return Pointer to the payload of the netlink message.
         */
        virtual void* nlmsg_get_payload(const struct nlmsghdr* nlh) = 0;

        /**
         * Get pointer to the attribute payload.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return Pointer to the attribute payload.
         */
        virtual void* attr_get_payload(const struct nlattr* attr) = 0;

        /**
         * Get type of netlink attribute.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return The attribute type.
         */
        virtual uint16_t attr_get_type(const struct nlattr* attr) = 0;

        /**
         * Get length of netlink attribute.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return The attribute length.
         */
        virtual uint16_t attr_get_len(const struct nlattr* attr) = 0;

        /**
         * Check if the attribute type is valid.
         * <p>
         * Strict attribute checking in user-space is not a good idea since you may run an
         * old application with a newer kernel that supports new attributes.
         * This leads to backward compatibility breakages in user-space. Better check if you
         * support an attribute, if not, skip it.
         *
         * @param attr Pointer to attribute to be checked.
         * @param max Maximum attribute type.
         *
         * @return If the attribute type is invalid, returns -1 and errno is set, 0 on success.
         */
        virtual int32_t attr_type_valid(const struct nlattr* attr, uint16_t max) = 0;

        /**
         * Validate netlink attribute (simplified version).
         * <p>
         * The validation is based on the data type. Specifically, it checks that
         * integers (u8, u16, u32 and u64) have enough room for them.
         *
         * @param attr Pointer to netlink attribute that we want to validate.
         * @param type Data type (see enum mnl_attr_data_type).
         *
         * @return Returns -1 in case of error, and errno is set, 0 on success.
         */
        virtual int32_t attr_validate(const struct nlattr* attr, enum mnl_attr_data_type type) = 0;

        /**
         * Validate netlink attribute (extended version).
         * <p>
         * This function allows to perform a more accurate validation for attributes whose size
         * is variable. If the size of the attribute is not what we expect.
         *
         * @param attr Pointer to netlink attribute that we want to validate.
         * @param type Data type (see enum mnl_attr_data_type).
         * @param exp_len Expected attribute data size.
         *
         * @return Returns -1 and errno is set, 0 on success
         */
        virtual int32_t attr_validate2(const struct nlattr* attr, enum mnl_attr_data_type type,
                                       size_t exp_len) = 0;


        /**
         * Parse attributes inside a payload.
         *
         * @param payload Pointer to payload.
         * @param payload_len Payload Length.
         * @param cb Callback function that is called for each attribute in the nest.
         * @param data Pointer to data passed to the callback function.
         *
         * @return This function propagates the return value of the callback.
         */
        virtual int attr_parse_payload(const void* payload, size_t payload_len,
                                       mnl_attr_cb_t cb, void* data) = 0;

        /**
         * Parse attributes inside a nest
         * <p>
         * Your callback may return three possible values:
         *  - MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
         *  - MNL_CB_STOP (=0): stop callback runqueue.
         *  - MNL_CB_OK (>=1): no problems has occurred.
         *
         * @param nested Pointer to netlink attribute that contains a nest.
         * @param cb Callback function that is called for each attribute in the nest.
         * @param data Pointer to data passed to the callback function.
         *
         * @return This function propagates the return value of the callback.
         */
        virtual int attr_parse_nested(const struct nlattr* nested, mnl_attr_cb_t cb,
                                      void* data) = 0;

        /**
         * Callback runqueue for netlink messages (simplified version).
         * <p>
         * This function allows to iterate over the sequence of attributes that compose
         * the Netlink message. You can then put the attribute in an array as it usually
         * happens at this stage or you can use any other data structure (such as lists or trees).
         * <p>
         * Your callback may return three possible values:
         *  - MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
         *  - MNL_CB_STOP (=0): stop callback runqueue.
         *  - MNL_CB_OK (>=1): no problems has occurred.
         *
         * @param buf Buffer that contains the netlink messages.
         * @param numbytes Number of bytes stored in the buffer.
         * @param portid Netlink PortID that we expect to receive.
         * @param cb_data Callback handler for data messages.
         * @param data Pointer to data that will be passed to the data callback handler
         *
         * @return This function propagates the callback return value.
         */
        virtual int32_t cb_run(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
                               mnl_cb_t cb_data, void* data) = 0;

        /**
         * Start an attribute nest.
         * <p>
         * This function adds the attribute header that identifies the beginning of
         * an attribute nest.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type.
         *
         * @return This function always returns a valid pointer to the beginning of the nest.
         */
        virtual struct nlattr* attr_nest_start(struct nlmsghdr* nlh, uint16_t type) = 0;

        /**
         * This function updates the attribute header that identifies the nest.
         *
         * @param nlh Pointer to the netlink message.
         * @param start Pointer to the attribute nest returned by attr_nest_start().
         */
        virtual void attr_nest_end(struct nlmsghdr* nlh, struct nlattr* start) = 0;

        /**
         * Gets an Attribute from the nlattr structure.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return Value of the attribute payload.
         */
        virtual uint8_t attr_get_u8(const struct nlattr* attr) = 0;

        /**
         * Gets an Attribute from the nlattr structure.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return Value of the attribute payload.
         */
        virtual uint16_t attr_get_u16(const struct nlattr* attr) = 0;

        /**
         * Gets an Attribute from the nlattr structure.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return Value of the attribute payload.
         */
        virtual uint32_t attr_get_u32(const struct nlattr* attr) = 0;

        /**
         * Gets an Attribute from the nlattr structure.
         *
         * @param attr Pointer to netlink attribute.
         *
         * @return Value of the attribute payload.
         */
        virtual uint64_t attr_get_u64(const struct nlattr* attr) = 0;

        /**
         * Adds an attribute to netlink message.
         * <p>
         * This function updates the length field of the Netlink message (nlmsg_len) by adding
         * the size (header + payload) of the new attribute.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type
         * @param len Size of data
         * @param data Data to be stored by the new attribute
         */
        virtual void attr_put(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data) = 0;

        /**
         * Adds an attribute to netlink message.
         * <p>
         * This function updates the length field of the Netlink message (nlmsg_len) by adding
         * the size (header + payload) of the new attribute.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type
         * @param data Data to be stored by the new attribute
         */
        virtual void attr_put_u8(struct nlmsghdr* nlh, uint16_t type, uint8_t data) = 0;

        /**
         * Adds an attribute to netlink message.
         * <p>
         * This function updates the length field of the Netlink message (nlmsg_len) by adding
         * the size (header + payload) of the new attribute.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type
         * @param data Data to be stored by the new attribute
         */
        virtual void attr_put_u16(struct nlmsghdr* nlh, uint16_t type, uint16_t data) = 0;

        /**
         * Adds an attribute to netlink message.
         * <p>
         * This function updates the length field of the Netlink message (nlmsg_len) by adding
         * the size (header + payload) of the new attribute.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type
         * @param data Data to be stored by the new attribute
         */
        virtual void attr_put_u32(struct nlmsghdr* nlh, uint16_t type, uint32_t data) = 0;

        /**
         * Adds an attribute to netlink message.
         * <p>
         * This function updates the length field of the Netlink message (nlmsg_len) by adding
         * the size (header + payload) of the new attribute.
         *
         * @param nlh Pointer to the netlink message.
         * @param type Netlink attribute type
         * @param data Data to be stored by the new attribute
         */
        virtual void attr_put_u64(struct nlmsghdr* nlh, uint16_t type, uint64_t data) = 0;

};

#endif
