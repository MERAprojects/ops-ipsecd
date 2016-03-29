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
* System Includes
**********************************/

/**********************************
* Local Includes
***********************************/
#include "LibmnlWrapper.h"

/**********************************
* Class Decl
**********************************/
LibmnlWrapper::LibmnlWrapper()
{
}

LibmnlWrapper::~LibmnlWrapper()
{
}

struct mnl_socket* LibmnlWrapper::socket_open(int32_t bus)
{
    return mnl_socket_open(bus);
}

int32_t LibmnlWrapper::socket_close(struct mnl_socket* nl)
{
    return mnl_socket_close(nl);
}

int32_t LibmnlWrapper::socket_bind(struct mnl_socket* nl, uint32_t groups, pid_t pid)
{
    return mnl_socket_bind(nl, groups, pid);
}

struct nlmsghdr* LibmnlWrapper::nlmsg_put_header(char* buf)
{
    return mnl_nlmsg_put_header(buf);
}

void* LibmnlWrapper::nlmsg_put_extra_header(struct nlmsghdr* nlh, size_t size)
{
    return mnl_nlmsg_put_extra_header(nlh, size);
}

uint32_t LibmnlWrapper::socket_get_portid(const struct mnl_socket* nl)
{
    return mnl_socket_get_portid(nl);
}

ssize_t LibmnlWrapper::socket_sendto(const struct mnl_socket* nl, const void* buf, size_t len)
{
    return mnl_socket_sendto(nl, buf, len);
}

ssize_t LibmnlWrapper::socket_recvfrom(const struct mnl_socket* nl, void* buf, size_t bufsiz)
{
    return mnl_socket_recvfrom(nl, buf, bufsiz);
}

void* LibmnlWrapper::nlmsg_get_payload(const struct nlmsghdr* nlh)
{
    return mnl_nlmsg_get_payload(nlh);
}

void* LibmnlWrapper::attr_get_payload(const struct nlattr* attr)
{
    return mnl_attr_get_payload(attr);
}

uint16_t LibmnlWrapper::attr_get_type(const struct nlattr* attr)
{
    return mnl_attr_get_type(attr);
}

int32_t LibmnlWrapper::attr_type_valid(const struct nlattr* attr, uint16_t max)
{
    return mnl_attr_type_valid(attr, max);
}

int32_t LibmnlWrapper::attr_validate(const struct nlattr* attr, enum mnl_attr_data_type type)
{
    return mnl_attr_validate(attr, type);
}

int32_t LibmnlWrapper::attr_validate2(const struct nlattr* attr, enum mnl_attr_data_type type,
                                      size_t exp_len)
{
    return mnl_attr_validate2(attr, type, exp_len);
}

int32_t LibmnlWrapper::attr_parse_payload(const void* payload, size_t payload_len,
                                          mnl_attr_cb_t cb, void* data)
{
    return mnl_attr_parse_payload(payload, payload_len, cb, data);
}

int32_t LibmnlWrapper::attr_parse_nested(const struct nlattr* nested, mnl_attr_cb_t cb, void* data)
{
    return mnl_attr_parse_nested(nested, cb, data);
}

int32_t LibmnlWrapper::cb_run(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid,
                              mnl_cb_t cb_data, void* data)
{
    return mnl_cb_run(buf, numbytes, seq, portid, cb_data, data);
}

struct nlattr* LibmnlWrapper::attr_nest_start(struct nlmsghdr* nlh, uint16_t type)
{
    return mnl_attr_nest_start(nlh, type);
}

void LibmnlWrapper::attr_nest_end(struct nlmsghdr* nlh, struct nlattr* start)
{
    return mnl_attr_nest_end(nlh, start);
}

uint8_t LibmnlWrapper::attr_get_u8(const struct nlattr* attr)
{
    return mnl_attr_get_u8(attr);
}

uint16_t LibmnlWrapper::attr_get_u16(const struct nlattr* attr)
{
    return mnl_attr_get_u16(attr);
}

uint32_t LibmnlWrapper::attr_get_u32(const struct nlattr* attr)
{
    return mnl_attr_get_u32(attr);
}

uint64_t LibmnlWrapper::attr_get_u64(const struct nlattr* attr)
{
    return mnl_attr_get_u64(attr);
}

void LibmnlWrapper::attr_put(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data)
{
    return mnl_attr_put(nlh, type, len, data);
}

void LibmnlWrapper::attr_put_u8(struct nlmsghdr* nlh, uint16_t type, uint8_t data)
{
    mnl_attr_put_u8(nlh, type, data);
}

void LibmnlWrapper::attr_put_u16(struct nlmsghdr* nlh, uint16_t type, uint16_t data)
{
    mnl_attr_put_u16(nlh, type, data);
}

void LibmnlWrapper::attr_put_u32(struct nlmsghdr* nlh, uint16_t type, uint32_t data)
{
    mnl_attr_put_u32(nlh, type, data);
}

void LibmnlWrapper::attr_put_u64(struct nlmsghdr* nlh, uint16_t type, uint64_t data)
{
    mnl_attr_put_u64(nlh, type, data);
}
