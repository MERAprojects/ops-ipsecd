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

#include "gmock/gmock.h"
#include "ILibmnlWrapper.h"

class MockILibmnlWrapper : public ILibmnlWrapper {
 public:
  MOCK_METHOD1(socket_open,
      struct mnl_socket*(int32_t bus));
  MOCK_METHOD1(socket_close,
      int32_t(struct mnl_socket* nl));
  MOCK_METHOD3(socket_bind,
      int32_t(struct mnl_socket* nl, uint32_t groups, pid_t pid));
  MOCK_METHOD1(nlmsg_put_header,
      struct nlmsghdr*(char* buf));
  MOCK_METHOD2(nlmsg_put_extra_header,
      void*(struct nlmsghdr* nlh, size_t size));
  MOCK_METHOD1(socket_get_portid,
      uint32_t(const struct mnl_socket* nl));
  MOCK_METHOD3(socket_sendto,
      ssize_t(const struct mnl_socket* nl, const void* buf, size_t len));
  MOCK_METHOD3(socket_recvfrom,
      ssize_t(const struct mnl_socket* nl, void* buf, size_t bufsiz));
  MOCK_METHOD1(nlmsg_get_payload,
      void*(const struct nlmsghdr* nlh));
  MOCK_METHOD1(attr_get_payload,
      void*(const struct nlattr* attr));
  MOCK_METHOD1(attr_get_type,
      uint16_t(const struct nlattr* attr));
  MOCK_METHOD1(attr_get_len,
      uint16_t(const struct nlattr* attr));
  MOCK_METHOD2(attr_type_valid,
      int32_t(const struct nlattr* attr, uint16_t max));
  MOCK_METHOD2(attr_validate,
      int32_t(const struct nlattr* attr, enum mnl_attr_data_type type));
  MOCK_METHOD3(attr_validate2,
      int32_t(const struct nlattr* attr, enum mnl_attr_data_type type, size_t exp_len));
  MOCK_METHOD4(attr_parse_payload,
      int(const void* payload, size_t payload_len, mnl_attr_cb_t cb, void* data));
  MOCK_METHOD3(attr_parse_nested,
      int(const struct nlattr* nested, mnl_attr_cb_t cb, void* data));
  MOCK_METHOD6(cb_run,
      int32_t(const void* buf, size_t numbytes, uint32_t seq, uint32_t portid, mnl_cb_t cb_data, void* data));
  MOCK_METHOD2(attr_nest_start,
      struct nlattr*(struct nlmsghdr* nlh, uint16_t type));
  MOCK_METHOD2(attr_nest_end,
      void(struct nlmsghdr* nlh, struct nlattr* start));
  MOCK_METHOD1(attr_get_u8,
      uint8_t(const struct nlattr* attr));
  MOCK_METHOD1(attr_get_u16,
      uint16_t(const struct nlattr* attr));
  MOCK_METHOD1(attr_get_u32,
      uint32_t(const struct nlattr* attr));
  MOCK_METHOD1(attr_get_u64,
      uint64_t(const struct nlattr* attr));
  MOCK_METHOD4(attr_put,
      void(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data));
  MOCK_METHOD3(attr_put_u8,
      void(struct nlmsghdr* nlh, uint16_t type, uint8_t data));
  MOCK_METHOD3(attr_put_u16,
      void(struct nlmsghdr* nlh, uint16_t type, uint16_t data));
  MOCK_METHOD3(attr_put_u32,
      void(struct nlmsghdr* nlh, uint16_t type, uint32_t data));
  MOCK_METHOD3(attr_put_u64,
      void(struct nlmsghdr* nlh, uint16_t type, uint64_t data));
};
