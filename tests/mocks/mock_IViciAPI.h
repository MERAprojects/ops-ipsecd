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
#include "IViciAPI.h"

class MockIViciAPI : public IViciAPI {
 public:
  MOCK_METHOD0(init,
      void());
  MOCK_METHOD0(deinit,
      void());
  MOCK_METHOD1(connect,
      vici_conn_t*(const char *uri));
  MOCK_METHOD1(disconnect,
      void(vici_conn_t *conn));
  MOCK_METHOD1(begin,
      vici_req_t*(const char *name));
  MOCK_METHOD3(add_key_value_str,
      void(vici_req_t *req, const char *key, const std::string& value));
  MOCK_METHOD3(add_key_value_uint,
      void(vici_req_t *req, const char *key, uint32_t value));
  MOCK_METHOD4(add_key_value,
      void(vici_req_t *req, const char *key, const void* data, uint32_t len));
  MOCK_METHOD2(submit,
      vici_res_t*(vici_req_t *req, vici_conn_t *conn));
  MOCK_METHOD3(find_str,
      const char*(vici_res_t *res, const char *def, const char *fmt));
  MOCK_METHOD1(free_res,
      void(vici_res_t *res));
  MOCK_METHOD2(begin_section,
      void(vici_req_t *req, const char *name));
  MOCK_METHOD2(begin_list,
      void(vici_req_t *req, const char *name));
  MOCK_METHOD2(add_list_item,
      void(vici_req_t *req, const std::string& item));
  MOCK_METHOD1(end_list,
      void(vici_req_t *req));
  MOCK_METHOD1(end_section,
      void(vici_req_t *req));
  MOCK_METHOD1(free_req,
      void(vici_req_t *req));
};
