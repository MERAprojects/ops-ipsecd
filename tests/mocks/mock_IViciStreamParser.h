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
#include "IViciStreamParser.h"

class MockIViciStreamParser : public IViciStreamParser {
 public:
  MOCK_CONST_METHOD0(get_parse_status,
      ipsec_ret());
  MOCK_CONST_METHOD0(get_vici_answer,
      const ViciSection&());
  MOCK_METHOD2(register_stream_cb,
      ipsec_ret(vici_conn_t* conn, const std::string& name));
  MOCK_METHOD0(unregister_stream_cb,
      void());
};
