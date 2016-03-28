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
#include "IIKEAPI.h"

class MockIIKEAPI : public IIKEAPI {
 public:
  MOCK_METHOD0(deinitialize,
      void());
  MOCK_METHOD0(initialize,
      ipsec_ret());
  MOCK_METHOD1(create_connection,
      ipsec_ret(const ipsec_ike_connection& conn));
  MOCK_METHOD1(delete_connection,
      ipsec_ret(const std::string& conn_name));
  MOCK_METHOD2(start_connection,
      ipsec_ret(const std::string& conn_name, uint32_t timeout_ms));
  MOCK_METHOD2(stop_connection,
      ipsec_ret(const std::string& conn_name, uint32_t timeout_ms));
  MOCK_METHOD1(load_credential,
      ipsec_ret(const ipsec_credential& cred));
  MOCK_METHOD2(get_connection_stats,
      ipsec_ret(const std::string& conn_name, ipsec_ike_connection_stats& stats));
  MOCK_METHOD1(load_authority,
      ipsec_ret(const ipsec_ca& ca));
  MOCK_METHOD1(unload_authority,
      ipsec_ret(const std::string& ca_name));
};
