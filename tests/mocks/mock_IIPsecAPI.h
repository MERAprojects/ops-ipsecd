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
#include "IIPsecAPI.h"

class MockIIPsecAPI : public IIPsecAPI {
 public:
  MOCK_METHOD1(add_sa,
      ipsec_ret(const ipsec_sa& sa));
  MOCK_METHOD1(modify_sa,
      ipsec_ret(const ipsec_sa& sa));
  MOCK_METHOD2(get_sa,
      ipsec_ret(uint32_t spi, ipsec_sa& sa));
  MOCK_METHOD1(del_sa,
      ipsec_ret(const ipsec_sa_id& id));
  MOCK_METHOD1(add_sp,
      ipsec_ret(const ipsec_sp& sp));
  MOCK_METHOD1(modify_sp,
      ipsec_ret(const ipsec_sp& sp));
  MOCK_METHOD2(get_sp,
      ipsec_ret(const ipsec_sp_id& sp_id, ipsec_sp& sp));
  MOCK_METHOD1(del_sp,
      ipsec_ret(const ipsec_sp_id& sp_id));
};
