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
#include "ISystemCalls.h"

class MockISystemCalls : public ISystemCalls {
 public:
  MOCK_METHOD6(s_mmap,
      void*(void *addr, size_t length, int prot, int flags, int fd, off_t offset));
  MOCK_METHOD2(s_munmap,
      int(void *addr, size_t length));
  MOCK_METHOD2(s_open,
      int(const char *pathname, int flags));
  MOCK_METHOD2(s_fstat,
      int(int fd, struct stat *buf));
  MOCK_METHOD3(s_connect,
      int(int sockfd, const struct sockaddr *addr, socklen_t addrlen));
  MOCK_METHOD3(s_socket,
      int(int domain, int type, int protocol));
  MOCK_METHOD3(s_read,
      ssize_t(int fd, void *buf, size_t count));
  MOCK_METHOD1(s_close,
      int(int fd));
};
