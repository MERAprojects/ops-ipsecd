
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

#ifndef SYSTEMCALLS_H
#define SYSTEMCALLS_H

/**********************************
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "ISystemCalls.h"

/**
 * System Calls Wrapper
 */
class SystemCalls : public ISystemCalls
{
    public:

        /**
         * Default Constructor
         */
        SystemCalls();

        /**
         * Default Destructor
         */
        virtual ~SystemCalls();

        /**
         * @copydoc ISystemCalls::s_mmap
         */
        void* s_mmap(void *addr, size_t length, int prot, int flags,
                     int fd, off_t offset) override;

        /**
         * @copydoc ISystemCalls::s_munmap
         */
        int s_munmap(void *addr, size_t length) override;

        /**
         * @copydoc ISystemCalls::s_open
         */
        int s_open(const char *pathname, int flags) override;

        /**
         * @copydoc ISystemCalls::s_fstat
         */
        int s_fstat(int fd, struct stat *buf) override;

        /**
         * @copydoc ISystemCalls::s_connect
         */
        int s_connect(int sockfd, const struct sockaddr *addr,
                      socklen_t addrlen) override;

        /**
         * @copydoc ISystemCalls::s_socket
         */
        int s_socket(int domain, int type, int protocol) override;

        /**
         * @copydoc ISystemCalls::s_read
         */
        ssize_t s_read(int fd, void *buf, size_t count) override;

        /**
         * @copydoc ISystemCalls::s_close
         */
        int s_close(int fd) override;
};

#endif /* ISYSTEMCALLS_H */