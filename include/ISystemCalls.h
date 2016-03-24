
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

#ifndef ISYSTEMCALLS_H
#define ISYSTEMCALLS_H

/**********************************
*System Includes
**********************************/
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

/**********************************
*Local Includes
**********************************/

/**
 * Base Class for System Calls
 */
class ISystemCalls
{
    public:

        /**
         * Default Constructor
         */
        ISystemCalls() {}

        /**
         * Default Destructor
         */
        virtual ~ISystemCalls() {}

        /**
         * Refer to http://linux.die.net/man/2/mmap
         */
        virtual void* s_mmap(void *addr, size_t length, int prot, int flags,
                             int fd, off_t offset) = 0;

        /**
         * Refer to http://linux.die.net/man/2/mmap
         */
        virtual int s_munmap(void *addr, size_t length) = 0;

        /**
         * Refer to http://linux.die.net/man/2/open
         */
        virtual int s_open(const char *pathname, int flags) = 0;

        /**
         * Refer to http://linux.die.net/man/2/fstat
         */
        virtual int s_fstat(int fd, struct stat *buf) = 0;
};

#endif /* ISYSTEMCALLS_H */