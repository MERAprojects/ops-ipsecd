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
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "SystemCalls.h"

/**********************************
*Function Declarations
**********************************/
SystemCalls::SystemCalls()
{
}

SystemCalls::~SystemCalls()
{
}

void* SystemCalls::s_mmap(void *addr, size_t length, int prot, int flags,
                          int fd, off_t offset)
{
    return mmap(addr, length, prot, flags, fd, offset);
}

int SystemCalls::s_munmap(void *addr, size_t length)
{
    return munmap(addr, length);
}

int SystemCalls::s_open(const char *pathname, int flags)
{
    return open(pathname, flags);
}

int SystemCalls::s_fstat(int fd, struct stat *buf)
{
    return fstat(fd, buf);
}
