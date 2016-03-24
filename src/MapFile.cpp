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
#include "MapFile.h"

/**********************************
*Function Declarations
**********************************/
MapFile::MapFile(ISystemCalls& systemCalls)
    : m_SystemCalls(systemCalls)
{
}

MapFile::~MapFile()
{
    unmap_file();
}

void MapFile::unmap_file()
{
    if(m_map_File == nullptr)
    {
        m_SystemCalls.s_munmap(m_map_File, m_size);
    }
}

ipsec_ret MapFile::map_file(const std::string& filepath)
{
    int fd = 0;
    int status = 0;
    struct stat s;

    fd = m_SystemCalls.s_open(filepath.c_str(), O_RDONLY);
    if(fd < 0)
    {
        return ipsec_ret::OPEN_FAILED;
    }

    /* Get the size of the file. */
    status = m_SystemCalls.s_fstat(fd, &s);
    if (status < 0)
    {
        return ipsec_ret::SSTAT_FAILED;
    }

    m_size = s.st_size;

    /* Memory-map the file. */
    m_map_File = m_SystemCalls.s_mmap(0, m_size, PROT_READ,
                                       MAP_PRIVATE, fd, 0);
    if (m_map_File == MAP_FAILED)
    {
        return ipsec_ret::MMAP_FAILED;
    }

    return ipsec_ret::OK;
}
