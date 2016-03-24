
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

#ifndef MAPFILE_H
#define MAPFILE_H

/**********************************
*System Includes
**********************************/
#include <stdint.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ISystemCalls.h"

/**
 * Class for to Map the Files
 */
class MapFile
{
    protected:

        /**
         * System Calls Interface
         */
        ISystemCalls& m_SystemCalls;

        /**
         * Size of the file that was map
         */
        uint32_t m_size = 0;

        /**
         * Map File
         */
        void* m_map_file = nullptr;

        /**
         * Unmap the File
         */
        void unmap_file();

    public:

        /**
         * Default Constructor
         *
         * @param systemCalls SystemCall Interface
         */
        MapFile(ISystemCalls& systemCalls);

        /**
         * Default Destructor
         */
        virtual ~MapFile();

        /**
         * Map The file using mmap
         *
         * @param filepath File path of the file to map
         */
        ipsec_ret map_file(const std::string& filepath);

        inline const void* get_map_file() const
        {
            return m_map_file;
        }

        inline uint32_t get_size() const
        {
            return m_size;
        }
};

#endif /* MAPFILE_H */