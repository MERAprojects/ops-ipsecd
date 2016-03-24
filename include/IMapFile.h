
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

#ifndef IMAPFILE_H
#define IMAPFILE_H

/**********************************
*System Includes
**********************************/
#include <stdint.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Base Class for to Map the Files
 */
class IMapFile
{
    protected:

        /**
         * Unmap the File
         */
        virtual void unmap_file() = 0;

    public:

        /**
         * Default Constructor
         */
        IMapFile() {}

        /**
         * Default Destructor
         */
        virtual ~IMapFile() {}

        /**
         * Map The file using mmap
         *
         * @param filepath File path of the file to map
         */
        virtual ipsec_ret map_file(const std::string& filepath) = 0;

        /**
         * Get the pointer to the map file
         *
         * @return Pointer to the map file
         */
        virtual const void* get_map_file() const = 0;

        /**
         * Gets the size of the map file
         *
         * @return Size of the map file
         */
        virtual uint32_t get_size() const = 0;
};

#endif /* IMAPFILE_H */