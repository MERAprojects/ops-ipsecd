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

#ifndef VICILIST_H
#define VICILIST_H

/**********************************
*System Includes
**********************************/
#include <string>
#include <vector>

/**********************************
*Local Includes
**********************************/
#include "ViciItem.h"

/**
 * Vici List Items
 */
class ViciList : public ViciItem
{
    protected:

        /**
         * Store Vici List Values
         */
        std::vector<std::string> m_values;

    public:

        /**
         * Default Constructor
         */
        ViciList();

        /**
         * Default Destructor
         */
        virtual ~ViciList();

        /**
         * Add a Value to the Vici List
         *
         * @param value Value to add to the list
         */
        void add_value(const std::string& value);

        /**
         * Get a Value by its index
         *
         * @param index Index of the Value
         *
         * @return Value at the index given
         */
        std::string get_value(uint32_t index) const;

        /**
         * Get the Size of the List
         *
         * @return Size of the list
         */
        inline uint32_t get_size() const
        {
            return m_values.size();
        }

};

#endif /* VICILIST_H */