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

#ifndef VICIVALUE_H
#define VICIVALUE_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ViciItem.h"

/**
 * Vici Value Item
 */
class ViciValue : public ViciItem
{
    protected:

        /**
         * Value Storage
         */
        std::string m_value = "";

    public:

        /**
         * Default Constructor
         */
        ViciValue();

        /**
         * Default destructor
         */
        virtual ~ViciValue();

        /**
         * Gets the Vici Value
         *
         * @return Vici Value
         */
        inline const std::string& get_value() const
        {
            return m_value;
        }

        /**
         * Sets the Vici Value
         *
         * @param value Value to save
         */
        inline void set_value(const std::string& value)
        {
            m_value = value;
        }

};

#endif /* VICIVALUE_H */