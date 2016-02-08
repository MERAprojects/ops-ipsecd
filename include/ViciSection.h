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

#ifndef VICISECTION_H
#define VICISECTION_H

/**********************************
*System Includes
**********************************/
#include <string>
#include <unordered_map>

/**********************************
*Local Includes
**********************************/
#include "ViciItem.h"

/**********************************
*Typedefs
**********************************/
typedef std::unordered_map<std::string, ViciItem*> ViciItemMap;
typedef ViciItemMap::iterator ViciItemMapIt;
typedef ViciItemMap::const_iterator ViciItemMapItConst;

/**
 * Vici Section Item
 */
class ViciSection : public ViciItem
{
    protected:

        /**
         * Name of the Section
         */
        std::string m_name = "";

        /**
         * Map of Vici Items in the Section
         */
        ViciItemMap m_items;

    public:

        /**
         * Default Constructor
         */
        ViciSection();

        /**
         * Default Destructor
         */
        virtual ~ViciSection();

        /**
         * Clear the Vici Section Map
         */
        void clear();

        /**
         * Gets the Size of the Vici Section Map
         *
         * @return Size of the Map
         */
        inline uint32_t get_size() const
        {
            return m_items.size();
        }

        /**
         * Gets the Name of the Section
         *
         * @return Section Name
         */
        inline const std::string& get_name() const
        {
            return m_name;
        }

        /**
         * Sets the name of the Section
         *
         * @param name Section Name
         */
        inline void set_name(const std::string& name)
        {
            m_name = name;
        }

        /**
         * Adds a Vici Item to the Section Map
         *
         * @param name Name of the Item
         *
         * @param item Vici Item
         */
        void set_item(const std::string& name, ViciItem* item);

        /**
         * Gets a Vici Item from the Section's map
         *
         * @param name Name of the Item
         *
         * @return Vici Item, if not found it will return null
         */
        ViciItem* get_item(const std::string& name) const;

        /**
         * Removes an item from the Section's map
         *
         * @param name Name of the Item
         *
         * @return true if removed
         */
        bool remove_item(const std::string& name);

        /**
         * Gets a Vici Item from the Section's map cast to a Type
         *
         * @param name Name of the item
         *
         * @return Vici Item, if not found it will return null
         */
        template<class T>
        T* get_item_type(const std::string& name) const
        {
            return dynamic_cast<T*>(get_item(name));
        }

        /**
         * Iterator to the Beginning of the map
         */
        ViciItemMapIt begin();

        /**
         * Iterator to the End of the map
         */
        ViciItemMapIt end();

        /**
         * Iterator to the Beginning of the map
         */
        ViciItemMapItConst begin() const;

        /**
         * Iterator to the End of the map
         */
        ViciItemMapItConst end() const;

        /**
         * Iterator to the Beginning of the map
         */
        ViciItemMapItConst cbegin() const;

        /**
         * Iterator to the End of the map
         */
        ViciItemMapItConst cend() const;
};

#endif /* VICISECTION_H */