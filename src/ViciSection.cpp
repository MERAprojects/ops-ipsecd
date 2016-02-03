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
*Local Includes
**********************************/
#include "ViciSection.h"

/**********************************
*Function Declarations
**********************************/

ViciSection::ViciSection()
    : ViciItem(ViciItemType::Section)
{
}

ViciSection::~ViciSection()
{
    clear();
}

void ViciSection::clear()
{
    for(auto item : m_items)
    {
        delete item.second;
    }
    m_items.clear();
}

void ViciSection::set_item(const std::string& name, ViciItem* item)
{
    m_items[name] = item;
}

ViciItem* ViciSection::get_item(const std::string& name) const
{
    auto it = m_items.find(name);
    if(it == m_items.end())
    {
        return nullptr;
    }

    return it->second;
}

ViciItemMapIt ViciSection::begin()
{
    return m_items.begin();
}

ViciItemMapIt ViciSection::end()
{
    return m_items.end();
}

ViciItemMapItConst ViciSection::begin() const
{
    return m_items.begin();
}

ViciItemMapItConst ViciSection::end() const
{
    return m_items.end();
}

ViciItemMapItConst ViciSection::cbegin() const
{
    return m_items.cbegin();
}

ViciItemMapItConst ViciSection::cend() const
{
    return m_items.cend();
}
