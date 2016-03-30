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

#ifndef IIPSECAPI_H
#define IIPSECAPI_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Base Interface Class for Configuration Queue
 */
class IIPsecAPI
{
    public:

        /**
         * Default Constructor
         */
        IIPsecAPI() {}

        /**
         * Default Destructor
         */
        virtual ~IIPsecAPI() {}

        /**
         * Loads a new SA to the IPsec Kernel Module
         *
         * @param sa SA to load
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret add_sa(const ipsec_sa& sa) = 0;

        /**
         * Gets a SA from the IPsec Kernel Module
         *
         * @param spi SPI of the SA to search for
         *
         * @param sa SA to load information into
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret get_sa(uint32_t spi, ipsec_sa& sa) = 0;

        /**
         * Deletes a SA from the IPsec Kernel Module
         *
         * @param spi spi of the SA to remove
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret del_sa(uint32_t spi) = 0;

        /**
         * Loads a new SP to the IPsec Kernel Module
         *
         * @param sp SP to load
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret add_sp(const ipsec_sp& sp) = 0;

        /**
         * Gets a SP from the IPsec Kernel Module
         *
         * @param sp_id ID of the SP to search for
         *
         * @param sa SP to load information into
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret get_sp(const ipsec_sp_id& sp_id, ipsec_sp& sp) = 0;

        /**
         * Deletes a SP from the IPsec Kernel Module
         *
         * @param sp_id ID of the SA to remove
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret del_sp(const ipsec_sp_id& sp_id) = 0;

};

#endif /* IIPSECAPI_H */