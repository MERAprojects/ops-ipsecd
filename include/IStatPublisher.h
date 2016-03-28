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

#ifndef ISTATPUBLISHER_H
#define ISTATPUBLISHER_H

/**********************************
*System Includes
**********************************/
#include <list>
#include <mutex>
#include <thread>
#include <stdint.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IStatPublisher.h"

/**
 * Base Class for to Publish Stats
 */
class IStatPublisher
{
    protected:

        /**
         * Publisher Method use to publish the stats
         */
        virtual void run_publisher() = 0;

        /**
         * Publish Stat
         *
         * @param stat_ipsec IPsec Stat to be publish
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret publish_stat(const ipsec_stat_pub& stat_ipsec) = 0;

    public:

        /**
         * Default Constructor
         */
        IStatPublisher() {}

        /**
         * Default Destructor
         */
        virtual ~IStatPublisher() {}

        /**
         *
         * @param value Interval to wait between publishing
         */
        virtual void set_publish_time_sec(uint32_t value) = 0;

        /**
         * Starts the stat publisher
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret start_thread() = 0;

        /**
         * Stop the stat publisher
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret stop_thread() = 0;

        /**
         * Stop the stat publisher
         *
         * @param stat_ipsec IPsec stats to publish
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret add_ipsec_stat(const ipsec_stat_pub& stat_ipsec) = 0;

        /**
         * Stop the stat publisher
         *
         * @param stat_ipsec IPsec stats to publish
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret remove_ipsec_stat(const ipsec_stat_pub& stat_ipsec) = 0;
};

#endif /* ISTATPUBLISHER_H */
