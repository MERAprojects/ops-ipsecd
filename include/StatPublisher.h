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

#ifndef STATPUBLISHER_H
#define STATPUBLISHER_H

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

/**********************************
*Forward Decl
**********************************/
class IIKEAPI;

/**
 * Class for to Publish Stats
 */
class StatPublisher : public IStatPublisher
{
    protected:

        /**
         * Is the Stat publisher thread running
         */
        bool m_is_running = false;

        /**
         * Stat publisher thread
         */
        std::thread m_publisher_thread;

        /**
         * Mutex for when modifying the publisher
         */
        std::mutex m_publisher_mutex;

        /**
         * Mutex for when modifying the publisher list
         */
        std::mutex m_publisher_list_mutex;

        /**
         * Seconds to wait before publishing
         */
        uint32_t m_publish_time_sec = 0;

        /**
         * Ticks that have pass
         */
        uint32_t m_current_ticks = 0;

        /**
         * List of IPsec stats to publish
         */
        std::list<ipsec_stat_pub> m_pub_list;

        /**
         * IKE API Interface
         */
        IIKEAPI& m_ike_api;

        /**
         * @copydoc IStatPublisher::run_publisher
         */
        void run_publisher() override;

        /**
         * @copydoc IStatPublisher::publish_stat
         */
        ipsec_ret publish_stat(const ipsec_stat_pub& stat_ipsec) override;

    public:

        /**
         * Default Constructor
         *
         * @param ike_api IKE API Interface
         */
        StatPublisher(IIKEAPI& ike_api);

        /**
         * Default Destructor
         */
        virtual ~StatPublisher();

        /**
         * @copydoc IStatPublisher::set_publish_time_sec
         */
        inline void set_publish_time_sec(uint32_t value) override
        {
            m_publish_time_sec = value;
        }

        /**
         * @copydoc IStatPublisher::start_thread
         */
        ipsec_ret start_thread() override;

        /**
         * @copydoc IStatPublisher::stop_thread
         */
        ipsec_ret stop_thread() override;

        /**
         * @copydoc IStatPublisher::add_ipsec_stat
         */
        ipsec_ret add_ipsec_stat(const ipsec_stat_pub& stat_ipsec) override;

        /**
         * @copydoc IStatPublisher::remove_ipsec_stat
         */
        ipsec_ret remove_ipsec_stat(const ipsec_stat_pub& stat_ipsec) override;
};

#endif /* STATPUBLISHER_H */
