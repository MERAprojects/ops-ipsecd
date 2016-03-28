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

#ifndef CONFIGQUEUE_H
#define CONFIGQUEUE_H

/**********************************
*System Includes
**********************************/
#include <mutex>
#include <queue>
#include <thread>
#include <string>
#include <condition_variable>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ConfigTask.h"
#include "IConfigQueue.h"

/**
 * Base Interface Class for Configuration Queue
 */
class ConfigQueue : public IConfigQueue
{
    protected:

        /**
         * IKE API Interface
         */
        IIKEAPI& m_ike_api;

        /**
         * Configuration Dispatcher Thread
         */
        std::thread m_config_thread;

        /**
         * Mutex for Config Queue Class
         */
        std::mutex m_config_task_mutex;

        /**
         * Mutex for Config Queue
         */
        std::mutex m_config_queue_mutex;

        /**
         * Configuration Task Queue
         */
        std::queue<ConfigTask> m_task_queue;

        /**
         * Conditional use to trigger a new task
         */
        std::condition_variable m_task_conditional;

        /**
         * Determines if the Configuration Thread is still running
         */
        bool m_is_running = false;

        /**
         * Configuration Dispatcher main method
         */
        void run_config_dispatcher();

        /**
         * Executes the Configuration Task
         */
        void run_config_task(const ConfigTask& task);

    public:

        /**
         * Default Constructor
         *
         * @param ike_api IKE API Interface
         */
        ConfigQueue(IIKEAPI& ike_api);

        /**
         * Default Destructor
         */
        virtual ~ConfigQueue();

        /**
         * Starts the Configuration Thread Dispatcher
         */
        ipsec_ret start_thread();

        /**
         * Stops the Configuration Thread Dispatcher
         */
        ipsec_ret stop_thread();

        /**
         * Adds a configuration task to the queue
         *
         * @param task Configuration Task
         */
        void add_task(const ConfigTask& task);

};

#endif /* CONFIGQUEUE_H */