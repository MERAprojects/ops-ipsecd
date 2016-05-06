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

#ifndef ERRORNOTIFYSS_H
#define ERRORNOTIFYSS_H

/**********************************
*System Includes
**********************************/
#include <thread>
#include <string>
#include <error_notify_msg.h>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "ISystemCalls.h"
#include "IErrorListener.h"
#include "IErrorNotifySS.h"

/**
 * Error Notify handler for StrongSWAN errors
 */
class ErrorNotifySS : public IErrorNotifySS
{
    protected:

        /**
         * System Call Interface Class
         */
        ISystemCalls& m_system_calls;

        /**
         * Listener class for the errors
         */
        IErrorListener& m_error_listener;

        /**
         * Connection to the error notify plugin
         */
        int m_conn = 0;

        /**
         * Lets know if the system is ready to be use
         */
        bool m_is_ready = false;

        /**
         * Lets know if the error receiver thread is running
         */
        bool m_is_running = false;

        /**
         * Error Receiver Thread
         */
        std::thread m_error_thread;

        /**
         * Error Receiver main method
         */
        ipsec_ret run_error_receiver();

        /**
         * Stop the thread and closes the socket
         *
         * @param join_thread If called from thread this will be false to prevent
         * a deadlock
         */
        void cleanup(bool join_thread = true);

        void process_error(const error_notify_msg_t& msg);

    public:

        /**
         * Constructor
         *
         * @param system_calls System Call Interface Class
         *
         * @param error_listener Class that will receive the error events
         */
        ErrorNotifySS(ISystemCalls& system_calls, IErrorListener& error_listener);

        /**
         * Default Destructor
         */
        virtual ~ErrorNotifySS();

        /**
         * Returns if the system has been initialized correctly
         */
        inline bool get_is_ready() const
        {
            return m_is_ready;
        }

        /**
         * Returns if the Error Receiver Thread is running
         */
        inline bool get_is_running() const
        {
            return m_is_running;
        }

        /**
         * @copydoc IErrorNotifySS::initialize
         */
        ipsec_ret initialize() override;
};

#endif