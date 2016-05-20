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


#ifndef IIPSEC_OVSDB_H
#define IIPSEC_OVSDB_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**********************************
*Class Decl
**********************************/
class IIPsecOvsdb
{
    public:
        /**
         * Default Constructor
         */
        IIPsecOvsdb() {}

        /**
         *  Default Destructor
         */
        virtual ~IIPsecOvsdb() {}

        /**
         * Create a connection to the OVSDB and create a DB cache
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret initialize() = 0;

        /**
         * Set the path where OVSDB is running
         *
         * @param path set the path for db.sock, usually using ovsdbrun
         */
        virtual void set_db_path(const std::string& path) = 0;

        /**
         * Get the path where OVSDB is running
         *
         * @return a string object
         */
        virtual const std::string& get_db_path() = 0;

        /**
         * Processes a batch of messages from the database server on 'm_idl'.
         *
         * @return ipsec_ret::IS_RUNNING if successful, otherwise an error code
         */
        virtual ipsec_ret run() = 0;

        /**
         * Arranges for poll_block() to wake up when m_idl_wrapper.idl_run()
         * has something to do
         *
         */
        virtual void wait() = 0;

        /**
         * Add a new SA(row) into the OVSDB ipsec_manual_sa table
         *
         * @param sa New SA to be inserted into the OVSDB
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sa_insert_row(const ipsec_sa& sa) = 0;

        /**
         * Delete a SA(row) from the OVSDB ipsec_manual_sa table
         *
         * @param sa SA to be deleted from OVSDB
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sa_delete_row(const ipsec_sa& sa) = 0;

        /**
         * Get a SA(row) from the OVSDB ipsec_manual_sa table
         *
         * @param spi The spi number of the SA
         *
         * @param sa the ipsec_sa struct to save the SA
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sa_get_row(
                int64_t spi, ipsec_sa& sa) = 0;

        /**
         * Replace every single column (except SPI) in a given row into the
         * OVSDB server by the the values on sa
         *
         * @param sa ipsec_sa type with the new information
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sa_modify_row(const ipsec_sa& sa) = 0;

        /**
         * Add a new SP(row) into the OVSDB ipsec_manual_sp table
         *
         * @param sp SP to be inserted into the OVSDB
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sp_insert_row(const ipsec_sp& sp) = 0;

        /**
         * Delete a SP(row) from the OVSDB ipsec_manual_sp table
         *
         * @param dir ipsec_direction type
         * @param selector Selector data
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sp_delete_row(ipsec_direction dir,
                const ipsec_selector& selector) = 0;

        /**
         * Get a SP(row) from the OVSDB ipsec_manual_sp table
         *
         * @param dir ipsec_direction type
         * @param selector Selector data
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sp_get_row(ipsec_direction dir,
                const ipsec_selector& selector, ipsec_sp& sp) = 0;

        /**
         * Update the values of a SP into the OVSDB with the new values on sp
         *
         * @param sp ipsec_sp type with the information to modify the OVSDB
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sp_modify_row(const ipsec_sp& sp) = 0;

        /**
         * Copy the information related to a SA on row into sa
         *
         * @param row ipsec_manual_sa_t type
         * @param sa ipsec_sa type to be modified
         */
        virtual void ovsrec_to_ipsec_sa(
                const ipsec_manual_sa_t row, ipsec_sa& sa) = 0;

        /**
         * Copy the information related to a SA on sa into row
         *
         * @param row ipsec_manual_sa_t type to be modified
         * @param sa ipsec_sa with the information related to a new SA
         */
        virtual void ipsec_sa_to_ovsrec(
                ipsec_sa& sa, ipsec_manual_sa_t& row) = 0;

        /**
         * Copy the information related to a SP on sp into row
         *
         * @param row ipsec_manual_sp_t type
         * @param sa ipsec_sp type to be modified
         */
        virtual void ipsec_sp_to_ovsrec(
                ipsec_sp& sp, ipsec_manual_sp_t& row) = 0;

        /**
         * Copy the information related to a SP on row into sp
         *
         * @param row ipsec_manual_sp_t type
         * @param sa ipsec_sp type to be modified
         */
        virtual void ovsrec_to_ipsec_sp(
                const ipsec_manual_sp_t row, ipsec_sp& sp) = 0;

        /**
         * Update cache for ops-ipsecd related tables
         *
         * @param seq_no sequence number to track
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret update_cache(unsigned int seq_no) = 0;

        /**
         * Handler used when any row from the OVSDB has been modified
         *
         * @param ipsec_events type
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsecd_ovsdb_event(
                ipsec_events event) = 0;

        /**
         * Set a integer value on 'column' into 'row'
         *
         * @param row Row to be modified
         * @param column Field to be modified in 'row'
         * @param value New value on column
         */
        virtual void set_integer_to_column(const idl_row_t row,
                idl_column_t column, int64_t value) = 0;

        /**
         * Set a string on column into row
         *
         * @param row Row to be modified
         * @param column Field to be modified in 'row'
         * @param str_value New string on column
         *
         * @return ipsec_ret::NULL_PARAMETERS if str_value is an empty string
         * or ipsec_ret::OK if successful
         */
        virtual ipsec_ret set_string_to_column(const idl_row_t row,
                idl_column_t column, const std::string& str_value) = 0;
};
#endif /*IPSEC_OVSDB_H*/
