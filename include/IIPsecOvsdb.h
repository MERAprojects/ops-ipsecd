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
#include <vector>

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
         * @param m_id m_id to perform a lookup for this SA
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret ipsec_manual_sa_delete_row(
                const ipsec_sa_id& m_id) = 0;

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
         * @param sp ipsec_sp Type to store the OVSDB row
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
         * @param is_new true if sa is going to be a new row, false otherwise
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_sa_to_ovsrec(const ipsec_sa& sa,
                const ipsec_manual_sa_t row, bool is_new) = 0;

        /**
         * Copy the information related to a SP on sp into row
         *
         * @param row ipsec_manual_sp_t type
         * @param sp ipsec_sp type to be modified
         * @param is_new true if sp is going to be a new row, false otherwise
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_sp_to_ovsrec(const ipsec_sp& sp,
                const ipsec_manual_sp_t row, bool is_new) = 0;

        /**
         * Delete a row from OVSDB ipsec_ike_policy table
         *
         * @param conn_name Name of the connection to be deleted from OVSDB
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_ike_policy_delete_row(
                const std::string& conn_name) = 0;

        /**
         * Get an IKE Policy from OVSDB ipsec_ike_policy table
         *
         * @param conn_name Name of the connection
         * @param conn ipsec_ike_connection Type to store the OVSDB row
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_ike_policy_get_row(
                const std::string& conn_name, ipsec_ike_connection& conn) = 0;

        /**
         * Insert a new IKE Policy into OVSDB ipsec_ike_policy table
         *
         * @param conn ipsec_ike_connection Type to be inserted into OVSDB
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_ike_policy_insert_row(
                const ipsec_ike_connection& conn) = 0;

        /**
         * Replace every single column (except name) in a given row into the
         * OVSDB server by the the values on conni
         *
         * @param conn IKE Policy to be updated
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_ike_policy_modify_row(
                const ipsec_ike_connection& conn) = 0;
        /**
         * Copy the information related to an IKE Policy into an OVSDB row
         *
         * @param conn ipsec_ike_connection Type
         * @param row Row to be modified
         * @param is_new true if conn name is going to be modified,
         * false otherwise
         *
         * @return ipsec_ret::OK if successfull, otherwise an error code
         */
        virtual ipsec_ret ipsec_ike_conn_to_ovsrec(
                const ipsec_ike_connection& conn,
                const ipsec_ike_policy_t row, bool is_new) = 0;

        /**
         * Copy the information related to an IKE Policy row into conn
         *
         * @param row ipsec_ike_policy table row
         * @param conn ipsec_ike_policy Type to be modified
         */
        virtual void ovsrec_to_ipsec_ike_conn(const ipsec_ike_policy_t row,
                ipsec_ike_connection& conn) = 0;

        /**
         * Copy the information related to a SP on row into sp
         *
         * @param row ipsec_manual_sp_t type
         * @param sp ipsec_sp type to be modified
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
         * @param event ipsec_events type
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
         * @param str_value New string on 'column'
         *
         * @return ipsec_ret::NULL_PARAMETERS if str_value is an empty string
         * or ipsec_ret::OK if successful
         */
        virtual ipsec_ret set_string_to_column(const idl_row_t row,
                idl_column_t column, const std::string& str_value) = 0;

        /**
         * Set a map on column into row. The caller retains ownership of
         * 'ipsec_map' and everything in it
         *
         * @param row Row to be modified
         * @param column Field to be modified in 'row'
         * @param ipsec_map New map on 'column'
         * @param keys Set of keys for ipsec_map smap
         * @param is_empty If true, send a empty datum OVSDB, if false ipsec_map
         * must have at least one key-value pair
         *
         * @return ipsec_ret::NULL_PARAMETERS if ipsec_map is nullptr and
         * is_empty is false, ipsec_ret::OK if successfull
         */
        virtual ipsec_ret set_map_to_column(const idl_row_t row,
                idl_column_t column, const struct smap *ipsec_map,
                const std::vector<std::string>& keys, bool is_empty) = 0;
        /**
         * Get the statistics from a given OVSDB IPsec_Manual_SP row
         *
         * @param dir ipsec_direction Type for the required sp
         * @param selector ipsec_selector Type for the required sp
         * @param stats ipsec_lifetime_current Type to store the information
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret get_sp_stats(ipsec_direction dir,
                const ipsec_selector& selector,
                ipsec_lifetime_current& stats) = 0;

        /**
         * Modify a statistic value given by stat_name in an OVSDB
         * IPsec_Manual_SP row with dir and selector
         *
         * @param dir ipsec_direction Type for the required sp
         * @param selector ipsec_selector Type for the required sp
         * @param stat_name key for statistic smap
         * @param value New value for pair with 'key' in statistics smap
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
          */
        virtual ipsec_ret modify_sp_stats(ipsec_direction dir,
                const ipsec_selector& selector,
                const std::string& stat_name,
                const std::string& value) = 0;

        /**
         * Get the statistics from a given OVSDB IPsec_Manual_SA row
         *
         * @param spi The SPI for the required SA
         * @param stats ipsec_lifetime_current Type to store the information
         * @param stats ipsec_sa_sp_stats Type to store the information
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
         */
        virtual ipsec_ret get_sa_stats(int64_t spi,
                ipsec_sa_sp_lifetime_current& lifetime_current,
                ipsec_sa_sp_stats& stats) = 0;

        /**
         * Modify a statistic value given by stat_name in an OVSDB
         * IPsec_Manual_SA row with spi
         *
         * @param spi The SPI for the required SA
         * @param stat_name key for statistic smap
         * @param value New value for pair with 'key' in statistics smap
         *
         * @return ipsec_ret::OK if successful, otherwise an error code
          */
        virtual ipsec_ret modify_sa_stats(int64_t spi,
                const std::string& stat_name, const std::string& value) = 0;
};
#endif /*IPSEC_OVSDB_H*/
