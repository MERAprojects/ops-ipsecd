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

#ifndef IPSEC_OVSDB_H
#define IPSEC_OVSDB_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"
#include "IIPsecOvsdbIDLWrapper.h"
#include "IIPsecOvsdb.h"

/**********************************
*Class Decl
**********************************/
class IPsecOvsdb : public IIPsecOvsdb
{
    /**
     * Removed Copy Constructor
     */
    IPsecOvsdb(const IPsecOvsdb& orig) = delete;

    protected:
        /**
         * Reference to the OVSDB IDL LIB wrapper object
         */
        IIPsecOvsdbIDLWrapper& m_idl_wrapper;

        /**
         * Main idl_t object
         */
        idl_t m_idl;

        /**
         * IDL sequence number
         */
        unsigned int m_idl_seqno = 0;

        /**
         * IDL sequence number used to compare against the current idl_seqno
         */
        unsigned int m_idl_seqno_new = 0;

        /**
         * Determines if the OVSDB configuration is ready, this variable
         * change just when ops-ipsecd is bring up for the first time
         */
        bool m_is_ready = false;

        /**
         * Path where the OVSDB socket is
         */
        std::string db_path = "";

        /**
         * Determines if the request for changes on the OVSDB is coming from
         * a member of the IPsecOvsdb class
         */
        bool local_change = false;

    public:
        /**
         * Default Constructor
         *
         * @param idl_wrapper reference to the main object of
         * IIPsecOvsdbIDLWrapper class
         */
        IPsecOvsdb(IIPsecOvsdbIDLWrapper& idl_wrapper);

        /**
         *  Default Destructor
         */
        ~IPsecOvsdb();

        /**
         * @copydoc IIPsecOvsdb::initialize
         */
        ipsec_ret initialize();

        /**
         * @copydoc IIPsecOvsdb::set_db_path
         */
        inline void set_db_path(const std::string& path)
        {
            db_path.assign(path);
        }

        /**
         * @copydoc IIPsecOvsdb::get_db_path
         */
        inline const std::string& get_db_path()
        {
            return db_path;
        }

        /**
         * @copydoc IIPsecOvsdb::run
         */
        ipsec_ret run() override;

        /**
         * @copydoc IIPsecOvsdb::wait
         */
        void wait() override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sa_insert_row
         */
        ipsec_ret ipsec_manual_sa_insert_row(const ipsec_sa& sa) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sa_delete_row
         */
        ipsec_ret ipsec_manual_sa_delete_row(const ipsec_sa& sa) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sa_get_row
         */
        ipsec_ret ipsec_manual_sa_get_row(int64_t spi, ipsec_sa& sa) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sa_modify_row
         */
        ipsec_ret ipsec_manual_sa_modify_row(const ipsec_sa& sa) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sp_insert_row
         */
        ipsec_ret ipsec_manual_sp_insert_row(const ipsec_sp& sp) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sp_delete_row
         */
        ipsec_ret ipsec_manual_sp_delete_row(ipsec_direction dir,
                const ipsec_selector& selector) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sp_get_row
         */
        ipsec_ret ipsec_manual_sp_get_row(ipsec_direction dir,
                const ipsec_selector& selector, ipsec_sp& sp) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_manual_sp_modify_row
         */
        ipsec_ret ipsec_manual_sp_modify_row(const ipsec_sp& sp) override;

        /**
         * @copydoc IIPsecOvsdb::ovsrec_to_ipsec_sa
         */
        void ovsrec_to_ipsec_sa(
                const ipsec_manual_sa_t row, ipsec_sa& sa) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_sa_to_ovsrec
         */
        void ipsec_sa_to_ovsrec(ipsec_sa& sa, ipsec_manual_sa_t& row) override;

        /**
         * @copydoc IIPsecOvsdb::ipsec_sp_to_ovsrec
         */
        void ipsec_sp_to_ovsrec(ipsec_sp& sp, ipsec_manual_sp_t& row) override;

        /**
         * @copydoc IIPsecOvsdb::ovsrec_to_ipsec_sp
         */
        void ovsrec_to_ipsec_sp(
                const ipsec_manual_sp_t row, ipsec_sp& sp) override;

        /**
         * @copydoc IIPsecOvsdb::update_cache
         */
        ipsec_ret update_cache(unsigned int seq_no) override;

        /**
         * @copydoc IIPsecOvsdb::ipsecd_ovsdb_event
         */
        ipsec_ret ipsecd_ovsdb_event(ipsec_events event) override;

        /**
         * @copydoc IIPsecOvsdb::set_integer_to_column
         */
        void set_integer_to_column(const idl_row_t row,
                idl_column_t column, int64_t value) override;

        /**
         * @copydoc IIPsecOvsdb::set_string_to_column
         */
        ipsec_ret set_string_to_column(const idl_row_t row,
                idl_column_t column, const std::string& str_value) override;
};

#endif /*IPSEC_OVSDB*/
