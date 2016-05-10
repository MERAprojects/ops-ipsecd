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

#ifndef IPSECOVSDBIDLWRAPPER_H
#define IPSECOVSDBIDLWRAPPER_H

/**********************************
*System Includes
**********************************/

/**********************************
*Local Includes
**********************************/
#include "IIPsecOvsdbIDLWrapper.h"


/**********************************
*Class Decl
**********************************/

/**
 * OVSDB IDL Library Wrapper Interface
 */
class IPsecOvsdbIDLWrapper: public IIPsecOvsdbIDLWrapper
{
    public:
        /**
         * Default Constructor
         */
        IPsecOvsdbIDLWrapper() {}

        /**
         * Default Destructor
         */
        virtual ~IPsecOvsdbIDLWrapper() {}

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_create
         */
        idl_t idl_create(const char *remote, const idl_class_t class_,
                bool monitor_everything, bool retry) override;

        /**
         *  @copydoc IIPsecOvsdbIDLWrapper::idl_run
         */
        void idl_run(idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_wait
         */
        void idl_wait(idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_add_table
         */
        void idl_add_table(idl_t idl, const idl_table_t tc) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_add_column
         */
        void idl_add_column(idl_t idl, const idl_column_t column) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_omit_alert
         */
        void idl_omit_alert(idl_t idl, const idl_column_t column) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_destroy
         */
        void idl_destroy(idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_first_row
         */
        const idl_row_t idl_first_row(const idl_t idl,
                const idl_table_t table_class) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_next_row
         */
        const idl_row_t idl_next_row(const idl_row_t row) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_read
         */
        const idl_datum_t idl_read(const idl_row_t row,
                const idl_column_t column) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_create
         */
        idl_txn_t idl_txn_create(idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_set_dry_run
         */
        void idl_txn_set_dry_run(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_destroy
         */
        void idl_txn_destroy(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_wait
         */
        void idl_txn_wait(const idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_commit
         */
        idl_txn_status_t idl_txn_commit(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_commit_block
         */
        idl_txn_status_t idl_txn_commit_block(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_abort
         */
        void idl_txn_abort(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_get_increment_new_value
         */
        int64_t idl_txn_get_increment_new_value(const idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_write
         */
        void idl_txn_write(const idl_row_t row,
                const idl_column_t column, idl_datum_t datum) override;

        /**
         *@copydoc IIPsecOvsdbIDLWrapper::idl_txn_delete
         */
        void idl_txn_delete(const idl_row_t row_);

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_txn_get_idl
         */
        idl_t idl_txn_get_idl(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_get_seqno
         */
        unsigned int idl_get_seqno(const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_set_lock
         */
        void idl_set_lock(idl_t idl, const char *lock_name) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_is_lock_contended
         */
        bool idl_is_lock_contended(const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_has_lock
        */
        bool idl_has_lock(const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_track_add_column
         */
        void idl_track_add_column(
                idl_t idl, const idl_column_t column) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::init
         */
        void init(void);

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_track_clear
         */
        void idl_track_clear(const idl_t idl);

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::idl_add_and_track_all_column
         */
        void idl_add_and_track_all_column(idl_t idl, const idl_table_t tc);

        ///////////////////////////////////////////////////////////////
        //     VSWITCH specific functions for ops-ipsecd tables     //
        /////////////////////////////////////////////////////////////

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sa_first
         */
        const ipsec_manual_sa_t ipsec_manual_sa_first(
                const idl_t idl) override;
        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sa_next
         */
        const ipsec_manual_sa_t ipsec_manual_sa_next(
                const ipsec_manual_sa_t row) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sa_insert
         */
        ipsec_manual_sa_t ipsec_manual_sa_insert(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sa_track_get_first
         */
        const ipsec_manual_sa_t ipsec_manual_sa_track_get_first(
                const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sa_track_get_next
         */
        const ipsec_manual_sa_t ipsec_manual_sa_track_get_next(
                const ipsec_manual_sa_t row) override;
        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sp_first
         */
        const ipsec_manual_sp_t ipsec_manual_sp_first(
                const idl_t idl) override;
        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sp_next
         */
        const ipsec_manual_sp_t ipsec_manual_sp_next(
                const ipsec_manual_sp_t row) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sp_insert
         */
        ipsec_manual_sp_t ipsec_manual_sp_insert(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sp_track_get_first
         */
        const ipsec_manual_sp_t ipsec_manual_sp_track_get_first(
                const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_manual_sp_track_get_next
         */
        const ipsec_manual_sp_t ipsec_manual_sp_track_get_next(
                const ipsec_manual_sp_t row) override;
        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_ike_policy_first
         */
        const ipsec_ike_policy_t ipsec_ike_policy_first(
                const idl_t idl) override;
        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_ike_policy_next
         */
        const ipsec_ike_policy_t ipsec_ike_policy_next(
                const ipsec_ike_policy_t row) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_ike_policy_insert
         */
        ipsec_ike_policy_t ipsec_ike_policy_insert(idl_txn_t txn) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_ike_policy_track_get_first
         */
        const ipsec_ike_policy_t ipsec_ike_policy_track_get_first(
                const idl_t idl) override;

        /**
         * @copydoc IIPsecOvsdbIDLWrapper::ipsec_ike_policy_track_get_next
         */
        const ipsec_ike_policy_t ipsec_ike_policy_track_get_next(
                const ipsec_ike_policy_t row) override;
};

#endif /*IPSECOVSDBIDLWRAPPER_H*/
