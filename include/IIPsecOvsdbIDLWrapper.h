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


#ifndef _IPSECOVSDBIDL_WRAPPER_H
#define _IPSECOVSDBIDL_WRAPPER_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
/**
 *  Replace C++ keywords used by OVSDB IDL Library
 *   */
extern "C" {
#define new _new
#define class _class
#define mutable _mutable
#include <dirs.h>
#include <vswitch-idl.h>
#undef mutable
#undef class
#undef new
}

/**********************************
*Typedef
**********************************/
typedef struct ovsdb_idl*                idl_t;
typedef struct ovsdb_idl_column*         idl_column_t;
typedef struct ovsdb_idl_table_class*    idl_table_t;
typedef struct ovsdb_idl_class*          idl_class_t;
typedef struct ovsdb_idl_row*            idl_row_t;
typedef struct ovsdb_datum*              idl_datum_t;
typedef struct ovsdb_idl_txn*            idl_txn_t;
typedef enum   ovsdb_idl_txn_status      idl_txn_status_t;
typedef struct ovsrec_ipsec_manual_sa*   ipsec_manual_sa_t;
typedef struct ovsrec_ipsec_manual_sp*   ipsec_manual_sp_t;
typedef struct ovsrec_ipsec_ike_policy*  ipsec_ike_policy_t;

/**********************************
*Class Decl
**********************************/

/**
 * OVSDB IDL Library Wrapper Interface
 */
class IIPsecOvsdbIDLWrapper
{
    public:
        /**
         * Default Constructor
         */
        IIPsecOvsdbIDLWrapper() {}

        /**
         * Default Destructor
         */
        virtual ~IIPsecOvsdbIDLWrapper() {}

        /**
         * Creates and returns a connection to database 'remote'
         *
         * @param remote char pointer to the path of db.sock
         * @param class_ ovsdb-idl class Type
         * @param monitor_everything Monitor all tables by default
         * @param retry Retry connection
         *
         * @return idl_t Type with the new connection
         */
        virtual idl_t idl_create(const char *remote, const idl_class_t class_,
                bool monitor_everything, bool retry) = 0;

        /**
         * Processes a batch of messages from the database server on 'idl
         *
         * @param idl ovsdb-idl object
         */
        virtual void idl_run(idl_t idl) = 0;

        /**
         * Arranges for poll_block() to wake up when ovsdb_idl_run() has
         * something to do or when activity occurs on a transaction on 'idl'.
         *
         * @param ovsdb-idl object
         */
        virtual void idl_wait(idl_t idl) = 0;

        /**
         * Ensures that the table with class 'tc' will be replicated on 'idl'
         * even if no columns are selected for replication.
         *
         * @param idl ovsdb-idl object
         * @param tc Table to be replicated
         */
        virtual void idl_add_table(idl_t idl, const idl_table_t tc) = 0;

        /**
         * Turns on OVSDB_IDL_MONITOR and OVSDB_IDL_ALERT for 'column' in 'idl'
         *
         * @param idl  ovsdb-idl object
         * @param column idl_column_t Type to be included
         */
        virtual void idl_add_column(idl_t idl, const idl_column_t column) = 0;

        /**
         * Turns off OVSDB_IDL_ALERT for 'column' in 'idl'.
         *
         * @param idl  ovsdb-idl object
         * @param column idl_column_t Type to be omited
         *
         */

        virtual void idl_omit_alert(idl_t idl,
                const idl_column_t column) = 0;

        /**
         * Destroys 'idl' and all of the data structures that it manages
         *
         * @param idl ovsdb-idl object to be destroyed
         */

        virtual void idl_destroy(idl_t idl) = 0;

        /**
         * Returns a row in 'table_class''s table in 'idl', or a null pointer
         * if that table is empty.
         *
         * @param idl ovsdb-idl object
         * @param table_class Table to be iterated
         *
         * @return idl_row_t Type or nullptr if table is empty
         */
        virtual const idl_row_t idl_first_row(const idl_t idl,
                const idl_table_t table_class) = 0;

        /**
         * Returns a row following 'row' within its table, or a null pointer
         * if 'row' is the last row in its table.
         *
         * @param row Row to used as reference
         *
         * @return idl_row_t Type or nullptr if 'row' is the last row in its
         * table
         */
        virtual const idl_row_t idl_next_row(const idl_row_t row) = 0;

        /**
         * Reads and returns the value of 'column' within 'row'.  If an
         * ongoing transaction has changed 'column''s value, the modified
         * value is returned.
         *
         * @param row Row to be read
         * @param column value from row required
         *
         * @return idl_datum_t with the value of column
         */
        virtual const idl_datum_t idl_read(const idl_row_t row,
                const idl_column_t column) = 0;

        /**
         * Starts a new transaction on 'idl'
         *
         * @param idl ovsdb-idl object
         *
         * @return idl_txn_t Type with a new transaction
         */
        virtual idl_txn_t idl_txn_create(idl_t idl) = 0;

        /**
         * Marks 'txn' as a transaction that will not actually modify the
         * database
         *
         * @param txn idl_txn_t object
         */
        virtual void idl_txn_set_dry_run(idl_txn_t txn) = 0;

        /**
         * Destroys 'txn' and frees all associated memory
         *
         * @param txn idl_txn_t object
         */
        virtual void idl_txn_destroy(idl_txn_t txn) = 0;

        /**
         * Causes poll_block() to wake up if 'txn' has completed committing.
         *
         * @param txn idl_txn_t object
         */
        virtual void idl_txn_wait(const idl_txn_t txn) = 0;

        /**
         * Attempts to commit 'txn'.  Returns the status of the commit
         * operation
         *
         * @param txn idl_txn_t object
         *
         * @return idl_txn_status_t object with the status of the commit
         * operation
         */
        virtual idl_txn_status_t idl_txn_commit(idl_txn_t txn) = 0;

        /**
         * Attempts to commit 'txn', blocking until the commit either succeeds
         * or fails.  Returns the final commit status, which may be any TXN_*
         * value other than TXN_INCOMPLETE.
         *
         * @param txn idl_txn_t object
         *
         * @return idl_txn_status_t object with the final status of the commit
         */
        virtual idl_txn_status_t idl_txn_commit_block(idl_txn_t txn) = 0;

        /**
         * Deletes 'row_' from its table.  May free 'row_', so it must not be
         * accessed afterward.
         *
         * @param row_ Row to be deleted
         */
        virtual void idl_txn_delete(const idl_row_t row_) = 0;

        /**
         * Aborts 'txn' without sending it to the database server.
         *
         * @param txn idl_txn_t object
         */
        virtual void idl_txn_abort(idl_txn_t txn) = 0;

        /**
         * Returns the final (incremented) value of the column in 'txn'
         *
         * @param txn idl_txn_t object
         *
         * @return int64_t the final value of the column in txn
         */
        virtual int64_t idl_txn_get_increment_new_value(
                const idl_txn_t txn) = 0;

        /**
         * Writes 'datum' to the specified 'column' in 'row'.  Updates both
         * 'row' itself and the structs derived from it void
         *
         * @param row Row to be modified
         * @param column Column to be modified in row
         * @param datum The data to be included
         */
        virtual void idl_txn_write(const idl_row_t row,
                const idl_column_t column, idl_datum_t datum) = 0;

        /**
         * Writes 'datum' to the specified 'column' in 'row'. A transaction
         * must be in progress.
         *
         * @param row Row to be modified
         * @param column Column to be modified in row
         * @param datum The date to be included
         */
        virtual void idl_txn_write_clone(const idl_row_t row,
                const idl_column_t column, const idl_datum_t datum) = 0;
        /**
         * Returns the IDL on which 'txn' acts.
         *
         * @param txn idl_txn_t type
         *
         * @return idl_t the ovsdb-idl object on which txn acts
         */
        virtual idl_t idl_txn_get_idl(idl_txn_t txn) = 0;

        /**
         * Returns a "sequence number" that represents the state of 'idl'.
         *
         * @param idl ovsdb-idl object
         *
         * @return sequence number as an unsigned int
         */
        virtual unsigned int idl_get_seqno(const idl_t idl) = 0;

        /**
         * If 'lock_name' is nonnull, configures 'idl' to obtain the named
         * lock from the database server and to avoid modifying the database
         * when the lock cannot be acquired (that is, when another client
         * has the same lock).
         *
         * @param idl ovsdb-idl object
         * @param lock_name the name for the lock attempt
         */
        virtual void idl_set_lock(idl_t idl, const char *lock_name) = 0;

        /**
         * Returns true if 'idl' is configured to obtain a lock but the database server
         * has indicated that some other client already owns the requested lock.
         *
         * @param idl ovsdb-idl object
         *
         * @return true  if idl is configured to obtain a lock,
         * false otherwise
         */
        virtual bool idl_is_lock_contended(const idl_t idl) = 0;

        /**
         * Returns true if 'idl' is configured to obtain a lock and owns
         * that lock.
         *
         * @param idl ovsdb-idl object
         *
         * @return true if idl has the lock, false otherwise
        */
        virtual bool idl_has_lock(const idl_t idl) = 0;

        /**
         * Initialize the metadata for the IDL cache
         */
        virtual void init(void) = 0;

        /**
         * Flushes the tracked rows. Client calls this function after calling
         * idl_run() and read all tracked rows with the
         * idl_track_get_*() functions
         *
         * @param idl ovsdb-idl object
         */
        virtual void idl_track_clear(const idl_t idl) = 0;

        /**
         * Turns on OVSDB_IDL_TRACK for 'column' in 'idl'.
         * This function should be called between ovsdb_idl_create() and
         * the first call to ovsdb_idl_run(). The column to be tracked
         * should have OVSDB_IDL_ALERT turned on.
         *
         * @param idl ovsdb-idl object
         * @param column column to be tracked
         */
        virtual void idl_track_add_column(idl_t idl,
                const idl_column_t column) = 0;

        /**
         * Turns on OVSDB_IDL_MONITOR, OVSDB_IDL_ALERT and OVSDB_IDL_TRACK
         * for all columns in table tc
         *
         * @param idl ovsdb-idl object
         * @param tc table to be tracked
         */
        virtual void idl_add_and_track_all_column(
                idl_t idl, const idl_table_t tc) = 0;

        /**
         * Get the path from where OVSDB is running
         *
         * @return The path(std::string) from where OVSDB is running
         */
        virtual const std::string rundir(void) = 0;

        ///////////////////////////////////////////////////////////////
        //     VSWITCH specific functions for ops-ipsecd tables     //
        /////////////////////////////////////////////////////////////

        /**
         * Returns a row in table "IPsec_Manual_SA" in 'idl', or a null
         * pointer if that table is empty
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row in ipsec_manual_sa table or nullptr otherwise
         */
        virtual const ipsec_manual_sa_t ipsec_manual_sa_first(
                  const idl_t idl) = 0;
        /**
        * Returns a row following 'row' within its table, or a null pointer
        * if 'row' is the last row in its table.
        *
        * @param row Row to be used as reference
        *
        * @return the next row in ipsec_manual_sa table
        */
        virtual const ipsec_manual_sa_t ipsec_manual_sa_next(
                  const ipsec_manual_sa_t row) = 0;

        /**
         * Inserts and returns a new row in the table "IPsec_Manual_SA" in the
         * database with open transaction 'txn'.
         *
         * @param txn idl_txn_t object
         *
         * @return a new row on ipsec_manual_sa table
         */
        virtual ipsec_manual_sa_t ipsec_manual_sa_insert(idl_txn_t txn) = 0;

        /**
         * Get the first row that has a new change on ipsec_manual_sa table
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row with some changes on ipsec_manual_sa table
         * or nullptr otherwise
         */
        virtual const ipsec_manual_sa_t ipsec_manual_sa_track_get_first(
                const idl_t idl) = 0;

        /**
         * Get the next row on  ipsec_manual_sa table with new changes
         *
         * @param row Row to be used as reference
         *
         * @return The next row with some changes on  ipsec_manual_sa table or
         * nullptr otherwise
         */
        virtual const ipsec_manual_sa_t ipsec_manual_sa_track_get_next(
                const ipsec_manual_sa_t row) = 0;

        /**
         * Returns a row in table "IPsec_Manual_SP" in 'idl', or a null
         * pointer if that table is empty
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row in ipsec_manual_sp table or nullptr otherwise
          */
        virtual const ipsec_manual_sp_t ipsec_manual_sp_first(
                  const idl_t idl) = 0;
        /**
        * Returns a row following 'row' within its table, or a null pointer
        * if 'row' is the last row in its table.
        *
        * @param row Row to be used as reference
        *
        * @return the next row on ipsec_manual_sp table or nullptr if row is
        * the last one row in this table
        */
        virtual const ipsec_manual_sp_t ipsec_manual_sp_next(
                  const ipsec_manual_sp_t row) = 0;

        /**
         * Inserts and returns a new row in the table "IPsec_Manual_SP" in the
         * database with open transaction 'txn'.
         *
         * @param txn idl_txn_t object
         *
         * @return A new empty row on ipsec_manual_sp table
         */
        virtual ipsec_manual_sp_t ipsec_manual_sp_insert(idl_txn_t txn) = 0;

        /**
         * Get the first row that has a new change on ipsec_manual_sp table
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row with some changes on ipsec_manual_sp table
         * or nullptr otherwise
         */
        virtual const ipsec_manual_sp_t ipsec_manual_sp_track_get_first(
                const idl_t idl) = 0;

        /**
         * Get the next row on  ipsec_manual_sp table with new changes
         *
         * @param row Row to be used as reference
         *
         * @return The next row with some changes on  ipsec_manual_sp table or
         * nullptr otherwise
         */
        virtual const ipsec_manual_sp_t ipsec_manual_sp_track_get_next(
                const ipsec_manual_sp_t row) = 0;
        /**
         * Returns a row in table "IPsec_IKE_Policy" in 'idl', or a null
         * pointer if that table is empty
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row on IPsec_IKE_Policy table or nullptr if
         * this table is empty
         */
        virtual const ipsec_ike_policy_t ipsec_ike_policy_first(
                  const idl_t idl) = 0;
        /**
        * Returns a row following 'row' within its table, or a null pointer
        * if 'row' is the last row in its table.
        *
        * @param row Row to be used as reference
        *
        * @return The next row on IPsec_IKE_Policy table or nullptr if row is
        * the last one row on this table
        */
        virtual const ipsec_ike_policy_t ipsec_ike_policy_next(
                  const ipsec_ike_policy_t row) = 0;

        /**
         * Inserts and returns a new row in the table "IPsec_IKE_Policy" in the
         * database with open transaction 'txn'.
         *
         * @param txn idl_txn_t object
         *
         * @return A new empty row on IPsec_IKE_Policy table
         */
        virtual ipsec_ike_policy_t ipsec_ike_policy_insert(idl_txn_t txn) = 0;

        /**
         * Get the first row that has a new change on IPsec_IKE_Policy table
         *
         * @param idl ovsdb-idl object
         *
         * @return the first row with some changes on IPsec_IKE_Policy table
         * or nullptr otherwise
         */
        virtual const ipsec_ike_policy_t ipsec_ike_policy_track_get_first(
                const idl_t idl) = 0;

        /**
         * Get the next row on IPsec_IKE_Policy table with new changes
         *
         * @param row Row to be used as reference
         *
         * @return The next row with some changes on IPsec_IKE_Policy table or
         * nullptr otherwise
         */
        virtual const ipsec_ike_policy_t ipsec_ike_policy_track_get_next(
                const ipsec_ike_policy_t row) = 0;
};
#endif/*_IPSECOVSDBIDL_WRAPPER_H*/
