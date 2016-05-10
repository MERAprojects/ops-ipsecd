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

/**********************************
* System Includes
**********************************/

/**********************************
* Local Includes
***********************************/
#include "IPsecOvsdbIDLWrapper.h"

/*IPsecOvsdbIDLWrapper::IPsecOvsdbIDLWrapper()
{
}

IPsecOvsdbIDLWrapper::~IPsecOvsdbIDLWrapper()
{
}
*/

void IPsecOvsdbIDLWrapper::idl_add_table(idl_t idl, const idl_table_t tc)
{
    ovsdb_idl_add_table(idl, tc);
}

void IPsecOvsdbIDLWrapper::idl_add_column(idl_t idl,
        const idl_column_t column)
{
    ovsdb_idl_add_column(idl, column);
}

void IPsecOvsdbIDLWrapper::idl_omit_alert(idl_t idl,
        const idl_column_t column)
{
    ovsdb_idl_omit_alert(idl, column);
}

void IPsecOvsdbIDLWrapper::idl_destroy(idl_t idl)
{
    ovsdb_idl_destroy(idl);
}

idl_t IPsecOvsdbIDLWrapper::idl_create(const char *remote,
        const idl_class_t class_, bool monitor_everything, bool retry)
{
    return ovsdb_idl_create(remote, class_, (int)monitor_everything, (int)retry);
}

void IPsecOvsdbIDLWrapper::idl_run(idl_t idl)
{
    ovsdb_idl_run(idl);
}

void IPsecOvsdbIDLWrapper::idl_wait(idl_t idl)
{
    ovsdb_idl_wait(idl);
}

const idl_row_t IPsecOvsdbIDLWrapper::idl_first_row(const idl_t idl,
        const idl_table_t table_class)
{
    return const_cast<idl_row_t>(ovsdb_idl_first_row(idl, table_class));
}

const idl_row_t IPsecOvsdbIDLWrapper::idl_next_row(const idl_row_t row)
{
    return const_cast<idl_row_t>(ovsdb_idl_next_row(row));
}

const idl_datum_t IPsecOvsdbIDLWrapper::idl_read(const idl_row_t row,
        const idl_column_t column)
{
    return const_cast<idl_datum_t>(ovsdb_idl_read(row, column));
}

idl_txn_t IPsecOvsdbIDLWrapper::idl_txn_create(idl_t idl)
{
    return ovsdb_idl_txn_create(idl);
}

void IPsecOvsdbIDLWrapper::idl_txn_set_dry_run(idl_txn_t txn)
{
    ovsdb_idl_txn_set_dry_run(txn);
}

void IPsecOvsdbIDLWrapper::idl_txn_destroy(idl_txn_t txn)
{
    ovsdb_idl_txn_destroy(txn);
}

void IPsecOvsdbIDLWrapper::idl_txn_wait(const idl_txn_t txn)
{
    ovsdb_idl_txn_wait(txn);
}

idl_txn_status_t IPsecOvsdbIDLWrapper::idl_txn_commit(idl_txn_t txn)
{
    return ovsdb_idl_txn_commit(txn);
}

idl_txn_status_t IPsecOvsdbIDLWrapper::idl_txn_commit_block(idl_txn_t txn)
{
    return ovsdb_idl_txn_commit_block(txn);
}

void IPsecOvsdbIDLWrapper::idl_txn_abort(idl_txn_t txn)
{
    ovsdb_idl_txn_abort(txn);
}

int64_t IPsecOvsdbIDLWrapper::idl_txn_get_increment_new_value(
        const idl_txn_t txn)
{
    return ovsdb_idl_txn_get_increment_new_value(txn);
}

void IPsecOvsdbIDLWrapper::idl_txn_write(const idl_row_t row,
        const idl_column_t column, idl_datum_t datum)
{
    ovsdb_idl_txn_write(row, column, datum);
}

idl_t IPsecOvsdbIDLWrapper::idl_txn_get_idl(idl_txn_t txn)
{
    return ovsdb_idl_txn_get_idl(txn);
}

void IPsecOvsdbIDLWrapper::idl_txn_delete(const idl_row_t row_)
{
    ovsdb_idl_txn_delete(row_);
}

unsigned int IPsecOvsdbIDLWrapper::idl_get_seqno(const idl_t idl)
{
    return ovsdb_idl_get_seqno(idl);
}

void IPsecOvsdbIDLWrapper::idl_set_lock(idl_t idl, const char *lock_name)
{
    ovsdb_idl_set_lock(idl, lock_name);
}

bool IPsecOvsdbIDLWrapper::idl_is_lock_contended(const idl_t idl)
{
    int result = ovsdb_idl_is_lock_contended(idl);
    if (result == 0){
        return false;
    }
    return true;
}

bool IPsecOvsdbIDLWrapper::idl_has_lock(const idl_t idl)
{
    int result = ovsdb_idl_has_lock(idl);
    if (result == 0)
    {
        return false;
    }
    return true;
}

void IPsecOvsdbIDLWrapper::idl_track_clear(const idl_t idl)
{
    ovsdb_idl_track_clear(idl);
}

void IPsecOvsdbIDLWrapper::idl_add_and_track_all_column(
        idl_t idl, const idl_table_t tc)
{
    for (unsigned int j = 0; j < tc->n_columns; j++)
    {
        const struct ovsdb_idl_column *column = &tc->columns[j];
        idl_add_column(idl, const_cast<idl_column_t>(column));
        idl_track_add_column(idl, const_cast<idl_column_t>(column));
    }
}

void IPsecOvsdbIDLWrapper::init(void)
{
    ovsrec_init();
}
void IPsecOvsdbIDLWrapper::idl_track_add_column(idl_t idl,
        const idl_column_t column)
{
    return ovsdb_idl_track_add_column(idl, column);
}
const ipsec_manual_sa_t IPsecOvsdbIDLWrapper::ipsec_manual_sa_first(
        const idl_t idl)
{
    return const_cast<ipsec_manual_sa_t>(ovsrec_ipsec_manual_sa_first(idl));
}
const ipsec_manual_sa_t IPsecOvsdbIDLWrapper::ipsec_manual_sa_next(
        const ipsec_manual_sa_t row)
{
    return const_cast<ipsec_manual_sa_t>(ovsrec_ipsec_manual_sa_next(row));
}

ipsec_manual_sa_t IPsecOvsdbIDLWrapper::ipsec_manual_sa_insert(idl_txn_t txn)
{
    return ovsrec_ipsec_manual_sa_insert(txn);
}

const ipsec_manual_sa_t IPsecOvsdbIDLWrapper::ipsec_manual_sa_track_get_first(
        const idl_t idl)
{
    return const_cast<ipsec_manual_sa_t>(
            ovsrec_ipsec_manual_sa_track_get_first(idl));
}
const ipsec_manual_sa_t IPsecOvsdbIDLWrapper::ipsec_manual_sa_track_get_next(
        const ipsec_manual_sa_t row)
{
    return const_cast<ipsec_manual_sa_t>(
            ovsrec_ipsec_manual_sa_track_get_next(row));
}

const ipsec_manual_sp_t IPsecOvsdbIDLWrapper::ipsec_manual_sp_first(
        const idl_t idl)
{
    return const_cast<ipsec_manual_sp_t>(
            ovsrec_ipsec_manual_sp_first(idl));
}

const ipsec_manual_sp_t IPsecOvsdbIDLWrapper::ipsec_manual_sp_next(
        const ipsec_manual_sp_t row)
{
    return const_cast<ipsec_manual_sp_t>(
            ovsrec_ipsec_manual_sp_next(row));
}

ipsec_manual_sp_t IPsecOvsdbIDLWrapper::ipsec_manual_sp_insert(idl_txn_t txn)
{
    return ovsrec_ipsec_manual_sp_insert(txn);
}

const ipsec_manual_sp_t IPsecOvsdbIDLWrapper::ipsec_manual_sp_track_get_first(
        const idl_t idl)
{
    return const_cast<ipsec_manual_sp_t>(
            ovsrec_ipsec_manual_sp_track_get_first(idl));
}

const ipsec_manual_sp_t IPsecOvsdbIDLWrapper::ipsec_manual_sp_track_get_next(
        const ipsec_manual_sp_t row)
{
    return const_cast<ipsec_manual_sp_t>(
            ovsrec_ipsec_manual_sp_track_get_next(row));
}

const ipsec_ike_policy_t IPsecOvsdbIDLWrapper::ipsec_ike_policy_first(
        const idl_t idl)
{
    return const_cast<ipsec_ike_policy_t>(
            ovsrec_ipsec_ike_policy_first(idl));
}

const ipsec_ike_policy_t IPsecOvsdbIDLWrapper::ipsec_ike_policy_next(
        const ipsec_ike_policy_t row)
{
    return const_cast<ipsec_ike_policy_t>(
            ovsrec_ipsec_ike_policy_next(row));
}

ipsec_ike_policy_t IPsecOvsdbIDLWrapper::ipsec_ike_policy_insert(
        idl_txn_t txn)
{
    return ovsrec_ipsec_ike_policy_insert(txn);
}

const ipsec_ike_policy_t IPsecOvsdbIDLWrapper::ipsec_ike_policy_track_get_first(
        const idl_t idl)
{
    return const_cast<ipsec_ike_policy_t>(
            ovsrec_ipsec_ike_policy_track_get_first(idl));
}

const ipsec_ike_policy_t IPsecOvsdbIDLWrapper::ipsec_ike_policy_track_get_next(
        const ipsec_ike_policy_t row)
{
    return const_cast<ipsec_ike_policy_t>(
            ovsrec_ipsec_ike_policy_track_get_next(row));
}
