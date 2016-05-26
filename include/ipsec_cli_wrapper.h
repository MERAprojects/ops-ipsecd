/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef IPSEC_CLI_WRAPPER_H
#define IPSEC_CLI_WRAPPER_H
#ifdef __cplusplus
extern "C" {
#endif

typedef enum e_vty_ipsec_ret
{
    VTY_ERROR = -10000,
    VTY_MODIFY_FAILED,
    VTY_ADD_FAILED,
    VTY_REMOVE_FAILED,
    VTY_NOT_FOUND,
    VTY_ALLOC_FAILED,
    VTY_NULL_PARAMETERS,
    VTY_EMPTY_STRING,
    VTY_OK = 0
} vty_ipsec_ret_t;

typedef enum e_vty_ipsec_values
{
    VTY_IPSEC_NONE,
    VTY_IPSEC_MODE_TRASPORT,
    VTY_IPSEC_MODE_TUNNEL,
    VTY_IPSEC_INT_SHA1,
    VTY_IPSEC_INT_SHA256,
    VTY_IPSEC_INT_SHA512,
    VTY_IPSEC_INT_MD5,
    VTY_IPSEC_CIPHER_AES,
    VTY_IPSEC_CIPHER_AES256,
    VTY_IPSEC_CIPHER_3DES,
    VTY_IPSEC_IKE_V1,
    VTY_IPSEC_IKE_V2,
    VTY_IPSEC_IKE_V1V2,
    VTY_IPSEC_AUTHBY_PUBKEY,
    VTY_IPSEC_AUTHBY_PSK,
    VTY_IPSEC_DIFFIE_GROUP2,
    VTY_IPSEC_DIFFIE_GROUP14
} vty_ipsec_value_t;

vty_ipsec_ret_t vty_policy_create(void **ipsec_pol);

vty_ipsec_ret_t vty_policy_id_set(const void *ipsec_pol,
                                  const char *pol_id);

vty_ipsec_ret_t vty_policy_id_get(const void *ipsec_pol,
                                  const char **pol_id);

vty_ipsec_ret_t vty_policy_desc_set(const void *ipsec_pol,
                                    const char *desc);

vty_ipsec_ret_t vty_policy_mode_set(const void *ipsec_pol,
                                    const vty_ipsec_value_t pol_mode);

vty_ipsec_ret_t vty_policy_esp_hash_set(const void *ipsec_pol,
                                        const vty_ipsec_value_t hash);

vty_ipsec_ret_t vty_policy_esp_encrypt_set(const void *ipsec_pol,
                                           const vty_ipsec_value_t encryption);

vty_ipsec_ret_t vty_policy_enable(const void *ipsec_pol);

vty_ipsec_ret_t vty_policy_disable(const void *ipsec_pol);

vty_ipsec_ret_t vty_policy_destroy(void **ipsec_pol);

vty_ipsec_ret_t vty_isakmp_create(const void *ipsec_pol,
                                  void **isakmp);

vty_ipsec_ret_t vty_isakmp_version_set(const void *isakmp,
                                       const vty_ipsec_value_t ike_version);

vty_ipsec_ret_t vty_isakmp_hash_set(const void *isakmp,
                                    const vty_ipsec_value_t hash);

vty_ipsec_ret_t vty_isakmp_encryption_set(const void *isakmp,
                                          const vty_ipsec_value_t encryption);

vty_ipsec_ret_t vty_isakmp_authentication_set(const void *isakmp,
                                              const vty_ipsec_value_t auth);

vty_ipsec_ret_t vty_isakmp_group_set(const void *isakmp,
                                     const vty_ipsec_value_t group);

vty_ipsec_ret_t vty_isakmp_localid_set(const void *isakmp,
                                       const char *local_id);

vty_ipsec_ret_t vty_isakmp_remoteid_set(const void *isakmp,
                                        const char *remote_id);

vty_ipsec_ret_t vty_isakmp_destroy(void **isakmp);

#ifdef __cplusplus
}
#endif
#endif
