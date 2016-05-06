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

#ifndef OPS_IPSECD_HELPER_H
#define OPS_IPSECD_HELPER_H

/**********************************
*System Includes
**********************************/
#include <string>

/**********************************
*Local Includes
**********************************/
#include "ops-ipsecd.h"

/**
 * Namespace Helper Functions for IPsec
 */
namespace ipsecd_helper
{
    /**
     * Converts a Cipher Enum to String
     *
     * @param cipher Cipher Type
     *
     * @return Enum type to String
     */
    extern const char* cipher_to_str(ipsec_cipher cipher);

    /**
     * Converts a Integrity Enum to String
     *
     * @param integrity Integrity Type
     *
     * @return Enum type to String
     */
    extern const char* integrity_to_str(ipsec_integrity integrity);

    /**
     * Converts a Diffie Group Enum to String
     *
     * @param group Diffie Group Type
     *
     * @return Enum type to String
     */
    extern const char* group_to_str(ipsec_diffie_group group);

    /**
     * Converts a AuthBy Enum to String
     *
     * @param auth_by AuthBy Type
     *
     * @return Enum type to String
     */
    extern const char* authby_to_str(ipsec_authby auth_by);

    /**
     * Converts a IKE Version Enum to String
     *
     * @param version IKE Version Type
     *
     * @return Enum type to String
     */
    extern const char* ike_version_to_str(ipsec_ike_version version);

    /**
     * Converts a IPsec Mode Enum to String
     *
     * @param mode Cipher Type
     *
     * @return Enum type to String
     */
    extern const char* mode_to_str(ipsec_mode mode);

    /**
     * Converts a Credential Enum to String
     *
     * @param cred Credential Type
     *
     * @return Enum type to String
     */
    extern const char* cred_to_str(ipsec_credential_type cred);

    /**
     * Converts a set of Cipher/UIntegrity/Diffie Group to a string.
     * Cipher-Integrity-Diffie Group. Use mostly for the IKE Daemon Connection
     * options.
     *
     * @param cipher Cipher type
     * @param integrity Integrity type
     * @param group Diffie group type
     *
     * @return [Cipher-Integrity-Diffie Group] String
     */
    extern std::string cipher_integrity_group_to_str(ipsec_cipher cipher,
                                                     ipsec_integrity integrity,
                                                     ipsec_diffie_group group);

    /**
     * Converts a IKE State (string) to an ipsec_state
     *
     * @param ike_state IKE String state to convert
     *
     * @return ipsec state
     */
    extern ipsec_state ike_state_to_ipsec_state(const std::string ike_state);

    /**
     * Converts a Char value to an Hexadecimal Value
     *
     * @param alpha Value to convert
     *
     * @param hex value in hexadecimal
     *
     * @return True if value could be converted
     */
    extern bool char_to_hex(char alpha, uint8_t& hex);

    /**
     * Converts a string of hexadecimals to a byte array
     *
     * @param str String to convert
     *
     * @param key Byte array where to save the results
     *
     * @param key_len Length of the byte array
     */
    extern void str_to_key(const std::string& str, char* key, uint32_t key_len);

    /**
     * Converts a byte array to a String of Hexadecimals
     *
     * @param key Byte Array to convert
     *
     * @param keyLen Size of Byte Array
     *
     * @return String of Hexadecimals
     */
    extern std::string key_to_str(const char* key, uint32_t keyLen);

    /**
     * Converts a StrongSWAN error code to an IPsec error event
     *
     * @param error StrongSWAN error code
     *
     * @return IPsec error event
     */
    extern ipsec_error_event ss_error_to_ipsec_error_event(int error);
}

#endif /* OPS_IPSECD_HELPER_H */