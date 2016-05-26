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

#include "IPsecVty.h"
#include "IPsecVtyIsaKmp.h"
#include "ipsec_vty.h"

extern "C" {

#include "vtysh/lib/version.h"
#include "getopt.h"
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"


static struct cmd_node ipsec_node =
{
  IPSEC_NODE,
  "%s(config-ipsec)# "
};

static struct cmd_node ipsec_isakmp_node =
{
  IPSEC_ISAKMP_NODE,
  "%s(config-ipsec-isakmp)# "
};

//TODO: define a show ipec command

DEFUN(vtysh_ipsec_policy,
      vtysh_ipsec_policy_cmd,
      "ipsec policy <NAME>",
      "Select or create an IKE IPsec policy\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_desc,
      vtysh_ipsec_policy_desc_cmd,
      "description <DESCRIPTION>",
      "Set a description for an IKE IPsec policy\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp,
      vtysh_ipsec_isakmp_cmd,
      "isakmp",
      "Enter configuration for ISAKMP for an IPsec policy\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_ike_version,
      vtysh_ipsec_isakmp_ike_version_cmd,
      "version (IKEv1/v2 | IKEv1 | IKEv2)",
      "Set IKE version for ISAKMP\n"
      "Set IKE version 1 and 2\n"
      "Set IKE version 1\n"
      "Set IKE version 2\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_hash,
      vtysh_ipsec_isakmp_hash_cmd,
      "hash (sha1 | md5)",
      "Set hash algorithm\n"
      "Set hash to sha1\n"
      "Set hash to md5\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_encryption,
      vtysh_ipsec_isakmp_encryption_cmd,
      "encryption (aes128 | aes256)",
      "Set encryption for ISAKMP\n"
      "Set encryption to aes128\n"
      "Set encryption to aes256\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_auth,
      vtysh_ipsec_isakmp_auth_cmd,
      "authentication (pre-share-key | certificate)",
      "Set authentication for ISAKMP\n"
      "Set authentication to pre shared key (PSK)\n"
      "Set authentication to certificate\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_group,
      vtysh_ipsec_isakmp_group_cmd,
      "group (diffie2 | diffie14)",
      "Set diffie group for ISAKMP\n"
      "Set group to diffie2\n"
      "Set group to diffie14\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_local_addr,
      vtysh_ipsec_isakmp_local_addr_cmd,
      "local address <IP_or_hostname>",
      "Set local address by hostname or ip address\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_remote_addr,
      vtysh_ipsec_isakmp_remote_addr_cmd,
      "remote address <IP_or_hostname>",
      "Set remote address by hostname or ip address\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_local_id,
      vtysh_ipsec_isakmp_local_id_cmd,
      "local id <ID>",
      "Set local ID for ISAKMP if authentication is by certificate\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_remote_id,
      vtysh_ipsec_isakmp_remote_id_cmd,
      "remote id <ID>",
      "Set remote ID for ISAKMP if authentication is by certificate\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_isakmp_local_cert,
      vtysh_ipsec_isakmp_local_cert_cmd,
      "local certificate <Certificate_Name>",
      "Set local certificate for ISAKMP\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_mode,
      vtysh_ipsec_policy_mode_cmd,
      "mode (tunnel | transport)",
      "Set mode for IKE IPsec policy\n"
      "Set mode to tunnel\n"
      "Set mode to transport\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_esp_encrypt,
      vtysh_ipsec_policy_esp_encrypt_cmd,
      "esp encryption (aes128 | aes256)",
      "Set ESP encryption for IKE IPsecPolicy\n"
      "Set ESP encryption to aes128\n"
      "Set ESP encryption to aes256\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_esp_hash,
      vtysh_ipsec_policy_esp_hash_cmd,
      "esp hash (sha1-hmac | sha256-hmac | sha512-hmac)",
      "Set ESP hash for IPsecPolicy\n"
      "Set ESP hash to sha1-hmac\n"
      "Set ESP hash to sha256-hmac\n"
      "Set ESP hash to sha512-hmac\n")

{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_enable,
      vtysh_ipsec_policy_enable_cmd,
      "enable",
      "Enable IKE IPsec policy\n")
{

    return CMD_SUCCESS;
}

DEFUN(vtysh_ipsec_policy_disable,
      vtysh_ipsec_policy_disable_cmd,
      "disable",
      "Disable IKE IPsec policy\n")
{

    return CMD_SUCCESS;
}

//TODO: Changes in ops-cli repo, add subnode for isakmp

void cli_pre_init(void)
{
    vtysh_ret_val retval = e_vtysh_error;
    install_node(&ipsec_node, NULL);
    vtysh_install_default(IPSEC_NODE);

    retval = install_show_run_config_context(e_vtysh_ipsec_context,
                              &vtysh_ipsec_callback,
                              NULL, NULL);
    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                        "IPsec context unable to add config callback");
        assert(0);
    }
}

void cli_post_init(void)
{
    install_element(CONFIG_NODE, &vtysh_ipsec_policy_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_desc_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_mode_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_esp_encrypt_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_esp_hash_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_enable_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_policy_disable_cmd);
    install_element(IPSEC_NODE, &vtysh_ipsec_isakmp_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_ike_version_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_hash_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_encryption_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_auth_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_group_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_local_addr_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_remote_addr_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_local_id_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_remote_id_cmd);
    install_element(IPSEC_ISAKMP_NODE, &vtysh_ipsec_isakmp_local_cert_cmd);
}


}
