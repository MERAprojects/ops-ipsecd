/*
 *  (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

/**********************************
*Includes
**********************************/
#include <iostream>
#include <string.h>

/*Debug purpose*/
#include <cstdio>
/**********************************
*Local Includes
**********************************/
#include "UnixctlCommands.h"
#include "ops_ipsecd_helper.h"
#include "DebugMode.h"

/**
* Return true if the input word is a valid input for the especific command
* and the index number for this word in params
*/
static bool ipsecd_ucc_getIndex(const std::string params[],
        const std::string in_word, const int n_args, int &index)
{
    for (int it = 0; it < n_args; it++)
    {
        /*This is a valid key input for this command*/
        if (params[it].compare(in_word) == 0)
        {
            index = it;
            return true;
        }
    }
    return false;
}

static bool ipsec_ucc_set_ike(const std::string value,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 3;

    /*Valid values for ike key word*/
    const std::string str_values[] =
    {
        "v1",
        "v2",
        "v1v2"
    };
    const ipsec_ike_version all_version[] =
    {
        ipsec_ike_version::v1,
        ipsec_ike_version::v2,
        ipsec_ike_version::v1v2
    };

    for (int idx =0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            result = true;
            conn.m_ike_version = all_version[idx];
            break;
        }
    }
    return result;
}

static bool ipsec_ucc_set_dgroup(const std::string value,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 3;

    /*Valid values for dgroup key word*/
    const std::string str_values[] =
    {
        "none",
        "2",
        "14"
     };
    const ipsec_diffie_group all_group[] =
    {
        ipsec_diffie_group::group_none,
        ipsec_diffie_group::group_2,
        ipsec_diffie_group::group_14
    };

    for (int idx =0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            conn.m_diffie_group = all_group[idx];
            result = true;
            break;
        }
    }
    return result;
}
static bool ipsec_ucc_set_integrity(const std::string value,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 5;

    /*Valid values for integrity key word*/
    const std::string str_values[] =
    {
        "none",
        "sha1",
        "sha256",
        "sha512",
        "md5"
    };
    const ipsec_integrity all_intr[] =
    {
        ipsec_integrity::none,
        ipsec_integrity::sha1,
        ipsec_integrity::sha256,
        ipsec_integrity::sha512,
        ipsec_integrity::md5
    };

    for (int idx =0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            result = true;
            conn.m_integrity = all_intr[idx];
            /*TODO default*/
            conn.m_child_sa.m_integrity = all_intr[idx];
            break;
        }
    }
    return result;
}

static bool ipsec_ucc_set_cipher(const std::string value, bool child,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 4;

    /*Valid values for cipher key word*/
    const std::string str_values[] =
    {
        "none",
        "aes",
        "aes256",
        "3des"
    };
    const ipsec_cipher all_cipher[] =
    {
        ipsec_cipher::cipher_none,
        ipsec_cipher::cipher_aes,
        ipsec_cipher::cipher_aes256,
        ipsec_cipher::cipher_3des
    };

    for (int idx =0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            if (child)
            {
                conn.m_child_sa.m_cipher = all_cipher[idx];
            }
            else
            {
                conn.m_cipher = all_cipher[idx];
            }
            result = true;
            break;
        }
    }
    return result;
}

static bool ipsec_ucc_set_authmethod(const std::string value,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 2;

    /*Valid values for authmode key word*/
    const std::string str_values[] =
    {
        "ah",
        "esp"
     };
    const ipsec_auth_method all_auth_m[] =
    {
        ipsec_auth_method::ah,
        ipsec_auth_method::esp
    };
    for (int idx = 0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            result = true;
            conn.m_child_sa.m_auth_method = all_auth_m[idx];
            break;
        }
    }
    return result;
}

static bool ipsec_ucc_set_mode(const std::string value,
        ipsec_ike_connection &conn)
{
    bool result = false;
    const int elements = 2;

    /*Valid values for mode key word*/
    const std::string str_values[] =
    {
        "transport",
        "tunnel"
    };
    const ipsec_mode all_modes[] =
    {
        ipsec_mode::transport,
        ipsec_mode::tunnel
    };
    for (int idx = 0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            result = true;
            conn.m_child_sa.m_mode = all_modes[idx];
            break;
        }
    }
    return result;

}

static void ipsec_ucc_connection_usage(std::string &msg)
{
    msg.append(" \n\nUsage: ipsecd/connection create PARAM [VALUES]\n\n"
        "Where valid PARAM VALUES are: \n"
        "    name [name]\n"
        "    ip [local remote]\n"
        "    id [local remote]\n"
        "    mode [transport, tunnel]\n"
        "    integrity [sha1,sha256,sha512,md5]\n"
        "    authby  [psk, pubkey]\n"
        "    ike [v1 v2 v1v2]\n"
        "    cert [cert_path_local cert_path_remote]\n"
        "    cipher [aes,aes256,3des]  [aes,aes256,3des] \n"
        "    authmode [esp, ah] \n"
        "    dgroup [none, 2, 14]\n\n"
        "ipsecd/connection delete [name_of_connection] \n\n");
}

static void ipsec_ucc_debug_usage(std::string &msg)
{
    msg.append("Usage: ipsecd/debug [VALUES] \n\n"
        "Where valid VALUES are: \n"
        "enable  : enable debugger Mode\n"
        "disable : disable debugger Mode\n\n");
}


static void ipsec_ucc_debug_print_conn__(const ipsec_ike_connection conn,
        std::string &msg)
{
    std::string temp = "";
    msg.append(" ***** From command line ***** \n\n");
    msg.append("Name         : " + conn.m_name + "\n");
    msg.append("ip local     : " + conn.m_local_ip + "\n");
    msg.append("ip remote    : " + conn.m_remote_ip + "\n");

    temp.assign(ipsecd_helper::ike_version_to_str(conn.m_ike_version));
    msg.append("IKE version  : " + temp + "\n");

    temp.assign(ipsecd_helper::cipher_to_str(conn.m_cipher));
    msg.append("Cipher conn  : " + temp + "\n");
    temp.assign(ipsecd_helper::cipher_to_str(conn.m_child_sa.m_cipher));
    msg.append("Cipher child : " + temp + "\n");

    temp.assign(ipsecd_helper::integrity_to_str(conn.m_integrity));
    msg.append("Integrity    : " + temp + "\n");

    temp.assign(ipsecd_helper::group_to_str(conn.m_diffie_group));
    msg.append("diff group   : " + temp + "\n");

    msg.append("local id     : " + conn.m_local_peer.m_id + "\n");
    msg.append("remote id    : " + conn.m_remote_peer.m_id + "\n");

    temp.assign(ipsecd_helper::authby_to_str(conn.m_local_peer.m_auth_by));
    msg.append("local authby : " + temp + "\n");
    temp.assign(ipsecd_helper::authby_to_str(conn.m_remote_peer.m_auth_by));
    msg.append("remot authby : " + temp + "\n");

    msg.append("local cert   : " + conn.m_local_peer.m_cert + "\n");
    msg.append("remote cert  : " + conn.m_remote_peer.m_cert + "\n");
}

ipsec_ret ipsecd_ucc_create_connection(int argc, const char **argv,
        std::string &message)
{
    enum param_index: uint32_t
    {
        NAME = 0,
        ID,
        IP,
        MODE,
        INTEGRITY,
        AUTHBY,
        IKE,
        CERT,
        DGROUP,
        CIPHER,
        AUTHMODE,
        START,
        STOP,
        DELETE,
        STATS,
        CREATE
    };
    /**
    * Key words for ovs-appctl "ipsecd/connect" command
    */
    const std::string conn_params[] = {
        "name",
        "id",
        "ip",
        "mode",
        "integrity",
        "authby",
        "ike",
        "cert",
        "dgroup",
        "cipher",
        "authmode",
        "start",
        "stop",
        "delete",
        "stats",
        "create"
    };

    /*Number of keywords allowed for this command*/
    const int k_allowed     = 16;

    /*Min number of arguments allowed for this command*/
    const int argc_allowed = 2;

    /*Min number of arguments required to create a new connection*/
    const int argc_min_conn = 21;

    /*Index for key word in conn_params*/
    int in_index            = -1;

    /*Current argument index in argv to parse*/
    int c_index             = 1;

    bool found              = false;
    std::string in_word     = "";
    std::string next_str    = "";

    /*Local variable to append to message*/
    ipsec_ret result = ipsec_ret::ERR;

    /*New connection*/
    ipsec_ike_connection conn;

    /*Debug object*/
    DebugMode *debugger = DebugMode::getInst();

    if (argc<argc_allowed)
    {
        goto input_error;
    }

    while(c_index<argc)
    {
        /*Current word to parse*/
        in_word.assign(argv[c_index]);

        found = ipsecd_ucc_getIndex(conn_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (c_index +2))
        {
            switch(in_index)
            {
                case NAME:
                    /*Assign value to name*/
                    conn.m_name = argv[c_index+1];
                    c_index = c_index + 2;
                    break;
                case IP:
                    /*Assign value to IP fields*/
                    conn.m_local_ip  = argv[c_index+1];
                    conn.m_remote_ip = argv[c_index+2];
                    c_index = c_index + 3;
                    break;
                case MODE:
                    /*Assign value to mode*/
                    next_str.assign(argv[c_index + 1]);
                    if(!(ipsec_ucc_set_mode(next_str, conn)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case INTEGRITY:
                    /*Assign value to integrity*/
                    next_str.assign(argv[c_index + 1]);
                    if(!(ipsec_ucc_set_integrity(next_str, conn)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case AUTHBY:
                    /*values for key word authby: psk, pub*/
                    next_str.assign(argv[c_index + 1]);
                    if (next_str.compare("psk")==0)
                    {
                        conn.m_local_peer.m_auth_by  = ipsec_authby::psk;
                        conn.m_remote_peer.m_auth_by = ipsec_authby::psk;
                    }
                    else if(next_str.compare("pubkey")==0)
                    {
                        conn.m_local_peer.m_auth_by = ipsec_authby::pubkey;
                        conn.m_remote_peer.m_auth_by = ipsec_authby::pubkey;
                    }
                    c_index = c_index + 2;
                    break;
                case IKE:
                    /*Assign value to IKE version*/
                    next_str.assign(argv[c_index + 1]);
                    if(!(ipsec_ucc_set_ike(next_str, conn)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case CERT:
                    /*cert {local [remote]}*/
                    /*Check if there is another cert for remote peer*/
                    if (argc >= (c_index + 3))
                    {
                        next_str.assign(argv[c_index+2]);
                        found = ipsecd_ucc_getIndex(conn_params,
                            next_str, k_allowed, in_index);
                        /*next word is a key word, local = remote*/
                        if(found)
                        {
                            next_str.assign(argv[c_index+1]);
                            conn.m_local_peer.m_cert = next_str;
                            conn.m_remote_peer.m_cert = next_str;
                            c_index = c_index + 2;
                        }
                        /*next word could a value for cert for remote peer*/
                        else
                        {
                            next_str.assign(argv[c_index+1]);
                            conn.m_local_peer.m_cert = next_str;
                            next_str.assign(argv[c_index+2]);
                            conn.m_remote_peer.m_cert = next_str;
                            c_index = c_index + 3;
                        }
                    }
                    else
                    {
                        next_str.assign(argv[c_index+1]);
                        conn.m_local_peer.m_cert = next_str;
                        conn.m_remote_peer.m_cert = next_str;
                        c_index = c_index +2;
                    }
                    break;
                case CIPHER:
                    if (argc >= (c_index + 3))
                    {
                        next_str.assign(argv[c_index+2]);
                        found = ipsecd_ucc_getIndex(conn_params,
                            next_str, k_allowed, in_index);
                        /*next word is a key word, conn = child*/
                        if(found)
                        {
                            /*Assign value to cipher*/
                            next_str.assign(argv[c_index + 1]);
                            if(!(ipsec_ucc_set_cipher(next_str, true, conn)) &&
                                 !(ipsec_ucc_set_cipher(next_str,false,conn)))
                            {
                                goto input_error;
                            }
                            c_index = c_index + 2;
                        }
                        /*next word is cipher value for child peer*/
                        else
                        {
                            next_str.assign(argv[c_index+1]);
                            if(!(ipsec_ucc_set_cipher(next_str, false, conn)))
                            {
                                goto input_error;
                            }
                            next_str.assign(argv[c_index+2]);
                            if(!(ipsec_ucc_set_cipher(next_str, true, conn)))
                            {
                                goto input_error;
                            }
                            c_index = c_index + 3;
                        }
                    }
                    else
                    {
                        /*Assign value to cipher*/
                        next_str.assign(argv[c_index + 1]);
                        if(!(ipsec_ucc_set_cipher(next_str, true, conn)) &&
                             !(ipsec_ucc_set_cipher(next_str, false, conn)))
                        {
                            goto input_error;
                        }
                        c_index = c_index + 2;
                    }
                    break;
                case AUTHMODE:
                    /*Assign value to authmode*/
                    next_str.assign(argv[c_index + 1]);
                    if (!(ipsec_ucc_set_authmethod(next_str, conn)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case DGROUP:
                    /*Assign value to integrity*/
                    next_str.assign(argv[c_index + 1]);
                    if(!(ipsec_ucc_set_dgroup(next_str, conn)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case ID:
                    /*Assign value to ID fields*/
                    conn.m_local_peer.m_id  = argv[c_index+1];
                    conn.m_remote_peer.m_id = argv[c_index+2];
                    c_index = c_index + 3;
                    break;
                case START:
                    if (argc == 4)
                    {
                        next_str.assign(argv[c_index+1]);
                        in_word.assign(argv[c_index+2]);
                        result = debugger->start_connection(next_str,
                                std::stoi(in_word,nullptr,0));
                        if (result == ipsec_ret::OK)
                        {
                            message.append("\n\n Done \n\n");
                            return ipsec_ret::OK;
                        }
                        else
                        {
                            return result;
                        }
                    }
                    else
                    {
                        goto input_error;
                    }
                    break;
                case STOP:
                    /*TODO stop subcommand wip*/
                    break;
                case DELETE:
                    if (argc == 3)
                    {
                        next_str.assign(argv[c_index+1]);
                        result = debugger->delete_connection(next_str);
                        if (result  == ipsec_ret::OK)
                        {
                            message.append("\n\nConnection deleted \n\n");
                        }
                        return result;
                    }
                    else
                    {
                        goto input_error;
                    }
                    break;
                case STATS:
                    /*TODO stats subcommand wip*/
                    break;
                case CREATE:
                    c_index = c_index + 1;
                    break;
                default:
                    goto input_error;
            }
        }
        else
        {
            /*Wrong key word*/
            return ipsec_ret::ERR;
        }
    }

    in_word.assign("create");
    if(in_word.compare(argv[1])==0 && argc>=argc_min_conn)
    {
        /*Debug purpose*/
        if (debugger->isEnable())
        {
            ipsec_ucc_debug_print_conn__(conn, message);
        }
        result = debugger->create_connection(conn);
        if (result == ipsec_ret::OK)
        {
            message.append("\n\nConnection created\n\n");
        }
        return result;
    }

    input_error:
        return ipsec_ret::ERR;
}

ipsec_ret ipsecd_ucc_help(int argc, const char **argv, std::string &message)
{
    if (argc == 1)
    {
        ipsec_ucc_connection_usage(message);
        ipsec_ucc_debug_usage(message);
        return ipsec_ret::OK;
    }
    else
    {
        return ipsec_ret::ERR;
    }
}

ipsec_ret ipsecd_ucc_debug (int argc, const char **argv, std::string &message)
{
    enum param_index: uint32_t
    {
        ENABLE = 0,
        DISABLE,
    };
    /**
    * Key words for ovs-appctl "ipsecd/debug" command
    */
    const std::string debug_params[] = {
        "enable",
        "disable"
    };

    /*Number of keywords allowed for this command*/
    const int k_allowed     = 2;

    /*Min number of arguments allowed for this command*/
    const int argc_allowed = 2;

    /*Index for key word in conn_params*/
    int in_index            = -1;

    bool found              = false;
    std::string in_word     = "";

    /*Get the DebugMode instance*/
    DebugMode *debug = DebugMode::getInst();

    if (argc < argc_allowed || argc > 2)
    {
        return ipsec_ret::ERR;
    }
    else
    {
        in_word.assign(argv[1]);

        found = ipsecd_ucc_getIndex(debug_params, in_word, k_allowed,
            in_index);

        if (found)
        {
            switch(in_index)
            {
                case ENABLE:
                    debug->set_Enable(true);
                    message.append("Debugger Mode enable \n\n");
                    break;
                case DISABLE:
                    debug->set_Enable(false);
                    message.append("Debugger Mode disable \n\n");
                    break;
                default:
                    return ipsec_ret::ERR;
            }
            return ipsec_ret::OK;
        }
    }
    return ipsec_ret::ERR;
}
