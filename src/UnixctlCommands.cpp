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
#include <arpa/inet.h>

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

static bool ipsec_ucc_set_action(const std::string value,
        ipsec_action& m_element)
{
    bool result = false;
    const int elements = 2;

    /*Valid values for mode key word*/
    const std::string str_values[] =
    {
        "allow",
        "block"
    };

    const ipsec_action all_modes[] =
    {
        ipsec_action::allow,
        ipsec_action::block
    };
    for (int idx = 0; idx < elements ; idx++)
    {
        if (value.compare(str_values[idx]) == 0)
        {
            result = true;
            m_element = all_modes[idx];
            break;
        }
    }
    return result;
}

static bool ipsec_ucc_set_mode(const std::string value, ipsec_mode& m_element)
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
            //conn.m_child_sa.m_mode = all_modes[idx];
            m_element = all_modes[idx];
            break;
        }
    }
    return result;

}

const char* state_to_str(ipsec_state state)
{
    switch(state)
    {
        case ipsec_state::config_error:
            return "config error";
        case ipsec_state::config_ok:
            return "config ok";
        case ipsec_state::created:
            return "created";
        case ipsec_state::connecting:
            return "connecting";
        case ipsec_state::passive:
            return "passive";
        case ipsec_state::rekeying:
            return "rekeying";
        case ipsec_state::deleting:
            return "deleting";
        case ipsec_state::destroying:
            return "destroying";
        case ipsec_state::routed:
            return "routed";
        case ipsec_state::installing:
            return "installing";
        case ipsec_state::updating:
            return "updating";
        case ipsec_state::rekeyed:
            return "rekeyed";
        case ipsec_state::retrying:
            return "retrying";
        case ipsec_state::installed:
            return "installed";
        case ipsec_state::establish:
            return "establish";
        default:
            return "";
    }
}

static bool get_connection_stats(const std::string conn_name,
        std::string &msg)
{
    ipsec_ike_connection_stats stats;
    /*Debug object*/
    DebugMode *debugger = DebugMode::getInst();


    if(debugger->get_connection_stats(conn_name, stats) != ipsec_ret::OK)
    {
        return false;
    }

    msg.append("\n\n");
    msg.append("Name of the Connection              : " + \
        stats.m_conn_name + "\n");
    msg.append("Seconds since been establish        : " + \
        std::to_string(stats.m_establish_secs) + "\n");
    msg.append("Initiator SPI/Cookie                : " + \
        std::to_string(stats.m_initiator_spi) + "\n");
    msg.append("Responder SPI/Cookie                : " + \
        std::to_string(stats.m_responder_spi) + "\n");
    msg.append("Seconds till IKE connection re-keys : " + \
        std::to_string(stats.m_rekey_time) +"\n");
    msg.append("State of the IKE Connection         : ");
    msg.append(state_to_str(stats.m_conn_state));
    msg.append("\n");
    msg.append("Seconds before SA expires           : " + \
        std::to_string(stats.m_sa_lifetime) + "\n");
    msg.append("Seconds before SA re-keys           : " + \
        std::to_string(stats.m_sa_rekey) + "\n");
    msg.append("Number of input bytes processed     : " + \
        std::to_string(stats.m_bytes_in) + "\n");
    msg.append("Number of output bytes processed    : " + \
        std::to_string(stats.m_bytes_out) + "\n");
    msg.append("Number of input packets processed   : " + \
        std::to_string(stats.m_packets_in) + "\n");
    msg.append("Number of output packets processed  : " + \
        std::to_string(stats.m_packets_out) + "\n");
    msg.append("State of the SA                     : ");
    msg.append(state_to_str(stats.m_sa_state));
    msg.append("\n");
    msg.append("Inbound SA SPI                      : " + \
        std::to_string(stats.m_sa_spi_in) + "\n");
    msg.append("Outbound SA SPI                     : " + \
        std::to_string(stats.m_sa_spi_out) + "\n");

    return true;
}

static bool ipsec_ucc_str_to_ipv4(std::string ip_str, in_addr_t& ipv4_addr)
{
    struct sockaddr_in add;

        //put address number into add
    if (inet_pton(AF_INET, ip_str.c_str(), &(add.sin_addr)) == 1)
    {
        ipv4_addr = (in_addr_t)(add.sin_addr.s_addr);
        return true;
    }
    return false;
}

static bool ipsec_ucc_str_to_ipsec_direction(std::string str_dir,
        ipsec_direction& direction)
{
    bool result = false;
    const int elements = 3;

    /*Valid values for direction key word*/
    const std::string str_values[] =
    {
        "in",
        "out",
        "fwd"
     };
    const ipsec_direction all_dir_values[] =
    {
        ipsec_direction::inbound,
        ipsec_direction::outbound,
        ipsec_direction::forward
    };
    for (int idx = 0; idx < elements ; idx++)
    {
        if (str_dir.compare(str_values[idx]) == 0)
        {
            result = true;
            direction = all_dir_values[idx];
            break;
        }
    }
    return result;

}

ipsec_ret ipsec_ucc_get_sp_subcmd(int argc, const char **argv,
        int& c_index, ipsec_sp& sp, ipsec_sp_id& sp_id, DebugMode *debugger)
{
    ipsec_ret result = ipsec_ret::ERR;

    const std::string get_params[] =
    {
        "direction",
        "ip",
        "mask"
    };

    enum param_index: uint32_t
    {
        DIRECTION,
        IP,
        MASK
    };

    /*copy for current global index parameter*/
    int index = c_index + 1;

    /*Index for key word in get_params*/
    int in_index = -1;

    /*Min number of arguments allowed for get sp subcommand*/
    const int argc_allowed = 8;

    bool found = false;

    /*Number of keywords allowed for this command*/
    const int k_allowed = 3;

    /*String to save the next keyword*/
    std::string next_str = "";
    std::string in_word = "";

    if (argc<(argc_allowed + c_index))
    {
        /*Input Error*/
        return result;
    }
    while(index <= (c_index + argc_allowed))
    {
        /*Current word to parse*/
        in_word.assign(argv[index]);

        found = ipsecd_ucc_getIndex(get_params, in_word, k_allowed,
            in_index);
        if (found && argc >= (index +2))
        {
            switch(in_index)
            {
                case DIRECTION:
                    next_str.assign(argv[index + 1]);
                    if(!ipsec_ucc_str_to_ipsec_direction(next_str,
                                sp_id.m_dir))
                    {
                        return result;
                    }
                    index = index + 2;
                    break;
                case IP:
                     /*2 more args are required*/
                     if(argc >= (index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp_id.m_selector.m_src_addr.m_ipv4)))
                        {
                            return result;
                        }
                        next_str.assign(argv[index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp_id.m_selector.m_dst_addr.m_ipv4)))
                        {
                            return result;
                        }
                    }

                    else
                    {
                        return result;
                    }
                    index = index + 3;
                    break;
                case MASK:
                    /*2 more args are required*/
                    if(argc >= (index + 2))
                    {
                        next_str.assign(argv[index + 1]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            return result;
                        }
                        sp_id.m_selector.m_src_mask = std::stoi(
                                next_str, nullptr, 0);
                        next_str.assign(argv[index + 2]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            return result;
                        }
                        sp_id.m_selector.m_dst_mask = std::stoi(
                                next_str, nullptr, 0);
                    }
                    else
                    {
                        return result;
                    }
                    index = index + 3;
                    break;
                default:
                    return result;
            }
        }
        else
        {
            return result;
        }
    }
    result = debugger->get_sp(sp_id, sp);
    return result;
}

ipsec_ret ipsec_ucc_delete_sa_subcmd(int argc, const char **argv,
        int& c_index, ipsec_sa_id& id, DebugMode *debugger)
{
    ipsec_ret result = ipsec_ret::ERR;

    const std::string delete_params[] =
    {
        "spi",
        "proto",
        "ip"
    };

    enum param_index: uint32_t
    {
        SPI,
        PROTO,
        IP
    };

    /*copy for current global index parameter*/
    int index = c_index + 1;

    /*Index for key word in delete_params*/
    int in_index = -1;

    /*Min number of arguments allowed for get sp subcommand*/
    const int argc_allowed = 7;

    bool found = false;

    /*Number of keywords allowed for this command*/
    const int k_allowed = 3;

    /*String to save the next keyword*/
    std::string next_str = "";
    std::string in_word = "";
    if (argc<(argc_allowed + c_index))
    {
        /*Input Error*/
        return result;
    }
    while(index <= (c_index + argc_allowed))
    {
        /*Current word to parse*/
        in_word.assign(argv[index]);

        found = ipsecd_ucc_getIndex(delete_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (index +2))
        {
            switch(in_index)
            {
                case SPI:
                    next_str.assign(argv[index + 1]);
                    id.m_spi= std::stoi(next_str, nullptr, 0);
                    index = index + 2;
                    break;
                case PROTO:
                    next_str.assign(argv[index + 1]);
                    if (std::stoi(next_str, nullptr, 0) > 255)
                    {
                        return result;
                    }
                    id.m_protocol= std::stoi(next_str, nullptr, 0);
                    index = index + 2;
                    break;
                case IP:
                     /*2 more args are required*/
                     if(argc >= (index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                        id.m_src_ip.m_ipv4)))
                        {
                            return result;
                        }
                        next_str.assign(argv[index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                        id.m_dst_ip.m_ipv4)))
                        {
                            return result;
                        }
                        /*TODO: remove default values*/
                        id.m_addr_family = AF_INET;
                    }

                    else
                    {
                        return result;
                    }
                    index = index + 3;
                    break;
                default:
                    return result;
            }
        }
        else
        {
            return result;
        }
    }
    result = debugger->del_sa(id);
    return result;
}

ipsec_ret ipsec_ucc_delete_sp_subcmd(int argc, const char **argv,
        int& c_index, ipsec_sp_id& sp_id, DebugMode *debugger)
{
    ipsec_ret result = ipsec_ret::ERR;

    const std::string delete_params[] =
    {
        "direction",
        "ip",
        "mask"
    };

    enum param_index: uint32_t
    {
        DIRECTION,
        IP,
        MASK
    };

    /*copy for current global index parameter*/
    int index = c_index + 1;

    /*Index for key word in delete_params*/
    int in_index = -1;

    /*Min number of arguments allowed for get sp subcommand*/
    const int argc_allowed = 8;

    bool found = false;

    /*Number of keywords allowed for this command*/
    const int k_allowed = 3;

    /*String to save the next keyword*/
    std::string next_str = "";
    std::string in_word = "";

    if (argc<(argc_allowed + c_index))
    {
        /*Input Error*/
        return result;
    }
    while(index <= (c_index + argc_allowed))
    {
        /*Current word to parse*/
        in_word.assign(argv[index]);

        found = ipsecd_ucc_getIndex(delete_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (index +2))
        {
            switch(in_index)
            {
                case DIRECTION:
                    next_str.assign(argv[index + 1]);
                    if(!ipsec_ucc_str_to_ipsec_direction(next_str,
                                sp_id.m_dir))
                    {
                        return result;
                    }
                    index = index + 2;
                    break;
                case IP:
                     /*2 more args are required*/
                     if(argc >= (index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp_id.m_selector.m_src_addr.m_ipv4)))
                        {
                            return result;
                        }
                        next_str.assign(argv[index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp_id.m_selector.m_dst_addr.m_ipv4)))
                        {
                            return result;
                        }
                    }

                    else
                    {
                        return result;
                    }
                    index = index + 3;
                    break;
                case MASK:
                    /*2 more args are required*/
                    if(argc >= (index + 2))
                    {
                        next_str.assign(argv[index + 1]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            return result;
                        }
                        sp_id.m_selector.m_src_mask = std::stoi(
                                next_str, nullptr, 0);
                        next_str.assign(argv[index + 2]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            return result;
                        }
                        sp_id.m_selector.m_dst_mask = std::stoi(
                                next_str, nullptr, 0);
                    }
                    else
                    {
                        return result;
                    }
                    index = index + 3;
                    break;
                default:
                    return result;
            }
        }
        else
        {
            return result;
        }
    }
    result = debugger->del_sp(sp_id);
    return result;
}

static void ipsec_ucc_show_sp(const ipsec_sp& sp, std::string& msg)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
    struct sockaddr_in add;
    /*set human readable IP number into str*/
    add.sin_addr.s_addr = sp.m_id.m_selector.m_src_addr.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_src, INET_ADDRSTRLEN);
    add.sin_addr.s_addr = sp.m_id.m_selector.m_dst_addr.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_dst, INET_ADDRSTRLEN);

    msg.append("\n\n");
    msg.append("Index           : " + std::to_string(sp.m_index) + "\n");
    msg.append("Priority        : " + std::to_string(sp.m_priority) + "\n");
    msg.append("IP selector src : ");
    msg.append(ip_src);
    msg.append("\n");
    msg.append("IP selector dst : ");
    msg.append(ip_dst);
    msg.append("\n");
    msg.append("Mask src        : " + std::to_string(
                (uint32_t)sp.m_id.m_selector.m_src_mask) + "\n");
    msg.append("Mask dst        : " + std::to_string(
                (uint32_t)sp.m_id.m_selector.m_dst_mask) + "\n");
    msg.append("\n\n");
}

static bool ipsec_ucc_template_sp_subcmd(int argc, const char **argv,
        int& c_index, ipsec_tmpl& tmpl)
{
    const std::string tmpl_params[] =
    {
        "ip",
        "proto",
        "mode",
        "id"
    };

    enum param_index: uint32_t
    {
        IP,
        PROTO,
        MODE,
        ID
    };

    /*copy for current global index parameter*/
    int index = c_index + 1;

    /*Index for key word in tmpl_params*/
    int in_index = -1;

    /*Min number of arguments allowed for tmpl subcommand*/
    const int argc_allowed = 9;

    bool found = false;

    /*Number of keywords allowed for this command*/
    const int k_allowed = 4;

    /*String to save the next keyword*/
    std::string next_str = "";
    std::string in_word = "";

    if (argc<(argc_allowed + c_index))
    {
        /*Input Error*/
        return false;
    }
    while(index <= (c_index + argc_allowed))
    {
        /*Current word to parse*/
        in_word.assign(argv[index]);

        found = ipsecd_ucc_getIndex(tmpl_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (index +2))
        {
            switch(in_index)
            {
                case IP:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    tmpl.m_src_ip.m_ipv4)))
                        {
                            return false;
                        }
                        next_str.assign(argv[index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    tmpl.m_dst_ip.m_ipv4)))
                        {
                            return false;
                        }
                    }

                    else
                    {
                        return false;
                    }
                    index = index + 3;
                    break;
                case PROTO:
                    next_str.assign(argv[index + 1]);
                    tmpl.m_protocol = std::stoi(next_str, nullptr, 0);
                    index = index + 2;
                    break;
                case MODE:
                    /*Assign value to mode*/
                    next_str.assign(argv[index + 1]);
                    if(!(ipsec_ucc_set_mode(next_str, tmpl.m_mode)))
                    {
                        return false;
                    }
                    index = index + 2;
                    break;
                case ID:
                    next_str.assign(argv[index + 1]);
                    tmpl.m_req_id = std::stoi(next_str, nullptr, 0);
                    index = index + 2;
                    break;
                default:
                    return false;
            }
        }
        else
        {
            return false;
        }
    }

    c_index = index;
    return true;
}

static void ipsec_ucc_show_sa(const ipsec_sa& sa, std::string& msg)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN],
         ip_src_sel[INET_ADDRSTRLEN], ip_dst_sel[INET_ADDRSTRLEN];
    struct sockaddr_in add;
    /*set human readable IP number into str*/
    add.sin_addr.s_addr = sa.m_id.m_src_ip.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_src, INET_ADDRSTRLEN);
    add.sin_addr.s_addr = sa.m_id.m_dst_ip.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_dst, INET_ADDRSTRLEN);

    add.sin_addr.s_addr = sa.m_selector.m_src_addr.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_src_sel, INET_ADDRSTRLEN);

    add.sin_addr.s_addr = sa.m_selector.m_dst_addr.m_ipv4;
    inet_ntop(AF_INET, &(add.sin_addr), ip_dst_sel, INET_ADDRSTRLEN);
    msg.append("\n\n");
    msg.append("SPI             : " + std::to_string(sa.m_id.m_spi) + "\n");
    msg.append("ID              : " + std::to_string(sa.m_req_id) + "\n");
    msg.append("Mode            : ");
    if (sa.m_mode==ipsec_mode::transport)
    {
        msg.append("Transport\n");
    }
    else
    {
        msg.append("Tunnel\n");
    }
    msg.append("Protocol        : " + std::to_string(
                sa.m_id.m_protocol) + "\n");
    msg.append("Flags           : " + std::to_string(sa.m_flags) + "\n");
    msg.append("IP src          : ");
    msg.append(ip_src);
    msg.append("\n");
    msg.append("IP dst          : ");
    msg.append(ip_dst);
    msg.append("\n");
    msg.append("IP selector src : ");
    msg.append(ip_src_sel);
    msg.append("\n");
    msg.append("IP selector dst : ");
    msg.append(ip_dst_sel);
    msg.append("\n");
    msg.append("Mask src        : " + std::to_string(
                (uint32_t)sa.m_selector.m_src_mask) + "\n");
    msg.append("Mask dst        : " + std::to_string(
                (uint32_t)sa.m_selector.m_dst_mask) + "\n");
    if (sa.m_auth_set)
    {
        msg.append("Auth            : yes\n");
    }
    if (sa.m_crypt_set)
    {
        msg.append("Crypt           : yes\n");
    }
    msg.append("\n\n");
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
        "ipsecd/connection delete [name_of_connection] \n\n"
        "ipsecd/connection start [name_of_connection] [timeout]\n\n"
        "ipsecd/connection stop [name_of_connection] [timeout] \n\n"
        "ipsecd/connection stats [name_of_connection] \n\n"
        "ipsecd/connection loadpsk [psk] \n\n");
}

static void ipsec_ucc_debug_usage(std::string &msg)
{
    msg.append("\n\nUsage: ipsecd/debug [VALUES] \n\n"
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
        CREATE,
        LOADPSK
    };
    /**
    * Key words for ovs-appctl "ipsecd/connection" command
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
        "create",
        "loadpsk"
    };

    /*Number of keywords allowed for this command*/
    const int k_allowed     = 17;

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

    /*Credentials*/
    ipsec_credential cred;

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
                    if(!(ipsec_ucc_set_mode(next_str, conn.m_child_sa.m_mode)))
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
                    if (argc == 4)
                    {
                        next_str.assign(argv[c_index+1]);
                        in_word.assign(argv[c_index+2]);
                        result = debugger->stop_connection(next_str,
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
                    if (argc == 3)
                    {
                        next_str.assign(argv[c_index+1]);
                        if(!get_connection_stats(next_str, message))
                        {
                            message.append("\n\nConnection not found\n\n");
                            return ipsec_ret::NOT_FOUND;
                        }
                        return ipsec_ret::OK;
                    }
                    else
                    {
                        goto input_error;
                    }
                    break;
                case CREATE:
                    c_index = c_index + 1;
                    break;
                case LOADPSK:
                    if (argc == 3)
                    {
                        cred.m_psk.assign(argv[c_index + 1]);
                        result = debugger->load_credential(cred);
                        if(result != ipsec_ret::OK)
                        {
                            message.append("\n\nUnable to set psk\n\n");
                            return ipsec_ret::NOT_FOUND;
                        }
                        message.append("\n\n Done\n\n");
                        return ipsec_ret::OK;
                    }
                    else
                    {
                        goto input_error;
                    }
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

    /*Index for key word in debug_params*/
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

ipsec_ret ipsecd_ucc_sa(int argc, const char **argv, std::string &message)
{
    enum param_index: uint32_t
    {
        ADD = 0,
        DELETE,
        GET,
        PROTOCOL,
        SPI,
        IP,
        MODE,
        ID,
        FLAGS,
        ADDR_RANGE,
        MASK,
        AUTH,
        CRYPT
    };
    /**
    * Key words for ovs-appctl "ipsecd/sa" command
    */
    const std::string sa_params[] = {
        "add",
        "delete",
        "get",
        "proto",
        "spi",
        "ip",
        "mode",
        "id",
        "flags",
        "addr_range",
        "mask",
        "auth",
        "crypt"
    };

    /*Number of keywords allowed for this command*/
    const int k_allowed     = 13;

    /*Min number of arguments allowed for this command*/
    const int argc_allowed = 2;

    /*Min number of arguments required to create a new sa*/
    const int argc_min_sa = 20;

    /*Index for key word in sa_params*/
    int in_index            = -1;

    /*Current argument index in argv to parse*/
    int c_index             = 1;

    bool found              = false;
    std::string in_word     = "";
    std::string next_str    = "";

    /*Local variable to append to message*/
    ipsec_ret result = ipsec_ret::ERR;

    /*Debug object*/
    DebugMode *debugger = DebugMode::getInst();

    /*Security Association object*/
    ipsec_sa sa;

    /*Security Association for delete subcommand*/
    ipsec_sa_id id;

    if (argc<argc_allowed)
    {
        goto input_error;
    }

    while(c_index<argc)
    {
        /*Current word to parse*/
        in_word.assign(argv[c_index]);

        found = ipsecd_ucc_getIndex(sa_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (c_index +2))
        {
            switch(in_index)
            {
                case ADD:
                    c_index = c_index + 1;
                    break;
                case DELETE:
                    result = ipsec_ucc_delete_sa_subcmd(
                            argc, argv, c_index, id, debugger);

                    if(result != ipsec_ret::OK)
                    {
                        return result;
                    }
                    message.append("\n\nSA successfully deleted\n\n");
                    return result;
                    break;
                case GET:
                    if(argc == 3)
                    {
                        next_str.assign(argv[c_index + 1]);
                        result = debugger->get_sa(
                                std::stoi(next_str, nullptr, 0), sa);
                        if(result != ipsec_ret::OK)
                        {
                            return result;
                        }
                        ipsec_ucc_show_sa(sa, message);
                        return result;
                    }
                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 1;
                    break;
                case PROTOCOL:
                    next_str.assign(argv[c_index + 1]);
                    sa.m_id.m_protocol = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                    break;
                case SPI:
                    next_str.assign(argv[c_index + 1]);
                    sa.m_id.m_spi = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                    break;
                case IP:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[c_index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sa.m_id.m_src_ip.m_ipv4)))
                        {
                            goto input_error;
                        }
                        next_str.assign(argv[c_index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sa.m_id.m_dst_ip.m_ipv4)))
                        {
                            goto input_error;
                        }
                    }

                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case MODE:
                    /*Assign value to mode*/
                    next_str.assign(argv[c_index + 1]);
                    if(!(ipsec_ucc_set_mode(next_str, sa.m_mode)))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case ID:
                    next_str.assign(argv[c_index + 1]);
                    sa.m_req_id = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                 break;
                case FLAGS:
                    next_str.assign(argv[c_index + 1]);
                    sa.m_flags = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                    break;
                case ADDR_RANGE:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[c_index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sa.m_selector.m_src_addr.m_ipv4)))
                        {
                            goto input_error;
                        }
                        next_str.assign(argv[c_index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sa.m_selector.m_dst_addr.m_ipv4)))
                        {
                            goto input_error;
                        }
                    }

                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case MASK:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        next_str.assign(argv[c_index + 1]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            goto input_error;
                        }
                        sa.m_selector.m_src_mask = std::stoi(
                                next_str, nullptr, 0);
                        next_str.assign(argv[c_index + 2]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            goto input_error;
                        }
                        sa.m_selector.m_dst_mask = std::stoi(
                                next_str, nullptr, 0);
                    }
                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case AUTH:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        sa.m_auth_set = true;
                        sa.m_auth.m_key.assign(argv[c_index + 2]);
                        sa.m_auth.m_name.assign(argv[c_index + 1]);

                    }
                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case CRYPT:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        sa.m_crypt_set = true;
                        sa.m_crypt.m_key.assign(argv[c_index + 2]);
                        sa.m_crypt.m_name.assign(argv[c_index + 1]);

                    }
                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
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

    in_word.assign("add");
    if(in_word.compare(argv[1])==0 && argc>=argc_min_sa)
    {
        /*TODO: remove default values*/
        sa.m_id.m_addr_family = AF_INET;
        /*Debug purpose*/
        if (debugger->isEnable())
        {
            ipsec_ucc_show_sa(sa, message);
        }
        result = debugger->add_sa(sa);
        if (result == ipsec_ret::OK)
        {
            message.append("\n\nSA successfully created\n\n");
        }
        return result;
    }

    input_error:
        return ipsec_ret::ERR;
}

ipsec_ret ipsecd_ucc_sp(int argc, const char **argv, std::string &message)
{
    enum param_index: uint32_t
    {
        ADD = 0,
        ACT,
        DIRECTION,
        INDEX,
        PRI,
        IP,
        MASK,
        TMPL,
        GET,
        DELETE
    };
    /**
    * Key words for ovs-appctl "ipsecd/sp" command
    */
    const std::string sp_params[] =
    {
        "add",
        "act",
        "direction",
        "index",
        "pri",
        "ip",
        "mask",
        "tmpl",
        "get",
        "delete"
    };

    /*Number of keywords allowed for this command*/
    const int k_allowed     = 10;

    /*Min number of arguments allowed for this command*/
    const int argc_allowed = 2;

    /*Min number of arguments required to add a new SP*/
    const int argc_min_sp = 25;

    /*Index for key word in sp_params*/
    int in_index            = -1;

    /*Current argument index in argv to parse*/
    int c_index             = 1;

    bool found              = false;
    std::string in_word     = "";
    std::string next_str    = "";

    /*Local variable to append to message*/
    ipsec_ret result = ipsec_ret::ERR;

    /*Debug object*/
    DebugMode *debugger = DebugMode::getInst();

    /*New sp object*/
    ipsec_sp sp;

    /*template object for tmpl subcommand*/
    ipsec_tmpl tmpl;

    /*ipsec_sp_id object to get a SP created before*/
    ipsec_sp_id sp_id;

    if (argc<argc_allowed)
    {
        goto input_error;
    }

    while(c_index<argc)
    {
        /*Current word to parse*/
        in_word.assign(argv[c_index]);

        found = ipsecd_ucc_getIndex(sp_params, in_word, k_allowed,
            in_index);

        if (found && argc >= (c_index +2))
        {
            switch(in_index)
            {
                case ADD:
                    c_index = c_index + 1;
                    break;
                case ACT:
                    next_str.assign(argv[c_index + 1]);
                    if(!ipsec_ucc_set_action(next_str, sp.m_action))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case DIRECTION:
                    next_str.assign(argv[c_index + 1]);
                    if(!ipsec_ucc_str_to_ipsec_direction(next_str,
                                sp.m_id.m_dir))
                    {
                        goto input_error;
                    }
                    c_index = c_index + 2;
                    break;
                case INDEX:
                    next_str.assign(argv[c_index + 1]);
                    sp.m_index = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                    break;
                case PRI:
                    next_str.assign(argv[c_index + 1]);
                    sp.m_priority = std::stoi(next_str, nullptr, 0);
                    c_index = c_index + 2;
                    break;
                case IP:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        /*For IPv4 only*/
                        next_str.assign(argv[c_index + 1]);

                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp.m_id.m_selector.m_src_addr.m_ipv4)))
                        {
                            goto input_error;
                        }
                        next_str.assign(argv[c_index + 2]);
                        if (!(ipsec_ucc_str_to_ipv4(next_str,
                                    sp.m_id.m_selector.m_dst_addr.m_ipv4)))
                        {
                            goto input_error;
                        }
                    }

                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case MASK:
                    /*2 more args are required*/
                    if(argc >= (c_index + 3))
                    {
                        next_str.assign(argv[c_index + 1]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            goto input_error;
                        }
                        sp.m_id.m_selector.m_src_mask = std::stoi(
                                next_str, nullptr, 0);
                        next_str.assign(argv[c_index + 2]);
                        if (std::stoi(next_str, nullptr, 0) > 255)
                        {
                            goto input_error;
                        }
                        sp.m_id.m_selector.m_dst_mask = std::stoi(
                                next_str, nullptr, 0);
                    }
                    else
                    {
                        goto input_error;
                    }
                    c_index = c_index + 3;
                    break;
                case TMPL:
                    if (!ipsec_ucc_template_sp_subcmd(
                                argc, argv, c_index, tmpl))
                    {
                        goto input_error;
                    }
                    /*TODO: remove default values*/
                    tmpl.m_addr_family = AF_INET;
                    sp.m_template_lists.push_back(tmpl);
                    break;

                case GET:
                    result = ipsec_ucc_get_sp_subcmd(argc, argv, c_index,
                                sp, sp_id, debugger);
                    if(result != ipsec_ret::OK)
                    {
                        return result;
                    }
                    ipsec_ucc_show_sp(sp, message);
                    return result;
                    break;
                case DELETE:
                    result = ipsec_ucc_delete_sp_subcmd(argc, argv, c_index,
                            sp_id, debugger);
                    if(result !=ipsec_ret::OK)
                    {
                        return result;
                    }
                    message.append("\n\nSP successfully deleted\n\n");
                    return result;
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

    in_word.assign("add");
    if(in_word.compare(argv[1])==0 && argc>=argc_min_sp)
    {
        /*Debug purpose*/
        if (debugger->isEnable())
        {
            ipsec_ucc_show_sp(sp, message);
        }
        //TODO: remove default values
        sp.m_id.m_selector.m_addr_family = AF_INET;
        result = debugger->add_sp(sp);
        if (result == ipsec_ret::OK)
        {
            message.append("\n\nSP successfully created\n\n");
        }
        return result;
    }

    input_error:
        return ipsec_ret::ERR;
}
