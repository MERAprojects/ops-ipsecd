# High-level design of ops-ipsecd
The ops-ipsecd daemon is responsible for monitoring user IPSEC configuration
requests, determining the operational state of the IPSEC (i.e., enabled,
disabled), and setting corresponding database fields to inform the kernel
and other daemons of the desired state.

## Reponsibilities
The ops-ipsecd daemon:
* Monitors the OVSDB IPSEC config tables for entries that are being added,
removed, or changed
* Updates strongSWAN and IPSEC kernel_any IPSEC config changes
* Helper functions to record any IPSEC stats

##  Design choices
ops-ipsecd could have been incorporated into other daemons, but it was considered
best to keep the ipsecd configuration separate so enhancements would be
straightforward.

## Relationships to external OpenSwitch entities
ops-ipsec operates on the Open vSwitch database, strongSWAN daemon and
IPsec Kernel Module. Other processes report the user intent (e.g., REST, CLI)
and record that into the database. ops-ipsec processes this information and
determines if the IPSEC should be enabled or disabled. It then likewise
updates the database. Other daemons, such as switchd, monitor the fields
that ops-ipsec writes and takes appropriate action.

```
+----------------------------------------------------------------------------------------------------------------------------------------------+
| OPS OS                                                                                                                                       |
|                                                                                                                                              |
|                                                                                                                                              |
|                                                                                                                                              |
|                        +-------------+              +----------+                               +---------+                                   |
|                        |             |              |          |                               |         |                                   |
|            +-----------+ strongSWAN  |              |  Kernel  |                               |  OVSDB  |                                   |
|            |           |             |              |          |                               |         |                                   |
|            |           +------^------+              +----^-----+                               +----^----+                                   |
|            |                  |                          |                                          |                                        |
|            |*Listens for      |*Sets IKE Credentials     |*Sets SAs & SPs                           |*Reads Initial Config                   |
|            | IKE Errors       |*Sets IKE Connections     |*Get stats for SAs & SPs                  |*Monitor IPsec Schema Changes           |
|            |                  |*Enables IKE Connections  |                                          |*Sets connection status                 |
|            |                  |*Get statistics           |                                          |*Publish stats for connections          |
|            |                  |                          |                                          |                                        |
+----------------------------------------------------------------------------------------------------------------------------------------------+
|            |                  |                          |                                          |                                        |
|  +---------v--------+   +-----v----+              +------v------+                             +-----v------+                                 |
|  |                  |   |          |              |             |                             |            <--------------------------+      |
|  | Error Notify Lib |   | VICI Lib <-------+------> Netlink Lib <------+                      | OVSDB Comm |                          |      |
|  |                  |   |          |       |      |             |      |                      |   Layer    |                          |      |
|  +--------+---------+   +----^-----+       |      +-------------+      |                      |            <-------------------+      |      |
|           |                  |             |                           |                      +-----+------+                   |      |      |
|           |*Reports          |             |*Configures Connections    |                            |                          |      |      |
|           | Erros            |             | (Automatic and Manual)    |                            |*Communicate              |      |      |
|           |                  |             |                           |                            | config changes           |      |      |
|           |                  |     +---------------+                   |                            |                          |      |      |
|  +--------v--------+         |     |       |       |                   |                            |                          |      |      |
|  |                 |         |     | Configuration <------------------------+                       |                          |      |      |
|  | External Error  |         |     | Thread Queue  |                   |    |*Adds a config  +------v-------+                  |      |      |
|  | Handling Thread |         |     |               |                   |    |                |              |                  |      |      |
|  |                 |         |     +---------------+                   |    +----------------+ Orchestrator |                  |      |      |
|  +--------+--------+         |                                         |                     |              |                  |      |      |
|           |                  +-------------+---------------------------+                     +------+-------+                  |      |      |
|           |*Sets error to                  |                                                        |                          |      |      |
|           | connection and                 |*Get stats for Connections                              |*Enables publishing       |      |      |
|           | adds the log                   | (Automatic and Manual                                  | of statistics            |      |      |
|           |                                |                                                        |                          |      |      |
|           |                       +--------+--------+                                               |                          |      |      |
|           |                       |                 |                                               |                          |      |      |
|           |                       | Stats Publisher <-----------------------------------------------+                          |      |      |
|           |                       |     Thread      |                                                                          |      |      |
|           |                       |                 |                                                                          |      |      |
|           |                       +-----------------+                                                                          |      |      |
|           |                                |* Publish stats                                                                    |      |      |
|           |                                +-----------------------------------------------------------------------------------+      |      |
|           |                                                                                                                           |      |
|           |                                                                                                                           |      |
|           +---------------------------------------------------------------------------------------------------------------------------+      |
|                                                                                                                                              |
| IPsec Configurator                                                                                                                           |
+----------------------------------------------------------------------------------------------------------------------------------------------+
```

## OVSDB-Schema
ops-ipsecd reads/monitors the following OVSDB Tables/Columns:
Table: System
      ssl
      ipsec_ike_policies
      ipsec_manual_sps
      ipsec_manual_sas
      stats_refresh_seconds
      stats_publish_all
Table: IPsec_IKE_Policy
      name
      protocol: AH | ESP
      mode: tunnel | transport
      integrity: SHA1HMAC | SHA256HMAC | SHA512HMAC
      encryption: AES128 | AES256
      ike_integrity: SHA1HMAC | SHA256HMAC | SHA512HMAC
      ike_encryption: AES128 | AES256
      ike_group: DIFFIE2 | DIFFIE14
      peer_auth_by: PSK | cert
      psk
      psk_selectors
      keep_alive_seconds
Table: Interface
   ipsec_ike_policy: as a reference to IPsec_IKE_Policy
   status: ops-ipsecd updates the interface status of the type
      string-string kv-map as documented on the xml file.
      ipsec_ike_established_time
      ipsec_ike_initiator_spi
      ipsec_ike_responder_spi
      ipsec_ike_reauth_time
      ipsec_ike_conn_state
      ipsec_sa_rekey_time
      ipsec_sa_expiration_time
      ipsec_bytes_in
      ipsec_bytes_out
      ipsec_packets_in
      ipsec_packets_out
Table: IPsec_Manual_SP
      priority
      direction: fwd | in | out
      action: none | discard | ipsec
      ip_family: ipv4 | ipv6
      src_prefix (prefix is IP address with a /XXX netmask)
      dest_prefix
      tmpl_request_id
      tmpl_protocol: AH | ESP
      tmpl_mode: tunnel | transport
      tmpl_ip_family: ipv4 | ipv6
      tmpl_src_ip
      tmpl_dest_ip
   ops-ipsecd writes to the following columns:
      status: string-string kv-map as documented on the xml file.
         sp_conn_added
         sp_conn_used
      statistics: string-string kv map as documented on the xml file.
         sp_bytes
         sp_packets
Table: IPsec_Manual_SA
      SPI (index)
      request_id
      addr_family: IPv4 | IPv6
      src_ip
      dest_ip
      protocol: AH | ESP
      mode: tunnel | transport
      authentication: SHA1HMAC | SHA256HMAC | SHA512HMAC
      auth_key
      encryption: AES128 | AES256
      encr_key
      selector_src_prefix (prefix is IP address with a /XXX netmask)
      selector_dest_prefix
   ops-ipsecd writes to the following columns:
      status: string-string kv-map as documented on the xml file.
          sa_conn_added
          sa_conn_used
       statistics: string-string kv map as documented on the xml file.
          sa_bytes
          sa_packets
