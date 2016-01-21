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
Table: IPSEC
    ipsecd reads the following columns:
        stats_refresh_seconds
    ipsecd updates the following columns:
        stats_publish_all
    ipsecd access the following tables:
        ipsec_ike_connections
        ipsec_manual_sps
        ipsec_manual_sas
Table: Ipsec_Ike_Connection
   ipsecd reads the following columns:
      policy_name
      policy_enable: true | false
      ip_family: IPv4 | IPv6
      ipsec_protocol: AH | ESP
      ipsec_mode: tunnel | transport
      integrity: sha1-hmac | sha256-hmac | sha512-hmac   #integ src and content
      encryption: aes128 | aes256
      ike_version: IKEv1/v2 | IKEv1 | IKEv2
      ike_integrity: sha1-hmac | sha256-hmac | sha512-hma
      ike_encryption: aes128 | aes256
      ike_group: diffie2 | diffie14
      ike_local_addr: localIP | hostname     #local addr of GRE tunnel
      ike_remote_addr: remoteIP | hostname   #remote addr of GRE tunnel
      peer_auth_by: psk | cert
      local_cert_id
      local_id
      remote_id
   ipsecd write the following columns:
      ipsec_ike_conn_statuses

IKE statuses: key ID's are documented in xml:
      policy_name
      request_id (index)
      ike_status
      ike_spi_inbound
      ike_spi_outbound
      ike_proposals
      ike_reauth_eta
      sa_status
      sa_mode
      sa_spi_inbound
      sa_spi_outbound
      sa_proposal
      sa_rekey_eta

Table: ipsec_manual_sp
   ipsecd reads the following columns:
      priority
      direction
      addr_family: IPv4 | IPv6
      src_addr (index with src/dest_addr, src/dest mask and direction)
      src_addr_mask
      dest_addr
      dest_addr_mask
      tmpl_request_id
      tmpl_protocol
      tmpl_mode
      tmpl_addr_family
      tmpl_src_addr
      tmpl_dest_addr
   ipsecd write the following columns:
      ipsec_manual_sp_statuses

Manual SP statuses: key ID's are documented in xml:
      src_ip
      src_ip_mask
      dest_ip
      dest_ip_mask
      direction
      action
      priority
      tmpl_protocol
      tmpl_addr_family
      tmpl_src_ip
      tmpl_dest_ip
      tmpl_sp_id
      tmpl_mode
      sp_data_bytes
      sp_data_packets
      sp_conn_added
      sp_conn_used

Table: ipsec_manual_sa
   ipsecd reads the following columns:
      spi (index)
      addr_family: IPv4 | IPv6
      src_addr
      dest_addr
      request_id
      protocol
      mode
      auth_type
      auth_key_id
      encr_type
      encr_key_id
      priority
      selector_addr_family
      selector_src_addr
      selector_src_addr_mask
      selector_dest_addr
      selector_dest_addr_mask
   ipsecd write the following columns:
      ipsec_manual_sa_statuses

Manual SA statuses: key ID's are documented in xml:
      src_ip
      dest_ip
      spi
      protocol
      mode
      selector_addr_family
      selector_src_addr
      selector_src_addr_mask
      selector_dest_addr
      selector_dest_addr_mask
      sa_data_bytes
      sa_data_packets
      sa_conn_added
      sa_conn_used
