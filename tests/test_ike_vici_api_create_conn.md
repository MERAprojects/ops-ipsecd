# IPsec Test Case

##  test_ipsec_ikeviciapi_create_conn

### Objective
Verify that IKEViciApi is able to create a new IKE connection using strongSwan

### Requirements
The requirements for this test case are:
 - Linux switch 3.14.19 or higher
 - strongSwan 5.3.5 or higher
 - vici pluging for strongSwan
 - IKEViciApi

### Setup

#### Topology Diagram
```ditaa

            +-------+      +-------+
            |  sw1   <----->  sw2  |
            +-------+      +-------+
```
#### Test Setup

### Description
sw1 and sw2 must be running Linux Switch to execute this test, should be by default configured and in the bash-shell context. The ops-ipsecd daemon mustn't be configured to run at boot level.

### Test Result Criteria

#### Test Pass Criteria
+ A Successfully connection between sw1 and sw2 using IPsec and a PSK. This condition include:
  * Successfull ping between sw1 and sw2
  * No complaints about ipsec absence
  * 'ipsec statusall' command must show that the IpsecdTest connection has been created (using the 'ovs-appctl ipsecd/connection create' command)
  * 'ipsec statusall' command must show that the IpsecdTest connection has been successfully established

#### Test Fail Criteria
+ Fail to establish a secure connection between sw1 and sw2. This include
  * ping command shows 'connection unreachable'
  * ipsec command is not found
  * 'ipsec statusall' doesn't shows any reference to IpsecdTest connection
