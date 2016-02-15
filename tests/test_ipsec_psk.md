# IPsec Test Case

##  test_ipsec_psk

### Objective
Verify that ipsec strongSwan is included on Linux switch and is working properly

### Requirements
The requirements for this test case are:
 - Linux switch 3.14.19 or higher
 - strongSwan 5.3.5 or higher

### Setup

#### Topology Diagram
```ditaa

            +-------+      +-------+
            |  sw1   <----->  sw2  |
            +-------+      +-------+
```
#### Test Setup

### Description
sw1 and sw2 must be running Linux Switch to execute this test, should be by default configured and in the bash-shell context.

### Test Result Criteria

#### Test Pass Criteria
+ A Successfully connection between sw1 and sw2 using IPsec and a PSK. This condition include:
  * Successfull ping between sw1 and sw2
  * No complaints about ipsec absence
  * 'ipsec statusall' command must show that the ipsec_tunnel connection is up
  * ESP protocol it's been used to send packets

#### Test Fail Criteria
+ Fail to stablish a secure connection between sw1 and sw2. This include
  * ping command shows 'connection unreachable'
  * ipsec command is not found
  * 'ipsec statusall' doesn't shows any reference to ipsec_tunnel connection
  * ESP protocol it's not been used
