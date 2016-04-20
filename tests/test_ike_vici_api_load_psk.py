# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from time import sleep

"""
OpenSwitch Test for ops-ipsecd IKEViciAPI
"""


TOPOLOGY = """
#
# +-------+      +-------+
# |  sw1   <----->  sw2  |
# +-------+      +-------+


# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2

# Links
sw1:right -- sw2:left
"""

# Global variables

# unixctl server
ucc_server = "/opt/ops-ipsecd.ctl"

# Alias for the main command to test with ucc_server as target
conn_cmd = 'ovs-appctl -t {0} ipsecd/connection'.format(ucc_server)

# Connection name
conn_name = "IpsecdTest"

# IP for sw1
ip_sw1 = "10.0.10.1"

# IP for sw2
ip_sw2 = "10.0.10.2"

# timeout
timeout_m = 50000


def get_sw_from_topology(topology):
    """
    Get sw1 and sw2
    """
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

    return sw1, sw2


def setup_sw1_sw2(sw1, sw2):
    """
    Method to bring up network interfaces
    """
    p_right = sw1.ports['right']
    p_left = sw2.ports['left']

    # Mark interfaces as enabled
    assert not sw1(
        'set interface {p_right} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not sw2(
        'set interface {p_left} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    # Configure IP and bring UP switch 1 interface
    with sw1.libs.vtysh.ConfigInterface('right') as ctx:
        ctx.ip_address(ip_sw1+"/24")
        ctx.no_shutdown()

    # Configure IP and bring UP switch 2 interface
    with sw2.libs.vtysh.ConfigInterface('left') as ctx:
        ctx.ip_address(ip_sw2+"/24")
        ctx.no_shutdown()

    show_sw1 = sw2('show interface {p_left}'.format(**locals()))
    show_sw2 = sw1('show interface {p_right}'.format(**locals()))

    return sw1, sw2


def restart_ipsec(sw1, sw2):
    """
    Method to restart Charon keying daemon
    """

    message = sw1('ipsec stop', shell='bash_swns')
    assert 'Stopping strongSwan IPsec...' in message

    message = sw1('ipsec start', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message

    message = sw2('ipsec stop', shell='bash_swns')
    assert 'Stopping strongSwan IPsec...' in message

    message = sw2('ipsec start', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message


def create_connection_using_strongswan(sw1, sw2, psk):
    """
    Create a new connection using strongSwan deamon
    """
    # empty PSK means that connection load command have been used
    if (psk != ""):
        # Add PSK to /etc/ipsec.secrets for SW1
        secrets = 'sudo echo \": PSK \"{0}\"\" > ' \
            '/etc/ipsec.secrets'.format(psk)
        sw1(secrets, shell='bash_swns')
        secrets_file = sw1('cat /etc/ipsec.secrets', shell='bash_swns')
        assert ': PSK' in secrets_file

        # Add PSK to /etc/ipsec.secrets for SW2
        sw2(secrets, shell='bash_swns')
        secrets_file = sw2('cat /etc/ipsec.secrets', shell='bash_swns')
        assert ': PSK' in secrets_file

    # Setup tunnel configuration on /etc/ipsec.conf for SW1 and SW2
    config = "\n" \
        "config setup\n" \
        "   charondebug=\"all\"\n" \
        "   uniqueids=yes\n" \
        "   strictcrlpolicy=no\n" \
        "\n" \
        "conn {0}\n" \
        "    authby=psk\n" \
        "    left={1}\n" \
        "    right={2}\n" \
        "    auto=start\n".format(conn_name, ip_sw1, ip_sw2)

    sw1('sudo echo -e \"{0}\" > /etc/ipsec.conf'.format(config),
        shell='bash_swns')
    config_file = sw1('cat /etc/ipsec.conf', shell='bash_swns')
    assert 'conn {0}'.format(conn_name) in config_file

    sw2('sudo echo -e \"{0}\" > /etc/ipsec.conf'.format(config),
        shell='bash_swns')
    config_file = sw2('cat /etc/ipsec.conf', shell='bash_swns')
    assert 'conn {0}'.format(conn_name) in config_file

    return sw1, sw2


def test_ipsec_ikeviciapi_load_psk(topology):
    """
    Load a PSK into memory  using the IKEViciApi
    """
    sw1, sw2 = get_sw_from_topology(topology)

    sw1, sw2 = setup_sw1_sw2(sw1, sw2)
    # ping to sw2
    ping = sw1('ping -c 5 {0}'.format(ip_sw2), shell='bash_swns')
    assert '0% packet loss' in ping

    restart_ipsec(sw1, sw2)

    # Create a PSK wich is 64 chars long using openssl
    psk = sw1('openssl rand -base64 48', shell='bash_swns')
    assert len(psk) == 64

    create_connection_using_strongswan(sw1, sw2, "")

    # restart Ipsec service
    message = sw2('ipsec restart', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message

    # restart Ipsec service
    message = sw1('ipsec restart', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message

    # restart Ipsec service
    message = sw2('ipsec restart', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message

    # restart Ipsec service
    message = sw1('ipsec restart', shell='bash_swns')
    assert '[starter]' in message
    assert 'no netkey IPsec stack detected' in message

    # Start up ops-ipsecd daemon
    sw1('ops-ipsecd --pidfile=/opt/ops-ipsecd.pid --unixctl={0} &'.format(
        ucc_server), shell='bash_swns')

    # Start up ops-ipsecd daemon
    sw2('ops-ipsecd --pidfile=/opt/ops-ipsecd.pid --unixctl={0} &'.format(
        ucc_server), shell='bash_swns')

    temp_cmd = '{0} loadpsk {1}'.format(conn_cmd, psk)
    # load a psk into memory using the IKEViciApi
    load = sw1(temp_cmd, shell='bash_swns')
    assert 'Done' in load

    load = sw2(temp_cmd, shell='bash_swns')
    assert 'Done' in load

    # Start ipsec conn
    service = sw1('ipsec up {0}'.format(conn_name), shell='bash_swns')

    # Wait 5 seconds for connection
    sleep(5)

    assert 'established successfully' in service

    status = sw1('ipsec statusall', shell='bash_swns')
    assert '10.0.10.1/32 === 10.0.10.2/32' in status
    assert 'Security Associations (1 up, 0 connecting)' in status
    assert conn_name in status
