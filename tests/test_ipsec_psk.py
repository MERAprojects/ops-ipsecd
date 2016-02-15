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

"""
OpenSwitch Test for ipsec/strongSwan using PSK and site-to-site case
"""

from pytest import mark
from time import sleep

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


@mark.test_id(10600)
@mark.timeout(300)
def test_ipsec_psk(topology):
    """
    Set network address between nodes and ping sw2 to sw1
    """
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

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
        ctx.ip_address('10.0.10.1/24')
        ctx.no_shutdown()

    # Configure IP and bring UP switch 2 interface
    with sw2.libs.vtysh.ConfigInterface('left') as ctx:
        ctx.ip_address('10.0.10.2/24')
        ctx.no_shutdown()
    show_sw1 = sw2('show interface {p_left}'.format(**locals()))
    show_sw2 = sw1('show interface {p_right}'.format(**locals()))

    # ping to sw2
    ping = sw1('ping -c 5 10.0.10.2', shell='bash_swns')
    assert '0% packet loss' in ping

    # Create a PSK wich is 64 chars long using openssl
    psk = sw1('openssl rand -base64 48', shell='bash')
    assert len(psk) == 64

    # Add PSK to /etc/ipsec.secrets for SW1
    secrets = 'sudo echo \": PSK \"{psk}\"\" > ' \
        '/etc/ipsec.secrets'.format(**locals())
    sw1(secrets, shell='bash')
    secrets_file = sw1('cat /etc/ipsec.secrets', shell='bash')
    assert ': PSK' in secrets_file

    # Add PSK to /etc/ipsec.secrets for SW2
    sw2(secrets, shell='bash')
    secrets_file = sw2('cat /etc/ipsec.secrets', shell='bash')
    assert ': PSK' in secrets_file

    # Setup tunnel configuration on /etc/ipsec.conf for SW1 and SW2
    config = "\n" \
        "config setup\n" \
        "   charondebug=\"all\"\n" \
        "   uniqueids=yes\n" \
        "   strictcrlpolicy=no\n" \
        "\n" \
        "conn ipsec_tunnel\n" \
        "    authby=psk\n" \
        "    left=10.0.10.1\n" \
        "    right=10.0.10.2\n" \
        "    auto=start\n" \

    sw1('sudo echo -e \"{config}\" > /etc/ipsec.conf'.format(**locals()),
        shell='bash')
    config_file = sw1('cat /etc/ipsec.conf', shell='bash')
    assert 'conn ipsec_tunnel' in config_file

    sw2('sudo echo -e \"{config}\" > /etc/ipsec.conf'.format(**locals()),
        shell='bash')
    config_file = sw2('cat /etc/ipsec.conf', shell='bash')
    assert 'conn ipsec_tunnel' in config_file

    # Start ipsec service
    restart_cmd = sw1('ipsec restart', shell="bash_swns")
    assert 'IPsec [starter]' in restart_cmd
    restart_cmd = sw2('ipsec restart', shell="bash_swns")
    assert 'IPsec [starter]' in restart_cmd

    # Start ipsec conn
    service = sw1('ipsec up ipsec_tunnel', shell='bash_swns')

    # Wait 5 seconds for connection
    sleep(5)

    assert 'established successfully' in service

    status = sw1('ipsec statusall', shell='bash_swns')
    assert '10.0.10.1/32 === 10.0.10.2/32' in status

    # Listening interface p_left and save the output in a local file
    tcpdump = 'tcpdump -i any -c 5 > /tmp/data &'
    tcpdump_cmd = sw2(tcpdump, shell='bash_swns')

    # Send a packet to SW2 and checks if ESP protocol it's been used
    ping = sw1('ping -c 5 10.0.10.2', shell='bash_swns')
    sw2('killall tcpdump', shell='bash_swns')
    data_output = sw2('cat /tmp/data', shell='bash_swns')
    assert 'ESP(spi=' in data_output
