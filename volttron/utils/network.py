# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
# Copyright 2020, Battelle Memorial Institute.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This material was prepared as an account of work sponsored by an agency of
# the United States Government. Neither the United States Government nor the
# United States Department of Energy, nor Battelle, nor any of their
# employees, nor any jurisdiction or organization that has cooperated in the
# development of these materials, makes any warranty, express or
# implied, or assumes any legal liability or responsibility for the accuracy,
# completeness, or usefulness or any information, apparatus, product,
# software, or process disclosed, or represents that its use would not infringe
# privately owned rights. Reference herein to any specific commercial product,
# process, or service by trade name, trademark, manufacturer, or otherwise
# does not necessarily constitute or imply its endorsement, recommendation, or
# favoring by the United States Government or any agency thereof, or
# Battelle Memorial Institute. The views and opinions of authors expressed
# herein do not necessarily state or reflect those of the
# United States Government or any agency thereof.
#
# PACIFIC NORTHWEST NATIONAL LABORATORY operated by
# BATTELLE for the UNITED STATES DEPARTMENT OF ENERGY
# under Contract DE-AC05-76RL01830
# }}}

import logging
import os
import sys
import re
import traceback

from volttron.utils import ClientContext as cc

_log = logging.getLogger(__name__)


def is_ip_private(vip_address):
    """Determines if the passed vip_address is a private ip address or not.

    :param vip_address: A valid ip address.
    :return: True if an internal ip address.
    """
    ip = vip_address.strip().lower().split("tcp://")[1]

    # https://en.wikipedia.org/wiki/Private_network

    priv_lo = re.compile(r"^127.\d{1,3}.\d{1,3}.\d{1,3}$")
    priv_24 = re.compile(r"^10.\d{1,3}.\d{1,3}.\d{1,3}$")
    priv_20 = re.compile(r"^192.168.\d{1,3}.\d{1,3}$")
    priv_16 = re.compile(r"^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")

    return (
        priv_lo.match(ip) is not None
        or priv_24.match(ip) is not None
        or priv_20.match(ip) is not None
        or priv_16.match(ip) is not None
    )


def get_hostname():
    with open("/etc/hostname") as fp:
        hostname = fp.read().strip()

    if not hostname:
        raise ValueError("/etc/hostname file not found!")
    return hostname


def get_address(verify_listening=False):
    """Return the VIP address of the platform
    If the VOLTTRON_VIP_ADDR environment variable is set, it is used to connect to.
    Otherwise, it is derived from get_home()."""
    address = os.environ.get("VOLTTRON_VIP_ADDR")
    if not address:
        # Connect via virtual unix socket if linux platform (mac doesn't have @ in it)
        abstract = "@" if sys.platform.startswith("linux") else ""
        address = "ipc://%s%s/run/vip.socket" % (
            abstract,
            cc.get_volttron_home(),
        )

    import zmq.green as zmqgreen
    import zmq

    # The following block checks to make sure that we can
    # connect to the zmq based upon the ipc address.
    #
    # The zmq.sock.bind() will raise an error because the
    # address is already bound (therefore volttron is running there)
    sock = None
    try:
        # TODO: We should not just do the connection test when verfiy_listening is True but always
        # Though we leave this here because we have backward compatible unit tests that require
        # the get_address to not have somethiing bound to the address.
        if verify_listening:
            ctx = zmqgreen.Context.instance()
            sock = ctx.socket(zmq.PUB)  # or SUB - does not make any difference
            sock.bind(address)
            raise ValueError(
                "Unable to connect to vip address "
                f"make sure VOLTTRON_HOME: {cc.get_volttron_home()} "
                "is set properly"
            )
    except zmq.error.ZMQError as e:
        _log.error(f"Zmq error was {e}\n{traceback.format_exc()}")
    finally:
        try:
            sock.close()
        except AttributeError as e:  # Raised when sock is None type
            pass

    return address
