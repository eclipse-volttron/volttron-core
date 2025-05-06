# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}

import logging
import os
import sys
import re
import traceback

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

    return (priv_lo.match(ip) is not None or priv_24.match(ip) is not None
            or priv_20.match(ip) is not None or priv_16.match(ip) is not None)


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
    from volttron.utils import ClientContext as cc

    import socket

    address = os.environ.get("VOLTTRON_VIP_ADDR")
    if not address:
        # TODO: Shouldn't address be got from config next?
        # Connect via virtual unix socket if linux platform (mac doesn't have @ in it)
        abstract = "@" if sys.platform.startswith("linux") else ""
        address = "ipc://%s%s/run/vip.socket" % (
            abstract,
            cc.get_volttron_home(),
        )

    new_sock = None
    socket_port = None
    if address.startswith("tcp://"):
        socket_address = address[6:] # address after tcp://
        socket_port = cc.get_config_param("port")
    else:
        socket_address = f"{cc.get_volttron_home()}/run/vip.socket"
    try:
        if socket_port:
            new_sock = socket.socket(socket.AF_INET)
            new_sock.bind((socket_address, socket_port))
        else:
            new_sock = socket.socket(socket.AF_UNIX)
            new_sock.bind(socket_address)
        raise ValueError("Unable to connect to vip address "
                         f"make sure VOLTTRON_HOME: {cc.get_volttron_home()} "
                         "is set properly")
    except OSError as e:
        if e.errno != 98:  # 98 = address already in use error
            raise e
    finally:
        try:
            new_sock.close()
        except AttributeError as e:    # Raised when sock is None type
            pass

    return address
