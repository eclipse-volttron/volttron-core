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
