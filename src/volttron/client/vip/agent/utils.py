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

from volttron.utils import get_address
from volttron.utils.keystore import KeyStore, KnownHostsStore
from volttron.client.vip.agent.connection import Connection

from volttron.client.logs import get_logger

_log = get_logger()

host_store = KnownHostsStore()


def get_known_host_serverkey(vip_address):
    return host_store.serverkey(vip_address)


def build_connection(identity,
                     peer="",
                     address=None,
                     publickey=None,
                     secretkey=None,
                     message_bus=None,
                     **kwargs):
    address = address if address is not None else get_address()
    if publickey is None or secretkey is None:
        publickey, secretkey = get_server_keys(publickey, secretkey)
    cn = Connection(address=address,
                    identity=identity,
                    peer=peer,
                    publickey=publickey,
                    secretkey=secretkey,
                    message_bus=message_bus,
                    **kwargs)
    return cn
