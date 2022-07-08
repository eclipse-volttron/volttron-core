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

from volttron.utils import get_address
from volttron.utils.keystore import KeyStore, KnownHostsStore
from volttron.client.vip.agent.connection import Connection

_log = logging.getLogger(__name__)

host_store = KnownHostsStore()


def get_known_host_serverkey(vip_address):
    return host_store.serverkey(vip_address)


def get_server_keys():
    try:
        # attempt to read server's keys. Should be used only by multiplatform connection and tests
        # If agents such as forwarder attempt this in secure mode this will throw access violation exception
        ks = KeyStore()
    except IOError as e:
        raise RuntimeError(
            "Exception accessing server keystore. Agents must use agent's public and private key"
            "to build dynamic agents when running in secure mode. Exception:{}".format(e))

    return ks.public, ks.secret


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
