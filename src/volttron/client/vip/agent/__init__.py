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

import logging as _log

import gevent

from .core import *
from .errors import *
from .decorators import *
from .subsystems import *

from volttron.utils import is_valid_identity, get_address, ClientContext as cc
from volttron.utils.keystore import get_server_keys


class Agent(object):

    class Subsystems(object):

        def __init__(
            self,
            owner,
            core,
            heartbeat_autostart,
            heartbeat_period,
            enable_store,
            enable_web,
            enable_channel,
            message_bus,
        ):
            self.peerlist = PeerList(core)
            self.ping = Ping(core)
            self.rpc = RPC(core, owner, self.peerlist)
            self.hello = Hello(core)
            if message_bus == "rmq":
                self.pubsub = RMQPubSub(core, self.rpc, self.peerlist, owner)
            else:
                self.pubsub = PubSub(core, self.rpc, self.peerlist, owner)
                # Available only for ZMQ agents
                if enable_channel:
                    self.channel = Channel(core)
            self.health = Health(owner, core, self.rpc)
            self.heartbeat = Heartbeat(
                owner,
                core,
                self.rpc,
                self.pubsub,
                heartbeat_autostart,
                heartbeat_period,
            )
            if enable_store:
                self.config = ConfigStore(owner, core, self.rpc)
            if enable_web:
                self.web = WebSubSystem(owner, core, self.rpc)
            self.auth = Auth(owner, core, self.rpc)

    def __init__(
        self,
        identity=None,
        address=None,
        context=None,
        publickey=None,
        secretkey=None,
        serverkey=None,
    # Since heartbeat is now 100% tied to status on the vctl change the defaults
    # to auto start the heartbeat.
        heartbeat_autostart=True,
        heartbeat_period=60,
        volttron_home=None,
        agent_uuid=None,
        enable_store=True,
        enable_web=False,
        enable_channel=False,
        reconnect_interval=None,
        version="0.1",
        instance_name=None,
        message_bus=None,
        volttron_central_address=None,
        volttron_central_instance_name=None,
    ):

        if volttron_home is None:
            volttron_home = cc.get_volttron_home()

        try:
            self._version = version

            if identity is not None and not is_valid_identity(identity):
                _log.warning("Deprecation warning")
                _log.warning("All characters in {identity} are not in the valid set.".format(
                    identity=identity))

            if message_bus is not None and message_bus.lower() == "rmq":
                _log.debug("Creating RMQ Core {}".format(identity))
                self.core = RMQCore(
                    self,
                    identity=identity,
                    address=address,
                    context=context,
                    publickey=publickey,
                    secretkey=secretkey,
                    serverkey=serverkey,
                    instance_name=instance_name,
                    volttron_home=volttron_home,
                    agent_uuid=agent_uuid,
                    reconnect_interval=reconnect_interval,
                    version=version,
                    volttron_central_address=volttron_central_address,
                    volttron_central_instance_name=volttron_central_instance_name,
                )
            else:
                _log.debug("Creating ZMQ Core {}".format(identity))
                self.core = ZMQCore(
                    self,
                    identity=identity,
                    address=address,
                    context=context,
                    publickey=publickey,
                    secretkey=secretkey,
                    serverkey=serverkey,
                    instance_name=instance_name,
                    volttron_home=volttron_home,
                    agent_uuid=agent_uuid,
                    reconnect_interval=reconnect_interval,
                    version=version,
                )
            self.vip = Agent.Subsystems(
                self,
                self.core,
                heartbeat_autostart,
                heartbeat_period,
                enable_store,
                enable_web,
                enable_channel,
                message_bus,
            )
            self.core.setup()
            self.vip.rpc.export(self.core.version, "agent.version")
        except Exception as e:
            _log.exception("Exception creating Agent. {}".format(e))
            raise e


class BasicAgent(object):

    def __init__(self, **kwargs):
        kwargs.pop("identity", None)
        super(BasicAgent, self).__init__(**kwargs)
        self.core = BasicCore(self)


def build_agent(address=None,
                identity=None,
                publickey=None,
                secretkey=None,
                timeout=10,
                serverkey=None,
                agent_class=Agent,
                volttron_central_address=None,
                volttron_central_instance_name=None,
                **kwargs) -> Agent:
    """Builds a dynamic agent connected to the specifiedd address.

    All key parameters should have been encoded with
    :py:meth:`volttron.client.vip.socket.encode_key`

    :param str address: VIP address to connect to
    :param str identity: Agent's identity
    :param str publickey: Agent's Base64-encoded CURVE public key
    :param str secretkey: Agent's Base64-encoded CURVE secret key
    :param str serverkey: Server's Base64-encoded CURVE public key
    :param class agent_class: Class to use for creating the instance
    :param int timeout: Seconds to wait for agent to start
    :param kwargs: Any Agent specific parameters
    :return: an agent based upon agent_class that has been started
    :rtype: agent_class
    """

    address = address if address is not None else get_address()

    # This is a fix allows the connect to message bus to be different than
    # the one that is currently running.
    if publickey is None or secretkey is None:
        publickey, secretkey = get_server_keys()

    message_bus = cc.get_messagebus()

    try:
        enable_store = kwargs.pop("enable_store")
    except KeyError:
        enable_store = False

    agent = agent_class(address=address,
                        identity=identity,
                        publickey=publickey,
                        secretkey=secretkey,
                        serverkey=serverkey,
                        volttron_central_address=volttron_central_address,
                        volttron_central_instance_name=volttron_central_instance_name,
                        message_bus=message_bus,
                        enable_store=enable_store,
                        **kwargs)
    event = gevent.event.Event()
    gevent.spawn(agent.core.run, event)
    with gevent.Timeout(timeout):
        event.wait()
    return agent
