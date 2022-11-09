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

from __future__ import annotations

import logging
import logging as _log
from dataclasses import dataclass, fields

import gevent

from volttron.client.vip.agent.core import Core, BasicCore
from volttron.client.vip.agent.subsystems import RPC, Hello, PeerList, Ping, Health, Heartbeat, PubSub, ConfigStore
from volttron.client.vip.agent.errors import Unreachable, VIPError
from volttron.utils import is_valid_identity, get_address, ClientContext as cc


@dataclass
class AgentStartupConfig:
    heartbeat_autostart: bool = True
    heartbeat_period: int = 30
    enable_store: bool = False
    logger: logging.Logger = None


class Agent(object):

    class Subsystems(object):

        def __init__(
            self,
            owner: Agent,
            core: Core,
            agent_startup_config: AgentStartupConfig,
            **kwargs
        ):
            self.hello = Hello(core=core)
            self.ping = Ping(core=core)
            self.peerlist = PeerList(core=core)
            self.rpc = RPC(core=core, owner=owner, peerlist_subsys=self.peerlist)
            self.pubsub = PubSub(core=core, owner=owner, peerlist_subsys=self.peerlist, rpc_subsys=self.rpc)
            self.health = Health(core=core, owner=owner, rpc_subsys=self.rpc)
            self.heartbeat = Heartbeat(
                owner,
                core,
                self.rpc,
                self.pubsub,
                agent_startup_config
            )
            if agent_startup_config.enable_store:
                self.config = ConfigStore(owner, core, self.rpc)

            # TODO add auth subsystem back in.
            # self.auth = Auth(owner, core, self.rpc_subsys)

    def get_core_from_environment(self, **kwargs):
        from volttron.utils import get_subclasses
        # TODO: Figure out standard way to do this.
        cls = get_subclasses("volttron.messagebus.zmq", Core)

        return cls[0](owner=self, **kwargs)

    # def build_client_context(self, **kwargs):
    #     from volttron.utils import get_subclasses, get_class
    #     core_cls = get_class("volttron.types", "ConnectionContext")
    #     cls = get_subclasses("volttron.messagebus.zmq", core_cls)
    #     return cls[0](**kwargs)

    def __init__(
        self,
        agent_startup_config: AgentStartupConfig = None,
        **kwargs
    #     identity=None,
    #     address=None,
    #     context=None,
    #     publickey=None,
    #     secretkey=None,
    #     serverkey=None,
    # # Since heartbeat is now 100% tied to status on the vctl change the defaults
    # # to auto start the heartbeat.
    #     heartbeat_autostart=True,
    #     heartbeat_period=60,
    #     volttron_home=None,
    #     agent_uuid=None,
    #     enable_store=True,
    #     enable_web=False,
    #     enable_channel=False,
    #     reconnect_interval=None,
    #     version="0.1",
    #     instance_name=None,
    #     message_bus=None,
    #     volttron_central_address=None,
    #     volttron_central_instance_name=None,
    ):
        identity = kwargs.get("identity")
              # try:

        if identity is not None and not is_valid_identity(identity):
            _log.warning("Deprecation warning")
            _log.warning("All characters in {identity} are not in the valid set.".format(
                identity=identity))


        volttron_home = kwargs.get("volttron_home")
        if volttron_home is None:
            volttron_home = cc.get_volttron_home()

        if agent_startup_config is None:
            # Create a configuration object and pop of kwargs that are fields based upon the dataclass.
            agent_startup_config = AgentStartupConfig()
            for fld in fields(agent_startup_config):
                if fld.name in kwargs:
                    setattr(agent_startup_config, fld.name, kwargs.pop(fld.name))
                    kwargs.pop(fld.name, None)

        self.core = self.get_core_from_environment(**kwargs)

        self.vip = Agent.Subsystems(owner=self, core=self.core, agent_startup_config=agent_startup_config)

            # if message_bus is not None and message_bus.lower() == "rmq":
            #     _log.debug("Creating RMQ Core {}".format(identity))
            #     self.core = RMQCore(
            #         self,
            #         identity=identity,
            #         address=address,
            #         context=context,
            #         publickey=publickey,
            #         secretkey=secretkey,
            #         serverkey=serverkey,
            #         instance_name=instance_name,
            #         volttron_home=volttron_home,
            #         agent_uuid=agent_uuid,
            #         reconnect_interval=reconnect_interval,
            #         version=version,
            #         volttron_central_address=volttron_central_address,
            #         volttron_central_instance_name=volttron_central_instance_name,
            #     )
            # else:
            #     _log.debug("Creating ZMQ Core {}".format(identity))
            #     self.core = ZMQCore(
            #         self,
            #         identity=identity,
            #         address=address,
            #         context=context,
            #         publickey=publickey,
            #         secretkey=secretkey,
            #         serverkey=serverkey,
            #         instance_name=instance_name,
            #         volttron_home=volttron_home,
            #         agent_uuid=agent_uuid,
            #         reconnect_interval=reconnect_interval,
            #         version=version,
            #     )
            # self.vip = Agent.Subsystems(
            #     self,
            #     self.core,
            #     heartbeat_autostart,
            #     heartbeat_period,
            #     enable_store,
            #     enable_web,
            #     enable_channel,
            #     message_bus,
            # )
            # self.core.setup()
            # self.vip.rpc_subsys.export(self.core.version, "agent.version")
        # except Exception as e:
        #     _log.exception("Exception creating Agent. {}".format(e))
        #     raise e


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
