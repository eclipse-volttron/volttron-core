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

import base64
import hashlib
import logging.config
import os
import shutil
import tempfile
from datetime import timedelta
from typing import Optional, Dict, Any

import gevent
import gevent.event
import sys

from volttron.client.messaging.health import Status, STATUS_BAD
from volttron.client.vip.agent import (
    Core,
    RPC,
)
from volttron.client.vip.agent.subsystems.query import Query
from volttron.types import ServiceInterface
from volttron.utils import (
    ClientContext as cc,
    get_aware_utc_now,
)
from volttron.utils import jsonapi
from volttron.utils.scheduling import periodic

# noinspection PyUnresolvedReferences
# TODO: Fix requests issues
# import grequests
# import requests
# from requests.exceptions import ConnectionError

# from volttron.platform import config
# from volttron.platform.auth import AuthEntry, AuthFile, AuthException
# TODO: Add rmq
# from volttron.utils.rmq_config_params import RMQConfig
# from volttron.utils.rmq_mgmt import RabbitMQMgmt
# from volttron.utils.rmq_setup import check_rabbit_status

# TODO Move to volttron-cmds
# from . install_agents import add_install_agent_parser, install_agent

_stdout = sys.stdout
_stderr = sys.stderr

_log = logging.getLogger(os.path.basename(sys.argv[0]) if __name__ == "__main__" else __name__)

message_bus = cc.get_messagebus()
rmq_mgmt = None

CHUNK_SIZE = 4096


class ControlService(ServiceInterface):

    @classmethod
    def get_kwargs_defaults(cls) -> Dict[str, Any]:
        """
        Class method that allows the specific class to have the ability to specify
        what service arguments are available as defaults.
        """
        return {"agent-monitor-frequency": 10}

    def __init__(self, aip, **kwargs):

        tracker = kwargs.pop("tracker", None)
        # Control config store not necessary right now
        kwargs["enable_store"] = False
        kwargs["enable_channel"] = True
        agent_monitor_frequency = kwargs.pop("agent-monitor-frequency", 10)
        super(ControlService, self).__init__(**kwargs)
        self._aip = aip
        self._tracker = tracker
        self.crashed_agents = {}
        self.agent_monitor_frequency = int(agent_monitor_frequency)

        if self.core.publickey is None or self.core.secretkey is None:
            (
                self.core.publickey,
                self.core.secretkey,
                _,
            ) = self.core._get_keys_from_addr()
        if self.core.publickey is None or self.core.secretkey is None:
            (
                self.core.publickey,
                self.core.secretkey,
            ) = self.core._get_keys_from_keystore()

    @Core.receiver("onsetup")
    def _setup(self, sender, **kwargs):
        if not self._tracker:
            return
        self.vip.rpc.export(lambda: self._tracker.enabled, "stats.enabled")
        self.vip.rpc.export(self._tracker.enable, "stats.enable")
        self.vip.rpc.export(self._tracker.disable, "stats.disable")
        self.vip.rpc.export(lambda: self._tracker.stats, "stats.get")

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        _log.debug(" agent monitor frequency is... {}".format(self.agent_monitor_frequency))
        self.core.schedule(periodic(self.agent_monitor_frequency), self._monitor_agents)

    def _monitor_agents(self):
        """
        Periodically look for agents that crashed and schedule a restart
        attempt. Attempts at most 5 times with increasing interval
        between attempts. Sends alert if attempts fail.
        """
        # Get status for agents that have been started at least once.
        stats = self._aip.status_agents()
        for (uid, name, (pid, stat), identity) in stats:
            if stat:
                # stat=0 means stopped and stat=None means running
                # will always have pid(current/crashed/stopped)
                attempt = self.crashed_agents.get(uid, -1) + 1
                if attempt < 5:
                    self.crashed_agents[uid] = attempt
                    next_restart = get_aware_utc_now() + timedelta(minutes=attempt * 5)
                    _log.debug("{} stopped unexpectedly. Will attempt to "
                               "restart at {}".format(name, next_restart))
                    self.core.schedule(next_restart, self._restart_agent, uid, name)
                else:
                    self.send_alert(uid, name)
                    self.crashed_agents.pop(uid)

    def _restart_agent(self, agent_id, agent_name):
        """
        Checks if a given agent has crashed. If so attempts to restart it.
        If successful removes the agent id from list of crashed agents
        :param agent_id:
        :param agent_name:
        :return:
        """
        (_id, stat) = self._aip.agent_status(agent_id)
        if stat:
            # if there is still some error status... attempt restart
            # call self.stop to inform router but call aip start to get
            # status back
            self.stop_agent(agent_id)
            (_id, stat) = self._aip.start_agent(agent_id)
            if stat is None:
                # start successful
                self.crashed_agents.pop(agent_id)
                _log.info("Successfully restarted agent {}".format(agent_name))
            else:
                _log.info("Restart of {} failed".format(agent_name))

    def send_alert(self, agent_id, agent_name):
        """Send an alert for the group, summarizing missing topics."""
        alert_key = "Agent {}({}) stopped unexpectedly".format(agent_name, agent_id)
        context = ("Agent {}({}) stopped unexpectedly. Attempts to "
                   "restart failed".format(agent_name, agent_id))
        status = Status.build(STATUS_BAD, context=context)
        self.vip.health.send_alert(alert_key, status)

    @RPC.export
    def peerlist(self):
        # We want to keep the same interface, so we convert the byte array to
        # string array when returning.
        peer_list = self.vip.peerlist().get(timeout=5)
        return peer_list

    @RPC.export
    def serverkey(self):
        q = Query(self.core)
        pk = q.query("serverkey").get(timeout=1)
        del q
        return pk

    @RPC.export
    def clear_status(self, clear_all=False):
        self._aip.clear_status(clear_all)

    @RPC.export
    def agent_status(self, uuid):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        return self._aip.agent_status(uuid)

    @RPC.export
    def agent_name(self, uuid):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        return self._aip.agent_name(uuid)

    @RPC.export
    def agent_version(self, uuid):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        return self._aip.agent_version(uuid)

    @RPC.export
    def agent_priority(self, uuid):
        return self._aip.agent_priority(uuid) or ""

    @RPC.export
    def agent_versions(self):
        return self._aip.agent_versions()

    @RPC.export
    def status_agents(self, get_agent_user=False):
        return self._aip.status_agents(get_agent_user)

    @RPC.export
    def start_agent(self, uuid):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        self._aip.start_agent(uuid)

    @RPC.export
    def stop_agent(self, uuid):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))

        identity = self.agent_vip_identity(uuid)
        self._aip.stop_agent(uuid)
        # Send message to router that agent is shutting down
        frames = [identity]

        # Was self.core.socket.send_vip(b'', b'agentstop', frames, copy=False)
        self.core.connection.send_vip("", "agentstop", args=frames, copy=False)

    @RPC.export
    def restart_agent(self, uuid):
        self.stop_agent(uuid)
        self.start_agent(uuid)

    @RPC.export
    def shutdown(self):
        self._aip.shutdown()

    @RPC.export
    def stop_platform(self):
        # XXX: Restrict call as it kills the process
        self.core.connection.send_vip("", "quit")

    @RPC.export
    def list_agents(self):
        _log.info("CONTROL RPC list_agents")
        tag = self._aip.agent_tag
        priority = self._aip.agent_priority
        return [{
            "name": name,
            "uuid": uuid,
            "tag": tag(uuid),
            "priority": priority(uuid),
            "identity": self.agent_vip_identity(uuid),
        } for uuid, name in self._aip.list_agents().items()]

    @RPC.export
    def tag_agent(self, uuid, tag):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        if not isinstance(tag, (type(None), str)):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'tag';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        self._aip.tag_agent(uuid, tag)

    @RPC.export
    def remove_agent(self, uuid, remove_auth=True):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))

        identity = self.agent_vip_identity(uuid)
        # Because we are using send_vip we should pass frames that have
        # bytes rather than
        # strings.
        frames = [identity]

        # Send message to router that agent is shutting down
        self.core.connection.send_vip("", "agentstop", args=frames)
        self._aip.remove_agent(uuid, remove_auth=remove_auth)

    @RPC.export
    def prioritize_agent(self, uuid, priority="50"):
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        if not isinstance(priority, (type(None), str)):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string or null for 'priority';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        self._aip.prioritize_agent(uuid, priority)

    @RPC.export
    def agent_vip_identity(self, uuid):
        """Lookup the agent's vip identity based upon it's uuid.

        @param uuid:
        @return:
        """
        if not isinstance(uuid, str):
            identity = bytes(self.vip.rpc.context.vip_message.peer).decode("utf-8")
            raise TypeError("expected a string for 'uuid';"
                            "got {!r} from identity: {}".format(type(uuid).__name__, identity))
        return self._aip.uuid_vip_id_map[uuid]

    @RPC.export
    def get_all_agent_publickeys(self):
        """
        RPC method to retrieve the public keys of all the agents installed
        on the VOLTTRON instance.

        This method does not differentiate between running and not running
        agents.

        .. note::

            This method will only retrieve a publickey for an installed agents.
            It is recommended that dynamic agents use the context of the
            containing agent's publickey for connections to external instances.

        :return: mapping of identity to agent publickey
        :rtype: dict
        """
        result = {}
        for vip_identity in self._aip.vip_id_uuid_map:
            result[vip_identity] = self._aip.__get_agent_keystore__(vip_identity).public
        return result

    @RPC.export
    def identity_exists(self, identity):
        if not identity:
            raise ValueError("Attribute identity cannot be None or empty")

        return self._vip_identity_exists(identity)

    @RPC.export
    def install_agent_rmq(self,
                          agent: str,
                          topic: str,
                          response_topic: str,
                          vip_identity: str = None,
                          publickey: str = None,
                          secretkey: str = None,
                          force: bool = False,
                          pre_release: bool = False,
                          agent_config: str = None):

        """
        Install the agent through the rmq message bus.
        """
        peer = self.vip.rpc.context.vip_message.peer
        protocol_request_size = 8192
        protocol_message = None
        protocol_headers = None
        response_received = False

        def protocol_subscription(peer, sender, bus, topic, headers, message):
            nonlocal protocol_message, protocol_headers, response_received
            _log.debug(f"Received topic, message topic {topic}, {message}")
            protocol_message = message
            protocol_message = base64.b64decode(protocol_message.encode("utf-8"))
            protocol_headers = headers
            response_received = True

        self._raise_error_if_identity_exists_without_force(vip_identity, force)
        if not agent.endswith(".whl"):
            # agent passed is package name to install from pypi.
            return self._aip.install_agent(agent, vip_identity, publickey, secretkey, agent_config, force, pre_release)

        # Else it is a .whl file that needs to be transferred from client to server before calling aip.install_agent
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp()
            path = os.path.join(tmpdir, os.path.basename(agent))
            store = open(path, "wb")
            sha512 = hashlib.sha512()

            try:
                request_checksum = base64.b64encode(jsonapi.dumps(
                    ["checksum"]).encode("utf-8")).decode("utf-8")
                request_fetch = base64.b64encode(
                    jsonapi.dumps(["fetch",
                                   protocol_request_size]).encode("utf-8")).decode("utf-8")

                _log.debug(f"Server subscribing to {topic}")
                self.vip.pubsub.subscribe(peer="pubsub",
                                          prefix=topic,
                                          callback=protocol_subscription).get(timeout=5)
                gevent.sleep(5)
                while True:

                    _log.debug(f"Requesting data {request_fetch} sending to "
                               f"{response_topic}")
                    response_received = False

                    # request a chunk of the file
                    self.vip.pubsub.publish("pubsub", topic=response_topic,
                                            message=request_fetch).get(timeout=5)
                    # chunk binary representation of the bytes read from
                    # the other side of the connection
                    with gevent.Timeout(30):
                        _log.debug("Waiting for chunk")
                        while not response_received:
                            gevent.sleep(0.1)

                    # Chunk will be bytes
                    chunk = protocol_message
                    _log.debug(f"chunk received is:\n{chunk}")
                    if chunk == b"complete":
                        _log.debug(f"File transfer complete!")
                        break

                    sha512.update(chunk)
                    store.write(chunk)

                    with gevent.Timeout(30):
                        _log.debug("Requesting checksum")
                        response_received = False
                        self.vip.pubsub.publish("pubsub",
                                                topic=response_topic,
                                                message=request_checksum).get(timeout=5)

                        while not response_received:
                            gevent.sleep(0.1)

                        checksum = protocol_message
                        assert checksum == sha512.digest()

                _log.debug("Outside of while loop in install agent service.")

            except AssertionError:
                _log.warning("Checksum mismatch on received file")
                raise
            except gevent.Timeout:
                _log.warning("Gevent timeout trying to receive data")
                raise
            finally:
                store.close()
                self.vip.pubsub.unsubscribe("pubsub", response_topic, protocol_subscription)
                _log.debug("Unsubscribing on server")

            agent_uuid = self._aip.install_agent(agent, vip_identity, publickey, secretkey, agent_config, force,
                                                 pre_release)
            return agent_uuid
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @RPC.export
    def install_agent(self,
                      agent: str,
                      channel_name: str,
                      vip_identity: str = None,
                      publickey: str = None,
                      secretkey: str = None,
                      force: bool = False,
                      pre_release: bool = False,
                      agent_config: str = None):
        """
        Installs an agent on the instance.

        The installation of an agent through this method involves sending
        the binary data of the agent file through a channel.  The following
        example is the protocol for sending the agent across the wire:

        Example Protocol:

        .. code-block:: python

            # client creates channel to this agent (control)
            channel = agent.vip.channel('control', 'channel_name')

            # Begin sending data
            sha512 = hashlib.sha512()
            while True:
                request, file_offset, chunk_size = channel.recv_multipart()

                # Control has all the file. Send hash for it to verify.
                if request == b'checksum':
                    channel.send(hash)
                assert request == b'fetch'

                # send a chunk of the file
                file_offset = int(file_offset)
                chunk_size = int(chunk_size)
                file.seek(file_offset)
                data = file.read(chunk_size)
                sha512.update(data)
                channel.send(data)

            agent_uuid = agent_uuid.get(timeout=10)
            # close and delete the channel
            channel.close(linger=0)
            del channel

        :param:string:filename:
            The name of the agent packaged file that is being written.
        :param:string:channel_name:
            The name of the channel that the agent file will be sent on.
        :param:string:publickey:
            Encoded public key the installed agent will use
        :param:string:secretkey:
            Encoded secret key the installed agent will use
        :param:bool:force:
            If true overwrite currently installed agent with same vip identity. defaults to false
        :param:dict:agent_config:
            Optional agent configuration
        """

        if agent_config is None:
            agent_config = dict()
        # TODO ship config

        # at this point if agent_uuid is populated then there is an
        # identity of that already available.
        self._raise_error_if_identity_exists_without_force(vip_identity, force)

        if not agent.endswith(".whl"):
            # agent passed is package name to install from pypi.
            return self._aip.install_agent(agent, vip_identity, publickey, secretkey, agent_config, force, pre_release)

        # Else it is a .whl file that needs to be transferred from client to server before calling aip.install_agent
        peer = self.vip.rpc.context.vip_message.peer
        channel = self.vip.channel(peer, channel_name)
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp()
            path = os.path.join(tmpdir, os.path.basename(agent))
            store = open(path, "wb")
            sha512 = hashlib.sha512()

            try:
                request_checksum = jsonapi.dumpb(["checksum"])
                request_fetch = jsonapi.dumpb(["fetch", 1024])
                while True:

                    # request a chunk of the file
                    channel.send(request_fetch)

                    # chunk binary representation of the bytes read from
                    # the other side of the connectoin
                    with gevent.Timeout(30):
                        chunk = channel.recv()
                        if chunk == b"complete":
                            _log.debug(f"File transfer complete!")
                            break

                    sha512.update(chunk)
                    store.write(chunk)

                    with gevent.Timeout(30):
                        channel.send(request_checksum)
                        checksum = channel.recv()

                        assert checksum == sha512.digest()

            except AssertionError:
                _log.warning("Checksum mismatch on received file")
                raise
            except gevent.Timeout:
                _log.warning("Gevent timeout trying to receive data")
                raise
            finally:
                store.close()
                _log.debug("Closing channel on server")
                channel.close(linger=0)
                del channel

            _log.debug("After transferring wheel to us now to do stuff.")
            agent_uuid = self._aip.install_agent(path, vip_identity, publickey, secretkey, agent_config, force,
                                                 pre_release)
            return agent_uuid
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _raise_error_if_identity_exists_without_force(self, vip_identity: str, force: bool):
        """
        This will raise a ValueError if the identity passed exists but
        force was not True when this function is called.

        This function should be called before any agent is installed through
        the respective message buses.
        """
        # at this point if agent_uuid is populated then there is an
        # identity of that already available.
        agent_uuid = None
        if vip_identity:
            agent_uuid = self._vip_identity_exists(vip_identity)
        if agent_uuid:
            if not force:
                raise ValueError("Identity already exists, but not forced!")
        return agent_uuid

    def _vip_identity_exists(self, vip_identity: str) -> Optional[str]:
        """
        Determines if an agent vip identity is already installed.  If installed,
        function returns the agent uuid of the agent with the passed
        vip identity.  If the identity  doesn't exist then returns None.
        """
        return self._aip.vip_id_uuid_map.get(vip_identity)
