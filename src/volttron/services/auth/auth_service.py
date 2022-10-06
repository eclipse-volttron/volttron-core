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

__all__ = [
    "AuthService", "AuthFile", "AuthEntry", "AuthFileEntryAlreadyExists", "AuthFileIndexError",
    "AuthException"
]

import bisect
import logging
import os
import random
import re
import shutil
from typing import Optional
import uuid
from collections import defaultdict

import gevent
import gevent.core
from gevent.fileobject import FileObject
from zmq import green as zmq

from volttron.types import ServiceInterface
from volttron.utils import (
    ClientContext as cc,
    create_file_if_missing,
    strip_comments,
)
from volttron.utils import jsonapi
from volttron.utils.filewatch import watch_file
from volttron.utils.certs import Certs
from volttron.utils.keystore import encode_key, BASE64_ENCODED_CURVE_KEY_LEN
from volttron.client.vip.agent import Agent, Core, RPC, VIPError
from volttron.client.known_identities import (
    VOLTTRON_CENTRAL_PLATFORM,
    CONTROL,
    CONTROL_CONNECTION,
)

# TODO: it seems this should not be so nested of a import path.
from volttron.client.vip.agent.subsystems.pubsub import ProtectedPubSubTopics
import volttron.types.server_config as server_config

# from volttron.platform.certs import Certs
# from volttron.platform.vip.agent.errors import VIPError
# from volttron.platform.vip.pubsubservice import ProtectedPubSubTopics
# from .agent.utils import strip_comments, create_file_if_missing, watch_file, get_messagebus
# from .vip.agent import Agent, Core, RPC
# from .vip.socket import encode_key, BASE64_ENCODED_CURVE_KEY_LEN

_log = logging.getLogger(__name__)

_dump_re = re.compile(r"([,\\])")
_load_re = re.compile(r"\\(.)|,")


def isregex(obj):
    return len(obj) > 1 and obj[0] == obj[-1] == "/"


def dump_user(*args):
    return ",".join([_dump_re.sub(r"\\\1", arg) for arg in args])


def load_user(string):

    def sub(match):
        return match.group(1) or "\x00"

    return _load_re.sub(sub, string).split("\x00")


class AuthException(Exception):
    """General exception for any auth error"""

    pass


class AuthService(ServiceInterface, Agent):

    def __init__(self, server_config: server_config.ServerConfig, *args, **kwargs):
        #auth_file, protected_topics_file, setup_mode, aip, *args, **kwargs):
        self.allow_any = kwargs.pop("allow_any", False)

        super(AuthService, self).__init__(*args, **kwargs)

        # This agent is started before the router so we need
        # to keep it from blocking.
        self.core.delay_running_event_set = False
        self._certs = None
        if cc.get_messagebus() == "rmq":
            self._certs = Certs()
        self.auth_file_path = str(server_config.auth_file)
        self.auth_file = AuthFile(self.auth_file_path)
        self.aip = server_config.aip
        self.zap_socket = None
        self._zap_greenlet = None
        self.auth_entries = []
        self._is_connected = False
        self._protected_topics_file_path = str(server_config.protected_topics_file)
        self._protected_topics_file = str(server_config.protected_topics_file)
        self._protected_topics_for_rmq = ProtectedPubSubTopics()
        self._setup_mode = server_config.opts.setup_mode
        self._auth_pending = []
        self._auth_denied = []
        self._auth_approved = []

        def topics():
            return defaultdict(set)

        self._user_to_permissions = topics()

    @Core.receiver("onsetup")
    def setup_zap(self, sender, **kwargs):
        self.zap_socket = zmq.Socket(zmq.Context.instance(), zmq.ROUTER)
        self.zap_socket.bind("inproc://zeromq.zap.01")
        if self.allow_any:
            _log.warning("insecure permissive authentication enabled")
        self.read_auth_file()
        self._read_protected_topics_file()
        self.core.spawn(watch_file, self.auth_file_path, self.read_auth_file)
        self.core.spawn(
            watch_file,
            self._protected_topics_file_path,
            self._read_protected_topics_file,
        )
        if self.core.messagebus == "rmq":
            self.vip.peerlist.onadd.connect(self._check_topic_rules)

    def _update_auth_lists(self, entries, is_allow=True):
        auth_list = []
        for entry in entries:
            auth_list.append({
                "domain": entry.domain,
                "address": entry.address,
                "mechanism": entry.mechanism,
                "credentials": entry.credentials,
                "user_id": entry.user_id,
                "retries": 0,
            })
        if is_allow:
            self._auth_approved = [entry for entry in auth_list if entry["address"] is not None]
        else:
            self._auth_denied = [entry for entry in auth_list if entry["address"] is not None]

    def read_auth_file(self):
        _log.info("loading auth file %s", self.auth_file_path)
        entries = self.auth_file.read_allow_entries()
        denied_entries = self.auth_file.read_deny_entries()
        # Populate auth lists with current entries
        self._update_auth_lists(entries)
        self._update_auth_lists(denied_entries, is_allow=False)

        entries = [entry for entry in entries if entry.enabled]
        # sort the entries so the regex credentails follow the concrete creds
        entries.sort()
        self.auth_entries = entries
        if self._is_connected:
            try:
                _log.debug("Sending auth updates to peers")
                # Give it few seconds for platform to startup or for the
                # router to detect agent install/remove action
                gevent.sleep(2)
                self._send_update()
            except BaseException as e:
                _log.error("Exception sending auth updates to peer. {}".format(e))
                raise e
        _log.info("auth file %s loaded", self.auth_file_path)

    def get_protected_topics(self):
        protected = self._protected_topics
        return protected

    def _read_protected_topics_file(self):
        # Read protected topics file and send to router
        try:
            create_file_if_missing(self._protected_topics_file)
            with open(self._protected_topics_file) as fil:
                # Use gevent FileObject to avoid blocking the thread
                data = FileObject(fil, close=False).read()
                self._protected_topics = jsonapi.loads(data) if data else {}
                if self.core.messagebus == "rmq":
                    self._load_protected_topics_for_rmq()
                    # Deferring the RMQ topic permissions to after "onstart" event
                else:
                    self._send_protected_update_to_pubsub(self._protected_topics)
        except Exception:
            _log.exception("error loading %s", self._protected_topics_file)

    def _send_update(self):
        user_to_caps = self.get_user_to_capabilities()
        i = 0
        exception = None
        peers = None
        # peerlist times out lots of times when running test suite. This happens even with higher timeout in get()
        # but if we retry peerlist succeeds by second attempt most of the time!!!
        while not peers and i < 3:
            try:
                i = i + 1
                peers = self.vip.peerlist().get(timeout=0.5)
            except BaseException as e:
                _log.warning("Attempt {} to get peerlist failed with exception {}".format(i, e))
                peers = list(self.vip.peerlist.peers_list)
                _log.warning("Get list of peers from subsystem directly".format(peers))
                exception = e

        if not peers:
            raise BaseException("No peers connected to the platform")

        _log.debug("after getting peerlist to send auth updates")

        for peer in peers:
            if peer not in [self.core.identity, CONTROL_CONNECTION]:
                _log.debug(f"Sending auth update to peers {peer}")
                self.vip.rpc.call(peer, "auth.update", user_to_caps)
        if self.core.messagebus == "rmq":
            self._check_rmq_topic_permissions()
        else:
            self._send_auth_update_to_pubsub()

    def _send_auth_update_to_pubsub(self):
        user_to_caps = self.get_user_to_capabilities()
        # Send auth update message to router
        json_msg = jsonapi.dumpb(dict(capabilities=user_to_caps))
        frames = [zmq.Frame(b"auth_update"), zmq.Frame(json_msg)]
        # <recipient, subsystem, args, msg_id, flags>
        self.core.socket.send_vip(b"", b"pubsub", frames, copy=False)

    def _send_protected_update_to_pubsub(self, contents):
        protected_topics_msg = jsonapi.dumpb(contents)

        frames = [zmq.Frame(b"protected_update"), zmq.Frame(protected_topics_msg)]
        if self._is_connected:
            try:
                # <recipient, subsystem, args, msg_id, flags>
                self.core.socket.send_vip(b"", b"pubsub", frames, copy=False)
            except VIPError as ex:
                _log.error("Error in sending protected topics update to clear PubSub: " + str(ex))

    @Core.receiver("onstop")
    def stop_zap(self, sender, **kwargs):
        if self._zap_greenlet is not None:
            self._zap_greenlet.kill()

    @Core.receiver("onfinish")
    def unbind_zap(self, sender, **kwargs):
        if self.zap_socket is not None:
            self.zap_socket.unbind("inproc://zeromq.zap.01")

    @Core.receiver("onstart")
    def zap_loop(self, sender, **kwargs):
        """
        The zap loop is the starting of the authentication process for
        the VOLTTRON zmq message bus.  It talks directly with the low
        level socket so all responses must be byte like objects, in
        this case we are going to send zmq frames across the wire.

        :param sender:
        :param kwargs:
        :return:
        """
        self._is_connected = True
        self._zap_greenlet = gevent.getcurrent()
        sock = self.zap_socket
        time = gevent.core.time
        blocked = {}
        wait_list = []
        timeout = None
        if self.core.messagebus == "rmq":
            # Check the topic permissions of all the connected agents
            self._check_rmq_topic_permissions()
        else:
            self._send_protected_update_to_pubsub(self._protected_topics)

        while True:
            events = sock.poll(timeout)
            now = time()
            if events:
                zap = sock.recv_multipart()

                version = zap[2]
                if version != b"1.0":
                    continue
                domain, address, userid, kind = zap[4:8]
                credentials = zap[8:]
                if kind == b"CURVE":
                    credentials[0] = encode_key(credentials[0])
                elif kind not in [b"NULL", b"PLAIN"]:
                    continue
                response = zap[:4]
                domain = domain.decode("utf-8")
                address = address.decode("utf-8")
                kind = kind.decode("utf-8")
                user = self.authenticate(domain, address, kind, credentials)
                _log.info(f"AUTH: After authenticate user id: {user}, {userid}")
                if user:
                    _log.info(
                        "authentication success: userid=%r domain=%r, address=%r, "
                        "mechanism=%r, credentials=%r, user=%r",
                        userid,
                        domain,
                        address,
                        kind,
                        credentials[:1],
                        user,
                    )
                    response.extend([b"200", b"SUCCESS", user.encode("utf-8"), b""])
                    sock.send_multipart(response)
                else:
                    userid = str(uuid.uuid4())
                    _log.info(
                        "authentication failure: userid=%r, domain=%r, address=%r, "
                        "mechanism=%r, credentials=%r",
                        userid,
                        domain,
                        address,
                        kind,
                        credentials,
                    )
                    # If in setup mode, add/update auth entry
                    if self._setup_mode:
                        self._update_auth_entry(domain, address, kind, credentials[0], userid)
                        _log.info(
                            "new authentication entry added in setup mode: domain=%r, address=%r, "
                            "mechanism=%r, credentials=%r, user_id=%r",
                            domain,
                            address,
                            kind,
                            credentials[:1],
                            userid,
                        )
                        response.extend([b"200", b"SUCCESS", b"", b""])
                        _log.debug("AUTH response: {}".format(response))
                        sock.send_multipart(response)
                    else:
                        if type(userid) == bytes:
                            userid = userid.decode("utf-8")
                        self._update_auth_pending(domain, address, kind, credentials[0], userid)

                    try:
                        expire, delay = blocked[address]
                    except KeyError:
                        delay = random.random()
                    else:
                        if now >= expire:
                            delay = random.random()
                        else:
                            delay *= 2
                            if delay > 100:
                                delay = 100
                    expire = now + delay
                    bisect.bisect(wait_list, (expire, address, response))
                    blocked[address] = expire, delay
            while wait_list:
                expire, address, response = wait_list[0]
                if now < expire:
                    break
                wait_list.pop(0)
                response.extend([b"400", b"FAIL", b"", b""])
                sock.send_multipart(response)
                try:
                    if now >= blocked[address][0]:
                        blocked.pop(address)
                except KeyError:
                    pass
            timeout = (wait_list[0][0] - now) if wait_list else None

    def authenticate(self, domain, address, mechanism, credentials):
        for entry in self.auth_entries:
            if entry.match(domain, address, mechanism, credentials):
                return entry.user_id or dump_user(domain, address, mechanism, *credentials[:1])
        if mechanism == "NULL" and address.startswith("localhost:"):
            parts = address.split(":")[1:]
            if len(parts) > 2:
                pid = int(parts[2])
                agent_uuid = self.aip.agent_uuid_from_pid(pid)
                if agent_uuid:
                    return dump_user(domain, address, "AGENT", agent_uuid)
            uid = int(parts[0])
            if uid == os.getuid():
                return dump_user(domain, address, mechanism, *credentials[:1])
        if self.allow_any:
            return dump_user(domain, address, mechanism, *credentials[:1])

    @RPC.export
    def get_user_to_capabilities(self):
        """RPC method

        Gets a mapping of all users to their capabiliites.

        :returns: mapping of users to capabilities
        :rtype: dict
        """
        user_to_caps = {}
        for entry in self.auth_entries:
            user_to_caps[entry.user_id] = entry.capabilities
        return user_to_caps

    @RPC.export
    def get_authorizations(self, user_id):
        """RPC method

        Gets capabilities, groups, and roles for a given user.

        :param user_id: user id field from VOLTTRON Interconnect Protocol
        :type user_id: str
        :returns: tuple of capabiliy-list, group-list, role-list
        :rtype: tuple
        """
        use_parts = True
        try:
            domain, address, mechanism, credentials = load_user(user_id)
        except ValueError:
            use_parts = False
        for entry in self.auth_entries:
            if entry.user_id == user_id:
                return [entry.capabilities, entry.groups, entry.roles]
            elif use_parts:
                if entry.match(domain, address, mechanism, [credentials]):
                    return entry.capabilities, entry.groups, entry.roles

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def approve_authorization_failure(self, user_id):
        """RPC method

        Approves a pending CSR or credential, based on provided identity.
        The approved CSR or credential can be deleted or denied later.
        An approved credential is stored in the allow list in auth.json.

        :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
        :type user_id: str
        """

        val_err = None
        if self._certs:
            # Will fail with ValueError when a zmq credential user_id is passed.
            try:
                self._certs.approve_csr(user_id)
                permissions = self.core.rmq_mgmt.get_default_permissions(user_id)

                if (
                        "federation" in user_id
                ):    # federation needs more than the current default permissions # TODO: Fix authorization in rabbitmq
                    permissions = dict(configure=".*", read=".*", write=".*")
                self.core.rmq_mgmt.create_user_with_permissions(user_id, permissions, True)
                _log.debug("Created cert and permissions for user: {}".format(user_id))
            # Stores error message in case it is caused by an unexpected failure
            except ValueError as e:
                val_err = e
        index = 0
        matched_index = -1
        for pending in self._auth_pending:
            if user_id == pending["user_id"]:
                self._update_auth_entry(
                    pending["domain"],
                    pending["address"],
                    pending["mechanism"],
                    pending["credentials"],
                    pending["user_id"],
                )
                matched_index = index
                val_err = None
                break
            index = index + 1
        if matched_index >= 0:
            del self._auth_pending[matched_index]

        for pending in self._auth_denied:
            if user_id == pending["user_id"]:
                self._update_auth_entry(
                    pending["domain"],
                    pending["address"],
                    pending["mechanism"],
                    pending["credentials"],
                    pending["user_id"],
                )
                self._remove_auth_entry(pending["credentials"], is_allow=False)
                val_err = None
        # If the user_id supplied was not for a ZMQ credential, and the pending_csr check failed,
        # output the ValueError message to the error log.
        if val_err:
            _log.error(f"{val_err}")

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def deny_authorization_failure(self, user_id):
        """RPC method

        Denies a pending CSR or credential, based on provided identity.
        The denied CSR or credential can be deleted or accepted later.
        A denied credential is stored in the deny list in auth.json.

        :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
        :type user_id: str
        """

        val_err = None
        if self._certs:
            # Will fail with ValueError when a zmq credential user_id is passed.
            try:
                self._certs.deny_csr(user_id)
                _log.debug("Denied cert for user: {}".format(user_id))
            # Stores error message in case it is caused by an unexpected failure
            except ValueError as e:
                val_err = e

        index = 0
        matched_index = -1
        for pending in self._auth_pending:
            if user_id == pending["user_id"]:
                self._update_auth_entry(
                    pending["domain"],
                    pending["address"],
                    pending["mechanism"],
                    pending["credentials"],
                    pending["user_id"],
                    is_allow=False,
                )
                matched_index = index
                val_err = None
                break
            index = index + 1
        if matched_index >= 0:
            del self._auth_pending[matched_index]

        for pending in self._auth_approved:
            if user_id == pending["user_id"]:
                self._update_auth_entry(
                    pending["domain"],
                    pending["address"],
                    pending["mechanism"],
                    pending["credentials"],
                    pending["user_id"],
                    is_allow=False,
                )
                self._remove_auth_entry(pending["credentials"])
                val_err = None
        # If the user_id supplied was not for a ZMQ credential, and the pending_csr check failed,
        # output the ValueError message to the error log.
        if val_err:
            _log.error(f"{val_err}")

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def delete_authorization_failure(self, user_id):
        """RPC method

        Deletes a pending CSR or credential, based on provided identity.
        To approve or deny a deleted pending CSR or credential,
        the request must be resent by the remote platform or agent.

        :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
        :type user_id: str
        """

        val_err = None
        if self._certs:
            # Will fail with ValueError when a zmq credential user_id is passed.
            try:
                self._certs.delete_csr(user_id)
                _log.debug("Denied cert for user: {}".format(user_id))
            # Stores error message in case it is caused by an unexpected failure
            except ValueError as e:
                val_err = e

        index = 0
        matched_index = -1
        for pending in self._auth_pending:
            if user_id == pending["user_id"]:
                self._update_auth_entry(
                    pending["domain"],
                    pending["address"],
                    pending["mechanism"],
                    pending["credentials"],
                    pending["user_id"],
                )
                matched_index = index
                val_err = None
                break
            index = index + 1
        if matched_index >= 0:
            del self._auth_pending[matched_index]

        index = 0
        matched_index = -1
        for pending in self._auth_pending:
            if user_id == pending["user_id"]:
                matched_index = index
                val_err = None
                break
            index = index + 1
        if matched_index >= 0:
            del self._auth_pending[matched_index]

        for pending in self._auth_approved:
            if user_id == pending["user_id"]:
                self._remove_auth_entry(pending["credentials"])
                val_err = None

        for pending in self._auth_denied:
            if user_id == pending["user_id"]:
                self._remove_auth_entry(pending["credentials"], is_allow=False)
                val_err = None

        # If the user_id supplied was not for a ZMQ credential, and the pending_csr check failed,
        # output the ValueError message to the error log.
        if val_err:
            _log.error(f"{val_err}")

    @RPC.export
    def get_authorization_pending(self):
        """RPC method

        Returns a list of failed (pending) ZMQ credentials.

        :rtype: list
        """
        return list(self._auth_pending)

    @RPC.export
    def get_authorization_approved(self):
        """RPC method

        Returns a list of approved ZMQ credentials.
        This list is updated whenever the auth file is read.
        It includes all allow entries from the auth file that contain a populated address field.

        :rtype: list
        """
        return list(self._auth_approved)

    @RPC.export
    def get_authorization_denied(self):
        """RPC method

        Returns a list of denied ZMQ credentials.
        This list is updated whenever the auth file is read.
        It includes all deny entries from the auth file that contain a populated address field.

        :rtype: list
        """
        return list(self._auth_denied)

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def get_pending_csrs(self):
        """RPC method

        Returns a list of pending CSRs.
        This method provides RPC access to the Certs class's get_pending_csr_requests method.
        This method is only applicable for web-enabled, RMQ instances.

        :rtype: list
        """
        if self._certs:
            csrs = [c for c in self._certs.get_pending_csr_requests()]
            return csrs
        else:
            return []

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def get_pending_csr_status(self, common_name):
        """RPC method

        Returns the status of a pending CSRs.
        This method provides RPC access to the Certs class's get_csr_status method.
        This method is only applicable for web-enabled, RMQ instances.
        Currently, this method is only used by admin_endpoints.

        :param common_name: Common name for CSR
        :type common_name: str
        :rtype: str
        """
        if self._certs:
            return self._certs.get_csr_status(common_name)
        else:
            return ""

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def get_pending_csr_cert(self, common_name):
        """RPC method

        Returns the cert of a pending CSRs.
        This method provides RPC access to the Certs class's get_cert_from_csr method.
        This method is only applicable for web-enabled, RMQ instances.
        Currently, this method is only used by admin_endpoints.

        :param common_name: Common name for CSR
        :type common_name: str
        :rtype: str
        """
        if self._certs:
            return self._certs.get_cert_from_csr(common_name).decode("utf-8")
        else:
            return ""

    @RPC.export
    @RPC.allow(capabilities="allow_auth_modifications")
    def get_all_pending_csr_subjects(self):
        """RPC method

        Returns a list of all certs subjects.
        This method provides RPC access to the Certs class's get_all_cert_subjects method.
        This method is only applicable for web-enabled, RMQ instances.
        Currently, this method is only used by admin_endpoints.

        :rtype: list
        """
        if self._certs:
            return self._certs.get_all_cert_subjects()
        else:
            return []

    def _get_authorizations(self, user_id, index):
        """Convenience method for getting authorization component by index"""
        auths = self.get_authorizations(user_id)
        if auths:
            return auths[index]
        return []

    @RPC.export
    def get_capabilities(self, user_id):
        """RPC method

        Gets capabilities for a given user.

        :param user_id: user id field from VOLTTRON Interconnect Protocol
        :type user_id: str
        :returns: list of capabilities
        :rtype: list
        """
        return self._get_authorizations(user_id, 0)

    @RPC.export
    def get_groups(self, user_id):
        """RPC method

        Gets groups for a given user.

        :param user_id: user id field from VOLTTRON Interconnect Protocol
        :type user_id: str
        :returns: list of groups
        :rtype: list
        """
        return self._get_authorizations(user_id, 1)

    @RPC.export
    def get_roles(self, user_id):
        """RPC method

        Gets roles for a given user.

        :param user_id: user id field from VOLTTRON Interconnect Protocol
        :type user_id: str
        :returns: list of roles
        :rtype: list
        """
        return self._get_authorizations(user_id, 2)

    def _update_auth_entry(self, domain, address, mechanism, credential, user_id, is_allow=True):
        # Make a new entry
        fields = {
            "domain": domain,
            "address": address,
            "mechanism": mechanism,
            "credentials": credential,
            "user_id": user_id,
            "groups": "",
            "roles": "",
            "capabilities": "",
            "comments": "Auth entry added in setup mode",
        }
        new_entry = AuthEntry(**fields)

        try:
            self.auth_file.add(new_entry, overwrite=False, is_allow=is_allow)
        except AuthException as err:
            _log.error("ERROR: %s\n" % str(err))

    def _remove_auth_entry(self, credential, is_allow=True):
        try:
            self.auth_file.remove_by_credentials(credential, is_allow=is_allow)
        except AuthException as err:
            _log.error("ERROR: %s\n" % str(err))

    def _update_auth_pending(self, domain, address, mechanism, credential, user_id):
        for entry in self._auth_denied:
            # Check if failure entry has been denied. If so, increment the failure's denied count
            if ((entry["domain"] == domain) and (entry["address"] == address)
                    and (entry["mechanism"] == mechanism)
                    and (entry["credentials"] == credential)):
                entry["retries"] += 1
                return

        for entry in self._auth_pending:
            # Check if failure entry exists. If so, increment the failure count
            if ((entry["domain"] == domain) and (entry["address"] == address)
                    and (entry["mechanism"] == mechanism)
                    and (entry["credentials"] == credential)):
                entry["retries"] += 1
                return
        # Add a new failure entry
        fields = {
            "domain": domain,
            "address": address,
            "mechanism": mechanism,
            "credentials": credential,
            "user_id": user_id,
            "retries": 1,
        }
        self._auth_pending.append(dict(fields))
        return

    def _load_protected_topics_for_rmq(self):
        try:
            write_protect = self._protected_topics["write-protect"]
        except KeyError:
            write_protect = []

        topics = ProtectedPubSubTopics()
        try:
            for entry in write_protect:
                topics.add(entry["topic"], entry["capabilities"])
        except KeyError:
            _log.exception("invalid format for protected topics ")
        else:
            self._protected_topics_for_rmq = topics

    def _check_topic_rules(self, sender, **kwargs):
        delay = 0.05
        self.core.spawn_later(delay, self._check_rmq_topic_permissions)

    def _check_rmq_topic_permissions(self):
        """
        Go through the topic permissions for each agent based on the protected topic setting.
        Update the permissions for the agent/user based on the latest configuration
        :return:
        """
        return
        # Get agent to capabilities mapping
        user_to_caps = self.get_user_to_capabilities()
        # Get topics to capabilities mapping
        topic_to_caps = self._protected_topics_for_rmq.get_topic_caps()    # topic to caps

        peers = self.vip.peerlist().get(timeout=5)
        # _log.debug("USER TO CAPS: {0}, TOPICS TO CAPS: {1}, {2}".format(user_to_caps,
        #                                                                 topic_to_caps,
        #                                                                 self._user_to_permissions))
        if not user_to_caps or not topic_to_caps:
            # clear all old permission rules
            for peer in peers:
                self._user_to_permissions[peer].clear()
        else:
            for topic, caps_for_topic in topic_to_caps.items():
                for user in user_to_caps:
                    try:
                        caps_for_user = user_to_caps[user]
                        common_caps = list(set(caps_for_user).intersection(caps_for_topic))
                        if common_caps:
                            self._user_to_permissions[user].add(topic)
                        else:
                            try:
                                self._user_to_permissions[user].remove(topic)
                            except KeyError as e:
                                if not self._user_to_permissions[user]:
                                    self._user_to_permissions[user] = set()
                    except KeyError as e:
                        try:
                            self._user_to_permissions[user].remove(topic)
                        except KeyError as e:
                            if not self._user_to_permissions[user]:
                                self._user_to_permissions[user] = set()

        all = set()
        for user in user_to_caps:
            all.update(self._user_to_permissions[user])

        # Set topic permissions now
        for peer in peers:
            not_allowed = all.difference(self._user_to_permissions[peer])
            self._update_topic_permission_tokens(peer, not_allowed)

    def _update_topic_permission_tokens(self, identity, not_allowed):
        """
        Make rules for read and write permission on topic (routing key)
        for an agent based on protected topics setting
        :param identity: identity of the agent
        :return:
        """
        read_tokens = [
            "{instance}.{identity}".format(instance=self.core.instance_name, identity=identity),
            "__pubsub__.*",
        ]
        write_tokens = ["{instance}.*".format(instance=self.core.instance_name, identity=identity)]

        if not not_allowed:
            write_tokens.append("__pubsub__.{instance}.*".format(instance=self.core.instance_name))
        else:
            not_allowed_string = "|".join(not_allowed)
            write_tokens.append("__pubsub__.{instance}.".format(instance=self.core.instance_name) +
                                "^(!({not_allow})).*$".format(not_allow=not_allowed_string))
        current = self.core.rmq_mgmt.get_topic_permissions_for_user(identity)
        # _log.debug("CURRENT for identity: {0}, {1}".format(identity, current))
        if current and isinstance(current, list):
            current = current[0]
            dift = False
            read_allowed_str = "|".join(read_tokens)
            write_allowed_str = "|".join(write_tokens)
            if re.search(current["read"], read_allowed_str):
                dift = True
                current["read"] = read_allowed_str
            if re.search(current["write"], write_allowed_str):
                dift = True
                current["write"] = write_allowed_str
                # _log.debug("NEW {0}, DIFF: {1} ".format(current, dift))
                # if dift:
                #     set_topic_permissions_for_user(current, identity)
        else:
            current = dict()
            current["exchange"] = "volttron"
            current["read"] = "|".join(read_tokens)
            current["write"] = "|".join(write_tokens)
            # _log.debug("NEW {0}, New string ".format(current))
            # set_topic_permissions_for_user(current, identity)

    def _check_token(self, actual, allowed):
        pending = actual[:]
        for tk in actual:
            if tk in allowed:
                pending.remove(tk)
        return pending


class String(str):

    def __new__(cls, value):
        obj = super(String, cls).__new__(cls, value)
        if isregex(obj):
            obj.regex = regex = re.compile("^" + obj[1:-1] + "$")
            obj.match = lambda val: bool(regex.match(val))
        return obj

    def match(self, value):
        return value == self


class List(list):

    def match(self, value):
        for elem in self:
            if elem.match(value):
                return True
        return False


class AuthEntryInvalid(AuthException):
    """Exception for invalid AuthEntry objects"""

    pass


class AuthEntry(object):
    """An authentication entry contains fields for authenticating and
    granting permissions to an agent that connects to the platform.

    :param str domain: Name assigned to locally bound address
    :param str address: Remote address of the agent
    :param str mechanism: Authentication mechanism, valid options are
        'NULL' (no authentication), 'PLAIN' (username/password),
        'CURVE' (CurveMQ public/private keys)
    :param str credentials: Value depends on `mechanism` parameter:
        `None` if mechanism is 'NULL'; password if mechanism is
        'PLAIN'; encoded public key if mechanism is 'CURVE' (see
        :py:meth:`volttron.platform.vip.socket.encode_key` for method
        to encode public key)
    :param str user_id: Name to associate with agent (Note: this does
        not have to match the agent's VIP identity)
    :param list capabilities: Authorized capabilities for this agent
    :param list roles: Authorized roles for this agent. (Role names map
        to a set of capabilities)
    :param list groups: Authorized groups for this agent. (Group names
        map to a set of roles)
    :param str comments: Comments to associate with entry
    :param bool enabled: Entry will only be used if this value is True
    :param kwargs: These extra arguments will be ignored
    """

    def __init__(
        self,
        domain=None,
        address=None,
        mechanism="CURVE",
        credentials=None,
        user_id=None,
        groups=None,
        roles=None,
        capabilities: Optional[dict] = None,
        comments=None,
        enabled=True,
        **kwargs,
    ):

        self.domain = AuthEntry._build_field(domain)
        self.address = AuthEntry._build_field(address)
        self.mechanism = mechanism
        self.credentials = AuthEntry._build_field(credentials)
        self.groups = AuthEntry._build_field(groups) or []
        self.roles = AuthEntry._build_field(roles) or []
        self.capabilities = AuthEntry.build_capabilities_field(capabilities) or {}
        self.comments = AuthEntry._build_field(comments)
        if user_id is None:
            user_id = str(uuid.uuid4())
        self.user_id = user_id
        self.enabled = enabled
        if kwargs:
            _log.debug("auth record has unrecognized keys: %r" % (list(kwargs.keys()), ))
        self._check_validity()

    def __lt__(self, other):
        """Entries with non-regex credentials will be less than regex
        credentials. When sorted, the non-regex credentials will be
        checked first."""
        try:
            self.credentials.regex
        except AttributeError:
            return True
        return False

    @staticmethod
    def _build_field(value):
        if not value:
            return None
        if isinstance(value, str):
            return String(value)
        return List(String(elem) for elem in value)

    @staticmethod
    def build_capabilities_field(value: Optional[dict]):
        # _log.debug("_build_capabilities {}".format(value))

        if not value:
            return None

        if isinstance(value, list):
            result = dict()
            for elem in value:
                # update if it is not there or if existing entry doesn't have args.
                # i.e. capability with args can override capability str
                temp = result.update(AuthEntry._get_capability(elem))
                if temp and result[next(iter(temp))] is None:
                    result.update(temp)
            _log.debug("Returning field _build_capabilities {}".format(result))
            return result
        else:
            return AuthEntry._get_capability(value)

    @staticmethod
    def _get_capability(value):
        err_message = (
            "Invalid capability value: {} of type {}. Capability entries can only be a string or "
            "dictionary or list containing string/dictionary. "
            "dictionaries should be of the format {'capability_name':None} or "
            "{'capability_name':{'arg1':'value',...}")
        if isinstance(value, str):
            return {value: None}
        elif isinstance(value, dict):
            return value
        else:
            raise AuthEntryInvalid(err_message.format(value, type(value)))

    def add_capabilities(self, capabilities):
        temp = AuthEntry.build_capabilities_field(capabilities)
        if temp:
            self.capabilities.update(temp)

    def match(self, domain, address, mechanism, credentials):
        return ((self.domain is None or self.domain.match(domain))
                and (self.address is None or self.address.match(address))
                and self.mechanism == mechanism
                and (self.mechanism == "NULL" or
                     (len(self.credentials) > 0 and self.credentials.match(credentials[0]))))

    def __str__(self):
        return ("domain={0.domain!r}, address={0.address!r}, "
                "mechanism={0.mechanism!r}, credentials={0.credentials!r}, "
                "user_id={0.user_id!r}, capabilities={0.capabilities!r}".format(self))

    def __repr__(self):
        cls = self.__class__
        return "%s.%s(%s)" % (cls.__module__, cls.__name__, self)

    @staticmethod
    def valid_credentials(cred, mechanism="CURVE"):
        """Raises AuthEntryInvalid if credentials are invalid"""
        AuthEntry.valid_mechanism(mechanism)
        if mechanism == "NULL":
            return
        if cred is None:
            raise AuthEntryInvalid(
                "credentials parameter is required for mechanism {}".format(mechanism))
        if isregex(cred):
            return
        if mechanism == "CURVE" and len(cred) != BASE64_ENCODED_CURVE_KEY_LEN:
            raise AuthEntryInvalid("Invalid CURVE public key {}")

    @staticmethod
    def valid_mechanism(mechanism):
        """Raises AuthEntryInvalid if mechanism is invalid"""
        if mechanism not in ("NULL", "PLAIN", "CURVE"):
            raise AuthEntryInvalid('mechanism must be either "NULL", "PLAIN" or "CURVE"')

    def _check_validity(self):
        """Raises AuthEntryInvalid if entry is invalid"""
        AuthEntry.valid_credentials(self.credentials, self.mechanism)


class AuthFile(object):

    def __init__(self, auth_file=None):
        if auth_file is None:
            auth_file_dir = cc.get_volttron_home()
            auth_file = os.path.join(auth_file_dir, "auth.json")
        self.auth_file = auth_file
        self._check_for_upgrade()

    @property
    def version(self):
        return {"major": 1, "minor": 2}

    def _check_for_upgrade(self):
        allow_list, deny_list, groups, roles, version = self._read()
        if version != self.version:
            if version["major"] <= self.version["major"]:
                self._upgrade(allow_list, deny_list, groups, roles, version)
            else:
                _log.error("This version of VOLTTRON cannot parse {}. "
                           "Please upgrade VOLTTRON or move or delete "
                           "this file.".format(self.auth_file))

    def _read(self):
        auth_data = {}
        try:
            create_file_if_missing(self.auth_file)
            with open(self.auth_file) as fil:
                # Use gevent FileObject to avoid blocking the thread
                before_strip_comments = FileObject(fil, close=False).read()
                if isinstance(before_strip_comments, bytes):
                    before_strip_comments = before_strip_comments.decode("utf-8")
                data = strip_comments(before_strip_comments)
                if data:
                    auth_data = jsonapi.loads(data)
        except Exception:
            _log.exception("error loading %s", self.auth_file)

        allow_list = auth_data.get("allow", [])
        deny_list = auth_data.get("deny", [])
        groups = auth_data.get("groups", {})
        roles = auth_data.get("roles", {})
        version = auth_data.get("version", {"major": 0, "minor": 0})
        return allow_list, deny_list, groups, roles, version

    def read(self):
        """Gets the allowed entries, groups, and roles from the auth
        file.

        :returns: tuple of allow-entries-list, groups-dict, roles-dict
        :rtype: tuple
        """
        allow_list, deny_list, groups, roles, _ = self._read()
        allow_entries, deny_entries = self._get_entries(allow_list, deny_list)
        self._use_groups_and_roles(allow_entries, groups, roles)
        return allow_entries, deny_entries, groups, roles

    def _upgrade(self, allow_list, deny_list, groups, roles, version):
        backup = self.auth_file + "." + str(uuid.uuid4()) + ".bak"
        shutil.copy(self.auth_file, backup)
        _log.info("Created backup of {} at {}".format(self.auth_file, backup))

        def warn_invalid(entry, msg=""):
            _log.warning("Invalid entry {} in auth file {}. {}".format(entry, self.auth_file, msg))

        def upgrade_0_to_1(allow_list):
            new_allow_list = []
            for entry in allow_list:
                try:
                    credentials = entry["credentials"]
                except KeyError:
                    warn_invalid(entry)
                    continue
                if isregex(credentials):
                    msg = "Cannot upgrade entries with regex credentials"
                    warn_invalid(entry, msg)
                    continue
                if credentials == "NULL":
                    mechanism = "NULL"
                    credentials = None
                else:
                    match = re.match(r"^(PLAIN|CURVE):(.*)", credentials)
                    if match is None:
                        msg = "Expected NULL, PLAIN, or CURVE credentials"
                        warn_invalid(entry, msg)
                        continue
                    try:
                        mechanism = match.group(1)
                        credentials = match.group(2)
                    except IndexError:
                        warn_invalid(entry, "Unexpected credential format")
                        continue
                new_allow_list.append({
                    "domain": entry.get("domain"),
                    "address": entry.get("address"),
                    "mechanism": mechanism,
                    "credentials": credentials,
                    "user_id": entry.get("user_id"),
                    "groups": entry.get("groups", []),
                    "roles": entry.get("roles", []),
                    "capabilities": entry.get("capabilities", []),
                    "comments": entry.get("comments"),
                    "enabled": entry.get("enabled", True),
                })
            return new_allow_list

        def upgrade_1_0_to_1_1(allow_list):
            new_allow_list = []
            user_id_set = set()
            for entry in allow_list:
                user_id = entry.get("user_id")
                if user_id:
                    if user_id in user_id_set:
                        new_user_id = str(uuid.uuid4())
                        msg = ("user_id {} is already present in "
                               "authentication entry. Changed to user_id to "
                               "{}").format(user_id, new_user_id)
                        _log.warning(msg)
                        user_id_ = new_user_id
                else:
                    user_id = str(uuid.uuid4())
                user_id_set.add(user_id)
                entry["user_id"] = user_id
                new_allow_list.append(entry)
            return new_allow_list

        def upgrade_1_1_to_1_2(allow_list):
            new_allow_list = []
            for entry in allow_list:
                user_id = entry.get("user_id")
                if user_id in [CONTROL, VOLTTRON_CENTRAL_PLATFORM]:
                    user_id = "/.*/"
                capabilities = entry.get("capabilities")
                entry["capabilities"] = (AuthEntry.build_capabilities_field(capabilities) or {})
                entry["capabilities"]["edit_config_store"] = {"identity": user_id}
                new_allow_list.append(entry)
            return new_allow_list

        if version["major"] == 0:
            allow_list = upgrade_0_to_1(allow_list)
            version["major"] = 1
            version["minor"] = 0
        if version["major"] == 1 and version["minor"] == 0:
            allow_list = upgrade_1_0_to_1_1(allow_list)
            version["minor"] = 1
        if version["major"] == 1 and version["minor"] == 1:
            allow_list = upgrade_1_1_to_1_2(allow_list)

        allow_entries, deny_entries = self._get_entries(allow_list, deny_list)
        self._write(allow_entries, deny_entries, groups, roles)

    def read_allow_entries(self):
        """Gets the allowed entries from the auth file.

        :returns: list of allow-entries
        :rtype: list
        """
        return self.read()[0]

    def read_deny_entries(self):
        """Gets the denied entries from the auth file.

        :returns: list of deny-entries
        :rtype: list
        """
        return self.read()[1]

    def find_by_credentials(self, credentials, is_allow=True):
        """Find all entries that have the given credentials

        :param str credentials: The credentials to search for
        :return: list of entries
        :rtype: list
        """

        if is_allow:
            return [
                entry for entry in self.read_allow_entries()
                if str(entry.credentials) == credentials
            ]
        else:
            return [
                entry for entry in self.read_deny_entries()
                if str(entry.credentials) == credentials
            ]

    def _get_entries(self, allow_list, deny_list):
        allow_entries = []
        for file_entry in allow_list:
            try:
                entry = AuthEntry(**file_entry)
            except TypeError:
                _log.warning("invalid entry %r in auth file %s", file_entry, self.auth_file)
            except AuthEntryInvalid as e:
                _log.warning(
                    "invalid entry %r in auth file %s (%s)",
                    file_entry,
                    self.auth_file,
                    str(e),
                )
            else:
                allow_entries.append(entry)

        deny_entries = []
        for file_entry in deny_list:
            try:
                entry = AuthEntry(**file_entry)
            except TypeError:
                _log.warn("invalid entry %r in auth file %s", file_entry, self.auth_file)
            except AuthEntryInvalid as e:
                _log.warn(
                    "invalid entry %r in auth file %s (%s)",
                    file_entry,
                    self.auth_file,
                    str(e),
                )
            else:
                deny_entries.append(entry)
        return allow_entries, deny_entries

    def _use_groups_and_roles(self, entries, groups, roles):
        """Add capabilities to each entry based on groups and roles"""
        for entry in entries:
            entry_roles = entry.roles
            # Each group is a list of roles
            for group in entry.groups:
                entry_roles += groups.get(group, [])
            capabilities = []
            # Each role is a list of capabilities
            for role in entry_roles:
                capabilities += roles.get(role, [])
            entry.add_capabilities(list(set(capabilities)))

    def _check_if_exists(self, entry, is_allow=True):
        """Raises AuthFileEntryAlreadyExists if entry is already in file"""
        if is_allow:
            for index, prev_entry in enumerate(self.read_allow_entries()):
                if entry.user_id == prev_entry.user_id:
                    raise AuthFileUserIdAlreadyExists(entry.user_id, [index])

                # Compare AuthEntry objects component-wise, rather than
                # using match, because match will evaluate regex.
                if (prev_entry.domain == entry.domain and prev_entry.address == entry.address
                        and prev_entry.mechanism == entry.mechanism
                        and prev_entry.credentials == entry.credentials):
                    raise AuthFileEntryAlreadyExists([index])
        else:
            for index, prev_entry in enumerate(self.read_deny_entries()):
                if entry.user_id == prev_entry.user_id:
                    raise AuthFileUserIdAlreadyExists(entry.user_id, [index])

                # Compare AuthEntry objects component-wise, rather than
                # using match, because match will evaluate regex.
                if (prev_entry.domain == entry.domain and prev_entry.address == entry.address
                        and prev_entry.mechanism == entry.mechanism
                        and prev_entry.credentials == entry.credentials):
                    raise AuthFileEntryAlreadyExists([index])

    def _update_by_indices(self, auth_entry, indices, is_allow=True):
        """Updates all entries at given indices with auth_entry"""
        for index in indices:
            self.update_by_index(auth_entry, index, is_allow)

    def add(self, auth_entry, overwrite=False, no_error=False, is_allow=True):
        """Adds an AuthEntry to the auth file

        :param auth_entry: authentication entry
        :param overwrite: set to true to overwrite matching entries
        :param no_error:
            set to True to not throw an AuthFileEntryAlreadyExists when attempting to add an exiting entry.

        :type auth_entry: AuthEntry
        :type overwrite: bool
        :type no_error: bool

        .. warning:: If overwrite is set to False and if auth_entry matches an
                     existing entry then this method will raise
                     AuthFileEntryAlreadyExists unless no_error is set to true
        """
        try:
            self._check_if_exists(auth_entry, is_allow)
        except AuthFileEntryAlreadyExists as err:
            if overwrite:
                _log.debug("Updating existing auth entry with {} ".format(auth_entry))
                self._update_by_indices(auth_entry, err.indices, is_allow)
            else:
                if not no_error:
                    raise err
        else:
            allow_entries, deny_entries, groups, roles = self.read()
            if is_allow:
                allow_entries.append(auth_entry)
            else:
                deny_entries.append(auth_entry)
            self._write(allow_entries, deny_entries, groups, roles)
            _log.debug("Added auth entry {} ".format(auth_entry))
        gevent.sleep(1)

    def remove_by_credentials(self, credentials, is_allow=True):
        """Removes entry from auth file by credential

        :para credential: entries will this credential will be
            removed
        :type credential: str
        """
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        entries = [e for e in entries if e.credentials != credentials]
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def remove_by_index(self, index, is_allow=True):
        """Removes entry from auth file by index

        :param index: index of entry to remove
        :type index: int

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        self.remove_by_indices([index], is_allow)

    def remove_by_indices(self, indices, is_allow=True):
        """Removes entry from auth file by indices

        :param indices: list of indicies of entries to remove
        :type indices: list

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        indices = list(set(indices))
        indices.sort(reverse=True)
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        for index in indices:
            try:
                del entries[index]
            except IndexError:
                raise AuthFileIndexError(index)
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def _set_groups_or_roles(self, groups_or_roles, is_group=True):
        param_name = "groups" if is_group else "roles"
        if not isinstance(groups_or_roles, dict):
            raise ValueError("{} parameter must be dict".format(param_name))
        for key, value in groups_or_roles.items():
            if not isinstance(value, list):
                raise ValueError("each value of the {} dict must be "
                                 "a list".format(param_name))
        allow_entries, deny_entries, groups, roles = self.read()
        if is_group:
            groups = groups_or_roles
        else:
            roles = groups_or_roles
        self._write(allow_entries, deny_entries, groups, roles)

    def set_groups(self, groups):
        """Define the mapping of group names to role lists

        :param groups: dict where the keys are group names and the
                       values are lists of capability names
        :type groups: dict

        .. warning:: Calling with invalid groups will raise ValueError
        """
        self._set_groups_or_roles(groups, is_group=True)

    def set_roles(self, roles):
        """Define the mapping of role names to capability lists

        :param roles: dict where the keys are role names and the
                      values are lists of group names
        :type groups: dict

        .. warning:: Calling with invalid roles will raise ValueError
        """
        self._set_groups_or_roles(roles, is_group=False)

    def update_by_index(self, auth_entry, index, is_allow=True):
        """Updates entry will given auth entry at given index

        :param auth_entry: new authorization entry
        :param index: index of entry to update
        :type auth_entry: AuthEntry
        :type index: int

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        try:
            entries[index] = auth_entry
        except IndexError:
            raise AuthFileIndexError(index)
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def _write(self, allow_entries, deny_entries, groups, roles):
        auth = {
            "allow": [vars(x) for x in allow_entries],
            "deny": [vars(x) for x in deny_entries],
            "groups": groups,
            "roles": roles,
            "version": self.version,
        }

        with open(self.auth_file, "w") as fp:
            jsonapi.dump(auth, fp, indent=2)


class AuthFileIndexError(AuthException, IndexError):
    """Exception for invalid indices provided to AuthFile"""

    def __init__(self, indices, message=None):
        if not isinstance(indices, list):
            indices = [indices]
        if message is None:
            message = "Invalid {}: {}".format("indicies" if len(indices) > 1 else "index", indices)
        super(AuthFileIndexError, self).__init__(message)
        self.indices = indices


class AuthFileEntryAlreadyExists(AuthFileIndexError):
    """Exception if adding an entry that already exists"""

    def __init__(self, indicies, message=None):
        if message is None:
            message = ("entry matches domain, address and credentials at "
                       "index {}").format(indicies)
        super(AuthFileEntryAlreadyExists, self).__init__(indicies, message)


class AuthFileUserIdAlreadyExists(AuthFileEntryAlreadyExists):
    """Exception if adding an entry that has a taken user_id"""

    def __init__(self, user_id, indicies, message=None):
        if message is None:
            message = ("user_id {} is already in use at "
                       "index {}").format(user_id, indicies)
        super(AuthFileUserIdAlreadyExists, self).__init__(indicies, message)
