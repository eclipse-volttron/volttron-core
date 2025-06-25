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
from gevent import monkey

monkey.patch_all()
import argparse
import collections
import logging
import logging.config
import logging.handlers
import os
import os as _os
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta
from typing import List

import gevent
import gevent.event
from attrs import define

from volttron.client.commands.connection import ControlConnection
from volttron.client.commands.rpc_parser import add_rpc_agent_parser
from volttron.client.commands.auth_parser import add_auth_parser
from volttron.client.commands.authz_parser import add_authz_parser
from volttron.client.commands.config_store_parser import add_config_store_parser
from volttron.client.commands.install_parser import add_install_agent_parser, add_install_lib_parser
from volttron.client.commands.publish_parser import add_publish_parser
from volttron.client.commands.subscribe_parser import add_subscribe_parser
from volttron.client.known_identities import (AUTH, CONFIGURATION_STORE, PLATFORM_HEALTH)
from volttron.client.vip.agent.errors import Unreachable, VIPError
from volttron.client.vip.agent.subsystems.query import Query
from volttron.utils import ClientContext as cc
from volttron.utils import argparser as config
from volttron.utils import get_address, jsonapi
from volttron.utils.commands import (is_volttron_running, wait_for_volttron_shutdown)
from volttron.utils.jsonrpc import MethodNotFound, RemoteError

_stdout = sys.stdout
_stderr = sys.stderr

# will be volttron.platform.main or main.py instead of __main__
from volttron.client.logs import get_default_client_log_config

_log = logging.getLogger(__name__)

# Allows server side logging.
#_log.setLevel(logging.DEBUG)

message_bus = cc.get_messagebus()

CHUNK_SIZE = 4096


@define
class AgentMeta:
    """Meta class for displaying agent details on the command line.
    """

    name: str
    """
    The name of the agent.
    """

    uuid: str
    """
    The uuid of the agent. This is a unique identifier for the agent.
    """

    identity: str
    """
    The vip identity of the agent.
    """

    agent_user: str = ''
    """
    The user that the agent is running as.  This is only available in agent isolation mode.
    """

    tag: str = ''
    """
    A tag associated with the agent.
    """

    priority: str = '50'
    """
    The startup priority of the agent.
    """

    def __hash__(self):
        return hash(self.uuid)

    def console_format(self, as_json=False, with_priority=False):
        if as_json:
            return jsonapi.dumps(self.__dict__, indent=2)
        else:
            if with_priority:
                return f"{self.name} {self.uuid} {self.identity} {self.agent_user} {self.tag} {self.priority}"
            else:
                return f"{self.name} {self.uuid} {self.identity} {self.agent_user} {self.tag}"

    def __str__(self):
        return f"{self.name} {self.tag} {self.uuid} {self.identity} {self.agent_user}"


def expandall(string):
    return _os.path.expanduser(_os.path.expandvars(string))


def _list_agents(opts) -> List[AgentMeta]:
    """
    Connected to the server and calls the list_agents method.

    Returns:
        List of AgentTuple
    """
    agents = opts.connection.call("list_agents")
    return [AgentMeta(**a) for a in agents]


def escape(pattern):
    strings = re.split(r"([*?])", pattern)
    if len(strings) == 1:
        return re.escape(pattern), False
    return (
        "".join(".*" if s == "*" else "." if s == "?" else s if s in [r"\?", r"\*"] else re.escape(s) for s in strings),
        True,
    )


def filter_agents(agents: List[AgentMeta], patterns: List[str], opts: argparse.Namespace):
    """
    Filters a given list of agent details based on the provided pattern and user options. User options specify
    what attributes of the agent metadata needs to match the pattern passed. For example should the pattern be applied
    to the agent's tag or agent's name

    :param agents: List of AgentMeta object that contains agents name, tag, uuid, vip_id, and agent_user
    :param patterns: List of patterns to match
    :param opts: command line options that specify what attribute of the agent should be matched against the pattern
    :return: yields the pattern and the List of AgentMeta that matched the pattern
    """
    by_name, by_tag, by_uuid, by_all_tagged = opts.by_name, opts.by_tag, opts.by_uuid, opts.by_all_tagged
    for pattern in patterns:
        regex, _ = escape(pattern)
        result = set()

        # if no option is selected, try matching based on uuid
        if not (by_uuid or by_name or by_tag or by_all_tagged):
            reobj = re.compile(regex)
            matches = [agent for agent in agents if reobj.match(agent.uuid)]
            if len(matches) == 1:
                result.update(matches)
            # if no match is found based on uuid, try matching on agent name
            elif len(matches) == 0:
                matches = [agent for agent in agents if reobj.match(agent.name)]
                if len(matches) >= 1:
                    result.update(matches)
        else:
            reobj = re.compile(regex + "$")
            if by_uuid:
                result.update(agent for agent in agents if reobj.match(agent.uuid))
            if by_name:
                result.update(agent for agent in agents if reobj.match(agent.name))
            if by_tag:
                result.update(agent for agent in agents if reobj.match(agent.tag or ""))
            if by_all_tagged:
                result.update(agent for agent in agents if reobj.match(agent.tag))
        yield pattern, result


def filter_agent(agents, pattern, opts):
    return next(filter_agents(agents, [pattern], opts))[1]


def backup_agent_data(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.sep)    # os.path.basename(source_dir))


def restore_agent_data_from_tgz(source_file, output_dir):
    # Open tarfile
    with tarfile.open(source_file, mode="r:gz") as tar:

        def is_within_directory(directory, target):

            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)

            prefix = os.path.commonprefix([abs_directory, abs_target])

            return prefix == abs_directory

        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):

            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")

            tar.extractall(path, members, numeric_owner=numeric_owner)

        safe_extract(tar, output_dir)


def get_agent_data_dir_by_uuid(opts, agent_uuid):
    # Find agent-data directory path, create if missing
    agent_data_dir = opts.aip.get_agent_data_dir(agent_uuid=agent_uuid)
    return agent_data_dir


def get_agent_data_dir_by_vip_id(opts, vip_identity):
    agent_data_dir = opts.aip.get_agent_data_dir(vip_identity=vip_identity)
    return agent_data_dir


def tag_agent(opts):
    agents = filter_agent(_list_agents(opts), opts.agent, opts)
    if len(agents) != 1:
        if agents:
            msg = "multiple agents selected"
        else:
            msg = "agent not found"
        _stderr.write("{}: error: {}: {}\n".format(opts.command, msg, opts.agent))
        return 10
    (agent, ) = agents
    if opts.tag:
        _stdout.write("Tagging {} {}\n".format(agent.uuid, agent.name))
        opts.connection.call("tag_agent", agent.uuid, opts.tag)
    elif opts.remove:
        if agent.tag is not None:
            _stdout.write("Removing tag for {} {}\n".format(agent.uuid, agent.name))
            opts.connection.call("tag_agent", agent.uuid, None)
    else:
        if agent.tag is not None:
            _stdout.writelines([agent.tag, "\n"])


def remove_agent(opts, remove_auth=True):
    agents = _list_agents(opts)
    for pattern, match in filter_agents(agents, opts.pattern, opts):
        if not match:
            _stderr.write("{}: error: agent not found: {}\n".format(opts.command, pattern))
        elif len(match) > 1 and not opts.force:
            _stderr.write("{}: error: pattern returned multiple agents: {}\n".format(opts.command, pattern))
            _stderr.write("Use -f or --force to force removal of multiple agents.\n")
            return 10
        for agent in match:
            _stdout.write("Removing {} {}\n".format(agent.uuid, agent.name))
            opts.connection.call("remove_agent", agent.uuid, remove_auth=remove_auth)


def _calc_min_uuid_length(agents: list[AgentMeta]):
    n = 0
    for agent1 in agents:
        for agent2 in agents:
            if agent1 is agent2:
                continue
            if isinstance(agent2, str) or isinstance(agent1, str):
                continue
            common_len = len(os.path.commonprefix([agent1.uuid, agent2.uuid]))
            if common_len > n:
                n = common_len
    return n + 1


def list_agents(opts):

    def get_priority(agent):
        return opts.aip.agent_priority(agent.uuid) or ""

    _show_filtered_agents(opts, "PRI", get_priority)


def list_peers(opts):
    conn = opts.connection
    peers = sorted(conn.call("peerlist"))
    for peer in peers:
        sys.stdout.write("{}\n".format(peer))


# def print_rpc_list(peers, code=False):
#     for peer in peers:
#         print(f"{peer}")
#         for method in peers[peer]:
#             if code:
#                 print(f"\tself.vip.rpc.call({peer}, {method}).get()")
#             else:
#                 print(f"\t{method}")

# def print_rpc_methods(opts, peer_method_metadata, code=False):
#     for peer in peer_method_metadata:
#         if code is True:
#             pass
#         else:
#             print(f"{peer}")
#         for method in peer_method_metadata[peer]:
#             params = peer_method_metadata[peer][method].get("params",
#                                                             "No parameters for this method.")
#             if code is True:
#                 if len(params) == 0:
#                     print(f"self.vip.rpc.call({peer}, {method}).get()")
#                 else:
#                     print(
#                         f"self.vip.rpc.call({peer}, {method}, {[param for param in params]}).get()"
#                     )
#                 continue
#             else:
#                 print(f"\t{method}")
#                 if opts.verbose == True:
#                     print("\tDocumentation:")
#                     doc = (peer_method_metadata[peer][method].get(
#                         "doc", "No documentation for this method.").replace("\n", "\n\t\t"))
#                     print(f"\t\t{doc}\n")
#             print("\tParameters:")
#             if type(params) is str:
#                 print(f"\t\t{params}")
#             else:
#                 for param in params:
#                     print(f"\t\t{param}:\n\t\t\t{params[param]}")

# def list_agents_rpc(opts):
#     conn = opts.connection
#     try:
#         peers = sorted(conn.call("peerlist"))
#     except Exception as e:
#         print(e)
#     if opts.by_vip == True or len(opts.pattern) == 1:
#         peers = [peer for peer in peers if peer in opts.pattern]
#     elif len(opts.pattern) > 1:
#         peer = opts.pattern[0]
#         methods = opts.pattern[1:]
#         peer_method_metadata = {peer: {}}
#         for method in methods:
#             try:
#                 peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
#                     peer, f"{method}.inspect").get(timeout=4)
#             except gevent.Timeout:
#                 print(f"{peer} has timed out.")
#             except Unreachable:
#                 print(f"{peer} is unreachable")
#             except MethodNotFound as e:
#                 print(e)

#         # _stdout.write(f"{peer_method_metadata}\n")
#         print_rpc_methods(opts, peer_method_metadata)
#         return
#     peer_methods = {}
#     for peer in peers:
#         try:
#             peer_methods[peer] = conn.server.vip.rpc.call(peer,
#                                                           "inspect").get(timeout=4)["methods"]
#         except gevent.Timeout:
#             print(f"{peer} has timed out")
#         except Unreachable:
#             print(f"{peer} is unreachable")
#         except MethodNotFound as e:
#             print(e)

#     if opts.verbose is True:
#         print_rpc_list(peer_methods)
#         # for peer in peer_methods:
#         #     _stdout.write(f"{peer}:{peer_methods[peer]}\n")
#     else:
#         for peer in peer_methods:
#             peer_methods[peer] = [method for method in peer_methods[peer] if "." not in method]
#             # _stdout.write(f"{peer}:{peer_methods[peer]}\n")
#         print_rpc_list(peer_methods)

# def list_agent_rpc_code(opts):
#     conn = opts.connection
#     try:
#         peers = sorted(conn.call("peerlist"))
#     except Exception as e:
#         print(e)
#     if len(opts.pattern) == 1:
#         peers = [peer for peer in peers if peer in opts.pattern]
#     elif len(opts.pattern) > 1:
#         peer = opts.pattern[0]
#         methods = opts.pattern[1:]
#         peer_method_metadata = {peer: {}}
#         for method in methods:
#             try:
#                 peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
#                     peer, f"{method}.inspect").get(timeout=4)
#             except gevent.Timeout:
#                 print(f"{peer} has timed out.")
#             except Unreachable:
#                 print(f"{peer} is unreachable")
#             except MethodNotFound as e:
#                 print(e)

#         # _stdout.write(f"{peer_method_metadata}\n")
#         print_rpc_methods(opts, peer_method_metadata, code=True)
#         return

#     peer_methods = {}
#     for peer in peers:
#         try:
#             peer_methods[peer] = conn.server.vip.rpc.call(peer,
#                                                           "inspect").get(timeout=4)["methods"]
#         except gevent.Timeout:
#             print(f"{peer} has timed out.")
#         except Unreachable:
#             print(f"{peer} is unreachable")
#         except MethodNotFound as e:
#             print(e)

#     if opts.verbose is True:
#         pass
#     else:
#         for peer in peer_methods:
#             peer_methods[peer] = [method for method in peer_methods[peer] if "." not in method]

#     peer_method_metadata = {}
#     for peer in peer_methods:
#         peer_method_metadata[peer] = {}
#         for method in peer_methods[peer]:
#             try:
#                 peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
#                     peer, f"{method}.inspect").get(timeout=4)
#             except gevent.Timeout:
#                 print(f"{peer} has timed out")
#             except Unreachable:
#                 print(f"{peer} is unreachable")
#             except MethodNotFound as e:
#                 print(e)
#     print_rpc_methods(opts, peer_method_metadata, code=True)


def list_remotes(opts):
    """Lists remote certs and credentials.
    Can be filters using the '--status' option, specifying
    pending, approved, or denied.
    The output printed includes:
        user id of a ZMQ credential, or the common name of a CSR
        remote address of the credential or csr
        status of the credential or cert (either APPROVED, DENIED, or PENDING)

    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    output_view = []
    try:
        pending_csrs = conn.server.vip.rpc.call(AUTH, "get_pending_csrs").get(timeout=4)
        for csr in pending_csrs:
            output_view.append({
                "entry": {
                    "user_id": csr["identity"],
                    "address": csr["remote_ip_address"],
                },
                "status": csr["status"],
            })
    except TimeoutError:
        print("Certs timed out")
    try:
        approved_certs = conn.server.vip.rpc.call(AUTH, "get_authorization_approved").get(timeout=4)
        for value in approved_certs:
            output_view.append({"entry": value, "status": "APPROVED"})
    except TimeoutError:
        print("Approved credentials timed out")
    try:
        denied_certs = conn.server.vip.rpc.call(AUTH, "get_authorization_denied").get(timeout=4)
        for value in denied_certs:
            output_view.append({"entry": value, "status": "DENIED"})
    except TimeoutError:
        print("Denied credentials timed out")
    try:
        pending_certs = conn.server.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=4)
        for value in pending_certs:
            output_view.append({"entry": value, "status": "PENDING"})
    except TimeoutError:
        print("Pending credentials timed out")

    if not output_view:
        print("No remote certificates or credentials")
        return

    if opts.status == "approved":
        output_view = [output for output in output_view if output["status"] == "APPROVED"]

    elif opts.status == "denied":
        output_view = [output for output in output_view if output["status"] == "DENIED"]

    elif opts.status == "pending":
        output_view = [output for output in output_view if output["status"] == "PENDING"]

    elif opts.status is not None:
        _stdout.write("Invalid parameter. Please use 'approved', 'denied', 'pending', or leave blank to list all.\n")
        return

    if len(output_view) == 0:
        print(f"No {opts.status} remote certificates or credentials")
        return

    for output in output_view:
        for value in output["entry"]:
            if not output["entry"][value]:
                output["entry"][value] = "-"

    userid_width = max(5, max(len(str(output["entry"]["user_id"])) for output in output_view))
    address_width = max(5, max(len(str(output["entry"]["address"])) for output in output_view))
    status_width = max(5, max(len(str(output["status"])) for output in output_view))
    fmt = "{:{}} {:{}} {:{}}\n"
    _stderr.write(fmt.format(
        "USER_ID",
        userid_width,
        "ADDRESS",
        address_width,
        "STATUS",
        status_width,
    ))
    fmt = "{:{}} {:{}} {:{}}\n"
    for output in output_view:
        _stdout.write(
            fmt.format(
                output["entry"]["user_id"],
                userid_width,
                output["entry"]["address"],
                address_width,
                output["status"],
                status_width,
            ))


def approve_remote(opts):
    """Approves either a pending CSR or ZMQ credential.
    The platform must be running for this command to succeed.
    :param opts.user_id: The ZMQ credential user_id or pending CSR common name
    :type opts.user_id: str
    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return
    conn.server.vip.rpc.call(AUTH, "approve_authorization_failure", opts.user_id).get(timeout=4)


def deny_remote(opts):
    """Denies either a pending CSR or ZMQ credential.
    The platform must be running for this command to succeed.
    :param opts.user_id: The ZMQ credential user_id or pending CSR common name
    :type opts.user_id: str
    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return
    conn.server.vip.rpc.call(AUTH, "deny_authorization_failure", opts.user_id).get(timeout=4)


def delete_remote(opts):
    """Deletes either a pending CSR or ZMQ credential.
    The platform must be running for this command to succeed.
    :param opts.user_id: The ZMQ credential user_id or pending CSR common name
    :type opts.user_id: str
    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return
    conn.server.vip.rpc.call(AUTH, "delete_authorization_failure", opts.user_id).get(timeout=4)


# the following global variables are used to update the cache so
# that we don't ask the platform too many times for the data
# associated with health.
health_cache_timeout_date = None
health_cache_timeout = 5
health_cache = {}


def update_health_cache(opts):
    global health_cache_timeout_date

    t_now = datetime.now()
    do_update = True
    # Make sure we update if we don't have any health dicts, or if the cache has timed out.
    if (health_cache_timeout_date is not None and t_now < health_cache_timeout_date and health_cache):
        do_update = False

    if do_update:
        health_cache.clear()
        response = opts.connection.server.vip.rpc.call(PLATFORM_HEALTH, "get_platform_health").get(timeout=4)
        health_cache.update(response)
        health_cache_timeout_date = datetime.now() + timedelta(seconds=health_cache_timeout)


def status_agents(opts):
    all_agents = {agent.uuid: agent for agent in _list_agents(opts)}
    status = {}
    agents_with_status = opts.connection.call("status_agents", get_agent_user=True)
    for details in agents_with_status:
        if cc.is_secure_mode():
            (uuid, name, agent_user, stat, identity) = details
        else:
            (uuid, name, stat, identity) = details
            agent_user = ""
        try:
            agent = all_agents[uuid]
            print(f"Agent user is {agent_user}")
            print(f"agent is {agent}")
            all_agents[uuid] = agent
        except KeyError:
            all_agents[uuid] = AgentMeta(name=name, uuid=uuid, identity=identity, agent_user=agent_user)
        status[uuid] = stat
    all_agents = list(all_agents.values())

    def get_status(agent):
        try:
            pid, stat = status[agent.uuid]
        except KeyError:
            pid = stat = None

        if stat is not None:
            return str(stat)
        if pid:
            return "running [{}]".format(pid)
        return ""

    def get_health(agent):
        update_health_cache(opts)

        try:
            health_dict = health_cache.get(agent.identity)

            if health_dict:
                if opts.json:
                    return health_dict
                else:
                    return health_dict.get("message", "")
            else:
                return ""
        except (VIPError, gevent.Timeout):
            return ""

    def get_priority(agent):
        return opts.connection.call("agent_priority", agent.uuid)

    _show_filtered_agents_status(opts, get_status, get_health, get_priority, all_agents)


def agent_health(opts):
    agents = {agent.uuid: agent for agent in _list_agents(opts)}.values()
    agents = get_filtered_agents(opts, agents)
    if not agents:
        if not opts.json:
            _stderr.write("No installed Agents found\n")
        else:
            _stdout.write(f"{jsonapi.dumps({}, indent=2)}\n")
        return
    agent = agents.pop()
    update_health_cache(opts)

    data = health_cache.get(agent.identity)

    if not data:
        if not opts.json:
            _stdout.write(f"No health associated with {agent.identity}\n")
        else:
            _stdout.write(f"{jsonapi.dumps({}, indent=2)}\n")
    else:
        _stdout.write(f"{jsonapi.dumps(data, indent=4)}\n")


def clear_status(opts):
    opts.connection.call("clear_status", opts.clear_all)


def enable_agent(opts):
    if opts.json:
        result_dict = {"enabled": True, "priority": opts.priority}
    else:
        result_dict = {"str_prefix": "Enabling", "str_suffix": f"with priority {opts.priority}"}

    enable_disable_agent(opts, result_dict)


def disable_agent(opts):
    if opts.json:
        result_dict = {"disabled": True}
    else:
        result_dict = {"str_prefix": "Disabling"}

    enable_disable_agent(opts, result_dict)


def enable_disable_agent(opts, result_info):
    """
    Enable or disable agent based on command set in opts.command and pattern set in opts
    :param opts: options that include the enable/disable command, any optional pattern and the agent attribute that
     should be matched against the given pattern
    :param result_info: dictionary of additional information to be added to result
    """
    agents = _list_agents(opts)
    results = []
    for pattern, match in filter_agents(agents, opts.pattern, opts):
        if not match:
            if opts.json:
                results.append({"command": opts.command, "error": f"agent not found {pattern}"})
            else:
                _stderr.write(f"{opts.command}: error: agent not found: {pattern}\n")
        for agent in match:
            if opts.json:
                result = {"uuid": agent.uuid, "name": agent.name}
                result.update(result_info)
                results.append(result)
            else:
                _stdout.write(f"{result_info.get('str_prefix', '')} {agent.uuid} {agent.name} "
                              f"{result_info.get('str_suffix', '')}\n")
            opts.connection.call("prioritize_agent", agent.uuid, None)
    if opts.json:
        if len(results) == 1:
            _stdout.write(f"{jsonapi.dumps(results[0], indent=2)}\n")
        else:
            _stdout.write(f"{jsonapi.dumps(results, indent=2)}\n")


def start_agent(opts):
    act_on_agent("start_agent", opts)


def stop_agent(opts):
    act_on_agent("stop_agent", opts)


def restart_agent(opts):
    stop_agent(opts)
    start_agent(opts)


def act_on_agent(action: str, opts: argparse.Namespace):
    """
    Starts or stops agents that match the given criteria

    :param action: "start_agent" or "stop_agent"
    :param opts: contains the patterns to match and the agent attribute/metadata that should be matched against the
                 given pattern
    """
    call = opts.connection.call
    agents = _list_agents(opts)
    pattern_to_use = opts.pattern

    if not opts.by_all_tagged and not opts.pattern:
        raise ValueError("Missing argument. Command requires at least one argument.")

    # prefilter all agents and update regex pattern for only tagged agents
    if opts.by_all_tagged and not opts.pattern:
        agents, pattern_to_use = [a for a in agents if a.tag is not None], '*'

    for pattern, match in filter_agents(agents, pattern_to_use, opts):
        if not match:
            _stderr.write(f"{opts.command}: error: agent not found: {pattern}\n")
        for agent in match:
            pid, status = call("agent_status", agent.uuid)
            _call_action_on_agent(agent, pid, status, call, action)


def _call_action_on_agent(agent: AgentMeta, pid, status, call, action):
    """
    Calls server side method to start or stop agent and writes the corresponding message to stdout

    :param agent: Agent metadata data containing uuid, name, vip_id, agent priority
    :param pid: pid of Agent process
    :param status: Status of the start or stop process
    :param call: method that makes the rpc call to corresponding server side method
    :param action: start_agent or stop_agent
    """
    if action == "start_agent":
        if pid is None or status is not None:
            _stdout.write(f"Starting {agent.uuid} {agent.name}\n")
            call(action, agent.uuid)
            return

    if action == "stop_agent":
        if pid and status is None:
            _stdout.write(f"Stopping {agent.uuid} {agent.name}\n")
            call(action, agent.uuid)
            return


def run_agent(opts):
    call = opts.connection.call
    for directory in opts.directory:
        call("run_agent", directory)


def shutdown_agents(opts):
    # TODO: RMQ
    # if 'rmq' == utils.get_messagebus():
    #     if not check_rabbit_status():
    #         rmq_cfg = RMQConfig()
    #         wait_period = rmq_cfg.reconnect_delay() if rmq_cfg.reconnect_delay() < 60 else 60
    #         _stderr.write(
    #             'RabbitMQ server is not running.\n'
    #             'Waiting for {} seconds for possible reconnection and to perform normal shutdown\n'.format(wait_period))
    #         gevent.sleep(wait_period)
    #         if not check_rabbit_status():
    #             _stderr.write(
    #                 'RabbitMQ server is still not running.\nShutting down the platform forcefully\n')
    #             opts.aip.brute_force_platform_shutdown()
    #             return
    opts.connection.call("shutdown")
    _log.debug("Calling stop_platform")
    if opts.platform:
        opts.connection.notify("stop_platform")
        wait_for_volttron_shutdown(cc.get_volttron_home(), 60)


# def _send_agent(connection, peer, path):
#     wheel = open(path, "rb")
#     channel = connection.vip.channel(peer)
#
#     def send():
#         try:
#             # Wait for peer to open compliment channel
#             channel.recv()
#             while True:
#                 data = wheel.read(8192)
#                 channel.send(data)
#                 if not data:
#                     break
#             # Wait for peer to signal all data received
#             channel.recv()
#         finally:
#             wheel.close()
#             channel.close(linger=0)
#
#     result = connection.vip.rpc.call(
#         peer, "install_agent", os.path.basename(path), channel.name
#     )
#     task = gevent.spawn(send)
#     result.rawlink(lambda glt: task.kill(block=False))
#     _log.debug(f"Result is {result}")
#     return result

# def send_agent(opts):
#     connection = opts.connection
#     for wheel in opts.wheel:
#         uuid = _send_agent(connection.server, connection.peer, wheel).get()
#         return uuid


def gen_keypair(opts):
    keypair = KeyStore.generate_keypair_dict()
    _stdout.write("{}\n".format(jsonapi.dumps(keypair, indent=2)))


def add_server_key(opts):
    store = KnownHostsStore()
    store.add(opts.host, opts.serverkey)
    _stdout.write("server key written to {}\n".format(store.filename))


def list_known_hosts(opts):
    store = KnownHostsStore()
    entries = store.load()
    if entries:
        _print_two_columns(entries, "HOST", "CURVE KEY")
    else:
        _stdout.write("No entries in {}\n".format(store.filename))


def remove_known_host(opts):
    store = KnownHostsStore()
    store.remove(opts.host)
    _stdout.write('host "{}" removed from {}\n'.format(opts.host, store.filename))


def do_stats(opts):
    call = opts.connection.call
    if opts.op == "status":
        _stdout.write("%sabled\n" % ("en" if call("stats.enabled") else "dis"))
    elif opts.op in ["dump", "pprint"]:
        stats = call("stats.get")
        if opts.op == "pprint":
            import pprint

            pprint.pprint(stats, _stdout)
        else:
            _stdout.writelines([str(stats), "\n"])
    else:
        call("stats." + opts.op)
        _stdout.write("%sabled\n" % ("en" if call("stats.enabled") else "dis"))


def show_serverkey(opts):
    """
    write serverkey to standard out.

    return 0 if success, 1 if false
    """
    q = Query(opts.connection.server.core)
    pk = q.query("serverkey").get(timeout=2)
    del q
    if pk is not None:
        _stdout.write("%s\n" % pk)
        return 0

    return 1


def _get_auth_file(volttron_home):
    path = os.path.join(volttron_home, "auth.json")
    return AuthFile(path)


def _print_two_columns(dict_, key_name, value_name):
    padding = 2
    key_lengths = [len(key) for key in dict_] + [len(key_name)]
    max_key_len = max(key_lengths) + padding
    _stdout.write("{}{}{}\n".format(key_name, " " * (max_key_len - len(key_name)), value_name))
    _stdout.write("{}{}{}\n".format(
        "-" * len(key_name),
        " " * (max_key_len - len(key_name)),
        "-" * len(value_name),
    ))
    for key in sorted(dict_):
        value = dict_[key]
        if isinstance(value, list):
            value = sorted(value)
        _stdout.write("{}{}{}\n".format(key, " " * (max_key_len - len(key)), value))


def list_auth(opts, indices=None):
    auth_file = _get_auth_file(opts.volttron_home)
    entries = auth_file.read_allow_entries()
    print_out = []
    if entries:
        for index, entry in enumerate(entries):
            if indices is None or index in indices:
                _stdout.write("\nINDEX: {}\n".format(index))
                _stdout.write("{}\n".format(jsonapi.dumps(vars(entry), indent=2)))
    else:
        _stdout.write("No entries in {}\n".format(auth_file.auth_file))


# TODO: This needs to be moved to lib-zmq hooks
def _ask_for_auth_fields(
    domain=None,
    address=None,
    user_id=None,
    capabilities=None,
    roles=None,
    groups=None,
    mechanism="CURVE",
    credentials=None,
    comments=None,
    enabled=True,
    **kwargs,
):

    class Asker(object):

        def __init__(self):
            self._fields = collections.OrderedDict()

        def add(
                self,
                name,
                default=None,
                note=None,
                callback=lambda x: x,
                validate=lambda x, y: (True, ""),
        ):
            self._fields[name] = {
                "note": note,
                "default": default,
                "callback": callback,
                "validate": validate,
            }

        def ask(self):
            for name in self._fields:
                note = self._fields[name]["note"]
                default = self._fields[name]["default"]
                callback = self._fields[name]["callback"]
                validate = self._fields[name]["validate"]
                if isinstance(default, list):
                    default_str = "{}".format(",".join(default))
                elif default is None:
                    default_str = ""
                else:
                    default_str = default
                note = "({}) ".format(note) if note else ""
                question = "{} {}[{}]: ".format(name, note, default_str)
                valid = False
                while not valid:
                    response = input(question).strip()
                    if response == "":
                        response = default
                    if response == "clear":
                        if _ask_yes_no("Do you want to clear this field?"):
                            response = None
                    valid, msg = validate(response, self._fields)
                    if not valid:
                        _stderr.write("{}\n".format(msg))

                self._fields[name]["response"] = callback(response)
            return {k: self._fields[k]["response"] for k in self._fields}

    def to_true_or_false(response):
        if isinstance(response, str):
            return {"true": True, "false": False}[response.lower()]
        return response

    def is_true_or_false(x, fields):
        if x is not None:
            if isinstance(x, bool) or x.lower() in ["true", "false"]:
                return True, None
        return False, "Please enter True or False"

    def valid_creds(creds, fields):
        try:
            mechanism = fields["mechanism"]["response"]
            AuthEntry.valid_credentials(creds, mechanism=mechanism)
        except AuthException as e:
            return False, str(e)
        return True, None

    def valid_mech(mech, fields):
        try:
            AuthEntry.valid_mechanism(mech)
        except AuthException as e:
            return False, str(e)
        return True, None

    asker = Asker()
    asker.add("domain", domain)
    asker.add("address", address)
    asker.add("user_id", user_id)
    asker.add(
        "capabilities",
        capabilities,
        "delimit multiple entries with comma",
        _parse_capabilities,
    )
    asker.add("roles", roles, "delimit multiple entries with comma", _comma_split)
    asker.add("groups", groups, "delimit multiple entries with comma", _comma_split)
    asker.add("mechanism", mechanism, validate=valid_mech)
    asker.add("credentials", credentials, validate=valid_creds)
    asker.add("comments", comments)
    asker.add(
        "enabled",
        enabled,
        callback=to_true_or_false,
        validate=is_true_or_false,
    )

    return asker.ask()


def _comma_split(line):
    if not isinstance(line, str):
        return line
    line = line.strip()
    if not line:
        return []
    return [word.strip() for word in line.split(",")]


def _parse_capabilities(line):
    if not isinstance(line, str):
        return line
    line = line.strip()
    try:
        result = jsonapi.loads(line.replace("'", '"'))
    except Exception as e:
        result = _comma_split(line)
    return result


# def add_auth(opts):
#     """Add authorization entry.

#     If all options are None, then use interactive 'wizard.'
#     """
#     fields = {
#         "domain": opts.domain,
#         "address": opts.address,
#         "mechanism": opts.mechanism,
#         "credentials": opts.credentials,
#         "user_id": opts.user_id,
#         "groups": _comma_split(opts.groups),
#         "roles": _comma_split(opts.roles),
#         "capabilities": _parse_capabilities(opts.capabilities),
#         "comments": opts.comments,
#     }

#     if any(fields.values()):
#         # Remove unspecified options so the default parameters are used
#         fields = {k: v for k, v in fields.items() if v}
#         fields["enabled"] = not opts.disabled
#         entry = AuthEntry(**fields)
#     else:
#         # No options were specified, use interactive wizard
#         responses = _ask_for_auth_fields()
#         entry = AuthEntry(**responses)

#     if opts.add_known_host:
#         if entry.address is None:
#             raise ValueError("host (--address) is required when "
#                              "--add-known-host is specified")
#         if entry.credentials is None:
#             raise ValueError("serverkey (--credentials) is required when "
#                              "--add-known-host is specified")
#         opts.host = entry.address
#         opts.serverkey = entry.credentials
#         add_server_key(opts)

#     auth_file = _get_auth_file(opts.volttron_home)
#     try:
#         auth_file.add(entry, overwrite=False)
#         _stdout.write("added entry {}\n".format(entry))
#     except AuthException as err:
#         _stderr.write("ERROR: %s\n" % str(err))


def _ask_yes_no(question, default="yes"):
    yes = set(["yes", "ye", "y"])
    no = set(["no", "n"])
    y = "y"
    n = "n"
    if default in yes:
        y = "Y"
    elif default in no:
        n = "N"
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while True:
        choice = input("{} [{}/{}] ".format(question, y, n)).lower()
        if choice == "":
            choice = default
        if choice in yes:
            return True
        if choice in no:
            return False
        _stderr.write("Please respond with 'yes' or 'no'\n")


def remove_auth(opts):
    auth_file = _get_auth_file(opts.volttron_home)
    entry_count = len(auth_file.read_allow_entries())

    for i in opts.indices:
        if i < 0 or i >= entry_count:
            _stderr.write("ERROR: invalid index {}\n".format(i))
            return

    _stdout.write("This action will delete the following:\n")
    list_auth(opts, opts.indices)
    if not _ask_yes_no("Do you wish to delete?"):
        return
    try:
        auth_file.remove_by_indices(opts.indices)
        if len(opts.indices) > 1:
            msg = "removed entries at indices {}".format(opts.indices)
        else:
            msg = msg = "removed entry at index {}".format(opts.indices)
        _stdout.write(msg + "\n")
    except AuthException as err:
        _stderr.write("ERROR: %s\n" % str(err))


def update_auth(opts):
    auth_file = _get_auth_file(opts.volttron_home)
    entries = auth_file.read_allow_entries()
    try:
        if opts.index < 0:
            raise IndexError
        entry = entries[opts.index]
        _stdout.write('(For any field type "clear" to clear the value.)\n')
        response = _ask_for_auth_fields(**entry.__dict__)
        updated_entry = AuthEntry(**response)
        auth_file.update_by_index(updated_entry, opts.index)
        _stdout.write("updated entry at index {}\n".format(opts.index))
    except IndexError:
        _stderr.write("ERROR: invalid index %s\n" % opts.index)
    except AuthException as err:
        _stderr.write("ERROR: %s\n" % str(err))


# def add_role(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     roles = auth_file.read()[3]
#     if opts.role in roles:
#         _stderr.write('role "{}" already exists\n'.format(opts.role))
#         return
#     roles[opts.role] = list(set(opts.capabilities))
#     auth_file.set_roles(roles)
#     _stdout.write('added role "{}"\n'.format(opts.role))

# def list_roles(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     roles = auth_file.read()[3]
#     _print_two_columns(roles, "ROLE", "CAPABILITIES")

# def update_role(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     roles = auth_file.read()[3]
#     if opts.role not in roles:
#         _stderr.write('role "{}" does not exist\n'.format(opts.role))
#         return
#     caps = roles[opts.role]
#     if opts.remove:
#         roles[opts.role] = list(set(caps) - set(opts.capabilities))
#     else:
#         roles[opts.role] = list(set(caps) | set(opts.capabilities))
#     auth_file.set_roles(roles)
#     _stdout.write('updated role "{}"\n'.format(opts.role))

# def remove_role(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     roles = auth_file.read()[3]
#     if opts.role not in roles:
#         _stderr.write('role "{}" does not exist\n'.format(opts.role))
#         return
#     del roles[opts.role]
#     auth_file.set_roles(roles)
#     _stdout.write('removed role "{}"\n'.format(opts.role))

# def add_group(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     groups = auth_file.read()[2]
#     if opts.group in groups:
#         _stderr.write('group "{}" already exists\n'.format(opts.group))
#         return
#     groups[opts.group] = list(set(opts.roles))
#     auth_file.set_groups(groups)
#     _stdout.write('added group "{}"\n'.format(opts.group))

# def list_groups(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     groups = auth_file.read()[2]
#     _print_two_columns(groups, "GROUPS", "ROLES")

# def update_group(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     groups = auth_file.read()[2]
#     if opts.group not in groups:
#         _stderr.write('group "{}" does not exist\n'.format(opts.group))
#         return
#     roles = groups[opts.group]
#     if opts.remove:
#         groups[opts.group] = list(set(roles) - set(opts.roles))
#     else:
#         groups[opts.group] = list(set(roles) | set(opts.roles))
#     auth_file.set_groups(groups)
#     _stdout.write('updated group "{}"\n'.format(opts.group))

# def remove_group(opts):
#     auth_file = _get_auth_file(opts.volttron_home)
#     groups = auth_file.read()[2]
#     if opts.group not in groups:
#         _stderr.write('group "{}" does not exist\n'.format(opts.group))
#         return
#     del groups[opts.group]
#     auth_file.set_groups(groups)
#     _stdout.write('removed group "{}"\n'.format(opts.group))


def get_filtered_agents(opts, agents=None):
    if opts.pattern:
        filtered = set()
        for pattern, match in filter_agents(agents, opts.pattern, opts):
            if not match:
                _stderr.write("{}: error: agent not found: {}\n".format(opts.command, pattern))
            filtered |= match
        agents = list(filtered)
    return agents


def _show_filtered_agents(opts, field_name, field_callback, agents=None):
    """Provides generic way to filter and display agent information.
    The agents will be filtered by the provided opts.pattern and the
    following fields will be displayed:
      * UUID (or part of the UUID)
      * agent name
      * VIP identiy
      * tag
      * field_name
    @param:Namespace:opts:
        Options from argparse
    @param:string:field_name:
        Name of field to display about agents
    @param:function:field_callback:
        Function that takes an Agent as an argument and returns data
        to display
    @param:list:agents:
        List of agents to filter and display
    """

    if not agents:
        agents = _list_agents(opts)

    agents = get_filtered_agents(opts, agents)

    if not agents:
        if not opts.json:
            _stderr.write("No installed Agents found\n")
        else:
            _stdout.write(f"{jsonapi.dumps({}, indent=2)}\n")
        return
    agents = sorted(agents, key=lambda x: x.name)
    if not opts.min_uuid_len:
        n = 36
    else:
        n = max(_calc_min_uuid_length(agents), opts.min_uuid_len)
    name_width = max(5, max(len(agent.name) for agent in agents))
    tag_width = max(3, max(len(agent.tag or "") for agent in agents))
    identity_width = max(3, max(len(agent.identity or "") for agent in agents))
    fmt = "{} {:{}} {:{}} {:{}} {:>6}\n"

    if not opts.json:
        _stderr.write(
            fmt.format(
                " " * n,
                "AGENT",
                name_width,
                "IDENTITY",
                identity_width,
                "TAG",
                tag_width,
                field_name,
            ))
        for agent in agents:
            _stdout.write(
                fmt.format(
                    agent.uuid[:n],
                    agent.name,
                    name_width,
                    agent.identity,
                    identity_width,
                    agent.tag or "",
                    tag_width,
                    field_callback(agent),
                ))
    else:
        json_obj = {}
        for agent in agents:
            json_obj[agent.identity] = {
                "agent_uuid": agent.uuid,
                "name": agent.name,
                "identity": agent.identity,
                "agent_tag": agent.tag or "",
                field_name: field_callback(agent),
            }
        _stdout.write(f"{jsonapi.dumps(json_obj, indent=2)}\n")


def _show_filtered_agents_status(opts, status_callback, health_callback, priority_callback, agents=None):
    """Provides generic way to filter and display agent information.

    The agents will be filtered by the provided opts.pattern and the
    following fields will be displayed:
      * UUID (or part of the UUID)
      * agent name
      * VIP identiy
      * tag
      * field_name

    @param:Namespace:opts:
        Options from argparse
    @param:string:field_name:
        Name of field to display about agents
    @param:function:field_callback:
        Function that takes an Agent as an argument and returns data
        to display
    @param:list:agents:
        List of agents to filter and display
    """
    if not agents:
        agents = _list_agents(opts)

    # Find max before so the uuid of the agent is available
    # when a usre has filtered the list.
    if not opts.min_uuid_len:
        n = 36
    else:
        n = max(_calc_min_uuid_length(agents), opts.min_uuid_len)

    agents = get_filtered_agents(opts, agents)

    if not agents:
        if not opts.json:
            _stderr.write("No installed Agents found\n")
        else:
            _stdout.write(f"{jsonapi.dumps({}, indent=2)}\n")
        return

    agents = sorted(agents, key=lambda x: x.name)
    if not opts.json:
        name_width = max(5, max(len(agent.name) for agent in agents))
        tag_width = max(3, max(len(agent.tag or "") for agent in agents))
        identity_width = max(3, max(len(agent.identity or "") for agent in agents))
        if cc.is_secure_mode():
            user_width = max(3, max(len(agent.agent_user or "") for agent in agents))
            fmt = "{:<6} {:{}} {:{}} {:{}} {:{}} {} {:>6} {:>15}\n"
            _stderr.write(
                fmt.format(
                    "UUID",
                    "AGENT",
                    name_width,
                    "IDENTITY",
                    identity_width,
                    "TAG",
                    tag_width,
                    "AGENT_USER",
                    user_width,
                    "PRIORITY",
                    "STATUS",
                    "HEALTH",
                ))
            fmt = "{:<6} {:{}} {:{}} {:{}} {:{}} {:<8} {:<15} {:<}\n"
            for agent in agents:
                status_str = status_callback(agent)
                agent_health_dict = health_callback(agent)
                _stdout.write(
                    fmt.format(
                        agent.uuid[:n],
                        agent.name,
                        name_width,
                        agent.identity,
                        identity_width,
                        agent.tag or "",
                        tag_width,
                        agent.agent_user if status_str.startswith("running") else "",
                        user_width,
                        priority_callback(agent) or "",
                        status_str,
                        health_callback(agent),
                    ))
        else:
            fmt = "{:<6} {:{}} {:{}} {:{}} {} {:>6} {:>15}\n"
            _stderr.write(
                fmt.format(
                    "UUID",
                    "AGENT",
                    name_width,
                    "IDENTITY",
                    identity_width,
                    "TAG",
                    tag_width,
                    "PRIORITY",
                    "STATUS",
                    "HEALTH",
                ))
            fmt = "{:<6} {:{}} {:{}} {:{}} {:<8} {:<15} {:<}\n"
            for agent in agents:
                _stdout.write(
                    fmt.format(
                        agent.uuid[:n],
                        agent.name,
                        name_width,
                        agent.identity,
                        identity_width,
                        agent.tag or "",
                        tag_width,
                        priority_callback(agent) or "",
                        status_callback(agent),
                        health_callback(agent),
                    ))
    else:
        json_obj = {}
        for agent in agents:
            json_obj[agent.identity] = {
                "agent_uuid": agent.uuid,
                "name": agent.name,
                "identity": agent.identity,
                "agent_tag": agent.tag or "",
                "status": status_callback(agent),
                "health": health_callback(agent),
            }
            if cc.is_secure_mode():
                json_obj[agent.identity]["agent_user"] = (
                    agent.agent_user if json_obj[agent.identity]["status"].startswith("running") else "")
        _stdout.write(f"{jsonapi.dumps(json_obj, indent=2)}\n")


def get_agent_publickey(opts):

    def get_key(agent):
        return opts.aip.get_agent_keystore(agent.uuid).public

    _show_filtered_agents(opts, "PUBLICKEY", get_key)


# XXX: reimplement over VIP
# def send_agent(opts):
#    _log.debug("send_agent: "+ str(opts))
#    ssh_dir = os.path.join(opts.volttron_home, 'ssh')
#    _log.debug('ssh_dir: ' + ssh_dir)
#    try:
#        host_key, client = comms.client(ssh_dir, opts.host, opts.port)
#    except (OSError, IOError, PasswordRequiredException, SSHException) as exc:
#        if opts.debug:
#            traceback.print_exc()
#        _stderr.write('{}: error: {}\n'.format(opts.command, exc))
#        if isinstance(exc, OSError):
#            return os.EX_OSERR
#        if isinstance(exc, IOError):
#            return os.EX_IOERR
#        return os.EX_SOFTWARE
#    if host_key is None:
#        _stderr.write('warning: no public key found for remote host\n')
#    with client:
#        for wheel in opts.wheel:
#            with open(wheel) as file:
#                client.send_and_start_agent(file)


def add_config_to_store(opts):
    opts.connection.peer = CONFIGURATION_STORE
    call = opts.connection.call

    file_contents = opts.infile.read()

    call(
        "set_config",
        opts.identity,
        opts.name,
        file_contents,
        config_type=opts.config_type,
    )


def delete_config_from_store(opts):
    opts.connection.peer = CONFIGURATION_STORE
    call = opts.connection.call
    if opts.delete_store:
        call("delete_store", opts.identity)
        return

    if opts.name is None:
        _stderr.write("ERROR: must specify a configuration when not deleting entire store\n")
        return

    call("delete_config", opts.identity, opts.name)


def list_store(opts):
    opts.connection.peer = CONFIGURATION_STORE
    call = opts.connection.call
    results = []
    if opts.identity is None:
        results = call("list_stores")
    else:
        results = call("list_configs", opts.identity)

    for item in results:
        _stdout.write(item + "\n")


def get_config(opts):
    opts.connection.peer = CONFIGURATION_STORE
    call = opts.connection.call
    results = call("get_config", opts.identity, opts.name, raw=opts.raw)

    if opts.raw:
        _stdout.write(results)
    else:
        if isinstance(results, str):
            _stdout.write(results)
        else:
            _stdout.write(jsonapi.dumps(results, indent=2))
            _stdout.write("\n")


def edit_config(opts):
    opts.connection.peer = CONFIGURATION_STORE
    call = opts.connection.call

    if opts.new_config:
        config_type = opts.config_type
        raw_data = ""
    else:
        try:
            results = call("get_metadata", opts.identity, opts.name)
            config_type = results["type"]
            raw_data = results["data"]
        except RemoteError as e:
            if "No configuration file" not in e.message:
                raise
            config_type = opts.config_type
            raw_data = ""

    # Write raw data to temp file
    # This will not work on Windows, FYI
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="r+") as f:
        f.write(raw_data)
        f.flush()

        success = True
        try:
            # do not use utils.execute_command as we don't want set stdout to
            #  subprocess.PIPE
            subprocess.check_call([opts.editor, f.name])
        except subprocess.CalledProcessError as e:
            _stderr.write("Editor returned with code {}. Changes not committed.\n".format(e.returncode))
            success = False

        if not success:
            return

        f.seek(0)
        new_raw_data = f.read()

        if new_raw_data == raw_data:
            _stderr.write("No changes detected.\n")
            return

        call(
            "set_config",
            opts.identity,
            opts.name,
            new_raw_data,
            config_type=config_type,
        )


# class ControlConnection(object):
#     def __init__(self, address, peer='control'):
#         self.address = address
#         self.peer = peer
#         message_bus = cc.get_messagebus()
#         self._server = BaseAgent(address=self.address,
#                                  enable_store=False,
#                                  identity=CONTROL_CONNECTION,
#                                  message_bus=message_bus,
#                                  enable_channel=True)
#         self._greenlet = None

#     @property
#     def server(self):
#         if self._greenlet is None:
#             event = gevent.event.Event()
#             self._greenlet = gevent.spawn(self._server.core.run, event)
#             event.wait()
#         return self._server

#     def call(self, method, *args, **kwargs):
#         return self.server.vip.rpc.call(
#             self.peer, method, *args, **kwargs).get()

#     def call_no_get(self, method, *args, **kwargs):
#         return self.server.vip.rpc.call(
#             self.peer, method, *args, **kwargs)

#     def notify(self, method, *args, **kwargs):
#         return self.server.vip.rpc.notify(
#             self.peer, method, *args, **kwargs)

#     def kill(self, *args, **kwargs):
#         if self._greenlet is not None:
#             self._greenlet.kill(*args, **kwargs)


def priority(value):
    n = int(value)
    if not 0 <= n < 100:
        raise ValueError("invalid priority (0 <= n < 100): {}".format(n))
    return "{:02}".format(n)


def get_keys(opts):
    """Gets keys from keystore and known-hosts store"""
    hosts = KnownHostsStore()
    serverkey = hosts.serverkey(opts.vip_address)
    key_store = KeyStore()
    publickey = key_store.public
    secretkey = key_store.secret
    return {
        "publickey": publickey,
        "secretkey": secretkey,
        "serverkey": serverkey,
    }


# TODO RMQ client side methods.
# # RabbitMQ management methods
# def add_vhost(opts):
#     try:
#         rmq_mgmt.create_vhost(opts.vhost)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("Error adding a Virtual Host: {} \n".format(opts.vhost))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def add_user(opts):
#     rmq_mgmt.create_user(opts.user, opts.pwd)
#     permissions = dict(configure="", read="", write="")
#     read = _ask_yes_no("Do you want to set READ permission ")
#     write = _ask_yes_no("Do you want to set WRITE permission ")
#     configure = _ask_yes_no("Do you want to set CONFIGURE permission ")
#
#     if read:
#         permissions['read'] = ".*"
#     if write:
#         permissions['write'] = ".*"
#     if configure:
#         permissions['configure'] = ".*"
#     try:
#         rmq_mgmt.set_user_permissions(permissions, opts.user)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("Error Setting User permissions : {} \n".format(opts.user))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def add_exchange(opts):
#     if opts.type not in ['topic', 'fanout', 'direct']:
#         print("Unknown exchange type. Valid exchange types are topic or fanout or direct")
#         return
#     durable = _ask_yes_no("Do you want exchange to be durable ")
#     auto_delete = _ask_yes_no("Do you want exchange to be auto deleted ")
#     alternate = _ask_yes_no("Do you want alternate exchange ")
#
#     properties = dict(durable=durable, type=opts.type, auto_delete=auto_delete)
#     try:
#         if alternate:
#             alternate_exch = opts.name + 'alternate'
#             properties['alternate-exchange'] = alternate_exch
#             # create alternate exchange
#             new_props = dict(durable=durable, type='fanout', auto_delete=auto_delete)
#             rmq_mgmt.create_exchange(alternate_exch, new_props)
#         rmq_mgmt.create_exchange(opts.name, properties)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("Error Adding Exchange : {} \n".format(opts.name))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def add_queue(opts):
#     durable = _ask_yes_no("Do you want queue to be durable ")
#     auto_delete = _ask_yes_no("Do you want queue to be auto deleted ")
#
#     properties = dict(durable=durable, auto_delete=auto_delete)
#     try:
#         rmq_mgmt.create_queue(opts.name, properties)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("Error Adding Queue : {} \n".format(opts.name))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def list_vhosts(opts):
#     try:
#         vhosts = rmq_mgmt.get_virtualhosts()
#         for item in vhosts:
#             _stdout.write(item + "\n")
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Virtual Hosts Found: {} \n")
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def list_users(opts):
#     try:
#         users = rmq_mgmt.get_users()
#         for item in users:
#             _stdout.write(item + "\n")
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Users Found: {} \n")
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def list_user_properties(opts):
#     try:
#         props = rmq_mgmt.get_user_props(opts.user)
#         for key, value in props.items():
#             _stdout.write("{0}: {1} \n".format(key, value))
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No User Found: {} \n".format(opts.user))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def list_exchanges(opts):
#     try:
#         exchanges = rmq_mgmt.get_exchanges()
#         for exch in exchanges:
#             _stdout.write(exch + "\n")
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No exchanges found \n")
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def list_exchanges_with_properties(opts):
#     exchanges = None
#     try:
#         exchanges = rmq_mgmt.get_exchanges_with_props()
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No exchanges found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     try:
#         name_width = max(8, max(len(e['name']) for e in exchanges))
#         dur_width = len('DURABLE')
#         auto_width = len('AUTO-DELETE')
#         type_width = max(6, max(len(e['type']) for e in exchanges))
#         # args_width = max(6, max(len(e['type']) for e in exchanges))
#         fmt = '{:{}} {:{}} {:{}} {:{}}\n'
#         _stderr.write(
#             fmt.format('EXCHANGE', name_width, 'TYPE', type_width, 'DURABLE', dur_width,
#                        'AUTO-DELETE', auto_width))
#         for exch in exchanges:
#             _stdout.write(fmt.format(exch['name'], name_width,
#                                      exch['type'], type_width,
#                                      str(exch['durable']), dur_width,
#                                      str(exch['auto_delete']), auto_width))
#             # exch['messages'], args_width))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in getting queue properties")
#
#
# def list_queues(opts):
#     queues = None
#     try:
#         queues = rmq_mgmt.get_queues()
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No queues found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     if queues:
#         for q in queues:
#             _stdout.write(q + "\n")
#
#
# def list_queues_with_properties(opts):
#     queues = None
#     try:
#         queues = rmq_mgmt.get_queues_with_props()
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No queues found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     try:
#         name_width = max(5, max(len(q['name']) for q in queues))
#         dur_width = len('DURABLE')
#         excl_width = len('EXCLUSIVE')
#         auto_width = len('auto-delete')
#         state_width = len('running')
#         unack_width = len('MESSAGES')
#         fmt = '{:{}} {:{}} {:{}} {:{}} {:{}} {:{}}\n'
#         _stderr.write(
#             fmt.format('QUEUE', name_width, 'STATE', state_width, 'DURABLE', dur_width,
#                        'EXCLUSIVE', excl_width, 'AUTO-DELETE', auto_width,
#                        'MESSAGES', unack_width))
#         for q in queues:
#             _stdout.write(fmt.format(q['name'], name_width,
#                                      str(q['state']), state_width,
#                                      str(q['durable']), dur_width,
#                                      str(q['exclusive']), excl_width,
#                                      str(q['auto_delete']), auto_width,
#                                      q['messages'], unack_width))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in getting queue properties")
#
#
# def list_connections(opts):
#     try:
#         conn = rmq_mgmt.get_connection()
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No connections found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#
#
# def list_fed_parameters(opts):
#     parameters = None
#     try:
#         parameters = rmq_mgmt.get_parameter('federation-upstream')
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Federation Parameters Found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     try:
#         if parameters:
#             name_width = max(5, max(len(p['name']) for p in parameters))
#             uri_width = max(3, max(len(p['value']['uri']) for p in parameters))
#             fmt = '{:{}} {:{}}\n'
#             _stderr.write(
#                 fmt.format('NAME', name_width, 'URI', uri_width))
#             for param in parameters:
#                 _stdout.write(fmt.format(param['name'], name_width,
#                                          param['value']['uri'], uri_width))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in federation parameters")
#
#
# def list_shovel_parameters(opts):
#     parameters = None
#     try:
#         parameters = rmq_mgmt.get_parameter('shovel')
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Shovel Parameters Found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     try:
#         if parameters:
#             name_width = max(5, max(len(p['name']) for p in parameters))
#             src_uri_width = max(len('SOURCE ADDRESS'),
#                                 max(len(p['value']['src-uri']) for p in parameters))
#             dest_uri_width = max(len('DESTINATION ADDRESS'),
#                                  max(len(p['value']['dest-uri']) for p in parameters))
#             binding_key = max(len('BINDING KEY'),
#                               max(len(p['value']['src-exchange-key']) for p in parameters))
#             fmt = '{:{}}  {:{}}  {:{}}  {:{}}\n'
#             _stderr.write(
#                 fmt.format('NAME', name_width,
#                            'SOURCE ADDRESS', src_uri_width,
#                            'DESTINATION ADDRESS', dest_uri_width,
#                            'BINDING KEY', binding_key))
#             for param in parameters:
#                 _stdout.write(fmt.format(param['name'], name_width,
#                                          param['value']['src-uri'], src_uri_width,
#                                          param['value']['dest-uri'], dest_uri_width,
#                                          param['value']['src-exchange-key'], binding_key))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in getting shovel parameters")
#
#
# def list_bindings(opts):
#     bindings = None
#     try:
#         bindings = rmq_mgmt.get_bindings(opts.exchange)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Bindings Found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#
#     try:
#         if bindings:
#             src_width = max(5, max(len(b['source']) for b in bindings))
#             exch_width = len('EXCHANGE')
#             dest_width = max(len('QUEUE'), max(len(b['destination']) for b in bindings))
#             bindkey = len('BINDING KEY')
#             rkey = max(10, max(len(b['routing_key']) for b in bindings))
#             fmt = '{:{}}  {:{}}  {:{}}\n'
#             _stderr.write(
#                 fmt.format('EXCHANGE', exch_width, 'QUEUE', dest_width, 'BINDING KEY', bindkey))
#             for b in bindings:
#                 _stdout.write(fmt.format(b['source'], src_width,
#                                          b['destination'], dest_width,
#                                          b['routing_key'], rkey))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in getting bindings")
#
#
# def list_policies(opts):
#     policies = None
#     try:
#         policies = rmq_mgmt.get_policies()
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Policies Found \n")
#         return
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#         return
#     try:
#         if policies:
#             name_width = max(5, max(len(p['name']) for p in policies))
#             apply_width = max(8, max(len(p['apply-to']) for p in policies))
#             fmt = '{:{}} {:{}}\n'
#             _stderr.write(
#                 fmt.format('NAME', name_width, 'APPLY-TO', apply_width))
#             for policy in policies:
#                 _stdout.write(fmt.format(policy['name'], name_width,
#                                          policy['apply-to'], apply_width))
#     except (AttributeError, KeyError) as ex:
#         _stdout.write("Error in getting policies")
#
#
# def remove_vhosts(opts):
#     try:
#         for vhost in opts.vhost:
#             rmq_mgmt.delete_vhost(vhost)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Vhost Found {} \n".format(opts.vhost))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_users(opts):
#     try:
#         for user in opts.user:
#             rmq_mgmt.delete_user(user)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No User Found {} \n".format(opts.user))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_exchanges(opts):
#     try:
#         for e in opts.exchanges:
#             rmq_mgmt.delete_exchange(e)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Exchange Found {} \n".format(opts.exchanges))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_queues(opts):
#     try:
#         for q in opts.queues:
#             rmq_mgmt.delete_queue(q)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Queues Found {} \n".format(opts.queues))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_fed_parameters(opts):
#     try:
#         for param in opts.parameters:
#             rmq_mgmt.delete_multiplatform_parameter('federation-upstream', param)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Federation Parameters Found {} \n".format(opts.parameters))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_shovel_parameters(opts):
#     try:
#         for param in opts.parameters:
#             rmq_mgmt.delete_multiplatform_parameter('shovel', param)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Shovel Parameters Found {} \n".format(opts.parameters))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))
#
#
# def remove_policies(opts):
#     try:
#         for policy in opts.policies:
#             rmq_mgmt.delete_policy(policy)
#     except requests.exceptions.HTTPError as e:
#         _stdout.write("No Policies Found {} \n".format(opts.policies))
#     except ConnectionError as e:
#         _stdout.write("Error making request to RabbitMQ Management interface.\n"
#                       "Check Connection Parameters: {} \n".format(e))

# TODO RMQ
# def create_ssl_keypair(opts):
#     fq_identity = utils.get_fq_identity(opts.identity)
#     certs = Certs()
#     certs.create_signed_cert_files(fq_identity)

# def export_pkcs12_from_identity(opts):

#     fq_identity = utils.get_fq_identity(opts.identity)

#     certs = Certs()
#     certs.export_pkcs12(fq_identity, opts.outfile)


def main():

    # Refuse to run as root
    if not getattr(os, "getuid", lambda: -1)():
        sys.stderr.write("%s: error: refusing to run as root to prevent "
                         "potential damage.\n" % os.path.basename(sys.argv[0]))
        sys.exit(77)

    volttron_home = cc.get_volttron_home()

    os.environ["VOLTTRON_HOME"] = volttron_home

    global_args = config.ArgumentParser(description="global options", add_help=False)
    global_args.add_argument(
        "--debug",
        action="store_true",
        help="show tracebacks for errors rather than a brief message",
    )
    global_args.add_argument(
        "-t",
        "--timeout",
        type=float,
        metavar="SECS",
        help="timeout in seconds for remote calls (default: %(default)g)",
    )
    global_args.add_argument(
        "--address",
        metavar="ADDR",
        help="URL to bind for VIP connections",
    )

    global_args.set_defaults(
        address=get_address(),
        timeout=60,
    )

    filterable = config.ArgumentParser(add_help=False)
    filterable.add_argument(
        "--name",
        dest="by_name",
        action="store_true",
        help="filter/search by agent name. value passed should be quoted if it contains a regular expression",
    )
    filterable.add_argument(
        "--tag",
        dest="by_tag",
        action="store_true",
        help="filter/search by tag name. value passed should be quoted if it contains a regular expression",
    )
    filterable.add_argument("--all-tagged",
                            dest="by_all_tagged",
                            action="store_true",
                            help="filter/search by all tagged agents")
    filterable.add_argument(
        "--uuid",
        dest="by_uuid",
        action="store_true",
        help="filter/search by UUID (default). value passed should be quoted if it contains a regular expression",
    )
    filterable.set_defaults(by_name=False, by_tag=False, by_all_tagged=False, by_uuid=False)
    parser = config.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        add_help=False,
        description="Manage and control VOLTTRON agents.",
        usage="%(prog)s command [OPTIONS] ...",
        argument_default=argparse.SUPPRESS,
        parents=[global_args],
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="FILE",
        default=None,
        help="send log output to FILE instead of stderr",
    )
    parser.add_argument(
        "-L",
        "--log-config",
        metavar="FILE",
        help="read logging configuration from FILE",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="add_const",
        const=10,
        dest="verboseness",
        help="decrease logger verboseness; may be used multiple times",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="add_const",
        const=-10,
        dest="verboseness",
        help="increase logger verboseness; may be used multiple times",
    )
    parser.add_argument(
        "--verboseness",
        type=int,
        metavar="LEVEL",
        default=logging.WARNING,
        help="set logger verboseness",
    )
    parser.add_argument("--show-config", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="format output to json",
    )

    parser.add_help_argument()
    parser.set_defaults(
        log_config=None,
        volttron_home=volttron_home,
    )

    top_level_subparsers = parser.add_subparsers(title="commands", metavar="", dest="command")

    def add_parser(*args, **kwargs) -> argparse.ArgumentParser:
        """Generic method for adding parents and subparsers to the argument parser.

        :return: A reference to the created parser.
        :rtype: argparse.ArgumentParser
        """
        parents = kwargs.get("parents", [])
        parents.append(global_args)
        kwargs["parents"] = parents
        subparser = kwargs.pop("subparser", top_level_subparsers)
        return subparser.add_parser(*args, **kwargs)
    
    add_publish_parser(add_parser)
    add_subscribe_parser(add_parser)
    add_install_agent_parser(add_parser)
    add_install_lib_parser(add_parser)
    add_rpc_agent_parser(add_parser)

    add_auth_parser(add_parser, filterable=filterable)
    add_authz_parser(add_parser, filterable=filterable)
    add_config_store_parser(add_parser)
    tag = add_parser("tag", parents=[filterable], help="set, show, or remove agent tag")
    tag.add_argument("agent", help="UUID or name of agent")
    group = tag.add_mutually_exclusive_group()
    group.add_argument("tag", nargs="?", const=None, help="tag to give agent")
    group.add_argument("-r", "--remove", action="store_true", help="remove tag")
    tag.set_defaults(func=tag_agent, tag=None, remove=False)

    remove = add_parser("remove", parents=[filterable], help="remove agent")
    remove.add_argument("pattern", nargs="+", help="UUID or name of agent")
    remove.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="force removal of multiple agents",
    )
    remove.set_defaults(func=remove_agent, force=False)

    peers = add_parser("peerlist", help="list the peers connected to the platform")
    peers.set_defaults(func=list_peers)

    status = add_parser("status", aliases=("list", ), parents=[filterable], help="show status of agents")
    status.add_argument("pattern", nargs="*", help="UUID or name of agent")
    status.add_argument(
        "-n",
        dest="min_uuid_len",
        type=int,
        metavar="N",
        help="show at least N characters of UUID (0 to show all)",
    )
    status.set_defaults(func=status_agents, min_uuid_len=1)

    health = add_parser("health", parents=[filterable], help="show agent health as JSON")
    health.add_argument("pattern", nargs=1, help="UUID or name of agent")
    health.set_defaults(func=agent_health, min_uuid_len=1)

    clear = add_parser("clear", help="clear status of defunct agents")
    clear.add_argument(
        "-a",
        "--all",
        dest="clear_all",
        action="store_true",
        help="clear the status of all agents",
    )
    clear.set_defaults(func=clear_status, clear_all=False)

    enable = add_parser(
        "enable",
        parents=[filterable],
        help="enable agent to start automatically",
    )
    enable.add_argument("pattern", nargs="+", help="UUID or name of agent")
    enable.add_argument(
        "-p",
        "--priority",
        type=priority,
        help="2-digit priority from 00 to 99",
    )
    enable.set_defaults(func=enable_agent, priority="50")

    disable = add_parser(
        "disable",
        parents=[filterable],
        help="prevent agent from start automatically",
    )
    disable.add_argument("pattern", nargs="+", help="UUID or name of agent")
    disable.set_defaults(func=disable_agent)

    start = add_parser("start", parents=[filterable], help="start installed agent.")
    start.add_argument("pattern", nargs="*", help="UUID or name of agent", default='')
    start.set_defaults(func=start_agent)

    stop = add_parser("stop", parents=[filterable], help="stop agent")
    stop.add_argument("pattern", nargs="*", help="UUID or name of agent", default='')
    stop.set_defaults(func=stop_agent)

    restart = add_parser("restart", parents=[filterable], help="restart agent")
    restart.add_argument("pattern", nargs="*", help="UUID or name of agent", default='')
    restart.set_defaults(func=restart_agent)

    run = add_parser("run", help="start any agent by path")
    run.add_argument("directory", nargs="+", help="path to agent directory")

    shutdown = add_parser("shutdown", help="stop all agents")
    shutdown.add_argument(
        "--platform",
        action="store_true",
        help="also stop the platform process",
    )
    shutdown.set_defaults(func=shutdown_agents, platform=False)

    stats = add_parser("stats", help="manage router message statistics tracking")
    op = stats.add_argument(
        "op",
        choices=["status", "enable", "disable", "dump", "pprint"],
        nargs="?",
    )
    stats.set_defaults(func=do_stats, op="status")

    # ==============================================================================
    global message_bus

    # Parse and expand options
    args = sys.argv[1:]

    # TODO: for auth some of the commands will work when volttron is down and
    # some will error (example vctl auth serverkey). Do check inside auth
    # function
    # Below vctl commands can work even when volttron is not up. For others
    # volttron need to be up.
    if len(args) > 0:
        if args[0] not in ("list", "tag", "auth", "rabbitmq", "certs"):
            # check pid file
            if not is_volttron_running(volttron_home):
                _stderr.write("VOLTTRON is not running. This command "
                              "requires VOLTTRON platform to be running\n")
                return 10

    conf = os.path.join(volttron_home, "config")
    # if os.path.exists(conf) and "SKIP_VOLTTRON_CONFIG" not in os.environ:
    #     args = ["--config", conf] + args

    opts = parser.parse_args(args)

    logging.config.dictConfig(get_default_client_log_config(level=max(1, opts.verboseness)))

    if opts.log:
        opts.log = config.expandall(opts.log)
    if opts.log_config:
        opts.log_config = config.expandall(opts.log_config)
    #opts.vip_address = config.expandall(opts.vip_address)
    if getattr(opts, "show_config", False):
        for name, value in sorted(vars(opts).items()):
            print(name, repr(value))
        return

    # Configure logging
    # TODO: Logging for vctl
    # level = max(1, opts.verboseness)
    # if opts.log is None:
    #     log_to_file(sys.stderr, level)
    # elif opts.log == "-":
    #     log_to_file(sys.stdout, level)
    # elif opts.log:
    #     log_to_file(opts.log, level, handler_class=logging.handlers.WatchedFileHandler)
    # else:
    #     log_to_file(None, 100, handler_class=lambda x: logging.NullHandler())
    # if opts.log_config:
    #     logging.config.fileConfig(opts.log_config)

    # logging.getLogger().setLevel(level=logging.DEBUG)

    if opts.command == 'subscribe':
        if opts.identity_stage:
            try:
                opts.func(opts)
            except KeyboardInterrupt:
                sys.stdout.write("Complete\n")
                sys.exit(0)
        else:
            opts.connection: ControlConnection = ControlConnection(address=opts.address)

    else:
        opts.connection: ControlConnection = ControlConnection(address=opts.address)

    # opts.connection: ControlConnection = None
    # if is_volttron_running(volttron_home):
    #     opts.connection = ControlConnection(opts.vip_address)

    # with gevent.Timeout(opts.timeout):
    #     return opts.func(opts)
    # with gevent.Timeout(opts.timeout):
    #     return opts.func(opts)
    # sys.exit(0)
    try:
        with gevent.Timeout(opts.timeout):
            return opts.func(opts)
    except gevent.Timeout:
        _stderr.write(f"{opts.command} function {opts.func.__name__}: operation timed out\n")
        return 75
    except RemoteError as exc:
        print_tb = exc.print_tb
        error = exc.message
    except AttributeError as exc:
        _stderr.write("Invalid command: '{}' or command requires additional arguments\n".format(opts.command))
        parser.print_help()
        return 1
    # raised during install if wheel not found.
    except FileNotFoundError as exc:
        _stderr.write(f"{exc.args[0]}\n")
        return 1
    except SystemExit as exc:
        # Handles if sys.exit is called from within a function if not 0
        # then we know there was an error and processing will continue
        # else we return 0 from here.  This has the added effect of
        # allowing us to cascade short circuit calls.
        if exc.args[0] != 0:
            print_tb = exc.print_tb
            error = exc.message
        else:
            return 0
    finally:
        # make sure the connection to the server is closed when this scriopt is about to exit.
        if opts.connection:
            try:
                opts.connection.kill()
            finally:
                opts.connection = None
            # try:
            #     opts.connection.server.core.stop(timeout=1)
            # except gevent.Timeout:
            #     pass
            # except Unreachable:
            #     # its ok for this to fail at this point it might not even be valid.
            #     pass
            # finally:
            #     opts.connection = None

    if opts.debug:
        print_tb()
    _stderr.write("{}: error: {}\n".format(opts.command, error))
    return 20


def _main():
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    _main()
