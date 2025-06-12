import argparse
import json
import re

from typing import Callable, List

from volttron.utils.context import ClientContext as cc

import volttron.types.auth.authz_types as authz

# Note: rpc call in volttron-lib-auth/src/volttron/services/auth/auth_service.py
from volttron.auth.auth_service import AUTH, VolttronAuthService


def add_authz_parser(add_parser_fn, filterable):
    """Create and populate an argparse parser for the authz command.

    First create the top level parser for authz.  Then create a subparser for
    the rpc subcommand.  Finally adds separate arguments to the rpc subparser
    for add, remove and list commands.

    The same method as above is how the pubsub subcommand will be added.

    :param add_parser_fn: A callback that will create a new parser based upon parameters passed
    :type add_parser_fn: Callable
    :param filterable: A filter function for filtering the results of the command
    :type filterable: Callable

    EXAMPLE:
    vctl authz -h
    usage: vctl command [OPTIONS] ... authz [-h] [--debug] [-t SECS] [--address ADDR]  ...

    options:
    -h, --help            show this help message and exit
    --debug               show tracebacks for errors rather than a brief message
    -t SECS, --timeout SECS
                            timeout in seconds for remote calls (default: 60)
    --address ADDR        URL to bind for VIP connections

    authz operations:

        add                 Add rpc method authorization
        remove              Remove rpc method authorization
        list                List authorized rpc methods.
    """

    # TODO: Verify that the filterable makes sense for the authz command.

    authz_command = add_parser_fn("authz", help="Manage authorization for rpc methods and pubsub topics")

    authz_operations = authz_command.add_subparsers(
        title="Authorization operations",
        metavar="<operations=add|remove|list>",
        dest="store_commands",
        required=True,
        help="Operations to add/merge, remove, and list volttron authorization rules.",
    )

    # Create the 'add' subparser under 'rpc'
    authz_add_parser = authz_operations.add_parser(
        "add", help="Add or merge a role, group,  agent authorization, or protected topics")
    # authz_add_parser.add_argument("identity_and_method", nargs="*", help="Format: 'identity.method_name'")
    # authz_add_parser.set_defaults(func=handel_role_parser)

    #### Create subparser for node ('role', 'group', 'topics', 'agent') under 'authz add'
    add_node_parser = authz_add_parser.add_subparsers(
        title="Add or merge role, group, agent authorization or protected topic entry",
        metavar="<NODE=role|group|topics|agent>",
        dest="store_commands",
        required=True,
    )
    capabilities_epilog = f"""
Additional information:\n
pubsub-capabilities:
    {AuthZUtils.topic_pattern_pubsub_constrain_valid_requirement()}
rpc-capabilities:
    {AuthZUtils.rpc_capability_format_requirement()}"""
    # Add a command "role" under 'authz add'
    add_role_command = add_node_parser.add_parser("role",
                                                  help="create a role or merge rules for an existing role",
                                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                                  epilog=capabilities_epilog)
    add_role_command.add_argument("role_name", help="name of the role")
    add_role_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="one or more pubsub-capabilities allowed for this role. see additional information")
    add_role_command.add_argument("--rpc-capabilities",
                                  "-rpc",
                                  nargs="+",
                                  help="one or more rpc capabilities allowed for this role. see additional information")
    add_role_command.set_defaults(func=authz_add_role)

    # Add a command "group" under 'authz add'
    add_group_command = add_node_parser.add_parser("group",
                                                   help="create a group or merge rules for an existing group",
                                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                                   epilog=capabilities_epilog)
    add_group_command.add_argument("group_name", help="name of the group")
    add_group_command.add_argument(
        "identities", nargs="+",
        help="one or more agent identity to be added to group")    # "+" means one or more inputs are required,
    add_group_command.add_argument("--role-names", "-rns", nargs="+", help="name of roles to be assigned to this group")
    add_group_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="one or more pubsub-capabilities allowed for this group. see additional information",
    )
    add_group_command.add_argument(
        "--rpc-capabilities",
        "-rpc",
        nargs="+",
        help="one or more rpc-capabilities allowed for this role. see additional information")
    add_group_command.set_defaults(func=authz_add_group)

    # Add a command "topics" under 'authz add'
    add_topic_command = add_node_parser.add_parser(
        "topics",
        help=("protect one or more topic or topic pattern by adding it to the protected_topics list."
              "topic patterns(regular expression) should be enclose within // Example: /devices.*/. "),
    )
    add_topic_command.add_argument("topic_names",
                                   nargs="+",
                                   help="one or more topic name or topic pattern to be protected")
    add_topic_command.set_defaults(func=authz_add_topic)

    # Add a command "agent" under 'authz add'
    add_agent_command = add_node_parser.add_parser("agent",
                                                   help="create or merge an agent's authorization rules",
                                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                                   epilog=capabilities_epilog)
    add_agent_command.add_argument("identity", help="vip identity of the agent")
    add_agent_command.add_argument("--role-names",
                                   "-rns",
                                   nargs="+",
                                   help="name of role(s) to be assigned to this agent")
    add_agent_command.add_argument("--protected-rpcs",
                                   "-pts",
                                   nargs="+",
                                   help="rpc exported methods of this agent that needs to be protected by "
                                   "authorization rules")
    add_agent_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="one or more pubsub-capabilities allowed for this group. see additional information",
    )
    add_agent_command.add_argument(
        "--rpc-capabilities",
        "-rpc",
        nargs="+",
        help="one or more rpc-capabilities allowed for this group. see additional information")
    add_agent_command.add_argument("--comments", "-c", help="comment string")
    add_agent_command.set_defaults(func=authz_add_agent)

    ### REMOVE parser
    remove_authz_method = add_parser_fn(
        "remove",
        subparser=authz_operations,
        help="Remove authorization entries for a agent, group, role or protected topics")

    #### Create subparser for node ('role', 'group', 'topics', 'agent') under 'authz remove'
    remove_node_parser = remove_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topics|agent>",
        dest="store_commands",
        required=True,
    )

    # Add a command "role" under 'authz remove'
    remove_role_command = remove_node_parser.add_parser("role", help="remove a given role")
    remove_role_command.add_argument("role_name", help="name of the role to be removed")
    remove_role_command.set_defaults(func=authz_remove_role)

    # Add a command "group" under 'authz remove'
    remove_group_command = remove_node_parser.add_parser("group", help="remove a given group")
    remove_group_command.add_argument("group_name", help="name of the group to be removed")
    remove_group_command.set_defaults(func=authz_remove_group)

    # Add a command "topics" under 'authz remove'
    remove_topic_command = remove_node_parser.add_parser(
        "topics", help="remove one or more topic or pattern from protected topics list")
    remove_topic_command.add_argument("topic_names",
                                      nargs="+",
                                      help="space separated list of topic or topic pattern to remove")
    remove_topic_command.set_defaults(func=authz_remove_topic)

    # Add a command "agent" under 'authz remove'
    remove_agent_command = remove_node_parser.add_parser("agent", help="remove an agent authorization rules")
    remove_agent_command.add_argument("identity",
                                      help="vip identity of the agent")    # "+" means one or more inputs are required,
    remove_agent_command.set_defaults(func=authz_remove_agent)

    ### LIST parser
    list_authz_method = add_parser_fn("list", subparser=authz_operations, help="List authorized rpc methods.")
    list_node_parser = list_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topics|agent>",
        dest="store_commands",
        required=False,
    )
    # Add a command "role" under 'authz remove'
    list_role_command = list_node_parser.add_parser("role", help="list role")
    # Add a command "group" under 'authz remove'
    list_group_command = list_node_parser.add_parser("group", help="list group")
    # Add a command "protected-topics" under 'authz remove'
    list_topic_command = list_node_parser.add_parser("topics", help="list protected topics")
    # Add a command "agent" under 'authz remove'
    list_agent_command = list_node_parser.add_parser("agent", help="list agent")
    # list_authz_method.set_defaults(func=list_dummy)
    list_authz_method.set_defaults(func=authz_list_dummy)

    list_role_command.set_defaults(func=authz_list_dummy)
    list_group_command.set_defaults(func=authz_list_dummy)
    list_topic_command.set_defaults(func=authz_list_dummy)
    list_agent_command.set_defaults(func=authz_list_dummy)


# def print_args(opts):
#     return f"{opts=}"


def get_local_authorizations() -> dict[str, dict]:
    # TODO maybe cache this maybe not depending, but we have made it so that only one place deals with io.
    with open(cc.get_volttron_home().join("/authz.json")) as fp:
        return json.load(fp)


def list_dummy(opts):
    """TODO: clean-up: Mock method for `vctl authz list` for now"""
    data = get_local_authorizations()
    # print(json.dumps(data, indent=4))
    print(data.keys())
    return data


def authz_list_dummy(opts):
    """TODO: clean-up: Mock method for `vctl authz list <node>` for now"""
    data = get_local_authorizations()
    list_content = data
    # opts.store_commands in ["role", "group", "topic", "agent"]:  #
    if opts.store_commands == "role":
        list_content = data.get("roles")
    elif opts.store_commands == "agent":
        list_content = data.get("agents")
    elif opts.store_commands == "group":
        list_content = data.get("agent_groups")
    elif opts.store_commands == "topics":
        list_content = data.get("protected_topics")
    else:
        pass
    # return list_content
    print(json.dumps(list_content, indent=4))
    # print(list_content.keys())


### authz control
def authz_add_role(opts):
    role_name: str = opts.role_name
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)

    rpc_method: Callable = VolttronAuthService.create_or_merge_role
    res = opts.connection.server.vip.rpc.call(AUTH,
                                              rpc_method.__name__,
                                              name=role_name,
                                              pubsub_capabilities=pubsub_capabilities,
                                              rpc_capabilities=rpc_capabilities).get()
    if res:
        print(f"Added Role: {rpc_capabilities_attr=}, {pubsub_capabilities_attr=} to {role_name=}.")


def authz_remove_role(opts):
    role_name: str = opts.role_name
    rpc_method: Callable = VolttronAuthService.remove_role
    res = opts.connection.server.vip.rpc.call(AUTH, rpc_method.__name__, name=role_name).get()
    if res:
        print(f"Removed Role: {role_name=}.")


def authz_add_agent(opts):
    identity: str = opts.identity
    role_names: List[str] | None = opts.role_names
    protected_rpcs: List[str] | None = opts.protected_rpcs
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities
    comments: str | None = opts.comments

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)
    roles = AuthZUtils.str_to_AgentRoles(role_names)

    rpc_method: Callable = VolttronAuthService.create_or_merge_agent_authz
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        identity=identity,
        protected_rpcs=protected_rpcs,
        roles=roles,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
        comments=comments,
    ).get()
    if res:
        print(f"Added Agent:  {role_names=}, \
{rpc_capabilities_attr=}, {pubsub_capabilities_attr=}, \
{comments=} to {identity=}.")


def authz_remove_agent(opts):
    identity: str = opts.identity
    rpc_method: Callable = VolttronAuthService.remove_agent
    # TODO: remove_agent is not robust. Often got "volttron.utils.jsonrpc.RemoteError: volttron.types.auth.auth_credentials.IdentityNotFound('role7')" need to figure out why.
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        identity=identity,
    ).get()
    if res:
        print(f"Removed Agent: {identity=}.")


def authz_add_topic(opts):
    topic_names: List[str] = opts.topic_names
    protected_topics = AuthZUtils.str_to_topic_patterns(topic_names)
    rpc_method: Callable = VolttronAuthService.create_protected_topics
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        topic_name_patterns=protected_topics,
    ).get()
    if res:
        print(f"Added Topic: {topic_names=}.")


def authz_remove_topic(opts):
    topic_names: str = opts.topic_names
    rpc_method: Callable = VolttronAuthService.remove_protected_topics
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        topic_name_patterns=topic_names,
    ).get()
    if res:
        print(f"Removed Topic: {topic_names=}.")
    else:
        # TODO error with silence if no such topic exists.
        print(f"SOMEHTING WRONG, probabely, one of such topics {topic_names=} didn't exist.")


def authz_add_group(opts):
    group_name: str = opts.group_name
    vip_ids: List[str] = opts.identities
    role_names: List[str] | None = opts.role_names
    # topic_names: List[str] | None = opts.topic_names
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities

    if not any([role_names, rpc_capabilities_attr, pubsub_capabilities_attr]):    # TODO: should we handle this here?
        raise ValueError(
            "agent group group1 should have non empty capabilities. Please pass non empty values for at least one of the three parameters - agent_roles, rpc_capabilities, pubsub_capabilities"
        )

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)
    roles = AuthZUtils.str_to_AgentRoles(role_names)

    rpc_method: Callable = VolttronAuthService.create_or_merge_agent_group
    res = opts.connection.server.vip.rpc.call(
        AUTH,    # "platform.auth",
        rpc_method.__name__,
        name=group_name,
        identities=vip_ids,
    # protected_rpcs=protected_rpcs,
        roles=roles,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
    ).get()
    if res:
        print(f"Added Group: {role_names=}, \
{rpc_capabilities_attr=}, {pubsub_capabilities_attr=}, \
to {group_name=}.")


def authz_remove_group(opts):
    group_name: str = opts.group_name
    rpc_method: Callable = VolttronAuthService.remove_agent_group
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        name=group_name,
    ).get()
    if res:
        print(f"Removed Group: {group_name=}.")
    else:
        # TODO error with silence if no such topic exists.
        print(f"SOMEHTING WRONG, probabely, one of such groups {group_name=} didn't exist.")


class AuthZUtils:

    @staticmethod
    def is_rpc_capability_format_valid(cap_attr: str) -> bool:
        """
        Validates that the value follows the 'string.string' format.
        This function uses regular expression to check the pattern.
        """
        # patern vipid.rpcmethod
        # vip id could have . in it. Ex. config.store.edit_config
        pattern = re.compile(r"^\w+[.\w]*\.\w+$")
        return bool(pattern.match(cap_attr))

    @staticmethod
    def rpc_capability_format_requirement() -> str:
        return "rpc-capabilities should be of the format '<vip id>.<rpc method name>' format. i.e., 'agent_1.rpcmethod1'"

    @staticmethod
    def is_topic_pattern_valid(topic_pattern: str) -> bool:
        """
        Check if the provided string matches the specific pattern:
        Can contain letters, '/', '.', '*', brackets, hyphens, undercore, and plus signs.

        Args:
        s (str): The string to be checked.

        Returns:
        bool: True if the string matches the format, False otherwise.

        # Examples of usage:
        test_strings = [
            "/devicez/ahu.*/",     # valid: follows specified characters and pattern
            "/devicez/ahu[1-9]+/", # valid: includes numbers and regex patterns
            "/devicez/ahu-123*/",  # valid: hyphen and asterisk used correctly
            "/devicez/ahu+/",      # valid: plus sign used correctly
            "/*/auth.*/",          # valid: asterisk used at the beginning and in pattern
            "/invalid_string$/",   # invalid: dollar sign is not in the allowed set
            "/devicez/ahu(!)/",    # invalid: parentheses are not allowed
            "/devicez|ahu.*/",     # invalid: pipe character is not allowed
            "/devicez/ahu[1-9]*/", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]
        """
        # Regex pattern to match the specified format
        pattern = r"^[a-zA-Z0-9/\.\*\[\]\-\+\_]*$"

        # Check if the string matches the pattern
        if re.match(pattern, topic_pattern):
            return True
        else:
            return False

    @staticmethod
    def topic_pattern_requirement() -> str:
        example_usage = r"""
        test_strings = [
            "/devicez/ahu.*/",     # valid: follows specified characters and pattern
            "/devicez/ahu[1-9]+/", # valid: includes numbers and regex patterns
            "/devicez/ahu-123*/",  # valid: hyphen and asterisk used correctly
            "/devicez/ahu+/",      # valid: plus sign used correctly
            "/*/auth.*/",          # valid: asterisk used at the beginning and in pattern
            "/invalid_string$/",   # invalid: dollar sign is not in the allowed set
            "/devicez/ahu(!)/",    # invalid: parentheses are not allowed
            "/devicez|ahu.*/",     # invalid: pipe character is not allowed
            "/devicez/ahu[1-9]*/", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]"""
        # return f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}"
        return bytes(
            f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}",
            "utf-8",
        ).decode("unicode_escape")    # Manually interpreting escape sequences

    @staticmethod
    def is_pubsub_constrain_valid(pubsub_constrain: str) -> bool:
        """
        Validates pubsub_constrain
        """
        # return pubsub_constrain in ["publish", "subscribe", "pub", "sub", "pubsub"]
        return pubsub_constrain in ["publish", "subscribe", "pubsub"]

    @staticmethod
    def pubsub_constrain_requirement() -> str:
        return 'topic_access in ["publish", "subscribe", "pubsub"]'

    @classmethod
    def is_topic_pattern_pubsub_constrain_valid(cls, input_string: str) -> bool:
        """
        Checks if the input string follows the format '<topic_pattern>:<pubsub_constraint>'

        Args:
        input_string (str): The input string to validate.

        Returns:
        bool: True if the input string is valid, False otherwise.
        """
        # Split the input string by the colon
        parts = input_string.split(":")

        # Ensure there are exactly two parts
        if len(parts) != 2:
            return False

        # Validate each part
        topic_pattern, pubsub_constrain = parts
        return cls.is_topic_pattern_valid(topic_pattern) and cls.is_pubsub_constrain_valid(pubsub_constrain)

    @staticmethod
    def topic_pattern_pubsub_constrain_valid_requirement() -> str:
        example_usage = r"""
        [
            "/devicez/ahu.*/:publish",         # valid
            "/auth.*/:pubsub",               # valid
            "devicez/ahu(!):publish",        # invalid: topic pattern invalid
            "devicez|ahu.*:fly",             # invalid: pubsub constraint invalid
            "/prefix/literal-topic-match:subscribe"    # valid
        ]"""
        # print(
        #     "The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'."
        # )
        # print(example_usage)
        # return f"The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'. {example_usage=}"
        return bytes(
            f"pubsub-capabilities should be of format '<topic>:<publish|subscribe|pubsub>'. If topic is a "
            f"regular expression enclosed within //\n"
            f"{example_usage}",
            "utf-8",
        ).decode("unicode_escape")    # Manually interpreting escape sequences

    # TODO: this method (str_to_RPCCapabilities and str_to_xx methods) should be adopted by authz.RPCCapabilities itself.
    @staticmethod
    def str_to_RPCCapabilities(rpc_capabilities_attr: List[str] | None, ) -> authz.RPCCapabilities | None:
        if rpc_capabilities_attr is None:
            return None
        # check rpc_cap in "id.rpc1" format
        rpc_caps: List[authz.RPCCapability] = []
        for rpc_cap in rpc_capabilities_attr:
            if not AuthZUtils.is_rpc_capability_format_valid(rpc_cap):
                msg = f"Input rpc-capability '{rpc_cap}' in {rpc_capabilities_attr} does not meet the required format: {AuthZUtils.rpc_capability_format_requirement()}"
                raise ValueError(msg)
            rpc_caps.append(authz.RPCCapability(rpc_cap))

        return authz.RPCCapabilities(rpc_caps)

    @staticmethod
    def str_to_PubsubCapabilities(pubsub_capabilities_attr: List[str] | None) -> authz.PubsubCapabilities | None:
        if pubsub_capabilities_attr is None:
            return None
        pubsub_caps = []
        # check pubsub_cap in "devicez/ahu.*:publish" format
        for pubsub_cap in pubsub_capabilities_attr:
            if ":" not in pubsub_cap:
                msg = f"Input pubsub-capability '{pubsub_cap}' in {pubsub_capabilities_attr} does not meet the required format: {AuthZUtils.topic_pattern_pubsub_constrain_valid_requirement()}"
                raise ValueError(msg)
            topic_pattern = pubsub_cap.split(":")[0]
            topic_access = pubsub_cap.split(":")[-1]
            if not AuthZUtils.is_topic_pattern_valid(topic_pattern):
                raise ValueError(
                    f"Input '<{topic_pattern=}>:<pubsub_constraint>' in {pubsub_capabilities_attr} does not meet the required format: {AuthZUtils.topic_pattern_requirement()}"
                )
            if not AuthZUtils.is_pubsub_constrain_valid(topic_access):
                raise ValueError(
                    f"Input '<topic_pattern>:<{topic_access=}>:' in {pubsub_capabilities_attr} does not meet the required format: {AuthZUtils.pubsub_constrain_requirement()}"
                )
            pubsub_caps.append(authz.PubsubCapability(topic_pattern=topic_pattern, topic_access=topic_access))
        return authz.PubsubCapabilities(pubsub_caps)

    @staticmethod
    def str_to_topic_patterns(topic_names: List[str] | None, ) -> List[str] | None:
        if topic_names is None:
            return None
        protected_rpcs: List[str] = []
        for topic_name in topic_names:
            if not AuthZUtils.is_topic_pattern_valid(topic_name):
                raise ValueError(
                    f"Input '{topic_name=}' in {topic_names} does not meet the required format: {AuthZUtils.topic_pattern_requirement()}"
                )
            protected_rpcs.append(topic_name)
        return protected_rpcs

    @staticmethod
    def str_to_AgentRoles(role_names: List[str] | None) -> authz.AgentRoles | None:
        if role_names is None:
            return None
        roles = authz.AgentRoles([authz.AgentRole(role_name=role_name) for role_name in role_names])
        return roles
