import argparse
import json
import os
import re
import shutil
from typing import Callable, List

# import argcomplete
import volttron.types.auth.authz_types as authz

# Note: rpc call in volttron-lib-auth/src/volttron/services/auth/auth_service.py
from volttron.services.auth.auth_service import AUTH, VolttronAuthService


def add_authz_parser(add_parser_fn, filterable):
    """Create and populate an argparse parser for the authz command.

    First create the top level parser for authz.  Then create a subparser for
    the rpc subcommand.  Finally adds seperate arguments to the rpc subparser
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

    authz_commands = add_parser_fn(
        "authz", help="Manage authorization for rpc methods and pubsub topics"
    )

    rpc_parser = authz_commands.add_subparsers(
        title="authz operations",
        metavar="<COMMAND=add|remove|list>",
        dest="store_commands",
        required=True,
        # help="Available commands are: add, remove, list",
    )

    # Create the 'add' subparser under 'rpc'
    add_authz_method = rpc_parser.add_parser("add", help="Add rpc method authorization")
    # add_authz_method.add_argument("identity_and_method", nargs="*", help="Format: 'identity.method_name'")
    # add_authz_method.set_defaults(func=handel_role_parser)

    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz add'
    add_node_parser = add_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topic|agent>",
        dest="store_commands",
        required=True,
    )

    # Add a command "role" under 'authz add'
    add_role_command = add_node_parser.add_parser("role", help="add role")
    add_role_command.add_argument("role_name", help="add role")
    add_role_command.add_argument(
        "--pubsub-capabilities", "-ps", nargs="+", help="add role --pubsub-capabilities"
    )  # TODO: confirm behavior
    add_role_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add role --rpc-capabilities"
    )
    add_role_command.set_defaults(func=authz_add_role)

    # Add a command "group" under 'authz add'
    add_group_command = add_node_parser.add_parser("group", help="add group")
    add_group_command.add_argument(
        "group_name", help="add group <group_name> <vips[s]>"
    )
    add_group_command.add_argument(
        "vip_ids", nargs="+", help="add group <group_name> <vips[s]>"
    )  # "+" means one or more inputs are required,
    add_group_command.add_argument(
        "--role_names", "-rns", nargs="+", help="add group --role_names <vips[s]>"
    )
    add_group_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="add group --pubsub-capabilities",
    )  # TODO: confirm behavior
    add_group_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add group --rpc-capabilities"
    )
    # TODO: confirm if group has (optional) --topics option (like in agent)
    add_group_command.set_defaults(func=authz_add_group)

    # Add a command "topics" under 'authz add'
    add_topic_command = add_node_parser.add_parser("topic", help="add topic")
    add_topic_command.add_argument(
        "topic_names", nargs="+", help="add topic <topics[s]>"
    )
    add_topic_command.set_defaults(func=authz_add_topic)

    # Add a command "agent" under 'authz add'
    add_agent_command = add_node_parser.add_parser("agent", help="add agent")
    add_agent_command.add_argument(
        "vip_id", help="add agent <vip_id>"
    )  # "+" means one or more inputs are required,
    add_agent_command.add_argument(
        "--role_names", "-rns", nargs="+", help="add agent --role_names"
    )
    add_agent_command.add_argument(
        "--topic_names", "-tns", nargs="+", help="add agent --topic_names"
    )
    add_agent_command.add_argument(
        "--pubsub-capabilities",
        "-ps",
        nargs="+",
        help="add agent --pubsub-capabilities",
    )  # TODO: confirm behavior
    add_agent_command.add_argument(
        "--rpc-capabilities", "-rpc", nargs="+", help="add agent --rpc-capabilities"
    )
    add_agent_command.add_argument("--comments", "-c", help="add agent --comments")
    add_agent_command.set_defaults(func=authz_add_agent)

    ### REMOVE parser
    remove_authz_method = add_parser_fn(
        "remove", subparser=rpc_parser, help="Remove rpc method authorization"
    )

    #### Create subparser for node ('role', 'group', 'protected-topic', 'agent') under 'authz remove'
    remove_node_parser = remove_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topic|agent>",
        dest="store_commands",
        required=True,
    )

    # Add a command "role" under 'authz remove'
    remove_role_command = remove_node_parser.add_parser("role", help="remove role")
    remove_role_command.add_argument("role_name", help="remove role")
    remove_role_command.set_defaults(func=authz_remove_role)

    # Add a command "group" under 'authz remove'
    remove_group_command = remove_node_parser.add_parser("group", help="remove group")
    remove_group_command.add_argument("group_name", help="remove group <group_name>")
    remove_group_command.set_defaults(func=authz_remove_group)

    # Add a command "protected-topics" under 'authz remove'
    remove_topic_command = remove_node_parser.add_parser("topic", help="remove topic")
    remove_topic_command.add_argument(
        "topic_names", nargs="+", help="remove group <topics[s]>"
    )
    remove_topic_command.set_defaults(func=authz_remove_topic)

    # Add a command "agent" under 'authz remove'
    remove_agent_command = remove_node_parser.add_parser("agent", help="remove agent")
    remove_agent_command.add_argument(
        "vip_id", help="add agent <vip_id>"
    )  # "+" means one or more inputs are required,
    remove_agent_command.set_defaults(func=authz_remove_agent)

    ### LIST parser
    list_authz_method = add_parser_fn(
        "list", subparser=rpc_parser, help="List authorized rpc methods."
    )
    list_node_parser = list_authz_method.add_subparsers(
        title="top nodes",
        metavar="<NODE=role|group|topic|agent>",
        dest="store_commands",
        required=False,
    )
    # Add a command "role" under 'authz remove'
    list_role_command = list_node_parser.add_parser("role", help="list role")
    # Add a command "group" under 'authz remove'
    list_group_command = list_node_parser.add_parser("group", help="remove group")
    # Add a command "protected-topics" under 'authz remove'
    list_topic_command = list_node_parser.add_parser("topic", help="remove topic")
    # Add a command "agent" under 'authz remove'
    list_agent_command = list_node_parser.add_parser("agent", help="remove agent")
    # list_authz_method.set_defaults(func=list_dummy)
    list_authz_method.set_defaults(func=authz_list_dummy)

    list_role_command.set_defaults(func=authz_list_dummy)
    list_group_command.set_defaults(func=authz_list_dummy)
    list_topic_command.set_defaults(func=authz_list_dummy)
    list_agent_command.set_defaults(func=authz_list_dummy)


# def print_args(opts):
#     return f"{opts=}"


FILE_NAME = os.environ["VOLTTRON_HOME"] + "/authz.json"


def list_dummy(opts):
    """TODO: clean-up: Mock method for `vctl authz list` for now"""
    with open(FILE_NAME, "r") as f:
        # data = f.read()
        data = json.load(f)
    # print(json.dumps(data, indent=4))
    print(data.keys())
    return data


def authz_list_dummy(opts):
    """TODO: clean-up: Mock method for `vctl authz list <node>` for now"""
    with open(FILE_NAME, "r") as f:
        data = json.load(f)
    list_content = data
    # opts.store_commands in ["role", "group", "topic", "agent"]:  #
    if opts.store_commands == "role":
        list_content = data.get("roles")
    elif opts.store_commands == "agent":
        list_content = data.get("agents")
    elif opts.store_commands == "group":
        list_content = data.get("agent_groups")
    elif opts.store_commands == "topic":
        list_content = data.get("protected_topics")
    else:
        pass
    # return list_content
    print(print(json.dumps(list_content, indent=4)))
    # print(list_content.keys())


### authz control
def authz_add_role(opts):
    role_name: str = opts.role_name
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)

    rpc_method: Callable = VolttronAuthService.create_or_merge_role
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        name=role_name,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
    ).get()
    if res:
        print(
            f"Added Role: {rpc_capabilities_attr=}, {pubsub_capabilities_attr=} to {role_name=}."
        )


def authz_remove_role(opts):
    role_name: str = opts.role_name
    rpc_method: Callable = VolttronAuthService.remove_role
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        name=role_name,
    ).get()
    if res:
        print(f"Removed Role: {role_name=}.")


def authz_add_agent(opts):
    vip_id: str = opts.vip_id
    role_names: List[str] | None = opts.role_names
    topic_names: List[str] | None = opts.topic_names
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities
    comments: str | None = opts.comments

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)
    protected_rpcs = AuthZUtils.str_to_vipid_dot_rpc_method(topic_names)
    roles = AuthZUtils.str_to_AgentRoles(role_names)

    rpc_method: Callable = VolttronAuthService.create_or_merge_agent_authz
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        identity=vip_id,
        protected_rpcs=protected_rpcs,
        roles=roles,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
        comments=comments,
    ).get()
    if res:
        print(
            f"Added Agent: {topic_names=}, {role_names=}, \
{rpc_capabilities_attr=}, {pubsub_capabilities_attr=}, \
{comments=} to {vip_id=}."
        )


def authz_remove_agent(opts):
    identity: str = opts.vip_id
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
    protected_rpcs = AuthZUtils.str_to_vipid_dot_rpc_method(topic_names)
    rpc_method: Callable = VolttronAuthService.create_protected_topics
    res = opts.connection.server.vip.rpc.call(
        AUTH,
        rpc_method.__name__,
        topic_name_patterns=protected_rpcs,
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
        print(
            f"SOMEHTING WRONG, probabely, one of such topics {topic_names=} didn't exist."
        )


def authz_add_group(opts):
    group_name: str = opts.group_name
    vip_ids: List[str] = opts.vip_ids
    role_names: List[str] | None = opts.role_names
    # topic_names: List[str] | None = opts.topic_names
    rpc_capabilities_attr: List[str] | None = opts.rpc_capabilities
    pubsub_capabilities_attr: List[str] | None = opts.pubsub_capabilities

    if not any(
        [role_names, rpc_capabilities_attr, pubsub_capabilities_attr]
    ):  # TODO: should we handle this here?
        raise ValueError(
            "agent group group1 should have non empty capabilities. Please pass non empty values for at least one of the three parameters - agent_roles, rpc_capabilities, pubsub_capabilities"
        )

    rpc_capabilities = AuthZUtils.str_to_RPCCapabilities(rpc_capabilities_attr)
    pubsub_capabilities = AuthZUtils.str_to_PubsubCapabilities(pubsub_capabilities_attr)
    # protected_rpcs = AuthZUtils.str_to_vipid_dot_rpc_method(topic_names)
    roles = AuthZUtils.str_to_AgentRoles(role_names)

    rpc_method: Callable = VolttronAuthService.create_or_merge_agent_group
    res = opts.connection.server.vip.rpc.call(
        AUTH,  # "platform.auth",
        rpc_method.__name__,
        name=group_name,
        identities=vip_ids,
        # protected_rpcs=protected_rpcs,
        roles=roles,
        pubsub_capabilities=pubsub_capabilities,
        rpc_capabilities=rpc_capabilities,
    ).get()
    if res:
        print(
            f"Added Group: {role_names=}, \
{rpc_capabilities_attr=}, {pubsub_capabilities_attr=}, \
to {group_name=}."
        )


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
        print(
            f"SOMEHTING WRONG, probabely, one of such groups {group_name=} didn't exist."
        )


class AuthZUtils:
    @staticmethod
    def is_capability_format_valid(cap_attr: str) -> bool:
        """
        Validates that the value follows the 'string.string' format.
        This function uses regular expression to check the pattern.
        """
        pattern = re.compile(r"^\w+\.\w+$")
        return bool(pattern.match(cap_attr))

    @staticmethod
    def capability_format_requirement() -> str:
        return "in 'str-dot-str' format. i.e., 'id1.method1'"

    @staticmethod
    def is_topic_pattern_valid(topic_patter: str) -> bool:
        """
        Check if the provided string matches the specific pattern:
        Can contain letters, '/', '.', '*', brackets, hyphens, undercore, and plus signs.

        Args:
        s (str): The string to be checked.

        Returns:
        bool: True if the string matches the format, False otherwise.

        # Examples of usage:
        test_strings = [
            "devicez/ahu.*",     # valid: follows specified characters and pattern
            "devicez/ahu[1-9]+", # valid: includes numbers and regex patterns
            "devicez/ahu-123*",  # valid: hyphen and asterisk used correctly
            "devicez/ahu+",      # valid: plus sign used correctly
            "*/auth.*",          # valid: asterisk used at the beginning and in pattern
            "invalid_string$",   # invalid: dollar sign is not in the allowed set
            "devicez/ahu(!)",    # invalid: parentheses are not allowed
            "devicez|ahu.*",     # invalid: pipe character is not allowed
            "devicez/ahu[1-9]*", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]
        """
        # Regex pattern to match the specified format
        pattern = r"^[a-zA-Z0-9/\.\*\[\]\-\+\_]*$"

        # Check if the string matches the pattern
        if re.match(pattern, topic_patter):
            return True
        else:
            return False

    @staticmethod
    def topic_pattern_requirement() -> str:
        example_usage = r"""
        test_strings = [
            "devicez/ahu.*",     # valid: follows specified characters and pattern
            "devicez/ahu[1-9]+", # valid: includes numbers and regex patterns
            "devicez/ahu-123*",  # valid: hyphen and asterisk used correctly
            "devicez/ahu+",      # valid: plus sign used correctly
            "*/auth.*",          # valid: asterisk used at the beginning and in pattern
            "invalid_string$",   # invalid: dollar sign is not in the allowed set
            "devicez/ahu(!)",    # invalid: parentheses are not allowed
            "devicez|ahu.*",     # invalid: pipe character is not allowed
            "devicez/ahu[1-9]*", # valid: correct use of brackets and asterisk
            "devicez/ahu{}",     # invalid: curly brackets are not allowed
            "hello world"        # invalid: space is not allowed
        ]"""
        # return f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}"
        return bytes(
            f"Can contain letters, '/', '.', '*', brackets, hyphens, and plus signs. {example_usage=}",
            "utf-8",
        ).decode("unicode_escape")  # Manually interpreting escape sequences

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
        return cls.is_topic_pattern_valid(
            topic_pattern
        ) and cls.is_pubsub_constrain_valid(pubsub_constrain)

    @staticmethod
    def topic_pattern_pubsub_constrain_valid_requirement() -> str:
        example_usage = r"""
        [
            "devicez/ahu.*:publish",         # valid
            "*/auth.*:pubsub",               # valid
            "devicez/ahu(!):publish",        # invalid: topic pattern invalid
            "devicez|ahu.*:fly",             # invalid: pubsub constraint invalid
            "devicez/ahu[1-9]*:subscribe"    # valid
        ]"""
        print(
            "The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'."
        )
        # print(example_usage)
        # return f"The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'. {example_usage=}"
        return bytes(
            f"The input string needs to follow the format '<topic_pattern>:<pubsub_constraint>'. {example_usage=}",
            "utf-8",
        ).decode("unicode_escape")  # Manually interpreting escape sequences

    # TODO: this method (str_to_RPCCapabilities and str_to_xx methods) should be adopted by authz.RPCCapabilities itself.
    @staticmethod
    def str_to_RPCCapabilities(
        rpc_capabilities_attr: List[str] | None,
    ) -> authz.RPCCapabilities | None:
        if rpc_capabilities_attr is None:
            return None
        # check rpc_cap in "id.rpc1" format
        rpc_caps: List[authz.RPCCapability] = []
        for rpc_cap in rpc_capabilities_attr:
            if not AuthZUtils.is_capability_format_valid(rpc_cap):
                msg = f"Input rpc-capability '{rpc_cap}' in {rpc_capabilities_attr} does not meet the required format: {AuthZService.capability_format_requirement()}"
                raise ValueError(msg)
            rpc_caps.append(authz.RPCCapability(rpc_cap))

        return authz.RPCCapabilities(rpc_caps)

    @staticmethod
    def str_to_PubsubCapabilities(
        pubsub_capabilities_attr: List[str] | None,
    ) -> authz.PubsubCapabilities | None:
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
                return f"Input '<{topic_pattern=}>:<pubsub_constraint>' in {pubsub_capabilities_attr} does not meet the required format: {AuthZUtils.topic_pattern_requirement()}"
            if not AuthZUtils.is_pubsub_constrain_valid(topic_access):
                raise ValueError(
                    f"Input '<topic_pattern>:<{topic_access=}>:' in {pubsub_capabilities_attr} does not meet the required format: {AuthZUtils.pubsub_constrain_requirement()}"
                )
            pubsub_caps.append(
                authz.PubsubCapability(
                    topic_pattern=topic_pattern, topic_access=topic_access
                )
            )
        return authz.PubsubCapabilities(pubsub_caps)

    @staticmethod
    def str_to_vipid_dot_rpc_method(
        topic_names: List[str] | None,
    ) -> List[authz.vipid_dot_rpc_method] | None:
        if topic_names is None:
            return None
        protected_rpcs: List[authz.vipid_dot_rpc_method] = []
        for topic_name in topic_names:
            if not AuthZUtils.is_topic_pattern_valid(topic_name):
                raise ValueError(
                    f"Input '{topic_name=}' in {topic_names} does not meet the required format: {AuthZUtils.topic_pattern_requirement()}"
                )
            protected_rpcs.append(authz.vipid_dot_rpc_method(topic_name))
        return protected_rpcs

    @staticmethod
    def str_to_AgentRoles(role_names: List[str] | None) -> authz.AgentRoles | None:
        if role_names is None:
            return None
        roles = authz.AgentRoles(
            [authz.AgentRole(role_name=role_name) for role_name in role_names]
        )
        return roles
