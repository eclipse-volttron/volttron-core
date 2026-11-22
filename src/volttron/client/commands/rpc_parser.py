# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2023 Battelle Memorial Institute
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

import argparse
import json
import logging
import pprint
import sys

import gevent

from volttron.client.vip.agent.errors import Unreachable
from volttron.utils import jsonapi
from volttron.utils.jsonrpc import MethodNotFound

_log = logging.getLogger(__name__)


def print_rpc_list(peers, code=False):
    for peer in peers:
        print(f"{peer}")
        for method in peers[peer]:
            if code:
                print(f"\tself.vip.rpc.call({peer}, {method}).get()")
            else:
                print(f"\t{method}")


def print_rpc_methods(opts, peer_method_metadata, code=False):
    for peer in peer_method_metadata:
        if code is True:
            pass
        else:
            print(f"{peer}")
        for method in peer_method_metadata[peer]:
            params = peer_method_metadata[peer][method].get("params",
                                                            "No parameters for this method.")
            if code is True:
                if len(params) == 0:
                    print(f"self.vip.rpc.call({peer}, {method}).get()")
                else:
                    print(f"self.vip.rpc.call({peer}, {method}, "
                          f"{[param for param in params]}).get()")
                continue
            else:
                print(f"\t{method}")
                if opts.verbose == True:
                    print("\tDocumentation:")
                    doc = (peer_method_metadata[peer][method].get(
                        "doc", "No documentation for this method.").replace("\n", "\n\t\t"))
                    print(f"\t\t{doc}\n")
            print("\tParameters:")
            if type(params) is str:
                print(f"\t\t{params}")
            else:
                for param in params:
                    print(f"\t\t{param}:\n\t\t\t{params[param]}")


def list_agents_rpc(opts):
    conn = opts.connection
    try:
        peers = sorted(conn.call("peerlist"))
    except Exception as e:
        print(e)
    if opts.by_vip == True or len(opts.pattern) == 1:
        peers = [peer for peer in peers if peer in opts.pattern]
    elif len(opts.pattern) > 1:
        peer = opts.pattern[0]
        methods = opts.pattern[1:]
        peer_method_metadata = {peer: {}}
        for method in methods:
            try:
                peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
                    peer, f"{method}.inspect").get(timeout=4)
                authorized_capabilities = conn.server.vip.rpc.call(peer,
                                                                   "auth.get_rpc_authorizations",
                                                                   method).get(timeout=4)
                peer_method_metadata[peer][method][
                    "authorized_capabilities"] = f"Authorized capabilities: {authorized_capabilities}"
            except gevent.Timeout:
                print(f"{peer} has timed out.")
            except Unreachable:
                print(f"{peer} is unreachable")
            except MethodNotFound as e:
                print(e)

        # _stdout.write(f"{peer_method_metadata}\n")
        print_rpc_methods(opts, peer_method_metadata)
        return
    peer_methods = {}
    for peer in peers:
        try:
            peer_methods[peer] = conn.server.vip.rpc.call(peer,
                                                          "inspect").get(timeout=4)["methods"]
        except gevent.Timeout:
            print(f"{peer} has timed out")
        except Unreachable:
            print(f"{peer} is unreachable")
        except MethodNotFound as e:
            print(e)

    if opts.verbose is True:
        print_rpc_list(peer_methods)
        # for peer in peer_methods:
        #     _stdout.write(f"{peer}:{peer_methods[peer]}\n")
    else:
        for peer in peer_methods:
            peer_methods[peer] = [method for method in peer_methods[peer] if "." not in method]
            # _stdout.write(f"{peer}:{peer_methods[peer]}\n")
        print_rpc_list(peer_methods)


def list_agent_rpc_code(opts):
    conn = opts.connection
    try:
        peers = sorted(conn.call("peerlist"))
    except Exception as e:
        print(e)
    if len(opts.pattern) == 1:
        peers = [peer for peer in peers if peer in opts.pattern]
    elif len(opts.pattern) > 1:
        peer = opts.pattern[0]
        methods = opts.pattern[1:]
        peer_method_metadata = {peer: {}}
        for method in methods:
            try:
                peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
                    peer, f"{method}.inspect").get(timeout=4)
            except gevent.Timeout:
                print(f"{peer} has timed out.")
            except Unreachable:
                print(f"{peer} is unreachable")
            except MethodNotFound as e:
                print(e)

        # _stdout.write(f"{peer_method_metadata}\n")
        print_rpc_methods(opts, peer_method_metadata, code=True)
        return

    peer_methods = {}
    for peer in peers:
        try:
            peer_methods[peer] = conn.server.vip.rpc.call(peer,
                                                          "inspect").get(timeout=4)["methods"]
        except gevent.Timeout:
            print(f"{peer} has timed out.")
        except Unreachable:
            print(f"{peer} is unreachable")
        except MethodNotFound as e:
            print(e)

    if opts.verbose is True:
        pass
    else:
        for peer in peer_methods:
            peer_methods[peer] = [method for method in peer_methods[peer] if "." not in method]

    peer_method_metadata = {}
    for peer in peer_methods:
        peer_method_metadata[peer] = {}
        for method in peer_methods[peer]:
            try:
                peer_method_metadata[peer][method] = conn.server.vip.rpc.call(
                    peer, f"{method}.inspect").get(timeout=4)
            except gevent.Timeout:
                print(f"{peer} has timed out")
            except Unreachable:
                print(f"{peer} is unreachable")
            except MethodNotFound as e:
                print(e)
    print_rpc_methods(opts, peer_method_metadata, code=True)


# ------------------------------------------------------------------------------------------------ vctl rpc call
# Command-line values are strings; RPC methods expect native values. A method's inspection reports each parameter's
# annotation only if its author wrote one, and often as a union or Any, so the annotation decides the type only when
# it names one simple type; everything else is read as JSON when it is valid JSON and sent as a string otherwise
# (volttron-core#386).

_SIMPLE_TYPES = {"str": "str", "int": "int", "float": "float", "bool": "bool"}
_JSON_TYPES = ("list", "dict", "tuple", "set", "List[", "Dict[", "Tuple[", "Set[", "Sequence[", "Mapping[",
               "Iterable[", "MutableMapping[", "MutableSequence[", "list[", "dict[", "tuple[", "set[")
_TRUE = {"true", "1", "yes", "on"}
INSPECT_TIMEOUT = 10.0    # seconds to wait for a method's inspection before converting without it
_FALSE = {"false", "0", "no", "off"}


def annotation_kind(annotation) -> str | None:
    """How to convert a value for a parameter with this annotation text: "str", "int", "float", "bool", "json",
    or None to read it as JSON when valid and as a string otherwise (no annotation, a union, Any, Optional)."""
    if not annotation:
        return None
    text = str(annotation).replace("typing.", "").strip().strip("'\"")
    if "|" in text or text.startswith(("Union[", "Optional[")) or text in ("Any", "object"):
        return None
    if text in _SIMPLE_TYPES:
        return _SIMPLE_TYPES[text]
    if text in ("list", "dict", "tuple", "set") or text.startswith(_JSON_TYPES):
        return "json"
    return None


def _strict_json(text: str):
    """Standard JSON only: NaN and Infinity are not values here, so a bare "NaN" stays a string."""
    def reject(constant):
        raise ValueError(f"not standard JSON: {constant}")
    return json.loads(text, parse_constant=reject)


def convert_value(text: str, kind: str | None, name: str):
    """Convert one command-line value for parameter ``name``; ValueError names the parameter on a bad value."""
    if kind == "str":
        return text
    if kind == "int":
        try:
            return int(text)
        except ValueError:
            raise ValueError(f"{name}: expected an integer, got {text!r}") from None
    if kind == "float":
        try:
            return float(text)
        except ValueError:
            raise ValueError(f"{name}: expected a number, got {text!r}") from None
    if kind == "bool":
        if text.lower() in _TRUE:
            return True
        if text.lower() in _FALSE:
            return False
        raise ValueError(f"{name}: expected true or false, got {text!r}")
    if kind == "json":
        try:
            return _strict_json(text)
        except ValueError:
            raise ValueError(f"{name}: expected JSON, got {text!r}") from None
    try:
        return _strict_json(text)
    except ValueError:
        return text


def convert_args(params: dict, args: list[str], kwargs: dict[str, str], raw: bool = False):
    """Positional and keyword values for a call, converted using the method's inspection ``params``
    (name -> {"kind", "annotation", ...}, in declaration order; may be empty when the method has no inspection)."""
    if raw:
        return list(args), dict(kwargs)
    positional = [(name, p) for name, p in params.items()
                  if p.get("kind") in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    var_positional = next((name for name, p in params.items() if p.get("kind") == "VAR_POSITIONAL"), None)
    converted_args = []
    for i, text in enumerate(args):
        if i < len(positional):
            name, p = positional[i]
            converted_args.append(convert_value(text, annotation_kind(p.get("annotation")), name))
        else:
            converted_args.append(convert_value(text, None, var_positional or f"argument {i + 1}"))
    converted_kwargs = {}
    for name, text in kwargs.items():
        p = params.get(name)
        kind = annotation_kind(p.get("annotation")) if p and p.get("kind") != "VAR_KEYWORD" else None
        converted_kwargs[name] = convert_value(text, kind, name)
    return converted_args, converted_kwargs


def _keyword_values(pairs) -> dict[str, str]:
    values = {}
    for pair in pairs or []:
        name, sep, value = pair.partition("=")
        if not sep or not name:
            raise ValueError(f"--kw expects NAME=VALUE, got {pair!r}")
        values[name] = value
    return values


def call_agent_rpc(opts):
    """vctl rpc call: call an agent's RPC method and print the result."""
    if (opts.json_args is not None or opts.json_kwargs is not None) and (opts.args or opts.kw):
        sys.stderr.write("error: --json-args/--json-kwargs cannot be combined with positional values or --kw\n")
        return 2
    try:
        peers = opts.connection.call("peerlist")
    except Exception as e:    # cannot list peers: let the call itself report what is wrong
        _log.debug(f"peerlist failed ({e}); calling without checking the identity")
        peers = None
    if peers is not None and opts.identity not in peers:
        sys.stderr.write(f"error: {opts.identity} is not connected to the platform (vctl peerlist shows who is)\n")
        return 1
    try:
        if opts.json_args is not None or opts.json_kwargs is not None:
            args = jsonapi.loads(opts.json_args) if opts.json_args is not None else []
            kwargs = jsonapi.loads(opts.json_kwargs) if opts.json_kwargs is not None else {}
            if not isinstance(args, list) or not isinstance(kwargs, dict):
                raise ValueError("--json-args must be a JSON list and --json-kwargs a JSON object")
        else:
            kwargs_text = _keyword_values(opts.kw)
            params = {}
            if not opts.raw:
                try:
                    params = opts.connection.server.vip.rpc.call(opts.identity, f"{opts.method}.inspect").get(
                        timeout=min(opts.timeout, INSPECT_TIMEOUT)).get("params", {})
                except (Exception, gevent.Timeout) as e:    # no inspection: convert without annotations
                    _log.debug(f"inspection of {opts.identity}.{opts.method} failed ({e}); converting without it")
            args, kwargs = convert_args(params, opts.args, kwargs_text, raw=opts.raw)
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    _log.debug(f"calling {opts.identity}.{opts.method} with args={args!r} kwargs={kwargs!r}")
    try:
        result = opts.connection.server.vip.rpc.call(opts.identity, opts.method, *args, **kwargs).get(
            timeout=opts.timeout)
    except MethodNotFound:
        sys.stderr.write(f"error: {opts.identity} has no RPC method {opts.method!r} "
                         f"(vctl rpc list {opts.identity} shows its methods)\n")
        return 1
    except Unreachable:
        sys.stderr.write(f"error: {opts.identity} is not connected to the platform (vctl peerlist shows who is)\n")
        return 1
    if getattr(opts, "json", False):
        sys.stdout.write(jsonapi.dumps(result, indent=2) + "\n")
    else:
        pprint.pprint(result)
    return 0


def add_rpc_agent_parser(add_parser_fn):
    rpc_ctl = add_parser_fn("rpc", help="rpc controls")

    rpc_subparsers = rpc_ctl.add_subparsers(title="subcommands", metavar="", dest="store_commands")

    rpc_code = add_parser_fn(
        "code",
        subparser=rpc_subparsers,
        help="shows how to use rpc call in other agents",
    )

    rpc_code.add_argument("pattern", nargs="*", help="Identity of agent, followed by method(s)"
                          "")
    rpc_code.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="list all subsystem rpc methods in addition to the agent's rpc "
        "methods",
    )

    rpc_code.set_defaults(func=list_agent_rpc_code, min_uuid_len=1)

    rpc_list = add_parser_fn("list",
                             subparser=rpc_subparsers,
                             help="lists all agents and their rpc methods")

    rpc_list.add_argument("-i",
                          "--vip",
                          dest="by_vip",
                          action="store_true",
                          help="filter by vip identity")

    rpc_list.add_argument("pattern", nargs="*", help="UUID or name of agent")

    rpc_list.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="list all subsystem rpc methods in addition to the agent's rpc "
        "methods. If a method "
        "is specified, display the doc-string associated with the "
        "method.",
    )

    rpc_list.set_defaults(func=list_agents_rpc, min_uuid_len=1)

    rpc_call = add_parser_fn("call", subparser=rpc_subparsers,
                             help="call an agent's RPC method and print the result")
    rpc_call.add_argument("identity", help="VIP identity of the agent")
    rpc_call.add_argument("method", help="name of the exported RPC method")
    rpc_call.add_argument("args", nargs="*", metavar="ARG",
                          help="positional values, converted by the method's annotations where they name one simple "
                          "type, otherwise read as JSON when valid JSON and sent as a string when not")
    rpc_call.add_argument("--kw", action="append", metavar="NAME=VALUE", help="a keyword value; may be repeated")
    rpc_call.add_argument("--json-args", metavar="JSON_LIST", help="all positional values as one JSON list, sent as is")
    rpc_call.add_argument("--json-kwargs", metavar="JSON_OBJECT",
                          help="all keyword values as one JSON object, sent as is")
    rpc_call.add_argument("--raw", action="store_true", help="send every value as the string typed")
    # No default, so "vctl --json rpc call ..." keeps vctl's top-level --json (volttron-core#374).
    rpc_call.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print the result as JSON")
    rpc_call.set_defaults(func=call_agent_rpc)
