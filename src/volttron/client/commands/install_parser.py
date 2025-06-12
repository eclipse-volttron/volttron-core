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

import argparse
import base64
import glob
import hashlib
import logging
import os
import shutil
from pathlib import Path
import sys
import tempfile
from typing import Callable

import gevent
import yaml

from volttron.client.vip.agent.results import AsyncResult
from volttron.types.agent_context import AgentInstallOptions

from volttron.utils import execute_command
from volttron.utils import jsonapi


class InstallRuntimeError(RuntimeError):
    pass


_log = logging.getLogger(__name__)

_stdout = sys.stdout
_stderr = sys.stderr


def _build_from_pyproject(install_path: Path) -> Path:
    """build project from poetry based upon the pyproject.toml file.

    This is a local build when the user passes a directory to the install command.

    :param install_path: Path to the directory containing the pyproject.toml file.
    :type install_path: Path
    :raises InstallRuntimeError: If no wheel file was built during the built process this is thrown.
    :return: Path to the wheel file that was built.
    :rtype: Path
    """

    pyproject_path = install_path / "pyproject.toml"
    assert pyproject_path.exists(), f"pyproject.toml not found in {install_path}"

    dist_path: Path = install_path / "dist"

    cmd = ["poetry", "build", "-vv"]
    output = execute_command(cmd, cwd=install_path)
    match = sorted(dist_path.glob("*.whl"))

    if match:
        return Path(match[-1])
    else:
        raise InstallRuntimeError(
            f"No .whl file found in {dist_path} after running command {' '.join(cmd)}. "
            f"\nCommand returned stdout:\n{output}")


def _install_and_initialize_agent(opts: argparse.Namespace,
                                  wheel_file: Path = None,
                                  pypi_string: str = None):
    """Create a new agent on the platform.

    This is the main installation function for sending/installing an agent on the platform. Depending
    on the arguments, the agent will be installed from a wheel file or from pypi.  The options will be
    retrieved from the opts namespace argument.

    This function creates an `AgentInstallOptions` object and sends it to the platform.  The platform
    will then install the agent and return the agent uuid.

    :param opts: The command line options for the install command.
    :type opts: argparse.Namespace
    :param wheel_file: If a path is specified ".whl" file will be sent, defaults to None
    :type wheel_file: Path, optional
    :param pypi_string: A string to install from pypi, defaults to None
    :type pypi_string: str, optional
    :raises InstallRuntimeError: Raised if a problem with a passed config file.
    :raises ValueError: Raised if the agent was not installed properly.
    """

    assert opts.connection, "Connection must have been created to access this feature."
    editable = False
    if opts.install_path and Path(opts.install_path).is_dir():
        editable = True

    assert editable or wheel_file or pypi_string, "Either a source directory or a wheel file or pypi string must be specified."
    assert not (editable and wheel_file
                and pypi_string), "Only one of source directory, wheel_file or pypi_string can be specified."

    connection = opts.connection

    if wheel_file and not wheel_file.exists():
        raise InstallRuntimeError(f"Wheel file {wheel_file} does not exist!")

    # Verify and load agent_config up from the opts.  agent_config will
    # be a yaml config file.
    agent_config = opts.agent_config
    if agent_config is None:
        agent_config = {}

    cfg = None    # temp file if agent_config is a dict
    # if not a dict then config should be a filename
    if not isinstance(agent_config, dict):
        config_file = Path(agent_config).expanduser().as_posix()
        if not Path(config_file).exists():
            raise InstallRuntimeError(f"Config file {config_file} does not exist!")
    else:
        cfg = tempfile.NamedTemporaryFile()
        with open(cfg.name, "w") as fout:
            fout.write(yaml.safe_dump(agent_config))
        config_file = cfg.name

    try:
        with open(config_file) as fp:
            config_dict = yaml.safe_load(fp)
    except Exception as exc:
        raise InstallRuntimeError(exc)
    finally:
        if cfg:
            cfg.close()

    agent = None    # holds the wheel file or the pypi string
    agent_data = None    # Holds the base64 encoded data of the wheel file.
    if wheel_file:
        with open(wheel_file, "rb") as fp:
            agent_data = base64.b64encode(fp.read()).decode("utf-8")
        agent = wheel_file.name
    elif pypi_string:
        agent = pypi_string
    elif editable:
        agent = os.path.abspath(opts.install_path)

    agent_install = AgentInstallOptions(source=agent,
                                        identity=opts.vip_identity,
                                        data=agent_data,
                                        agent_config=config_dict,
                                        force=opts.force,
                                        allow_prerelease=opts.pre_release,
                                        editable=editable)

    agent_uuid = connection.call("install_agent", agent_install.to_dict())

    if not agent_uuid:
        raise ValueError(f"Agent was not installed properly.")

    if isinstance(agent_uuid, AsyncResult):
        agent_uuid = agent_uuid.get()

    output_dict = dict(agent_uuid=agent_uuid)

    if opts.tag:
        _log.debug(f"Tagging agent {agent_uuid}, {opts.tag}")
        opts.connection.call("tag_agent", agent_uuid, opts.tag)
        output_dict["tag"] = opts.tag

    if opts.enable or opts.priority != -1:
        output_dict["enabling"] = True
        if opts.priority == -1:
            opts.priority = "50"
        _log.debug(f"Prioritinzing agent {agent_uuid},{opts.priority}")
        output_dict["priority"] = opts.priority

        opts.connection.call("prioritize_agent", agent_uuid, str(opts.priority))

    try:

        if opts.start:
            gevent.sleep(2)
            _log.debug(f"Staring agent {agent_uuid}")
            opts.connection.call("start_agent", agent_uuid)
            output_dict["starting"] = True

            _log.debug(f"Getting agent status {agent_uuid}")
            gevent.sleep(opts.agent_start_time)
            status = opts.connection.call("agent_status", agent_uuid)
            if status[0] is not None and status[1] is None:
                output_dict["started"] = True
                output_dict["pid"] = status[0]
            else:
                output_dict["started"] = False
            _log.debug(f"Status returned {status}")
    except Exception as e:
        _log.error(e)

    if opts.json:
        sys.stdout.write("%s\n" % jsonapi.dumps(output_dict, indent=4))
    else:
        if output_dict.get("started"):
            sys.stdout.write(f"Agent {agent_uuid} installed and started [{output_dict['pid']}]\n")
        else:
            sys.stdout.write(f"Agent {agent_uuid} installed\n")
    if opts.csv:
        keylen = len(output_dict)
        keyline = ""
        valueline = ""
        keys = list(output_dict.keys())
        for k in range(keylen):
            if k < keylen - 1:
                keyline += "%s," % keys[k]
                valueline += "%s," % output_dict[keys[k]]
            else:
                keyline += "%s" % keys[k]
                valueline += "%s" % output_dict[keys[k]]
        sys.stdout.write("%s\n%s\n" % (keyline, valueline))


def _install_lib(opts: argparse.Namespace,
                 wheel_file: Path = None,
                 pypi_string: str = None):
    """Create a new agent on the platform.

    This is the main installation function for sending/installing an agent on the platform. Depending
    on the arguments, the agent will be installed from a wheel file or from pypi.  The options will be
    retrieved from the opts namespace argument.

    This function calls the server's install_library method which return the installed library name.

    :param opts: The command line options for the command.
    :type opts: argparse.Namespace
    :param wheel_file: If a path is specified ".whl" file will be sent, defaults to None
    :type wheel_file: Path, optional
    :param pypi_string: A string to install from pypi, defaults to None
    :type pypi_string: str, optional
    :raises ValueError: Raised if the library was not installed properly.
    """

    assert opts.connection, "Connection must have been created to access this feature."
    assert wheel_file or pypi_string, "Either a wheel file or pypi string must be specified."
    assert not (wheel_file
                and pypi_string), "Only one of wheel_file or pypi_string can be specified."

    connection = opts.connection

    if wheel_file and not wheel_file.exists():
        raise InstallRuntimeError(f"Wheel file {wheel_file} does not exist!")

    lib_data = None  # Holds the base64 encoded data of the wheel file.
    if wheel_file:
        with open(wheel_file, "rb") as fp:
            lib_data = base64.b64encode(fp.read()).decode("utf-8")
        source = wheel_file.name
    else:
        source = pypi_string
    lib_name = connection.call("install_library", source=source, data=lib_data, force=opts.force,
                             allow_prerelease=opts.pre_release)

    if not lib_name:
        raise ValueError(f"Library was not installed properly.")

    if isinstance(lib_name, AsyncResult):
        lib_name = lib_name.get()
    sys.stdout.write(f"Installed {lib_name} \n")



def install_lib_vctl(opts: argparse.Namespace, callback=None):
    """
    The `install_lib_vctl` function is called from the volttron-ctl or vctl install-lib
    sub-parser.

    This function uses the `opts` namespace install_path and wheel attributes to install
    the library on the connected platform instance.  The `opts`.connection attribute must
    be set and connected prior to calling this function.

    If an error occurs during this function it will be passed up the stack and the callback
    function will not be called.

    :param opts: The namespace object containing the install_path and wheel attributes.
    :type opts: argparse.Namespace
    :param callback: A callback function to call after the agent is successfully installed.
    :type callback: function
    """

    assert opts.connection, "Connection must have been created to access this feature."

    try:
        install_path = Path(opts.install_path)
    except AttributeError:
        install_path = Path(opts.wheel)

    if install_path.is_dir():
        print(f"Building from {install_path}")
        install_path = _build_from_pyproject(install_path)

    if install_path.is_file() and install_path.suffix == ".whl":
        print(f"Installing from wheel {install_path}")
        _install_lib(opts, wheel_file=install_path)
    else:
        print(f"Installing from pypi {install_path}")
        _install_lib(opts, pypi_string=install_path.as_posix())

    if callback:
        callback()


def install_agent_vctl(opts: argparse.Namespace, callback=None):
    """
    The `install_agent_vctl` function is called from the volttron-ctl or vctl install
    sub-parser.

    This function uses the `opts` namespace install_path and wheel attributes to install
    the agent on the connected platform instance.  The `opts`.connection attribute must
    be set and connected prior to calling this function.

    If an error occurs during this function it will be passed up the stack and the callback
    function will not be called.

    :param opts: The namespace object containing the install_path and wheel attributes.
    :type opts: argparse.Namespace
    :param callback: A callback function to call after the agent is successful installation.
    :type callback: function
    """

    assert opts.connection, "Connection must have been created to access this feature."

    try:
        install_path = Path(opts.install_path)
    except AttributeError:
        install_path = Path(opts.wheel)

    editable = False
    if install_path.is_dir():
        if opts.connection.address.startswith("ipc:"):
            editable =True
        else:
            print(f"Building agent from {install_path}")
            install_path = _build_from_pyproject(install_path)

    if editable:
        # No wheel file was built. install editable
        print(f"Installing editable agent package on local server: {install_path} opts {opts.install_path}")
        _install_and_initialize_agent(opts)
    elif install_path.is_file() and install_path.suffix == ".whl":
        print(f"Installing from wheel {install_path}")
        _install_and_initialize_agent(opts, wheel_file=install_path)
    else:
        print(f"Installing from pypi {install_path}")
        _install_and_initialize_agent(opts, pypi_string=install_path.as_posix())

    if callback:
        callback()


def add_install_agent_parser(add_parser_fn: Callable):
    """Create and add the parser for vctl install command.

    :param add_parser_fn: A
    :type add_parser_fn: _type_
    """
    install = add_parser_fn(
        "install",
        help="install agent from wheel",
        epilog="Optionally you may specify the --tag argument to tag the "
        "agent during install without requiring a separate call to "
        "the tag command. ",
    )
    install.add_argument(
        "--skip-requirements",
        help=
        "Skip installing requirements from a requirements.txt if present in the agent directory.",
    )
    install.add_argument(
        "install_path",
        help="path to agent wheel or directory for agent installation",
    )
    install.add_argument("--tag", help="tag for the installed agent")
    install.add_argument(
        "--vip-identity",
        help="VIP IDENTITY for the installed agent. "
        "Overrides any previously configured VIP IDENTITY.",
    )
    install.add_argument("--agent-config", help="Agent configuration!")
    install.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=
        "agents are uninstalled by tag so force allows multiple agents to be removed at one go.",
    )
    install.add_argument(
        "--priority",
        default=-1,
        type=int,
        help="priority of startup during instance startup",
    )
    install.add_argument(
        "--start",
        action="store_true",
        help="start the agent during the script execution",
    )
    install.add_argument(
        "--enable",
        action="store_true",
        help="enable the agent with default 50 priority unless --priority set",
    )
    install.add_argument(
        "--csv",
        action="store_true",
        help="format the standard out output to csv",
    )
    install.add_argument(
        "--json",
        action="store_true",
        help="format the standard out output to json",
    )
    install.add_argument(
        "-st",
        "--agent-start-time",
        default=5,
        type=int,
        help="the amount of time to wait and verify that the agent has started up.",
    )
    install.add_argument(
        "--pre-release",
        "--pre",
        "--allow-prereleases",
        action="store_true",
        help="enables installation of pre-releases and development releases",
    )

    install.set_defaults(func=install_agent_vctl, verify_agents=True)

def add_install_lib_parser(add_parser_fn: Callable):
    """Create and add the parser for vctl install-lib command.

    :param add_parser_fn: A
    :type add_parser_fn: _type_
    """
    install = add_parser_fn(
        "install-lib",
        help="install volttron library by name or path",
    )
    install.add_argument(
        "--skip-requirements",
        help=
        "Skip installing requirements from a requirements.txt if present in the agent directory.",
    )
    install.add_argument(
        "install_path",
        help="path to agent wheel or directory for agent installation",
    )
    install.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=
        "uninstall and reinstall given library version",
    )
    install.add_argument(
        "--pre-release",
        "--pre",
        "--allow-prereleases",
        action="store_true",
        help="enables installation of pre-releases and development releases",
    )

    install.set_defaults(func=install_lib_vctl)

