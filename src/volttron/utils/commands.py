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

__all__ = [
    "execute_command", "vip_main", "is_volttron_running", "wait_for_volttron_startup",
    "wait_for_volttron_shutdown", "start_agent_thread", "isapipe"
]

import logging
import os
from pathlib import Path
import subprocess
import stat
import sys

import gevent
import psutil

_log = logging.getLogger(__name__)


def execute_command(cmds, env=None, cwd=None, logger=None, err_prefix=None) -> str:
    """Executes a command as a subprocess (Not greenlet safe!)

    If the return code of the call is 0 then return stdout otherwise
    raise a RuntimeError.  If logger is specified then write the exception
    to the logger otherwise this call will remain silent.

    :param cmds:list of commands to pass to subprocess.run
    :param env: environment to run the command with
    :param cwd: working directory for the command
    :param logger: a logger to use if errors occur
    :param err_prefix: an error prefix to allow better tracing through the error message
    :return: stdout string if successful

    :raises RuntimeError: if the return code is not 0 from suprocess.run
    """

    results = subprocess.run(cmds,
                             env=env,
                             cwd=cwd,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
    if results.returncode != 0:
        err_prefix = err_prefix if err_prefix is not None else "Error executing command"
        err_message = ("\n{}: Below Command failed with non zero exit code.\n"
                       "Command:{} \nStdout:\n{}\nStderr:\n{}\n".format(
                           err_prefix, results.args, results.stdout, results.stderr))
        if logger:
            logger.exception(err_message)
            raise RuntimeError()
        else:
            raise RuntimeError(err_message)

    return results.stdout.decode("utf-8")


def start_agent_thread(cls, **kwargs):
    """Instantiate an agent class and run it in a new daemon thread.

    Returns the thread object.
    """
    import threading

    agent = cls(**kwargs)
    thread = threading.Thread(target=agent.run)
    thread.daemon = True
    thread.start()
    return thread


def isapipe(fd):
    fd = getattr(fd, "fileno", lambda: fd)()
    return stat.S_ISFIFO(os.fstat(fd).st_mode)


def vip_main(agent_class, version: str = "0.1", **kwargs):
    """Default main entry point implementation for VIP agents."""
    from volttron.client.vip.agent import Agent
    from volttron.utils import (ClientContext as cc, is_valid_identity, get_address)
    from volttron.types.auth.auth_credentials import CredentialsFactory
    try:
        # If stdout is a pipe, re-open it line buffered
        if isapipe(sys.stdout):
            # Hold a reference to the previous file object so it doesn't
            # get garbage collected and close the underlying descriptor.
            stdout = sys.stdout
            sys.stdout = os.fdopen(stdout.fileno(), "w", 1)

        # Quiet printing of KeyboardInterrupt by greenlets
        Hub = gevent.hub.Hub
        Hub.NOT_ERROR = Hub.NOT_ERROR + (KeyboardInterrupt, )

        config = os.environ.pop("AGENT_CONFIG", {})
        identity = os.environ.pop("AGENT_VIP_IDENTITY", None)
        address = get_address()

        creds = CredentialsFactory.load_from_environ()
        del os.environ["AGENT_CREDENTIALS"]

        if not os.environ.get("_LAUNCHED_BY_PLATFORM"):
            if not creds:
                raise ValueError(
                    "Please set AGENT_CREDENTIALS to the credentials to connect to the server.")
            if not address:
                raise ValueError(
                    "Please set VOLTTRON_PLATFORM_ADDRESS to the address for connecting to the server."
                )

        if identity != creds.identity:
            raise ValueError("AGENT_VIP_IDENTITY and identity from credentials do not match!")

        if identity is not None:
            if not is_valid_identity(identity):
                _log.warning("Deprecation warning")
                _log.warning(f"All characters in {identity} are not in the valid set.")

        agent = agent_class(credentials=creds, config_path=config, address=address, **kwargs)

        try:
            run = agent.run
        except AttributeError:
            run = agent.core.run
        task = gevent.spawn(run)
        try:
            task.join()
        finally:
            task.kill()
    except KeyboardInterrupt:
        pass


def is_volttron_running(volttron_home):
    """
    Checks if volttron is running for the given volttron home. Checks if a VOLTTRON_PID file exist and if it does
    check if the PID in the file corresponds to a running process. If so, returns True else returns False
    :param vhome: volttron home
    :return: True if VOLTTRON_PID file exists and points to a valid process id
    """

    pid_file = os.path.join(volttron_home, "VOLTTRON_PID")
    if os.path.exists(pid_file):
        running = False
        with open(pid_file, "r") as pf:
            pid = int(pf.read().strip())
            running = psutil.pid_exists(pid)
        return running
    else:
        return False


def wait_for_volttron_startup(vhome, timeout):
    """
    Wait for the VOLTTRON_PID file to be written.  Raises
    Exception if timeout is hit first.
    """
    
    # Check for VOLTTRON_PID
    sleep_time = 0
    while (not is_volttron_running(vhome)) and sleep_time < timeout:
        gevent.sleep(3)
        sleep_time += 3
    if sleep_time >= timeout:
        raise Exception("Platform startup failed. Please check volttron.log in {}".format(vhome))


def wait_for_volttron_shutdown(vhome, timeout):
    # Check for VOLTTRON_PID
    sleep_time = 0
    while (is_volttron_running(vhome)) and sleep_time < timeout:
        gevent.sleep(1)
        sleep_time += 1
    if sleep_time >= timeout:
        raise Exception(
            "Platform shutdown failed. Please check volttron.cfg.log in {}".format(vhome))
