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

"""Component for the instantiation and packaging of agents."""

import errno
import grp
import logging
import os
import pwd
import re
import shutil
import signal
import sys
import uuid
from typing import Optional

# import requests
import gevent
import gevent.event
import yaml
from gevent import subprocess
from gevent.subprocess import PIPE

# from wheel.tool import unpack
from volttron.utils import (ClientContext as cc, get_utc_seconds_from_epoch, execute_command)
from ..utils import jsonapi
from volttron.utils.certs import Certs
from volttron.utils.identities import is_valid_identity
from volttron.utils.keystore import KeyStore
from volttron.client.known_identities import VOLTTRON_CENTRAL_PLATFORM
from volttron.client.vip.agent import Agent

# from volttron.platform.agent.utils import load_platform_config, \
#     get_utc_seconds_from_epoch

from volttron.services.auth.auth_service import AuthFile, AuthEntry, AuthFileEntryAlreadyExists

# TODO route to wheel_wrap
# from .packages import UnpackedPackage

# from volttron.utils.rmq_mgmt import RabbitMQMgmt
# from volttron.platform import update_volttron_script_path

_log = logging.getLogger(__name__)


def process_wait(p):
    timeout = 0.01
    while True:
        result = p.poll()
        if result is not None:
            return result
        gevent.sleep(timeout)
        if timeout < 0.5:
            timeout *= 2


# LOG_* constants from syslog module (not available on Windows)
_level_map = {
    7: logging.DEBUG,    # LOG_DEBUG
    6: logging.INFO,    # LOG_INFO
    5: logging.INFO,    # LOG_NOTICE
    4: logging.WARNING,    # LOG_WARNING
    3: logging.ERROR,    # LOG_ERR
    2: logging.CRITICAL,    # LOG_CRIT
    1: logging.CRITICAL,    # LOG_ALERT
    0: logging.CRITICAL,
}    # LOG_EMERG


def log_entries(name, agent, pid, level, stream):
    log = logging.getLogger(name)
    extra = {'processName': agent, 'process': pid}
    for l in stream:
        for line in l.splitlines():
            if line.startswith('{') and line.endswith('}'):
                try:
                    obj = jsonapi.loads(line)
                    try:
                        obj['args'] = tuple(obj['args'])
                    except (KeyError, TypeError, ValueError):
                        pass
                    record = logging.makeLogRecord(obj)
                except Exception:
                    pass
                else:
                    if record.name in log.manager.loggerDict:
                        if not logging.getLogger(record.name).isEnabledFor(record.levelno):
                            continue
                    elif not log.isEnabledFor(record.levelno):
                        continue
                    record.remote_name, record.name = record.name, name
                    record.__dict__.update(extra)
                    log.handle(record)
                    continue
            if line[0:1] == '<' and line[2:3] == '>' and line[1:2].isdigit():
                yield _level_map.get(int(line[1]), level), line[3:]
            else:
                yield level, line


def log_stream(name, agent, pid, path, stream):
    log = logging.getLogger(name)
    extra = {'processName': agent, 'process': pid}
    unset = {'thread': None, 'threadName': None, 'module': None}
    for level, line in stream:
        if log.isEnabledFor(level):
            record = logging.LogRecord(name, level, path, 0, line, [], None)
            record.__dict__.update(extra)
            record.__dict__.update(unset)
            log.handle(record)


class IgnoreErrno(object):
    ignore = []

    def __init__(self, errno, *more):
        self.ignore = [errno]
        self.ignore.extend(more)

    def __enter__(self):
        return

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return exc_value.errno in self.ignore
        except AttributeError:
            pass


ignore_enoent = IgnoreErrno(errno.ENOENT)


class ExecutionEnvironment(object):
    """Environment reserved for agent execution.

    Deleting ExecutionEnvironment objects should cause the process to
    end and all resources to be returned to the system.
    """

    def __init__(self):
        self.process = None
        self.env = None

    def execute(self, *args, **kwargs):
        try:
            self.env = kwargs.get("env", None)
            self.process = subprocess.Popen(*args, **kwargs, universal_newlines=True)
        except OSError as e:
            if e.filename:
                raise
            raise OSError(*(e.args + (args[0], )))

    def stop(self):
        if self.process.poll() is None:
            # pylint: disable=catching-non-exception
            self.process.send_signal(signal.SIGINT)
            try:
                return gevent.with_timeout(60, process_wait, self.process)
            except gevent.Timeout:
                _log.warning("First timeout")
                self.process.terminate()
            try:
                return gevent.with_timeout(30, process_wait, self.process)
            except gevent.Timeout:
                _log.warning("2nd timeout")
                self.process.kill()
            try:
                return gevent.with_timeout(30, process_wait, self.process)
            except gevent.Timeout:
                _log.error("last timeout")
                raise ValueError("process is unresponsive")
        return self.process.poll()

    def __call__(self, *args, **kwargs):
        self.execute(*args, **kwargs)


class SecureExecutionEnvironment(object):

    def __init__(self, agent_user):
        self.process = None
        self.env = None
        self.agent_user = agent_user

    def execute(self, *args, **kwargs):
        try:
            self.env = kwargs.get("env", None)
            run_as_user = ["sudo", "-E", "-u", self.agent_user]
            run_as_user.extend(*args)
            _log.debug(run_as_user)
            self.process = subprocess.Popen(run_as_user, universal_newlines=True, **kwargs)
        except OSError as e:
            if e.filename:
                raise
            raise OSError(*(e.args + (args[0], )))

    def stop(self):
        if self.process.poll() is None:
            cmd = [
                "sudo",
                update_volttron_script_path("scripts/secure_stop_agent.sh"), self.agent_user,
                str(self.process.pid)
            ]
            _log.debug("In aip secureexecutionenv {}".format(cmd))
            process = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            _log.info("stopping agent: stdout {} stderr: {}".format(stdout, stderr))
            if process.returncode != 0:
                _log.error("Exception stopping agent: stdout {} stderr: {}".format(stdout, stderr))
                raise RuntimeError("Exception stopping agent: stdout {} stderr: {}".format(
                    stdout, stderr))
        return self.process.poll()

    def __call__(self, *args, **kwargs):
        self.execute(*args, **kwargs)


class AIPplatform(object):
    """Manages the main workflow of receiving and sending agents."""

    def __init__(self, env, **kwargs):
        self.env = env
        self.active_agents = {}
        self.vip_id_uuid_map = {}
        self.uuid_vip_id_map = {}
        self.secure_agent_user = cc.is_secure_mode()
        self.message_bus = cc.get_messagebus()

        # if self.message_bus == 'rmq':
        #     self.rmq_mgmt = RabbitMQMgmt()
        self.instance_name = cc.get_instance_name()    # get_platform_instance_name()

    def add_agent_user_group(self):
        user = pwd.getpwuid(os.getuid())
        group_name = "volttron_{}".format(self.instance_name)
        try:
            group = grp.getgrnam(group_name)
        except KeyError:
            _log.info("Creating the volttron agent group {}.".format(group_name))
            groupadd = ["sudo", "groupadd", group_name]
            groupadd_process = subprocess.Popen(groupadd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = groupadd_process.communicate()
            if groupadd_process.returncode != 0:
                # TODO alert?
                raise RuntimeError("Add {} group failed ({}) - Prevent "
                                   "creation of agent users".format(stderr, group_name))
            group = grp.getgrnam(group_name)

    def add_agent_user(self, agent_name, agent_dir):
        """
        Invokes sudo to create a unique unix user for the agent.
        :param agent_name:
        :param agent_dir:
        :return:
        """

        # Ensure the agent users unix group exists
        self.add_agent_user_group()

        # Create a USER_ID file, truncating existing USER_ID files which
        # should at this point be considered unsafe
        user_id_path = os.path.join(agent_dir, "USER_ID")

        with open(user_id_path, "w+") as user_id_file:
            volttron_agent_user = "volttron_{}".format(
                str(get_utc_seconds_from_epoch()).replace(".", ""))
            _log.info("Creating volttron user {}".format(volttron_agent_user))
            group = "volttron_{}".format(self.instance_name)
            useradd = ["sudo", "useradd", volttron_agent_user, "-r", "-G", group]
            useradd_process = subprocess.Popen(useradd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = useradd_process.communicate()
            if useradd_process.returncode != 0:
                # TODO alert?
                raise RuntimeError("Creating {} user failed: {}".format(
                    volttron_agent_user, stderr))
            user_id_file.write(volttron_agent_user)
        return volttron_agent_user

    def set_acl_for_path(self, perms, user, path):
        """
        Sets the file access control list setting for a given user/directory
        :param perms:
        :param user:
        :param directory:
        :return:
        """
        acl_perms = "user:{user}:{perms}".format(user=user, perms=perms)
        permissions_command = ["setfacl", "-m", acl_perms, path]
        _log.debug("PERMISSIONS COMMAND {}".format(permissions_command))
        permissions_process = subprocess.Popen(permissions_command,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
        stdout, stderr = permissions_process.communicate()
        if permissions_process.returncode != 0:
            _log.error("Set {} permissions on {}, stdout: {}".format(perms, path, stdout))
            # TODO alert?
            raise RuntimeError("Setting {} permissions on {} failed: {}".format(
                perms, path, stderr))

    def set_agent_user_permissions(self, volttron_agent_user, agent_uuid, agent_dir):
        name = self.agent_name(agent_uuid)
        agent_path_with_name = os.path.join(agent_dir, name)
        # Directories in the install path have read/execute
        # except agent-data dir. agent-data dir has rwx
        self.set_acl_for_path("rx", volttron_agent_user, agent_dir)
        # creates dir if it doesn't exist
        data_dir = self._get_agent_data_dir(agent_path_with_name)

        for (root, directories, files) in os.walk(agent_dir, topdown=True):
            for directory in directories:
                if directory == os.path.basename(data_dir):
                    self.set_acl_for_path("rwx", volttron_agent_user,
                                          os.path.join(root, directory))
                else:
                    self.set_acl_for_path("rx", volttron_agent_user, os.path.join(root, directory))
        # In install directory, make all files' permissions to 400.
        # Then do setfacl -m "r" to only agent user
        self._set_agent_dir_file_permissions(agent_dir, volttron_agent_user, data_dir)

        # if messagebus is rmq.
        # TODO: For now provide read access to all agents since this is used for
        #  multi instance connections. This will not be requirement in
        #  VOLTTRON 8.0 once CSR is implemented for
        #  federation and shovel. The below lines can be removed then
        if self.message_bus == "rmq":
            os.chmod(os.path.join(cc.get_volttron_home, "certificates/private"), 0o755)
            self.set_acl_for_path(
                "r",
                volttron_agent_user,
                os.path.join(
                    cc.get_volttron_home(),
                    "certificates/private",
                    self.instance_name + "-admin.pem",
                ),
            )

    def _set_agent_dir_file_permissions(self, input_dir, agent_user, data_dir):
        """Recursively change permissions to all files in given directrory to 400 but for files in
        agent-data directory
        """
        for (root, directories, files) in os.walk(input_dir, topdown=True):
            for f in files:
                permissions = "r"
                if root == data_dir:
                    permissions = "rwx"
                file_path = os.path.join(root, f)
                # in addition agent user has access
                self.set_acl_for_path(permissions, agent_user, file_path)

    def remove_agent_user(self, volttron_agent_user):
        """
        Invokes sudo to remove the unix user for the given environment.
        """
        if pwd.getpwnam(volttron_agent_user):
            _log.info("Removing volttron agent user {}".format(volttron_agent_user))
            userdel = ["sudo", "userdel", volttron_agent_user]
            userdel_process = subprocess.Popen(userdel,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
            stdout, stderr = userdel_process.communicate()
            if userdel_process.returncode != 0:
                _log.error("Remove {user} user failed: {stderr}".format(user=volttron_agent_user,
                                                                        stderr=stderr))
                raise RuntimeError(stderr)

    def setup(self):
        """Creates paths for used directories for the instance."""
        for path in [self.run_dir, self.config_dir, self.install_dir]:
            if not os.path.exists(path):
                # others should have read and execute access to these directory
                # so explicitly set to 755.
                _log.debug("Setting up 755 permissions for path {}".format(path))
                os.makedirs(path)
                os.chmod(path, 0o755)
        # Create certificates directory and its subdirectory at start of platform
        # so if volttron is run in secure mode, the first agent install would already have
        # the directories ready. In secure mode, agents will be run as separate user and will
        # not have access to create these directories
        Certs()

        # load installed agent vip_id ids and uuids

        for vip_id in os.listdir(self.install_dir):
            with open(os.path.join(self.install_dir, vip_id, "UUID"), "r") as f:
                agent_uuid = f.read().strip()
                self.uuid_vip_id_map[agent_uuid] = vip_id
                self.vip_id_uuid_map[vip_id] = agent_uuid

    def finish(self):
        for exeenv in self.active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.send_signal(signal.SIGINT)
        for exeenv in self.active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.terminate()
        for exeenv in self.active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.kill()

    def shutdown(self):
        for agent_uuid in self.active_agents.keys():
            _log.debug("Stopping agent UUID {}".format(agent_uuid))
            self.stop_agent(agent_uuid)
        event = gevent.event.Event()
        agent = Agent(identity="aip", address="inproc://vip", message_bus=self.message_bus)
        task = gevent.spawn(agent.core.run, event)
        try:
            event.wait()
        finally:
            agent.core.stop()
            task.kill()

    def brute_force_platform_shutdown(self):
        for agent_uuid in list(self.active_agents.keys()):
            _log.debug("Stopping agent UUID {}".format(agent_uuid))
            self.stop_agent(agent_uuid)
        # kill the platform
        pid = None
        pid_file = "{vhome}/VOLTTRON_PID".format(vhome=cc.get_volttron_home())
        with open(pid_file) as f:
            pid = int(f.read())
        if pid:
            os.kill(pid, signal.SIGINT)
            os.remove(pid_file)

    subscribe_address = property(lambda me: me.env.subscribe_address)
    publish_address = property(lambda me: me.env.publish_address)

    config_dir = property(lambda me: os.path.abspath(me.env.volttron_home))
    install_dir = property(lambda me: os.path.join(me.config_dir, "agents"))
    run_dir = property(lambda me: os.path.join(me.config_dir, "run"))

    def autostart(self):
        agents, errors = [], []
        for agent_uuid, agent_name in self.list_agents().items():
            try:
                priority = self._agent_priority(agent_uuid)
            except EnvironmentError as exc:
                errors.append((agent_uuid, str(exc)))
                continue
            if priority is not None:
                agents.append((priority, agent_uuid))
        agents.sort(reverse=True)
        for _, agent_uuid in agents:
            try:
                self.start_agent(agent_uuid)
            except Exception as exc:
                errors.append((agent_uuid, str(exc)))
        return errors

    def land_agent(self, agent_wheel):
        if auth is None:
            raise NotImplementedError()
        agent_uuid = self.install_agent(agent_wheel)
        try:
            self.start_agent(agent_uuid)
            self.prioritize_agent(agent_uuid)
        except:
            self.remove_agent(agent_uuid)
            raise
        return agent_uuid

    def install_agent(self,
                      agent_wheel,
                      vip_identity=None,
                      publickey=None,
                      secretkey=None,
                      agent_config=None):
        """
        Install the agent into the current environment.

        Installs the agent into the current environment, setup the agent data directory and
        agent data structure.
        """
        _log.info(f"AGENT_WHEEL: {agent_wheel}")

        if agent_config is None:
            agent_config = dict()

        cmd = ["pip", "install", agent_wheel]
        response = execute_command(cmd)
        agent_name = None
        find_success = re.match("Successfully installed (.*)", response.strip().split("\n")[-1])

        if find_success:
            _log.debug("Successfully installed package: {find_success}")
            agent_name = self._get_agent_name_on_success(
                find_success, self._construct_package_name_from_agent_wheel(agent_wheel))
        elif not find_success:
            find_already_installed = re.match(
                f"Requirement already satisfied: (.*) from file://{agent_wheel}", response)
            if not find_already_installed:
                _log.debug("Wheel NOT already installed...")
                agent_name = self._get_agent_name_on_response(response, agent_wheel)
            else:
                _log.info("Wheel already installed...")
                agent_name = find_already_installed.groups()[0].replace("==", "-")
        _log.info(f"AGENT_NAME: {agent_name}")
        final_identity = self._setup_agent_vip_id(agent_name, vip_identity=vip_identity)

        if self.secure_agent_user:
            _log.info("Installing secure Volttron agent...")

        uuid_values = self.uuid_vip_id_map.keys()

        # After the while statement either error out or we have
        # an agent directory with UUID file in it.
        # agents/
        #     agent_identity/
        #           data/
        #           UUID
        #
        while True:
            agent_uuid = str(uuid.uuid4())
            # will need below check if dynamic agents get uuid
            # if agent_uuid in self.agents:
            #     continue
            if agent_uuid not in uuid_values:
                break

        agent_path = os.path.join(self.install_dir, final_identity)
        try:
            os.makedirs(os.path.join(agent_path, "data"))
            with open(os.path.join(agent_path, "UUID"), "w") as f:
                f.write(agent_uuid)
            with open(os.path.join(agent_path, "NAME"), "w") as f:
                f.write(agent_name)
            with open(os.path.join(agent_path, "config"), "w") as f:
                yaml.dump(agent_config, f)
        except OSError as exc:
            raise
        try:
            # if auth is not None and self.env.verify_agents:
            #     unpacker = auth.VolttronPackageWheelFile(agent_wheel, certsobj=Certs())
            #     unpacker.unpack(dest=agent_path)

            keystore = self.__get_agent_keystore__(final_identity, publickey, secretkey)

            self._authorize_agent_keys(final_identity, keystore.public)

            if self.message_bus == "rmq":
                rmq_user = cc.get_fq_identity(final_identity, cc.get_instance_name())
                # rmq_user = get_fq_identity(final_identity,
                #                            self.instance_name)
                Certs().create_signed_cert_files(rmq_user, overwrite=False)

            if self.secure_agent_user:
                # When installing, we always create a new user, as anything
                # that already exists is untrustworthy
                created_user = self.add_agent_user(self.agent_name(agent_uuid), agent_path)
                self.set_agent_user_permissions(created_user, agent_uuid, agent_path)

            # finally update the vip id uuid maps
            self.vip_id_uuid_map[final_identity] = agent_uuid
            self.uuid_vip_id_map[agent_uuid] = final_identity

        except Exception:
            shutil.rmtree(agent_path)
            raise

        return agent_uuid

    def _construct_package_name_from_agent_wheel(self, agent_wheel):
        wheel = agent_wheel.split("/")[-1]
        wheel = wheel.replace("-py3-none-any.whl", "")
        return wheel.replace("_", "-")

    def _get_agent_name_on_success(self, find_success, wheel_target):
        _log.info(f"wheel_target: {wheel_target}")

        for package in find_success.groups()[0].split():
            # search for the agent name nthat we want
            _log.debug(f"package: {package}")
            if package == wheel_target:
                return package
        raise ValueError("Could not find package")

    def _get_agent_name_on_response(self, response, agent_wheel):
        groups = re.search(".*\n(.*) is already installed with the same version",
                           response).groups()
        if groups:
            find_already_installed = groups[0].strip()
            cmd = ["pip", "show", find_already_installed]
            response = execute_command(cmd)
            version = re.search(".*\nVersion: (.*)", response).groups()[0].strip()
            return find_already_installed + "-" + version
        raise ValueError(f"Couldn't install {agent_wheel}\n{response}")

    def _setup_agent_vip_id(self, agent_name, vip_identity=None):
        # agent_path = os.path.join(self.install_dir, agent_name)
        # name = self.agent_name(agent_name)
        # pkg = None
        # # TODO: wheel wrap
        # # pkg = UnpackedPackage(os.path.join(agent_path, name))
        # identity_template_filename = os.path.join(pkg.distinfo, "IDENTITY_TEMPLATE")

        # rm_id_template = False
        #
        # if not os.path.exists(identity_template_filename):
        #     agent_name = self.agent_name(agent_name)
        #     name_template = agent_name + "_{n}"
        # else:
        #     with open(identity_template_filename, "r") as fp:
        #         name_template = fp.read(64)
        #
        #     rm_id_template = True
        #
        name_template = agent_name + "_{n}"

        if vip_identity is not None:
            name_template = vip_identity

        _log.debug('Using name template "' + name_template + '" to generate VIP ID')

        final_identity = self._get_available_agent_identity(name_template)

        if final_identity is None:
            raise ValueError(
                "Agent with VIP ID {} already installed on platform.".format(name_template))

        if not is_valid_identity(final_identity):
            raise ValueError("Invalid identity detected: {}".format(",".format(final_identity)))

        # identity_filename = os.path.join(agent_path, "IDENTITY")
        #
        # with open(identity_filename, "w") as fp:
        #     fp.write(final_identity)
        #
        # _log.info(
        #     "Agent {uuid} setup to use VIP ID {vip_identity}".format(
        #         uuid=agent_name, vip_identity=final_identity
        #     )
        # )
        #
        # # Cleanup IDENTITY_TEMPLATE file.
        # if rm_id_template:
        #     os.remove(identity_template_filename)
        #     _log.debug("IDENTITY_TEMPLATE file removed.")

        return final_identity

    def __get_agent_keystore__(self,
                               vip_identity: str,
                               encoded_public: Optional[str] = None,
                               encoded_secret: Optional[str] = None):
        agent_path = os.path.join(self.install_dir, vip_identity)
        keystore_path = os.path.join(agent_path, "keystore.json")
        return KeyStore(keystore_path, encoded_public, encoded_secret)

    def get_agent_keystore(self, agent_uuid, encoded_public=None, encoded_secret=None):
        # TODO fix path
        agent_path = os.path.join(self.install_dir, agent_uuid)
        agent_name = self.agent_name(agent_uuid)
        dist_info = os.path.join(agent_path, agent_name, agent_name + ".dist-info")
        keystore_path = os.path.join(dist_info, "keystore.json")
        return KeyStore(keystore_path, encoded_public, encoded_secret)

    def _authorize_agent_keys(self, identity, publickey):
        capabilities = {"edit_config_store": {"identity": identity}}

        if identity == VOLTTRON_CENTRAL_PLATFORM:
            capabilities = {"edit_config_store": {"identity": "/.*/"}}

        entry = AuthEntry(
            credentials=publickey,
            user_id=identity,
            capabilities=capabilities,
            comments="Automatically added on agent install",
        )
        try:
            AuthFile().add(entry)
        except AuthFileEntryAlreadyExists:
            pass

    def _unauthorize_agent_keys(self, agent_uuid):
        publickey = self.__get_agent_keystore__(self.uuid_vip_id_map[agent_uuid]).public
        AuthFile().remove_by_credentials(publickey)

    def _get_agent_data_dir(self, agent_path):
        pkg = None
        # TODO: wheel_wrap
        # pkg = UnpackedPackage(agent_path)
        data_dir = os.path.join(os.path.dirname(pkg.distinfo),
                                "{}.agent-data".format(pkg.package_name))
        if not os.path.exists(data_dir):
            os.mkdir(data_dir)
        return data_dir

    def get_agent_data_dir(self, agent_uuid=None, vip_identity=None):
        data_dir = None
        if vip_identity and vip_identity in self.vip_id_uuid_map.keys():
            data_dir = os.path.join(self.install_dir, vip_identity, "data")
        elif agent_uuid and agent_uuid in self.uuid_vip_id_map.keys():
            data_dir = os.path.join(self.install_dir, self.uuid_vip_id_map[agent_uuid], "data")
        return data_dir

    def _get_available_agent_identity(self, name_template):
        all_agent_identities = self.vip_id_uuid_map.keys()

        # Provided name template is static
        if name_template == name_template.format(n=0):
            return name_template if name_template not in all_agent_identities else None

        # Find a free ID
        count = 1
        while True:
            test_name = name_template.format(n=count)
            if test_name not in all_agent_identities:
                return test_name
            count += 1

    def remove_agent(self, agent_uuid, remove_auth=True):
        if self.secure_agent_user:
            _log.info("Running Volttron agents securely with Unix Users.")
        else:
            _log.info("Not running with secure users.")
        if agent_uuid not in self.uuid_vip_id_map:
            raise ValueError("invalid agent")
        self.stop_agent(agent_uuid)
        msg_bus = self.message_bus
        vip_identity = self.uuid_vip_id_map[agent_uuid]

        # get list of agent uuid to name mapping
        uuid_name_map = self.list_agents()
        agent_name = uuid_name_map.pop(agent_uuid)
        # TODO replace when adding rmq in a container addin/plugin
        # if msg_bus == "rmq":
        #     # Delete RabbitMQ user for the agent
        #     instance_name = self.instance_name
        #     rmq_user = instance_name + "." + vip_identity
        #     try:
        #         self.rmq_mgmt.delete_user(rmq_user)
        #     except requests.exceptions.HTTPError as e:
        #         _log.error(
        #             f"RabbitMQ user {rmq_user} is not available to delete. Going ahead and removing agent directory"
        #         )
        self.active_agents.pop(agent_uuid, None)
        agent_directory = os.path.join(self.install_dir, vip_identity)
        volttron_agent_user = None
        if self.secure_agent_user:
            user_id_path = os.path.join(agent_directory, "USER_ID")
            try:
                with open(user_id_path, "r") as user_id_file:
                    volttron_agent_user = user_id_file.readline()
            except (KeyError, IOError) as user_id_err:
                _log.warning("Volttron agent user not found at {}".format(user_id_path))
                _log.warning(user_id_err)
        if remove_auth:
            self._unauthorize_agent_keys(agent_uuid)
        shutil.rmtree(agent_directory)
        if volttron_agent_user:
            self.remove_agent_user(volttron_agent_user)

        # check if there are other instances of the same agent.
        if agent_name not in uuid_name_map.values():
            # if no other uuid has the same agent name. There was only one instance that we popped earlier
            # so safe to uninstall source
            execute_command(["pip", "uninstall", "-y", agent_name[:agent_name.rfind("-")]])
        # update uuid vip id maps
        self.uuid_vip_id_map.pop(agent_uuid)
        self.vip_id_uuid_map.pop(vip_identity)

    def agent_name(self, agent_uuid=None, vip_identity=None):
        name = None
        if vip_identity or agent_uuid:
            if not vip_identity:
                vip_identity = self.uuid_vip_id_map.get(agent_uuid)
            if vip_identity:
                agent_path = os.path.join(self.install_dir, vip_identity)
                with open(os.path.join(agent_path, "NAME")) as uuid_file:
                    name = uuid_file.read().strip()
        return name

    def agent_uuid(self, vip_identity):
        agent_path = os.path.join(self.install_dir, vip_identity)
        agent_uuid = None
        with open(os.path.join(agent_path, "UUID")) as uuid_file:
            agent_uuid = uuid_file.read().strip()
        return agent_uuid

    def list_agents(self):
        agents = {}
        for vip_identity, agent_uuid in self.vip_id_uuid_map.items():
            try:
                agents[agent_uuid] = self.agent_name(vip_identity=vip_identity)
            except KeyError:
                pass
        return agents

    def get_active_agents_meta(self, get_agent_user=False):
        if self.secure_agent_user and get_agent_user:
            return {
                agent_uuid: (execenv.name, execenv.agent_user)
                for agent_uuid, execenv in self.active_agents.items()
            }
        else:
            return {agent_uuid: execenv.name for agent_uuid, execenv in self.active_agents.items()}

    def clear_status(self, clear_all=False):
        remove = []
        for agent_uuid, execenv in self.active_agents.items():
            if execenv.process.poll() is not None:
                if clear_all:
                    remove.append(agent_uuid)
                else:
                    path = os.path.join(self.install_dir, agent_uuid)
                    if not os.path.exists(path):
                        remove.append(agent_uuid)
        for agent_uuid in remove:
            self.active_agents.pop(agent_uuid, None)

    def status_agents(self, get_agent_user=False):
        if self.secure_agent_user and get_agent_user:
            return [(agent_uuid, agent[0], agent[1], self.agent_status(agent_uuid),
                     self.uuid_vip_id_map[agent_uuid])
                    for agent_uuid, agent in self.get_active_agents_meta().items()]
        else:
            return [(agent_uuid, agent_name, self.agent_status(agent_uuid),
                     self.uuid_vip_id_map[agent_uuid])
                    for agent_uuid, agent_name in self.get_active_agents_meta().items()]

    def tag_agent(self, agent_uuid, tag):
        tag_file = os.path.join(self.install_dir, self.uuid_vip_id_map[agent_uuid], "TAG")
        if not tag:
            with ignore_enoent:
                os.unlink(tag_file)
        else:
            with open(tag_file, "w") as file:
                file.write(tag[:64])

    def agent_identity(self, agent_uuid):
        """Return the identity of the agent that is installed.

        The IDENTITY file is written to the agent's install directory the
        the first time the agent is installed.  This function reads that
        file and returns the read value.

        @param agent_uuid:
        @return:
        """
        raise RuntimeError("TODO")

    def agent_tag(self, agent_uuid=None, vip_identity=None):
        if not agent_uuid and not vip_identity:
            raise ValueError("invalid agent")

        if not vip_identity:
            if "/" in agent_uuid or agent_uuid in [".", ".."
                                                   ] or not self.uuid_vip_id_map.get(agent_uuid):
                raise ValueError("invalid agent")
            vip_identity = self.uuid_vip_id_map[agent_uuid]

        tag_file = os.path.join(self.install_dir, vip_identity, "TAG")
        with ignore_enoent, open(tag_file, "r") as file:
            return file.readline(64)

    def agent_version(self, agent_uuid):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        agent_path = os.path.join(self.install_dir, agent_uuid)
        name = self.agent_name(agent_uuid)
        pkg = None
        pkg.version = "4.4"
        # TODO: wheel_wrap
        # pkg = UnpackedPackage(os.path.join(agent_path, name))
        return pkg.version

    def agent_dir(self, agent_uuid):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        return os.path.join(self.install_dir, agent_uuid, self.agent_name(agent_uuid))

    def agent_versions(self):
        agents = {}
        for agent_uuid in os.listdir(self.install_dir):
            try:
                agents[agent_uuid] = (
                    self.agent_name(agent_uuid),
                    self.agent_version(agent_uuid),
                )
            except KeyError:
                pass
        return agents

    def _agent_priority(self, agent_uuid):
        # TODO update path
        autostart = os.path.join(self.install_dir, agent_uuid, "AUTOSTART")
        with ignore_enoent, open(autostart) as file:
            return file.readline(100).strip()

    def agent_priority(self, agent_uuid):
        # TODO update path
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        return self._agent_priority(agent_uuid)

    def prioritize_agent(self, agent_uuid, priority="50"):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        autostart = os.path.join(self.install_dir, agent_uuid, "AUTOSTART")
        if priority is None:
            with ignore_enoent:
                os.unlink(autostart)
        else:
            with open(autostart, "w") as file:
                file.write(priority.strip())

    def _check_resources(self, resmon, execreqs, reserve=False, agent_user=None):
        hard_reqs = execreqs.get("hard_requirements", {})
        failed_terms = resmon.check_hard_resources(hard_reqs)
        if failed_terms:
            msg = "\n".join("  {}: {} ({})".format(term, hard_reqs[term], avail)
                            for term, avail in failed_terms.items())
            _log.error("hard resource requirements not met:\n%s", msg)
            raise ValueError("hard resource requirements not met")
        requirements = execreqs.get("requirements", {})
        try:
            if reserve:
                # return resmon.reserve_soft_resources(requirements)
                if agent_user:
                    return SecureExecutionEnvironment(agent_user=agent_user)
                else:
                    return ExecutionEnvironment()
            else:
                failed_terms = resmon.check_soft_resources(requirements)
                if failed_terms:
                    errmsg = "soft resource requirements not met"
                else:
                    return
        except ResourceError as exc:
            errmsg, failed_terms = exc.args
        msg = "\n".join("  {}: {} ({})".format(term, requirements.get(term, "<unset>"), avail)
                        for term, avail in failed_terms.items())
        _log.error("%s:\n%s", errmsg, msg)
        raise ValueError(errmsg)

    def check_resources(self, execreqs, agent_user=None):
        resmon = getattr(self.env, "resmon", None)
        if resmon:
            return self._check_resources(resmon, execreqs, reserve=False, agent_user=agent_user)

    def _reserve_resources(self, resmon, execreqs, agent_user=None):
        return self._check_resources(resmon, execreqs, reserve=True, agent_user=agent_user)

    def get_execreqs(self, agent_uuid):
        name = self.agent_name(agent_uuid)
        pkg = None
        # pkg = UnpackedPackage(os.path.join(self.install_dir, agent_uuid, name))
        return self._read_execreqs(pkg.distinfo)

    def _read_execreqs(self, dist_info):
        execreqs_json = os.path.join(dist_info, "execreqs.json")
        try:
            with ignore_enoent, open(execreqs_json) as file:
                return jsonapi.load(file)
        except Exception as exc:
            msg = "error reading execution requirements: {}: {}".format(execreqs_json, exc)
            _log.error(msg)
            raise ValueError(msg)
        _log.warning("missing execution requirements: %s", execreqs_json)
        return {}

    def start_agent(self, agent_uuid):
        name = self.agent_name(agent_uuid)
        name_no_version = name[0:name.rfind(
            "-")]    # get last index of - to split version number from name

        vip_identity = self.uuid_vip_id_map[agent_uuid]
        agent_dir = os.path.join(self.install_dir, vip_identity)
        execenv = self.active_agents.get(agent_uuid)
        if execenv and execenv.process.poll() is None:
            _log.warning("request to start already running agent %s", name)
            raise ValueError("agent is already running")

        # python3.8 and above have this implementation.
        from importlib import metadata
        entrypoint = None
        entrypoints = metadata.distribution(name_no_version).entry_points
        for entrypoint in entrypoints:
            if entrypoint.group == "console_scripts":
                break
            if entrypoint.group == "setuptools.installation" and entrypoint.name == "eggsecutable":
                break
            if entrypoint.group == "volttron.agent" and entrypoint.name == "launch":
                break

        if not entrypoints or not entrypoint:
            raise ValueError("Unable to find entry point ['console_scripts'] or "
                             "['setuptools.installation']['eggsecutable'] or "
                             "['volttron.agent']['launch']")
        parts = entrypoint.value.split(":")
        module = parts[0]
        fn = parts[1]
        argv = [sys.executable, "-c", f"from {module} import {fn}; {fn}()"]

        config = os.path.join(self.install_dir, vip_identity, "config")
        tag = self.agent_tag(agent_uuid)
        environ = os.environ.copy()
        # environ["PYTHONPATH"] = ":".join([agent_path_with_name] + sys.path)
        # environ["PATH"] = (
        #     os.path.abspath(os.path.dirname(sys.executable)) + ":" + environ["PATH"]
        # )
        if os.path.exists(config):
            environ["AGENT_CONFIG"] = config
        else:
            environ.pop("AGENT_CONFIG", None)
        if tag:
            environ["AGENT_TAG"] = tag
        else:
            environ.pop("AGENT_TAG", None)
        environ["AGENT_SUB_ADDR"] = self.subscribe_address
        environ["AGENT_PUB_ADDR"] = self.publish_address
        environ["AGENT_UUID"] = agent_uuid
        environ["_LAUNCHED_BY_PLATFORM"] = "1"

        environ["AGENT_VIP_IDENTITY"] = vip_identity
        environ["VOLTTRON_SERVERKEY"] = KeyStore().public
        keystore_path = os.path.join(cc.get_volttron_home(), "agents", vip_identity,
                                     "keystore.json")
        keystore = KeyStore(keystore_path)
        environ["AGENT_PUBLICKEY"], environ["AGENT_SECRETKEY"] = keystore.public, keystore.secret

        #module, _, func = module.partition(":")
        # if func:
        #     code = '__import__({0!r}, fromlist=[{1!r}]).{1}()'.format(module,
        #                                                               func)
        #     argv = [sys.executable, '-c', code]
        # else:
        # argv = [sys.executable, "-m", module]
        agent_user = None

        if self.secure_agent_user:
            # TODO: fix agent path and permissions for secure mode
            _log.info("Starting agent securely...")
            user_id_path = os.path.join(agent_dir, "USER_ID")
            try:
                with open(user_id_path, "r") as user_id_file:
                    volttron_agent_id = user_id_file.readline()
                    pwd.getpwnam(volttron_agent_id)
                    agent_user = volttron_agent_id
                    _log.info("Found secure volttron agent user {}".format(agent_user))
            except (IOError, KeyError) as err:
                _log.info("No existing volttron agent user was found at {} due "
                          "to {}".format(user_id_path, err))

                # May be switched from normal to secure mode with existing agents. To handle this case
                # create users and also set permissions again for existing files
                agent_user = self.add_agent_user(name, agent_dir)
                self.set_agent_user_permissions(agent_user, agent_uuid, agent_dir)

                # additionally give permissions to contents of agent-data dir.
                # This is needed only for agents installed before switching to
                # secure mode. Agents installed in secure mode will own files
                # in agent-data dir
                # Moved this to the top so that "agent-data" directory gets
                # created in the beginning
                # data_dir = self._get_agent_data_dir(agent_path_with_name)

                for (root, directories, files) in os.walk(data_dir, topdown=True):
                    for directory in directories:
                        self.set_acl_for_path("rwx", agent_user, os.path.join(root, directory))
                    for f in files:
                        self.set_acl_for_path("rwx", agent_user, os.path.join(root, f))

        if self.message_bus == "rmq":
            rmq_user = cc.get_fq_identity(vip_identity, self.instance_name)
            _log.info("Create RMQ user {} for agent {}".format(rmq_user, vip_identity))

            self.rmq_mgmt.create_user_with_permissions(
                rmq_user, self.rmq_mgmt.get_default_permissions(rmq_user), ssl_auth=True)
            key_file = Certs().private_key_file(rmq_user)
            if not os.path.exists(key_file):
                # This could happen when user switches from zmq to rmq after installing agent
                _log.info(f"agent certs don't exists. creating certs for agent")
                Certs().create_signed_cert_files(rmq_user, overwrite=False)

            if self.secure_agent_user:
                # give read access to user to its own private key file.
                self.set_acl_for_path("r", agent_user, key_file)

        if agent_user:
            execenv = SecureExecutionEnvironment(agent_user=agent_user)
        else:
            execenv = ExecutionEnvironment()

        execenv.name = name
        _log.info("starting agent %s", name)
        _log.info("starting agent using {} ".format(type(execenv)))
        execenv.execute(
            argv,
            env=environ,
            close_fds=True,
            stdin=open(os.devnull),
            stdout=PIPE,
            stderr=PIPE,
        )
        self.active_agents[agent_uuid] = execenv
        proc = execenv.process
        _log.info("agent %s has PID %s", name, proc.pid)
        gevent.spawn(
            log_stream,
            "agents.stderr",
            name,
            proc.pid,
            argv[0],
            log_entries("agents.log", name, proc.pid, logging.ERROR, proc.stderr),
        )
        gevent.spawn(
            log_stream,
            "agents.stdout",
            name,
            proc.pid,
            argv[0],
            ((logging.INFO, line) for line in (l.splitlines() for l in proc.stdout)),
        )

        return self.agent_status(agent_uuid)

    def agent_status(self, agent_uuid):
        execenv = self.active_agents.get(agent_uuid)
        if execenv is None:
            return (None, None)
        return execenv.process.pid, execenv.process.poll()

    def stop_agent(self, agent_uuid):
        try:
            execenv = self.active_agents[agent_uuid]
            return execenv.stop()
        except KeyError:
            return

    def agent_uuid_from_pid(self, pid):
        for agent_uuid, execenv in self.active_agents.items():
            if execenv.process.pid == pid:
                return agent_uuid if execenv.process.poll() is None else None
