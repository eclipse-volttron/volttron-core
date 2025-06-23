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
import tarfile
import uuid
from typing import Optional

# import requests
import gevent
import gevent.event
import yaml
from gevent import subprocess
from gevent.subprocess import PIPE

from volttron.client.known_identities import VOLTTRON_CENTRAL_PLATFORM
from volttron.server.decorators import service
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_service import AuthService
from volttron.types.auth.auth_credentials import CredentialsStore

# from wheel.tool import unpack
from volttron.utils import ClientContext as cc, jsonapi
from volttron.utils import execute_command, get_utc_seconds_from_epoch
from volttron.utils.certs import Certs
from volttron.utils.identities import is_valid_identity

# TODO route to wheel_wrap
# from .packages import UnpackedPackage

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
                raise RuntimeError("Exception stopping agent: stdout {} stderr: {}".format(stdout, stderr))
        return self.process.poll()

    def __call__(self, *args, **kwargs):
        self.execute(*args, **kwargs)


@service
class AIPplatform:
    """Manages the main workflow of receiving and sending agents."""

    def __init__(self,
                 server_opts: ServerOptions,
                 auth_service: AuthService | None = None,
                 credentials_store: CredentialsStore | None = None,
                 **kwargs):
        self._server_opts = server_opts
        self._auth_service = auth_service
        self._credentials_store = credentials_store
        self._active_agents = {}
        self._vip_id_uuid_map = {}
        self._uuid_vip_id_map = {}
        self._secure_agent_user = cc.is_secure_mode()
        self._instance_name = cc.get_instance_name()    # get_platform_instance_name()

    # methods for agent isolation mode. Test with next round of changes
    def add_agent_user_group(self):
        user = pwd.getpwuid(os.getuid())
        group_name = "volttron_{}".format(self._instance_name)
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
            volttron_agent_user = "volttron_{}".format(str(get_utc_seconds_from_epoch()).replace(".", ""))
            _log.info("Creating volttron user {}".format(volttron_agent_user))
            group = "volttron_{}".format(self._instance_name)
            useradd = ["sudo", "useradd", volttron_agent_user, "-r", "-G", group]
            useradd_process = subprocess.Popen(useradd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = useradd_process.communicate()
            if useradd_process.returncode != 0:
                # TODO alert?
                raise RuntimeError("Creating {} user failed: {}".format(volttron_agent_user, stderr))
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
        permissions_process = subprocess.Popen(permissions_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = permissions_process.communicate()
        if permissions_process.returncode != 0:
            _log.error("Set {} permissions on {}, stdout: {}".format(perms, path, stdout))
            # TODO alert?
            raise RuntimeError("Setting {} permissions on {} failed: {}".format(perms, path, stderr))

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
                    self.set_acl_for_path("rwx", volttron_agent_user, os.path.join(root, directory))
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
            os.chmod(os.path.join(cc.get_volttron_home(), "certificates/private"), 0o755)
            self.set_acl_for_path(
                "r",
                volttron_agent_user,
                os.path.join(
                    cc.get_volttron_home(),
                    "certificates/private",
                    self._instance_name + "-admin.pem",
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
            userdel_process = subprocess.Popen(userdel, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = userdel_process.communicate()
            if userdel_process.returncode != 0:
                _log.error("Remove {user} user failed: {stderr}".format(user=volttron_agent_user, stderr=stderr))
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
                self._uuid_vip_id_map[agent_uuid] = vip_id
                self._vip_id_uuid_map[vip_id] = agent_uuid

    def finish(self):
        for exeenv in self._active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.send_signal(signal.SIGINT)
        for exeenv in self._active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.terminate()
        for exeenv in self._active_agents.values():
            if exeenv.process.poll() is None:
                exeenv.process.kill()

    def shutdown(self):
        """
        Stop each of the agents that are currently running on the platform.  This allows
        clean shutdown rather than just killing off the individual processes.
        """

        for agent_uuid in self._active_agents.keys():
            _log.debug("Stopping agent UUID {}".format(agent_uuid))
            self.stop_agent(agent_uuid)

    def brute_force_platform_shutdown(self):
        for agent_uuid in list(self._active_agents.keys()):
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

    # subscribe_address = property(lambda me: me.env.subscribe_address)
    # publish_address = property(lambda me: me.env.publish_address)

    config_dir = property(lambda me: os.path.abspath(me._server_opts.volttron_home))
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

    def backup_agent_data(self, agent_uuid, vip_identity):
        backup_agent_file = None
        if agent_uuid:
            _log.debug(f"There is an existing agent {agent_uuid}")
            old_agent_data_dir = self.get_agent_data_dir(agent_uuid)
            if os.listdir(old_agent_data_dir):
                # And there is data to backup
                backup_agent_file = "/tmp/{}.tar.gz".format(agent_uuid)
                with tarfile.open(backup_agent_file, "w:gz") as tar:
                    tar.add(old_agent_data_dir, arcname=os.path.sep)    # os.path.basename(source_dir))
        return backup_agent_file

    @staticmethod
    def restore_agent_data_from_tgz(source_file, output_dir):
        # Open tarfile
        with tarfile.open(source_file, mode="r:gz") as tar:
            tar.extractall(output_dir)

    def install_agent(self, agent, vip_identity=None, agent_config=None, force=False, pre_release=False, editable=False):
        """
        Installs the agent into the current environment, set up the agent data directory and
        agent data structure.
        """
        if agent_config is None:
            agent_config = dict()

        name, name_with_version, site_package_dir = self.install_agent_or_lib_source(agent, force, pre_release, editable)
        # get default vip_identity if vip_identity is not passed
        # default value will be in "agent_name-default-vip-id" file in site-packages dir
        if vip_identity is None:
            # get default vip id if one is specified in src
            default_vip_id_file = os.path.join(site_package_dir, f"{name}-default-vip-id")
            _log.info(f"Default vip id file is {default_vip_id_file}")
            if os.path.isfile(default_vip_id_file):
                with open(str(default_vip_id_file)) as fin:
                    vip_identity = fin.read().strip()

        agent_uuid = self._raise_error_if_identity_exists_without_force(vip_identity, force)
        # This should happen before install of source. why?
        backup_agent_file = self.backup_agent_data(agent_uuid, vip_identity)

        if agent_uuid:
            _log.info('Removing previous version of agent "{}"\n'.format(vip_identity))
            # we are either installing new agent or if using --force. if --force is true src would have got updated
            # in install_agent_source
            self.remove_agent(agent_uuid, remove_auth=False, remove_unused_src=False)

        final_identity = self._setup_agent_vip_id(name_with_version, vip_identity=vip_identity)

        if self._secure_agent_user:
            _log.info("Installing secure Volttron agent...")

        uuid_values = self._uuid_vip_id_map.keys()

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
                f.write(name_with_version)
            with open(os.path.join(agent_path, "config"), "w") as f:
                yaml.dump(agent_config, f)
        except OSError as exc:
            raise
        try:
            # if auth is not None and self.env.verify_agents:
            #     unpacker = auth.VolttronPackageWheelFile(agent_wheel, certsobj=Certs())
            #     unpacker.unpack(dest=agent_path)

            # will reuse credentials and capabilities if already exists.
            # Else will create new creds and default capabilities
            self._auth_service.create_agent(identity=final_identity)

            # if self.message_bus == "rmq":
            #     rmq_user = cc.get_fq_identity(final_identity, cc.get_instance_name())
            #     # rmq_user = get_fq_identity(final_identity,
            #     #                            self._instance_name)
            #     Certs().create_signed_cert_files(rmq_user, overwrite=False)

            if self._secure_agent_user:
                # When installing, we always create a new user, as anything
                # that already exists is untrustworthy
                created_user = self.add_agent_user(self.agent_name(agent_uuid), agent_path)
                self.set_agent_user_permissions(created_user, agent_uuid, agent_path)

            # finally update the vip id uuid maps
            self._vip_id_uuid_map[final_identity] = agent_uuid
            self._uuid_vip_id_map[agent_uuid] = final_identity

            if backup_agent_file is not None:
                self.restore_agent_data_from_tgz(
                    backup_agent_file,
                    self.get_agent_data_dir(agent_uuid),
                )

        except Exception:
            shutil.rmtree(agent_path)
            raise

        return agent_uuid


    def install_library(self, library, force=False, pre_release=False):
        """
        Adds the library to the current pyproject toml project, which in turn installs the library in the current
        venv
        Return installed agent or library name with version. example volttron-listener-2.0.0rc2
        """
        name, name_with_version, _ = self.install_agent_or_lib_source(library, force, pre_release)
        return name_with_version
        

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
            agent_uuid = self._vip_id_uuid_map.get(vip_identity)
        if agent_uuid and not force:
            raise ValueError("Identity already exists, but not forced!")
        return agent_uuid

    def install_agent_or_lib_source(self, source: str, force: bool = False, pre_release: bool = False,
                                    editable:bool = False):
        """
        Installs a agent or library from wheel or pypi or as editable source
        Returns installed agent/library's name, name-<version>, package directory in which this is installed
        """
        agent_or_lib_name = None
        site_package_dir = None
        version = None
        if editable and os.path.isdir(source):
            cmd = ["poetry", "version"]
            response = execute_command(cmd, cwd=source)
            if response:
                # response is of the format <agent-name> <version number>
                agent_or_lib_name, version = response.split()
                site_package_dir = source
        elif source.endswith(".whl") and os.path.isfile(source):
            agent_or_lib_name = self._construct_package_name_from_wheel(source)
        else:
            # this is a pypi package.
            # if vctl install got source dir, it would have got built into a whl before getting shipped to server
            # it could be just a package-name(ex. volttron-listener)
            # or package-name with version constraints- ex. volttron-agent@latest, volttron-agent>=1.0.0
            # so match till we hit a character that is NOT alphanumeric character or  _ or -
            m = re.match("[\w\-]+", source)
            if m:
                agent_or_lib_name = m[0]

        if agent_or_lib_name is None:
            # ideally we should never get here! if we get here we haven't handled some specific input format.
            raise RuntimeError(f"Unexpected Error: Unable to get agent or library name based on {source}")

        cmd_add = ["poetry", "--directory", self._server_opts.poetry_project_path.as_posix()]
        if pre_release:
            cmd_add.append("--allow-prereleases")
        if editable:
            cmd_add.append("--editable")
        cmd_add.append("add")
        cmd_add.append(source)

        current_version = None
        if force:
            # check if there is even a current version to uninstall
            try:
                cmd = ["pip", "show", agent_or_lib_name]
                response = execute_command(cmd)
                current_version = re.search(".*\nVersion: (.*)", response).groups()[0].strip()
            except RuntimeError as e:
                # unable to find any existing agent or lib to uninstall so make force = False
                force = False

        if force and current_version:
            # act on force=True only if there is a current installed version of the agent
            # poetry does not provide --force-reinstall.
            # We essentially have to remove and add. so do a dry run to see nothing will break
            #
            try:
                cmd_dry_run = [
                    "poetry", "--directory",
                    self._server_opts.poetry_project_path.as_posix(), "remove", agent_or_lib_name, "--dry-run"
                ]
                # we only care about the return code. is return code is non-zero below will raise exception
                execute_command(cmd_dry_run)
            except RuntimeError as r:
                raise RuntimeError(f"Attempting to remove current version of agent or library {agent_or_lib_name} "
                                   f"using poetry fails with following error: {r}")

            try:
                cmd_dry_run = []
                cmd_dry_run.extend(cmd_add)
                cmd_dry_run.append("--dry-run")
                # we only care about the return code. is return code is non-zero below will raise exception
                execute_command(cmd_dry_run)
            except RuntimeError as r:
                raise RuntimeError(f"Attempt to install {agent_or_lib_name} using poetry fails "
                                   f"with following error:{r}")

            # but that alone won't be enough For ex. if agent to be installed is just a name without version, and there
            # is already a version of the agent installed, then doing "poetry add agent_name --dry-run"
            # poetry will simply return "package already exists" it won't check version compatibility or availability
            # so if you have current version installed from a local wheel and latest version on pypi is not compatible
            # then dry run with just agent name won't catch the error. (unlike poetry add agent_name@latest --dry-run)
            # In such case, we should be able to revert to current version - so explicitly find current version and
            # see if that can be installed from pypi because local wheel might not be there anymore.
            try:
                cmd_dry_run = [
                    "poetry", "--directory",
                    self._server_opts.poetry_project_path.as_posix(), "add", f"{agent_or_lib_name}=={current_version}",
                    "--dry-run"
                ]
                execute_command(cmd_dry_run)
            except RuntimeError as r:
                raise RuntimeError(f"Unable to find currently installed version of {agent_or_lib_name} "
                                   f"({current_version}) in pypi. Aborting --force install of {source} as we dont have "
                                   f"any way of reverting to existing version in case of failure. If you are using "
                                   f"agent/library without version number. Try using name@latest or name==version to "
                                   f"install. Or manually remove agent/library and install with specific version")

            # No exception. Worst case we can revert so safely uninstall current version.
            _log.warning(f"Removing current version of {agent_or_lib_name}")
            cmd = [
                "poetry", "--directory",
                self._server_opts.poetry_project_path.as_posix(), "remove", f"{agent_or_lib_name}"
            ]
            execute_command(cmd)

        # finally install agent passed!
        response = None
        try:
            _log.debug(f"Executing agent install command : {cmd_add}")
            response = execute_command(cmd_add)
            # if above cmd returned non-zero code it would throw exception.
            # if we are here we succeeded installing some compatible version of the package.
            # Now find agent version installed
        except RuntimeError as e:
            _log.error("Install agent failed", e)
            if force and current_version:
                _log.info("--force was used. Attempting to reinstall agent/library version that was previously "
                          f"present in env ({agent_or_lib_name}=={current_version})")
                try:
                    cmd = [
                        "poetry", "--directory",
                        self._server_opts.poetry_project_path.as_posix(), "add",
                        f"{agent_or_lib_name}=={current_version}"
                    ]
                    execute_command(cmd)
                except RuntimeError as e:
                    # We are in trouble. we are not able to install give agent version and unable to roll back to the
                    # version that was already there either!
                    raise RuntimeError(
                        "ERROR: --force was used. we successfully uninstalled current version of agent/library"
                        f"{agent_or_lib_name}=={current_version}. But there was error installing {source} and "
                        f"we are unable to reinstall current version either. \n", e)
            else:
                raise e

        if not editable:
            # now get the version installed, because poetry add could have been for volttron-agent@latest.
            # we need to find the specific version installed
            cmd = ["pip", "show", agent_or_lib_name]
            response = execute_command(cmd)
            version = re.search(".*\nVersion: (.*)", response).groups()[0].strip()
            site_package_dir = re.search(".*\nLocation: (.*)", response).groups()[0].strip()
        if site_package_dir is None:
            # we should not get here unless pip changed format of pip show output.
            raise RuntimeError(f"Unable to find installed location of {source} based on pip show command")
        if version is None:
            # we should not get here unless pip changed format of pip show output.
            raise RuntimeError(f"Unable to find installed version of {source} based on pip show command")

        return agent_or_lib_name, agent_or_lib_name + "-" + version, site_package_dir

    @staticmethod
    def _construct_package_name_from_wheel(agent_wheel):
        agent_name = agent_wheel
        if agent_wheel.endswith(".whl"):
            wheel = agent_wheel.split("/")[-1]
            agent_name_with_version = wheel.replace("-py3-none-any.whl", "").replace("_", "-")
            agent_name = agent_name_with_version[:agent_name_with_version.rfind("-")]
        return agent_name

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
            raise ValueError("Agent with VIP ID {} already installed on platform.".format(name_template))

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
        publickey = self.__get_agent_keystore__(self._uuid_vip_id_map[agent_uuid]).public
        AuthFile().remove_by_credentials(publickey)

    def _get_agent_data_dir(self, agent_path):
        pkg = None
        # TODO: wheel_wrap
        # pkg = UnpackedPackage(agent_path)
        data_dir = os.path.join(os.path.dirname(pkg.distinfo), "{}.agent-data".format(pkg.package_name))
        if not os.path.exists(data_dir):
            os.mkdir(data_dir)
        return data_dir

    def get_agent_data_dir(self, agent_uuid=None, vip_identity=None):
        data_dir = None
        if vip_identity and vip_identity in self._vip_id_uuid_map.keys():
            data_dir = os.path.join(self.install_dir, vip_identity, "data")
        elif agent_uuid and agent_uuid in self._uuid_vip_id_map.keys():
            data_dir = os.path.join(self.install_dir, self._uuid_vip_id_map[agent_uuid], "data")
        return data_dir

    def _get_available_agent_identity(self, name_template):
        all_agent_identities = self._vip_id_uuid_map.keys()

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

    def remove_agent(self, agent_uuid, remove_auth=True, remove_unused_src=True):
        if self._secure_agent_user:
            _log.info("Running Volttron agents securely with Unix Users.")
        else:
            _log.info("Not running with secure users.")
        if agent_uuid not in self._uuid_vip_id_map:
            raise ValueError("invalid agent")
        self.stop_agent(agent_uuid)
        vip_identity = self._uuid_vip_id_map[agent_uuid]

        # get list of agent uuid to name mapping
        uuid_name_map = self.list_agents()
        agent_name = uuid_name_map.pop(agent_uuid)
        # TODO replace when adding rmq in a container addin/plugin
        # if msg_bus == "rmq":
        #     # Delete RabbitMQ user for the agent
        #     _instance_name = self._instance_name
        #     rmq_user = _instance_name + "." + vip_identity
        #     try:
        #         self.rmq_mgmt.delete_user(rmq_user)
        #     except requests.exceptions.HTTPError as e:
        #         _log.error(
        #             f"RabbitMQ user {rmq_user} is not available to delete. Going ahead and removing agent directory"
        #         )
        self._active_agents.pop(agent_uuid, None)
        agent_directory = os.path.join(self.install_dir, vip_identity)
        volttron_agent_user = None
        if self._secure_agent_user:
            user_id_path = os.path.join(agent_directory, "USER_ID")
            try:
                with open(user_id_path, "r") as user_id_file:
                    volttron_agent_user = user_id_file.readline()
            except (KeyError, IOError) as user_id_err:
                _log.warning("Volttron agent user not found at {}".format(user_id_path))
                _log.warning(user_id_err)
        if remove_auth:
            self._auth_service.remove_agent(identity=vip_identity)
        shutil.rmtree(agent_directory)
        if volttron_agent_user:
            self.remove_agent_user(volttron_agent_user)

        # check if there are other instances of the same agent.
        if remove_unused_src:
            if agent_name not in uuid_name_map.values():
                # if no other uuid has the same agent name. There was only one instance that we popped earlier
                # so safe to uninstall source
                execute_command([
                    "poetry", "--directory",
                    self._server_opts.poetry_project_path.as_posix(), "remove", agent_name[:agent_name.rfind("-")]
                ])
        # update uuid vip id maps
        self._uuid_vip_id_map.pop(agent_uuid)
        self._vip_id_uuid_map.pop(vip_identity)

    def agent_name(self, agent_uuid=None, vip_identity=None):
        name = None
        if vip_identity or agent_uuid:
            if not vip_identity:
                vip_identity = self._uuid_vip_id_map.get(agent_uuid)
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
        for vip_identity, agent_uuid in self._vip_id_uuid_map.items():
            try:
                agents[agent_uuid] = self.agent_name(vip_identity=vip_identity)
            except KeyError:
                pass
        return agents

    def get_active_agents_meta(self, get_agent_user=False):
        if self._secure_agent_user and get_agent_user:
            return {
                agent_uuid: (execenv.name, execenv.agent_user)
                for agent_uuid, execenv in self._active_agents.items()
            }
        else:
            return {agent_uuid: execenv.name for agent_uuid, execenv in self._active_agents.items()}

    def clear_status(self, clear_all=False):
        remove = []
        for agent_uuid, execenv in self._active_agents.items():
            if execenv.process.poll() is not None:
                if clear_all:
                    remove.append(agent_uuid)
                else:
                    path = os.path.join(self.install_dir, agent_uuid)
                    if not os.path.exists(path):
                        remove.append(agent_uuid)
        for agent_uuid in remove:
            self._active_agents.pop(agent_uuid, None)

    def status_agents(self, get_agent_user=False):
        if self._secure_agent_user and get_agent_user:
            return [(agent_uuid, agent[0], agent[1], self.agent_status(agent_uuid), self._uuid_vip_id_map[agent_uuid])
                    for agent_uuid, agent in self.get_active_agents_meta().items()]
        else:
            return [(agent_uuid, agent_name, self.agent_status(agent_uuid), self._uuid_vip_id_map[agent_uuid])
                    for agent_uuid, agent_name in self.get_active_agents_meta().items()]

    def tag_agent(self, agent_uuid, tag):
        tag_file = os.path.join(self.install_dir, self._uuid_vip_id_map[agent_uuid], "TAG")
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
            if "/" in agent_uuid or agent_uuid in [".", ".."] or not self._uuid_vip_id_map.get(agent_uuid):
                raise ValueError("invalid agent")
            vip_identity = self._uuid_vip_id_map[agent_uuid]

        tag_file = self.get_subpath(vip_identity, "TAG")
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

    def get_subpath(self, uuid_or_identity: str, path: str = "") -> str:
        """ Retrieve a path inside the agent's directory

        This method does not check for existence of the path.  It will only return the
        correct string reference.  It is up to the caller to check for existence or non-existence
        of the path.

        :param uuid_or_identity:
            An identifier for the agent either the uuid associated with the agent or it's identity.

        :param path:
            A path below the agent's directory in VOLTTRON_HOME/agents/<identity> that the
            caller wants to referenece.

        :returns: A string referencing the correct subpath to the requestors path.

        :since
        """

        try:
            uuid_passed = uuid.UUID(uuid_or_identity)
            identity = self._uuid_vip_id_map[uuid_or_identity]
        except ValueError:
            identity = uuid_or_identity

        return os.path.join(self.install_dir, identity, path)

    def agent_dir(self, agent_uuid):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        return self.get_subpath(agent_uuid)

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
        autostart = self.get_subpath(agent_uuid, "AUTOSTART")
        with ignore_enoent, open(autostart) as file:
            return file.readline(100).strip()

    def agent_priority(self, agent_uuid):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        return self._agent_priority(agent_uuid)

    def prioritize_agent(self, agent_uuid, priority="50"):
        if "/" in agent_uuid or agent_uuid in [".", ".."]:
            raise ValueError("invalid agent")
        autostart = self.get_subpath(agent_uuid, "AUTOSTART")
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
        resmon = getattr(self._server_opts, "resmon", None)
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
        # get last index of - to split version number from name
        name_no_version = name[0:name.rfind("-")]

        vip_identity = self._uuid_vip_id_map[agent_uuid]
        agent_dir = os.path.join(self.install_dir, vip_identity)
        execenv = self._active_agents.get(agent_uuid)
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
        # environ["AGENT_SUB_ADDR"] = self.subscribe_address
        # environ["AGENT_PUB_ADDR"] = self.publish_address
        environ["AGENT_UUID"] = agent_uuid
        environ["_LAUNCHED_BY_PLATFORM"] = "1"

        environ["AGENT_VIP_IDENTITY"] = vip_identity
        creds = self._credentials_store.retrieve_credentials(identity=vip_identity)
        environ["AGENT_CREDENTIALS"] = creds.to_json()
        # TODO: Perhaps we should do something other than this here?
        _log.info(f"server opts: {self._server_opts}")
        #environ["VOLTTRON_PLATFORM_ADDRESS"] = self._server_opts.address[0]
        # environ["AGENT_CREDENTIALS"] = self._auth.

        # environ["VOLTTRON_SERVERKEY"] = KeyStore().public
        # keystore_path = os.path.join(cc.get_volttron_home(), "agents", vip_identity,
        #                              "keystore.json")
        # keystore = KeyStore(keystore_path)
        # environ["AGENT_PUBLICKEY"], environ["AGENT_SECRETKEY"] = keystore.public, keystore.secret

        # module, _, func = module.partition(":")
        # if func:
        #     code = '__import__({0!r}, fromlist=[{1!r}]).{1}()'.format(module,
        #                                                               func)
        #     argv = [sys.executable, '-c', code]
        # else:
        # argv = [sys.executable, "-m", module]
        agent_user = None

        if self._secure_agent_user:
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
            cwd=os.path.join(self.install_dir, vip_identity),
            close_fds=True,
            stdin=open(os.devnull),
            stdout=PIPE,
            stderr=PIPE,
        )
        self._active_agents[agent_uuid] = execenv
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
        execenv = self._active_agents.get(agent_uuid)
        if execenv is None:
            return (None, None)
        return execenv.process.pid, execenv.process.poll()

    def stop_agent(self, agent_uuid):
        try:
            execenv = self._active_agents[agent_uuid]
            return execenv.stop()
        except KeyError:
            return

    def agent_uuid_from_pid(self, pid):
        for agent_uuid, execenv in self._active_agents.items():
            if execenv.process.pid == pid:
                return agent_uuid if execenv.process.poll() is None else None
