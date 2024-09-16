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
from volttron.types import MessageBusStopHandler

monkey.patch_socket()
monkey.patch_ssl()
import subprocess
import argparse
import importlib
import logging
import logging.config
import os
import resource
import stat
import sys
from logging import handlers
from pathlib import Path

import gevent

from volttron.server import aip
from volttron.server import server_argparser as config
from volttron.server.containers import service_repo
from volttron.server.logs import (LogLevelAction, configure_logging, log_to_file)
from volttron.server.server_options import ServerOptions
from volttron.server.tracking import Tracker
from volttron.types.peer import ServicePeerNotifier
from volttron.utils import ClientContext as cc, execute_command
from volttron.utils import (get_version, store_message_bus_config)
from volttron.utils.persistance import load_create_store

_log = logging.getLogger(os.path.basename(sys.argv[0]) if __name__ == "__main__" else __name__)

# No need for str after python 3.8
VOLTTRON_INSTANCES = Path("~/.volttron_instances").expanduser().resolve()


def run_server():
    """Start the main volttron process.

    Typically, this function is used from main.py and just uses the argparser's
    Options arguments as inputs.   It also can be called with a dictionary.  In
    that case the dictionaries keys are mapped into a value that acts like the
    args options.
    """
    from volttron.types.blinker_events import volttron_home_set_evnt

    os.environ['VOLTTRON_SERVER'] = "1"
    volttron_home = Path(os.environ.get("VOLTTRON_HOME", "~/.volttron")).expanduser()
    os.environ["VOLTTRON_HOME"] = volttron_home.as_posix()

    # Raise events that the volttron_home has been set.
    volttron_home_set_evnt.send(run_server)

    if volttron_home.joinpath("config").exists():
        service_repo.add_instance(ServerOptions, ServerOptions(config_file=volttron_home.joinpath("config")))
    else:
        service_repo.add_instance(ServerOptions, ServerOptions(volttron_home=volttron_home))

    server_options: ServerOptions = service_repo.resolve(ServerOptions)

    parser = build_arg_parser(server_options)

    if server_options.messagebus is None:
        raise ValueError("Message Bus Not Found")

    # Parse and expand options
    args = sys.argv[1:]
    conf = os.path.join(volttron_home, "config")
    if os.path.exists(conf) and "SKIP_VOLTTRON_CONFIG" not in os.environ:
        # command line args get preference over same args in config file
        args = args + ["--config", conf]

    opts = parser.parse_args(args)

    # Handle the fact that we don't use store_true and config that requires
    # inverse.  This is not a switch but a mode of operation, so we change
    # from the string to a boolean value here.
    opts.agent_isolation_mode = opts.agent_isolation_mode != 'False'
    dev_mode = opts.dev_mode
    # Update the server options with the command line parameter options.
    server_options.update(opts)
    server_options.store()

    # create poetry project and poetry lock file in VOLTTRON_HOME
    if dev_mode:
        if not os.path.isfile(server_options.poetry_project_path / "pyproject.toml"):
            raise ValueError("VOLTTRON is run with --dev but unable to fund pyproject.toml is current directory - "
                             f"{server_options.poetry_project_path}")
    else:
        setup_poetry_project(server_options.poetry_project_path)

    start_volttron_process(server_options)


def setup_poetry_project(volttron_home):
    toml = os.path.join(volttron_home, "pyproject.toml")
    if not os.path.isfile(toml):
        cmd = [
            "poetry", "init", "--directory",
            volttron_home.as_posix(), "--name", "volttron", "--author", "volttron <volttron@pnnl.gov>", "--quiet"
        ]
        execute_command(cmd)
    # now do multiple piped commands
    pip_cmd = ["pip", "list", "--format", "freeze"]
    # Second command
    grep_cmd = ["grep", "-v", "volttron=="]
    # Third command
    poetry_cmd = ["xargs", "poetry", "add", "--directory", volttron_home.as_posix()]
    # Execute the first command
    p1 = subprocess.Popen(pip_cmd, stdout=subprocess.PIPE)

    # Execute the second command, with stdin from the first command's stdout
    p2 = subprocess.Popen(grep_cmd, stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()    # Allow p1 to receive a SIGPIPE if p2 exits.

    # Execute the third command, with stdin from the second command's stdout
    p3 = subprocess.Popen(poetry_cmd, stdin=p2.stdout)
    p2.stdout.close()    # Allow p2 to receive a SIGPIPE if p3 exits.

    # Wait for the last command to finish
    stdout, stderr = p3.communicate()

    if p3.returncode != 0:
        err_msg = (f"Unable to update pyproject.toml in {volttron_home.as_posix()} with venv's current list of libs\n"
                   f"Command '{poetry_cmd}' failed with return code {p3.returncode} \n"
                   f"stdout: {stdout} \n"
                   f"stderr: {stderr}")
        raise RuntimeError(err_msg)


def start_volttron_process(options: ServerOptions):
    opts = options
    # Change working dir
    os.chdir(opts.volttron_home)

    # vip_address is meant to be a list so make it so.
    if not isinstance(opts.address, list):
        opts.address = [opts.address]
    if opts.log:
        opts.log = config.expandall(opts.log)
    if opts.log_config:
        opts.log_config = config.expandall(opts.log_config)

    # Configure logging
    level = max(1, opts.verboseness)
    if opts.monitor and level > logging.INFO:
        level = logging.INFO

    if opts.log is None:
        log_to_file(sys.stderr, level)
    elif opts.log == "-":
        log_to_file(sys.stdout, level)
    elif opts.log:
        log_to_file(opts.log, level, handler_class=handlers.WatchedFileHandler)
    else:
        log_to_file(None, 100, handler_class=lambda x: logging.NullHandler())

    if opts.log_config:
        with open(opts.log_config, "r") as f:
            for line in f.readlines():
                _log.info(line.rstrip())

        error = configure_logging(opts.log_config)

        if error:
            _log.error("{}: {}".format(*error))
            sys.exit(1)

    if opts.agent_isolation_mode == "True":
        _log.info("VOLTTRON starting in secure mode")
        os.umask(0o007)
    else:
        opts.agent_isolation_mode = "False"

    logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.INFO)

    opts.address = [config.expandall(addr) for addr in opts.address]
    opts.local_address = config.expandall(opts.local_address)

    opts.messagebus = config.expandall(opts.messagebus)

    os.environ["MESSAGEBUS"] = opts.messagebus
    os.environ["AGENT_ISOLATION_MODE"] = opts.agent_isolation_mode
    if opts.instance_name is None:
        if len(opts.address) > 0:
            opts.instance_name = opts.address[0]

    _log.debug("opts.instancename {}".format(opts.instance_name))
    if opts.instance_name:
        store_message_bus_config(opts.messagebus, opts.instance_name)
    else:
        # if there is no _instance_name given get_platform_instance_name will
        # try to retrieve from config or default a value and store it in the config
        cc.get_instance_name()

    # Log configuration options
    if getattr(opts, "show_config", False):
        _log.info("volttron version: {}".format(get_version()))
        for name, value in sorted(vars(opts).items()):
            _log.info("%s: %s" % (name, str(repr(value))))

    # Increase open files resource limit to max or 8192 if unlimited
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

    except OSError:
        _log.exception("error getting open file limits")
    else:
        if soft != hard and soft != resource.RLIM_INFINITY:
            try:
                limit = 8192 if hard == resource.RLIM_INFINITY else hard
                resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
            except OSError:
                _log.exception("error setting open file limits")
            else:
                _log.debug(
                    "open file resource limit increased from %d to %d",
                    soft,
                    limit,
                )
        _log.debug("open file resource limit %d to %d", soft, hard)

    # TODO: Dynamic loading needs to happen instead of this.
    if opts.auth_enabled:
        import volttron.services.auth

    aip_platform = service_repo.resolve(aip.AIPplatform)
    aip_platform.setup()
    opts.aip = aip_platform

    # Check for secure mode/permissions on VOLTTRON_HOME directory
    mode = os.stat(opts.volttron_home).st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        _log.warning("insecure mode on directory: %s", opts.volttron_home)

    tracker = Tracker()
    external_address_file = os.path.join(opts.volttron_home, "external_address.json")
    _log.debug("external_address_file file %s", external_address_file)

    if opts.agent_monitor_frequency:
        try:
            int(opts.agent_monitor_frequency)
        except ValueError as e:
            raise ValueError("agent-monitor-frequency should be integer "
                             "value. Units - seconds. This determines how "
                             "often the platform checks for any crashed agent "
                             "and attempts to restart. {}".format(e))

    address = "inproc://vip"
    pid_file = os.path.join(opts.volttron_home, "VOLTTRON_PID")
    try:
        protected_topics = {}
        proxy_router = None
        proxy_router_task = None

        _log.debug("********************************************************************")
        _log.debug("VOLTTRON PLATFORM RUNNING ON {} MESSAGEBUS".format(opts.messagebus))
        _log.debug("********************************************************************")
        from volttron.server.decorators import start_service_agents
        from volttron.services.config_store.config_store_service import \
            ConfigStoreService
        from volttron.types.auth import CredentialsStore
        from volttron.services.control.control_service import ControlService
        from volttron.services.health.health_service import HealthService
        from volttron.types.known_host import \
            KnownHostProperties as known_host_properties

        spawned_greenlets = []

        mb = None

        # TODO Replace with module level zmq that holds all of the zmq bits in order to start and
        #  run the message bus regardless of whether it's zmq or rmq.

        auth_service = None
        if options.auth_enabled:
            from volttron.types.auth import Authenticator
            from volttron.types.auth.auth_service import AuthService
            import importlib

            # Use volttron.services.auth to load the main auth service.  A user may choose
            # to not use our default auth service and can install their own service to this
            # location.
            loader = importlib.util.find_spec("volttron.services.auth")
            authenticator = service_repo.resolve(Authenticator)
            auth_service = service_repo.resolve(AuthService)

        # First load auth_service so that config_store can use
        # auth service to wrap protected_rpcs
        if auth_service is not None:
            event = gevent.event.Event()
            task = gevent.spawn(auth_service.core.run, event)
            event.wait()
            del event
            spawned_greenlets.append(task)

        config_store = service_repo.resolve(ConfigStoreService)
        event = gevent.event.Event()
        task = gevent.spawn(config_store.core.run, event)
        event.wait()
        del event
        spawned_greenlets.append(task)

        from volttron.types import MessageBus

        mb: MessageBus = service_repo.resolve(MessageBus)

        class StopHandler(MessageBusStopHandler):

            def message_bus_shutdown(self):
                for spawned_task in spawned_greenlets:
                    spawned_task.kill(block=False)
                gevent.wait(spawned_greenlets)

        mb.set_stop_handler(StopHandler())

        # from volttron.server.decorators import get_messagebus_class
        # MessageBusClass = get_messagebus_class()
        # # Allows registration agents to callbacks for peers
        # notifier = ServicePeerNotifier()
        #
        # mb = MessageBusClass(opts, notifier, tracker, protected_topics, external_address_file, config_store.core.stop)

        mb.start()

        assert mb.is_running()

        # TODO Better make this so that it removes instances from this file or it will just be an
        #  ever increasing file depending on the number of instances it could get quite large.
        # The instance file is where we are going to record the instance and
        # its details according to
        instance_file = str(VOLTTRON_INSTANCES)
        try:
            instances = load_create_store(instance_file)
        except ValueError:
            os.remove(instance_file)
            instances = load_create_store(instance_file)

        # Trim instances from instance file.
        for k in list(instances):
            try:
                # Raises OSError if the pid is not found
                # TODO if necessary include all the cases found
                # https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python/6940314#6940314
                os.kill(instances[k]['pid'], 0)
            except OSError:
                del instances[k]

        this_instance = instances.get(opts.volttron_home, {})
        this_instance["pid"] = os.getpid()
        this_instance["version"] = get_version()
        # note vip_address is a list
        this_instance["address"] = opts.address
        this_instance["volttron-home"] = opts.volttron_home
        this_instance["volttron-root"] = os.path.abspath("../../..")
        this_instance["start-args"] = sys.argv[1:]
        instances[opts.volttron_home] = this_instance
        instances.async_sync()

        protected_topics_file = os.path.join(opts.volttron_home, "protected_topics.json")
        _log.debug("protected topics file %s", protected_topics_file)
        external_address_file = os.path.join(opts.volttron_home, "external_address.json")
        _log.debug("external_address_file file %s", external_address_file)

        spawned_greenlets.extend(start_service_agents())

        # control_service = service_repo.resolve(ControlService)
        # event = gevent.event.Event()
        # task = gevent.spawn(control_service.core.run, event)
        # event.wait()
        # del event
        # spawned_greenlets.append(task)
        # #control_service = service_configs.get_service_instance("volttron.services.control")

        # entry = AuthEntry(
        #     credentials=control_service.core.publickey,
        #     user_id=CONTROL,
        #     capabilities=[
        #         {
        #             "edit_config_store": {
        #                 "identity": "/.*/"
        #             }
        #         },
        #         "allow_auth_modifications",
        #     ],
        #     comments="Automatically added by platform on start",
        # )
        # try:
        #     AuthFile().add(entry)
        # except AuthFileUserIdAlreadyExists:
        #     pass

        # # # TODO Key discovery agent add in.
        # # # KeyDiscoveryAgent(
        # # #     address=address,
        # # #     serverkey=publickey,
        # # #     identity=KEY_DISCOVERY,
        # # #     external_address_config=external_address_file,
        # # #     setup_mode=opts.setup_mode,
        # # #     bind_web_address=opts.bind_web_address,
        # # #     enable_store=False,
        # # #     message_bus="zmq",
        # # # ),
        # # ]

        # #health_service = service_configs.get_service_instance("volttron.services.health")
        # health_service = service_repo.resolve(HealthService)
        # event = gevent.event.Event()
        # task = gevent.spawn(health_service.core.run, event)
        # event.wait()
        # del event
        # if health_service is not None:
        #     notifier.register_peer_callback(health_service.peer_added, health_service.peer_dropped)

        _log.debug("Finished Startup of Platform.")
        # Auto-start agents now that all services are up
        if opts.autostart:
            for name, error in opts.aip.autostart():
                _log.error("error starting {!r}: {}\n".format(name, error))

        # Done with all start up process write a PID file

        with open(pid_file, "w+") as f:
            f.write(str(os.getpid()))

        # Wait for any service to stop, signaling exit
        try:
            gevent.wait(spawned_greenlets, count=1)
        except KeyboardInterrupt:
            _log.info("SIGINT received; shutting down")
        finally:
            sys.stderr.write("Shutting down.\n")
            if proxy_router_task:
                proxy_router.core.stop()
            _log.debug("Kill all service agent tasks")
            for task in spawned_greenlets:
                task.kill(block=False)
            gevent.wait(spawned_greenlets)
    except Exception as e:
        _log.error(e)
        import traceback
        _log.error(traceback.print_exc())
    finally:
        _log.debug("AIP finally")
        opts.aip.finish()
        instance_file = str(VOLTTRON_INSTANCES)
        try:
            instances = load_create_store(instance_file)
            instances.pop(opts.volttron_home, None)
            instances.sync()
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception:
            _log.warning(f"Unable to load {VOLTTRON_INSTANCES}")
        _log.debug("********************************************************************")
        _log.debug("VOLTTRON PLATFORM HAS SHUTDOWN")
        _log.debug("********************************************************************")


def build_arg_parser(options: ServerOptions) -> argparse.ArgumentParser:
    """
    Builds and returns an argument parser.

    :return: The argument parser.
    :rtype: argparse.ArgumentParser
    """

    from volttron.server.server_options import ServerOptions
    from volttron.types.events import volttron_home_set_evnt

    default_levels_for_modules = {
        "volttron.server.decorators": logging.WARNING,
        "volttron.server.containers": logging.INFO,
        "volttron.loader": logging.WARNING,
        "volttron.server.run_server": logging.INFO,
        "volttron.client.decorators": logging.INFO,
    # "volttron.messagebus.zmq.socket": logging.INFO
    }
    [logging.getLogger(k).setLevel(v) for k, v in default_levels_for_modules.items()]

    volttron_home = os.path.normpath(config.expandall(os.environ.get("VOLTTRON_HOME", "~/.volttron")))
    os.environ["VOLTTRON_HOME"] = volttron_home

    argv = sys.argv

    # Refuse to run as root
    if not getattr(os, "getuid", lambda: -1)():
        sys.stderr.write("%s: error: refusing to run as root to prevent "
                         "potential damage.\n" % os.path.basename(argv[0]))
        sys.exit(77)

    # Setup option parser
    parser = config.ArgumentParser(
        prog=os.path.basename(argv[0]),
        add_help=False,
        description="VOLTTRON platform service",
        usage="%(prog)s [OPTION]...",
        argument_default=argparse.SUPPRESS,
        epilog="Boolean options, which take no argument, may be inversed by "
        "prefixing the option with no- (e.g. --autostart may be "
        "inversed using --no-autostart).",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="FILE",
        action="parse_config",
        ignore_unknown=False,
        sections=[None, "volttron"],
        help="read configuration from FILE",
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
        "--log-level",
        metavar="LOGGER:LEVEL",
        action=LogLevelAction,
        help="override default logger logging level",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="monitor and log connections (implies -v)",
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
    parser.add_argument("--messagebus",
                        type=str,
                        default=options.messagebus,
                        help="The message bus to use during startup.")
    # parser.add_argument("--auth-service",
    #                     type=str,
    #                     default=options.auth_service,
    #                     help="The auth service to use for authentication of clients.")
    # parser.add_argument("--authentication-class",
    #                     type=str,
    #                     default=options.authentication_class,
    #                     help="Class used with the AuthService for authentication")
    # parser.add_argument("--authorization-class",
    #                     type=str,
    #                     default=options.authorization_class,
    #                     help="Class used with the AuthService for authorization")
    # parser.add_argument(
    #    '--volttron-home', env_var='VOLTTRON_HOME', metavar='PATH',
    #    help='VOLTTRON configuration directory')
    parser.add_argument("--auth-enabled",
                        action="store_true",
                        inverse="--auth-disabled",
                        dest="auth_enabled",
                        help=argparse.SUPPRESS)
    parser.add_argument("--auth-disabled", action="store_false", help=argparse.SUPPRESS)
    parser.add_argument("--show-config", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dev",
                        action="store_true",
                        dest="dev_mode",
                        default=False,
                        help="development mode with poetry environment to build volttron libraries from source/pypi")

    parser.add_help_argument()
    parser.add_version_argument(version="%(prog)s " + str(get_version()))

    agents = parser.add_argument_group("agent options")
    agents.add_argument(
        "--autostart",
        action="store_true",
        inverse="--no-autostart",
        help="automatically start enabled agents and services",
    )
    agents.add_argument(
        "--no-autostart",
        action="store_false",
        dest="autostart",
        help=argparse.SUPPRESS,
    )

    agents.add_argument(
        "--address",
        metavar="MESSAGE_BUS_ADDR",
        action="append",
        default=[],
        help="Address for binding to the message bus.",
    )
    agents.add_argument(
        "--local-address",
        metavar="ZMQADDR",
        help="ZeroMQ URL to bind for local agent VIP connections",
    )

    agents.add_argument(
        "--instance-name",
        default=options.instance_name,
        help="The name of the VOLTTRON instance this command is starting up.",
    )
    # TODO: Determine if we need this
    # agents.add_argument(
    #     "--msgdebug",
    #     action="store_true",
    #     help="Route all messages to an agent while debugging.",
    # )
    # agents.add_argument(
    #     "--setup-mode",
    #     action="store_true",
    #     help="Setup mode flag for setting up authorization of external platforms.",
    # )
    agents.add_argument(
        "--agent-monitor-frequency",
        default=600,
        help="How often should the platform check for crashed agents and "
        "attempt to restart. Units=seconds. Default=600",
    )
    agents.add_argument(
        "--agent-isolation-mode",
        default=False,
        help="Require that agents run with their own users (this requires "
        "running scripts/secure_user_permissions.sh as sudo)",
    )

    agents.add_argument("--server-messagebus-id", default="vip.server", help="A connection from the server")

    ipc = "ipc://%s$VOLTTRON_HOME/run/" % ("@" if sys.platform.startswith("linux") else "")

    parser.set_defaults(log=None,
                        log_config=None,
                        monitor=False,
                        verboseness=logging.WARNING,
                        volttron_home=options.volttron_home,
                        autostart=True,
                        address=options.address,
                        local_address=ipc + "vip.socket",
                        instance_name=options.instance_name,
                        resource_monitor=True,
                        msgdebug=None,
                        setup_mode=False,
                        agent_isolation_mode=False,
                        server_messagebus_id="vip.server")

    return parser


# def main(argv=sys.argv):
#     import coloredlogs

#     from volttron.server.server_options import ServerOptions
#     from volttron.types.events import volttron_home_set_evnt
#     from volttron.utils.logs import setup_logging

#     # Refuse to run as root
#     if not getattr(os, "getuid", lambda: -1)():
#         sys.stderr.write("%s: error: refusing to run as root to prevent "
#                          "potential damage.\n" % os.path.basename(argv[0]))
#         sys.exit(77)

#     default_levels_for_modules = {
#         "volttron.server.decorators": logging.WARNING,
#         "volttron.server.containers": logging.INFO,
#         "volttron.loader": logging.WARNING,
#         "volttron.server.run_server": logging.INFO,
#         "volttron.client.decorators": logging.INFO,
#         "volttron.messagebus.zmq.socket": logging.INFO
#     }
#     [logging.getLogger(k).setLevel(v) for k, v in default_levels_for_modules.items()]

#     volttron_home = os.path.normpath(
#         config.expandall(os.environ.get("VOLTTRON_HOME", "~/.volttron")))
#     os.environ["VOLTTRON_HOME"] = volttron_home

#     #load_volttron_packages()
#     # Setup option parser
#     parser = config.ArgumentParser(
#         prog=os.path.basename(argv[0]),
#         add_help=False,
#         description="VOLTTRON platform service",
#         usage="%(prog)s [OPTION]...",
#         argument_default=argparse.SUPPRESS,
#         epilog="Boolean options, which take no argument, may be inversed by "
#         "prefixing the option with no- (e.g. --autostart may be "
#         "inversed using --no-autostart).",
#     )
#     parser.add_argument(
#         "-c",
#         "--config",
#         metavar="FILE",
#         action="parse_config",
#         ignore_unknown=False,
#         sections=[None, "volttron"],
#         help="read configuration from FILE",
#     )
#     parser.add_argument(
#         "-l",
#         "--log",
#         metavar="FILE",
#         default=None,
#         help="send log output to FILE instead of stderr",
#     )
#     parser.add_argument(
#         "-L",
#         "--log-config",
#         metavar="FILE",
#         help="read logging configuration from FILE",
#     )
#     parser.add_argument(
#         "--log-level",
#         metavar="LOGGER:LEVEL",
#         action=LogLevelAction,
#         help="override default logger logging level",
#     )
#     parser.add_argument(
#         "--monitor",
#         action="store_true",
#         help="monitor and log connections (implies -v)",
#     )
#     parser.add_argument(
#         "-q",
#         "--quiet",
#         action="add_const",
#         const=10,
#         dest="verboseness",
#         help="decrease logger verboseness; may be used multiple times",
#     )
#     parser.add_argument(
#         "-v",
#         "--verbose",
#         action="add_const",
#         const=-10,
#         dest="verboseness",
#         help="increase logger verboseness; may be used multiple times",
#     )
#     parser.add_argument(
#         "--verboseness",
#         type=int,
#         metavar="LEVEL",
#         default=logging.WARNING,
#         help="set logger verboseness",
#     )
#     # parser.add_argument(
#     #    '--volttron-home', env_var='VOLTTRON_HOME', metavar='PATH',
#     #    help='VOLTTRON configuration directory')
#     parser.add_argument("--show-config", action="store_true", help=argparse.SUPPRESS)
#     parser.add_help_argument()
#     parser.add_version_argument(version="%(prog)s " + str(get_version()))

#     agents = parser.add_argument_group("agent options")
#     agents.add_argument(
#         "--autostart",
#         action="store_true",
#         inverse="--no-autostart",
#         help="automatically start enabled agents and services",
#     )
#     agents.add_argument(
#         "--no-autostart",
#         action="store_false",
#         dest="autostart",
#         help=argparse.SUPPRESS,
#     )
#     agents.add_argument(
#         "--address",
#         metavar="ZMQADDR",
#         action="append",
#         default=[],
#         help="ZeroMQ URL to bind for VIP connections",
#     )
#     agents.add_argument(
#         "--local-address",
#         metavar="ZMQADDR",
#         help="ZeroMQ URL to bind for local agent VIP connections",
#     )
#     agents.add_argument(
#         "--instance-name",
#         default=None,
#         help="The name of the instance that will be reported to "
#         "VOLTTRON central.",
#     )
#     agents.add_argument(
#         "--msgdebug",
#         action="store_true",
#         help="Route all messages to an agent while debugging.",
#     )
#     agents.add_argument(
#         "--setup-mode",
#         action="store_true",
#         help="Setup mode flag for setting up authorization of external platforms.",
#     )
#     parser.add_argument(
#         "--messagebus",
#         action="store",
#         default="zmq",
#         dest="messagebus",
#         help="set message to be used. valid values are zmq and rmq",
#     )
#     agents.add_argument(
#         "--agent-monitor-frequency",
#         default=600,
#         help="How often should the platform check for crashed agents and "
#         "attempt to restart. Units=seconds. Default=600",
#     )
#     agents.add_argument(
#         "--agent-isolation-mode",
#         default=False,
#         help="Require that agents run with their own users (this requires "
#         "running scripts/secure_user_permissions.sh as sudo)",
#     )

#     # XXX: re-implement control options
#     # on
#     # control.add_argument(
#     #    '--allow-root', action='store_true', inverse='--no-allow-root',
#     #    help='allow root to connect to control socket')
#     # control.add_argument(
#     #    '--no-allow-root', action='store_false', dest='allow_root',
#     #    help=argparse.SUPPRESS)
#     # control.add_argument(
#     #    '--allow-users', action='store_list', metavar='LIST',
#     #    help='users allowed to connect to control socket')
#     # control.add_argument(
#     #    '--allow-groups', action='store_list', metavar='LIST',
#     #    help='user groups allowed to connect to control socket')

#     ipc = "ipc://%s$VOLTTRON_HOME/run/" % ("@" if sys.platform.startswith("linux") else "")

#     parser.set_defaults(
#         log=None,
#         log_config=None,
#         monitor=False,
#         verboseness=logging.WARNING,
#         volttron_home=volttron_home,
#         autostart=True,
#         address=[],
#         local_address=ipc + "vip.socket",
#         _instance_name=None,
#     # allow_root=False,
#     # allow_users=None,
#     # allow_groups=None,
#         verify_agents=True,
#         resource_monitor=True,
#     # mobility=True,
#         msgdebug=None,
#         setup_mode=False,
#     # Type of underlying message bus to use - ZeroMQ or RabbitMQ
#         messagebus="zmq",
#     )

#     # Parse and expand options
#     args = argv[1:]
#     conf = os.path.join(volttron_home, "config")
#     if os.path.exists(conf) and "SKIP_VOLTTRON_CONFIG" not in os.environ:
#         # command line args get preference over same args in config file
#         args = args + ["--config", conf]
#     logging.getLogger().setLevel(logging.NOTSET)
#     opts = parser.parse_args(args)

#     load_messagebus_module(opts.messagebus)

#     start_volttron_process(opts)


def _main():
    """Entry point for scripts."""
    try:
        sys.exit(run_server())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
