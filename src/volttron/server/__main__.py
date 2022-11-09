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
import argparse
import importlib
import logging
import logging.config
import os
import resource
import sys
import threading
from logging import handlers
from pathlib import Path

import gevent
import yaml
from gevent import monkey

from volttron.types.parameter import Parameter

monkey.patch_socket()
monkey.patch_ssl()


from volttron.utils.dynamic_helper import get_all_subclasses
from volttron.types import (
    MessageBusInterface,
    ServiceConfigs,
    Factories,
    CredentialsManager,
    CredentialsGenerator,
    CredentialsError, ServerOptions, ServerRuntime)
from volttron.server.aip import AIPplatform


# import gevent.monkey
# import gevent.threading as threading
#
from volttron.utils import ClientContext as cc, get_class, get_subclasses
# from volttron.utils.keystore import get_random_key
#
# # gevent.monkey.patch_socket()
# # gevent.monkey.patch_ssl()
# import zmq
# from zmq import green

# Link to the volttron-client library
from volttron.utils import get_version

# Create a context common to the green and non-green zmq modules.
# green.Context._instance = green.Context.shadow(zmq.Context.instance().underlying)

# from .vip.router import *
# from .vip.socket import decode_key, encode_key, Address
# from .vip.tracking import Tracker

from volttron.client.known_identities import (
    PLATFORM_WEB,
    CONTROL,
    CONTROL_CONNECTION,
)
from volttron.utils import store_message_bus_config
# TODO Keystore is only good for zmq??
from volttron.utils.persistance import load_create_store


# TODO Enable from zmq?
# from .tracking import Tracker

# TODO rmq
# from .vip.rmq_router import RMQRouter

# from volttron.utils.rmq_setup import start_rabbit
# from volttron.utils.rmq_config_params import RMQConfig

# TODO Router
#  from volttron.server.router import Router, GreenRouter
# TODO SERVICE
#  from ..services.health import HealthService
# TODO ONLY ZMQ?
# from ..services.peer import PeerNotifier
# TODO Do we need this here?
# from ..services.auth import AuthService, AuthFile, AuthEntry
# TODO This is auto loaded
# from ..services.control import ControlService
# TODO This is autoloaded.
# from ..services.config_store import ConfigStoreService

# TODO Key Discovery RPC
# from ..services.external import ExternalRPCService, KeyDiscoveryAgent
# TODO no proxy routing.
# from ..services.routing import ZMQProxyRouter

from volttron.server.log_actions import log_to_file, configure_logging, LogLevelAction
from volttron.server import server_argparser as config, aip


_log = logging.getLogger(os.path.basename(sys.argv[0]) if __name__ == "__main__" else __name__)

# Only show debug on the platform when really necessary!
# log_level_info = (
#     'volttron.platform.main',
#     'volttron.platform.vip.zmq_connection',
#     'urllib3.connectionpool',
#     'watchdog.observers.inotify_buffer',
#     'volttron.platform.auth',
#     'volttron.platform.store',
#     'volttron.platform.control',
#     'volttron.platform.vip.agent.core',
#     'volttron.utils',
#     'volttron.platform.vip.router'
# )

# for log_name in log_level_info:
#     logging.getLogger(log_name).setLevel(logging.INFO)

# No need for str after python 3.8
VOLTTRON_INSTANCES = Path("~/.volttron_instances").expanduser().resolve()


server_options = ServerOptions()
server_runtime = ServerRuntime(server_options)


def start_volttron_process(runtime: ServerRuntime):
    """Start the main volttron process.

    Typically, this function is used from main.py and just uses the argparser's
    Options arguments as inputs.   It also can be called with a dictionary.  In
    that case the dictionaries keys are mapped into a value that acts like the
    args options.
    """
    logging.basicConfig(level=logging.DEBUG)
    # if isinstance(opts, dict):
    #     opts = type("Options", (), opts)()
    #     # vip_address is meant to be a list so make it so.
    #     if not isinstance(opts.vip_address, list):
    #         opts.vip_address = [opts.vip_address]
    # if opts.log:
    #     opts.log = config.expandall(opts.log)
    # if opts.log_config:
    #     opts.log_config = config.expandall(opts.log_config)

    # TODO: Functionalize This
    # Configure logging
    # level = max(1, opts.verboseness)
    # if opts.monitor and level > logging.INFO:
    #     level = logging.INFO
    #
    # if opts.log is None:
    #     log_to_file(sys.stderr, level)
    # elif opts.log == "-":
    #     log_to_file(sys.stdout, level)
    # elif opts.log:
    #     log_to_file(opts.log, level, handler_class=handlers.WatchedFileHandler)
    # else:
    #     log_to_file(None, 100, handler_class=lambda x: logging.NullHandler())
    #
    # if opts.log_config:
    #     with open(opts.log_config, "r") as f:
    #         for line in f.readlines():
    #             _log.info(line.rstrip())
    #
    #     error = configure_logging(opts.log_config)
    #
    #     if error:
    #         _log.error("{}: {}".format(*error))
    #         sys.exit(1)

    # if opts.secure_agent_users == "True":
    #     _log.info("VOLTTRON starting in secure mode")
    #     os.umask(0o007)
    # else:
    #     opts.secure_agent_users = "False"

    # opts.vip_address = [config.expandall(addr) for addr in opts.vip_address]
    # opts.vip_local_address = config.expandall(opts.vip_local_address)

    # os.environ["MESSAGEBUS"] = opts.message_bus
    #os.environ["SECURE_AGENT_USERS"] = opts.secure_agent_users
    # if opts.instance_name is None:
    #     if len(opts.vip_address) > 0:
    #         opts.instance_name = opts.vip_address[0]

    _log.debug(f"instance name set to: {runtime.options.instance_name}")
    # if opts.instance_name:
    #     store_message_bus_config(opts.message_bus, opts.instance_name)
    # else:
    #     # if there is no instance_name given get_platform_instance_name will
    #     # try to retrieve from config or default a value and store it in the config
    #     cc.get_instance_name()

    # Log configuration options
    # if getattr(opts, "show_config", False):
    #     _log.info("volttron version: {}".format(get_version()))
    #     for name, value in sorted(vars(opts).items()):
    #         _log.info("%s: %s" % (name, str(repr(value))))

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

    # Create the root VOLTTRON_HOME and parents if necessary.
    runtime.options.volttron_home.mkdir(mode=0o777, exist_ok=True, parents=True)

    # Retrieve the parameters that are available for the passed message bus.
    message_bus_params = runtime.message_bus_cls.get_default_parameters()

    # Populate the parameters based upon config parameters.
    print(message_bus_params)

    # Set up the credential store to manage the credentials for agents/services/server.
    credential_store = Path(runtime.options.volttron_home).joinpath("credential_store")
    # TODO get from config.
    # This is using the file based credential store so we pass on the store location.
    cred_manager = runtime.credential_manager_cls(str(credential_store), "CURVE")
    cred_generator = runtime.credential_generator_cls()

    # Create minimal set of identities that should be in the store in order for the system to work.
    # Note all the services will utilize the credentials of the CONTROL identity.
    for identity in (CONTROL, CONTROL_CONNECTION, "server"):
        try:
            cred_manager.load(identity)
        except CredentialsError:
            creds = cred_generator.generate(identity)
            cred_manager.store(creds)

    server_creds = cred_manager.load("server")
    service_creds = cred_manager.load(CONTROL)

    aip = AIPplatform(runtime=runtime)
    aip.setup()

    # TODO see if there is a bus wide way of doing this.
    #  tracker = Tracker()
    protected_topics_file = os.path.join(server_options.volttron_home, "protected_topics.json")
    _log.debug("protected topics file %s", protected_topics_file)
    external_address_file = os.path.join(server_options.volttron_home, "external_address.json")
    _log.debug("external_address_file file %s", external_address_file)
    protected_topics = {}
    # if opts.agent_monitor_frequency:
    #     try:
    #         int(opts.agent_monitor_frequency)
    #     except ValueError as e:
    #         raise ValueError("agent-monitor-frequency should be integer "
    #                          "value. Units - seconds. This determines how "
    #                          "often the platform checks for any crashed agent "
    #                          "and attempts to restart. {}".format(e))

    pid_file = os.path.join(server_options.volttron_home, "VOLTTRON_PID")

    # The return value will be added to the service_config.yml file in order to pass in
    # the expected defaults. From there the user may choose to modify the defaults.
    service_config_file = server_options.volttron_home.joinpath("service_config.yml")
    service_config = ServiceConfigs(service_config_file=service_config_file,
                                    service_credentials=service_creds,
                                    server_credentials=server_creds)
    # Start up the platform
    spawned_greenlets = []

    service_config.init_services(aip)

    # Retrieve the config store service as it is first to load even before the message bus.
    config_store = service_config.get_service_instance("volttron.services.config_store")

    # Determine message bus and setup
    auth_service = service_config.get_service_instance("volttron.services.auth")

    mb_params = runtime.message_bus_cls.get_default_parameters()
    mb_params.credential_manager = cred_manager
    mb_params.auth_service = auth_service

    _log.info("Loaded Message Bus Parameters")
    mb = runtime.message_bus_cls()
    mb.set_parameters(mb_params)

    _log.debug("Starting volttron.services.config_store")
    event = gevent.event.Event()
    config_store_task = gevent.spawn(config_store.core.run, event)
    event.wait()
    del event

    spawned_greenlets.append(config_store_task)

    _log.info(f"Starting MessageBus {mb.__class__.__name__}")
    mb.start()

    _log.debug("Starting volttron.services.auth")
    event = gevent.event.Event()
    auth_task = gevent.spawn(auth_service.core.run, event)
    event.wait()
    del event
    spawned_greenlets.append(auth_task)

    start_up_services = ("volttron.services.config_store",
                         "volttron.services.auth")

    for service_name in service_config.get_service_names():
        if service_name not in start_up_services:
            instance = service_config.get_service_instance(service_name)
            if instance is not None:
                _log.debug(f"Starting {service_name}")
                event = gevent.event.Event()
                task = gevent.spawn(instance.core.run, event)
                event.wait()
                del event
                spawned_greenlets.append(task)

    _log.info("********************************************Startup Complete")
    gevent.wait(spawned_greenlets, count=1)

    mb.stop()

    # # TODO Replace with module level zmq that holds all of the zmq bits in order to start and
    # #  run the message bus regardless of whether it's zmq or rmq.
    # if opts.message_bus == "zmq":
    #     # first service loaded must be the config store
    #     config_store = service_instances[0]
    #     assert type(config_store).__name__ == "ConfigStoreService"
    #     # assert isinstance(config_store, ConfigStoreService)
    #     # start it up before anything else
    #     spawned_greenlets.append(config_store.spawn_in_greenlet())
    #
    #     # If auth service is not found then we have no auth installed, therefore
    #     # a value error is raised and no authentication is available.
    #     try:
    #         auth_index = plugin_names.index("volttron.services.auth")
    #         auth_service = service_instances[auth_index]
    #     except ValueError:
    #         auth_service = None
    #
    #     # if we have an auth service it should be started before the
    #     # zmq router.
    #     if auth_service:
    #         spawned_greenlets.append(auth_service.spawn_in_greenlet())
    #
    #     # Start ZMQ router in separate thread to remain responsive
    #     thread = threading.Thread(target=zmq_router, args=(config_store.core.stop,))
    #     thread.daemon = True
    #     thread.start()
    #
    #     gevent.sleep(0.1)
    #     if not thread.is_alive():
    #         sys.exit()
    # else:
    #     pass
    # TODO: Add rabbit
    # Start RabbitMQ server if not running
    # rmq_config = RMQConfig()
    # if rmq_config is None:
    #     _log.error("DEBUG: Exiting due to error in rabbitmq config file. Please check.")
    #     sys.exit()

    # # If RabbitMQ is started as service, don't start it through the code
    # if not rmq_config.rabbitmq_as_service:
    #     try:
    #         start_rabbit(rmq_config.rmq_home)
    #     except AttributeError as exc:
    #         _log.error("Exception while starting RabbitMQ. Check the path in the config file.")
    #         sys.exit()
    #     except subprocess.CalledProcessError as exc:
    #         _log.error("Unable to start rabbitmq server. "
    #                    "Check rabbitmq log for errors")
    #         sys.exit()

    # Start the config store before auth so we may one day have auth use it.
    # config_store = ConfigStoreService(
    #     address=address,
    #     identity=CONFIGURATION_STORE,
    #     message_bus=opts.message_bus,
    # )
    #
    # thread = threading.Thread(target=rmq_router, args=(config_store.core.stop, ))
    # thread.daemon = True
    # thread.start()
    #
    # gevent.sleep(0.1)
    # if not thread.is_alive():
    #     sys.exit()
    #
    # gevent.sleep(1)
    # event = gevent.event.Event()
    # config_store_task = gevent.spawn(config_store.core.run, event)
    # event.wait()
    # del event
    #
    # # Ensure auth service is running before router
    # auth_file = os.path.join(opts.volttron_home, "auth.json")
    # auth = AuthService(
    #     auth_file,
    #     protected_topics_file,
    #     opts.setup_mode,
    #     opts.aip,
    #     address=address,
    #     identity=AUTH,
    #     enable_store=False,
    #     message_bus="rmq",
    # )
    #
    # event = gevent.event.Event()
    # auth_task = gevent.spawn(auth.core.run, event)
    # event.wait()
    # del event
    #
    # protected_topics = auth.get_protected_topics()
    #
    # # Spawn Greenlet friendly ZMQ router
    # # Necessary for backward compatibility with ZMQ message bus
    # green_router = GreenRouter(
    #     opts.vip_local_address,
    #     opts.vip_address,
    #     secretkey=secretkey,
    #     publickey=publickey,
    #     default_user_id="vip.service",
    #     monitor=opts.monitor,
    #     tracker=tracker,
    #     volttron_central_address=opts.volttron_central_address,
    #     volttron_central_serverkey=opts.volttron_central_serverkey,
    #     instance_name=opts.instance_name,
    #     bind_web_address=opts.bind_web_address,
    #     protected_topics=protected_topics,
    #     external_address_file=external_address_file,
    #     msgdebug=opts.msgdebug,
    #     service_notifier=notifier,
    # )
    #
    # proxy_router = ZMQProxyRouter(
    #     address=address,
    #     identity=PROXY_ROUTER,
    #     zmq_router=green_router,
    #     message_bus=opts.message_bus,
    # )
    # event = gevent.event.Event()
    # proxy_router_task = gevent.spawn(proxy_router.core.run, event)
    # event.wait()
    # del event

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
    this_instance = instances.get(opts.volttron_home, {})
    this_instance["pid"] = os.getpid()
    this_instance["version"] = get_version()
    # note vip_address is a list
    this_instance["vip-address"] = opts.vip_address
    this_instance["volttron-home"] = opts.volttron_home
    this_instance["volttron-root"] = os.path.abspath("../../..")
    this_instance["start-args"] = sys.argv[1:]
    instances[opts.volttron_home] = this_instance
    instances.async_sync()

    protected_topics_file = os.path.join(opts.volttron_home, "protected_topics.json")
    _log.debug("protected topics file %s", protected_topics_file)
    external_address_file = os.path.join(opts.volttron_home, "external_address.json")
    _log.debug("external_address_file file %s", external_address_file)

    # Auth and config store services have already been run, so we can run the others now.
    for i, plugin_name in enumerate(plugin_names):
        if plugin_name not in ('volttron.services.auth', 'volttron.services.config_store'):
            _log.debug(f"spawning {plugin_name}")
            spawned_greenlets.append(service_instances[i].spawn_in_greenlet())

    # Allow auth entry to be able to manage all config store entries.
    control_service_index = plugin_names.index("volttron.services.control")
    control_service = service_instances[control_service_index]
    entry = AuthEntry(
        credentials=control_service.core.publickey,
        user_id=CONTROL,
        capabilities=[
            {
                "edit_config_store": {
                    "identity": "/.*/"
                }
            },
            "allow_auth_modifications",
        ],
        comments="Automatically added by platform on start",
    )
    AuthFile().add(entry, overwrite=True)

    # # TODO Key discovery agent add in.
    # # KeyDiscoveryAgent(
    # #     address=address,
    # #     serverkey=publickey,
    # #     identity=KEY_DISCOVERY,
    # #     external_address_config=external_address_file,
    # #     setup_mode=opts.setup_mode,
    # #     bind_web_address=opts.bind_web_address,
    # #     enable_store=False,
    # #     message_bus="zmq",
    # # ),
    # ]

    # Begin the webserver based options here.
    if opts.bind_web_address is not None:
        if not HAS_WEB:
            sys.stderr.write("Web libraries not installed, but bind web address specified\n")
            sys.stderr.write("Please install web libraries using python3 bootstrap.py --web\n")
            sys.exit(-1)

        if opts.instance_name is None:
            _update_config_file()

        if opts.message_bus == "rmq":
            if (opts.web_ssl_key is None or opts.web_ssl_cert is None
                    or (not os.path.isfile(opts.web_ssl_key)
                        and not os.path.isfile(opts.web_ssl_cert))):
                # This is different than the master.web cert which is used for the agent to connect
                # to rmq server.  The master.web-server certificate will be used for the platform web
                # services.
                base_webserver_name = PLATFORM_WEB + "-server"
                from volttron.utils.certs import Certs

                certs = Certs()
                certs.create_signed_cert_files(base_webserver_name, cert_type="server")
                opts.web_ssl_key = certs.private_key_file(base_webserver_name)
                opts.web_ssl_cert = certs.cert_file(base_webserver_name)

        _log.info("Starting platform web service")
        services.append(
            PlatformWebService(
                serverkey=publickey,
                identity=PLATFORM_WEB,
                address=address,
                bind_web_address=opts.bind_web_address,
                volttron_central_address=opts.volttron_central_address,
                enable_store=False,
                message_bus=opts.message_bus,
                volttron_central_rmq_address=opts.volttron_central_rmq_address,
                web_ssl_key=opts.web_ssl_key,
                web_ssl_cert=opts.web_ssl_cert,
                web_secret_key=opts.web_secret_key,
            ))

    # ks_platformweb = KeyStore(KeyStore.get_agent_keystore_path(PLATFORM_WEB))
    # entry = AuthEntry(
    #     credentials=encode_key(decode_key(ks_platformweb.public)),
    #     user_id=PLATFORM_WEB,
    #     capabilities=["allow_auth_modifications"],
    #     comments="Automatically added by platform on start",
    # )
    # AuthFile().add(entry, overwrite=True)

    # # PLATFORM_WEB did not work on RMQ. Referred to agent as master
    # # Added this auth to allow RPC calls for credentials authentication
    # # when using the RMQ messagebus.
    # ks_platformweb = KeyStore(KeyStore.get_agent_keystore_path('master'))
    # entry = AuthEntry(credentials=encode_key(decode_key(ks_platformweb.public)),
    #                   user_id='master',
    #                   capabilities=['allow_auth_modifications'],
    #                   comments='Automatically added by platform on start')
    # AuthFile().add(entry, overwrite=True)

    health_service_index = plugin_names.index("volttron.services.health")
    health_service = service_instances[health_service_index]
    notifier.register_peer_callback(health_service.peer_added, health_service.peer_dropped)
    # # #services.append(health_service)
    # events = [gevent.event.Event() for service in service_instances]
    # # tasks = [gevent.spawn(service.core.run, event) for service, event in zip(services, events)]
    # # tasks.append(config_store_task)
    # # tasks.append(auth_task)
    # # if stop_event:
    # #     tasks.append(stop_event)
    # gevent.wait()
    #
    # del events

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
    # except Exception as e:
    #     _log.error(e)
    #     import traceback
    #
    #     _log.error(traceback.print_exc())
    # finally:
    #     _log.debug("AIP finally")
    #     opts.aip.finish()
    #     instance_file = str(VOLTTRON_INSTANCES)
    #     try:
    #         instances = load_create_store(instance_file)
    #         instances.pop(opts.volttron_home, None)
    #         instances.sync()
    #         if os.path.exists(pid_file):
    #             os.remove(pid_file)
    #     except Exception:
    #         _log.warning(f"Unable to load {VOLTTRON_INSTANCES}")
    #     _log.debug("********************************************************************")
    #     _log.debug("VOLTTRON PLATFORM HAS SHUTDOWN")
    #     _log.debug("********************************************************************")


def build_arg_parser(options: ServerOptions) -> argparse.ArgumentParser:
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
    # parser.add_argument(
    #    '--volttron-home', env_var='VOLTTRON_HOME', metavar='PATH',
    #    help='VOLTTRON configuration directory')
    parser.add_argument("--show-config", action="store_true", help=argparse.SUPPRESS)
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
    # agents.add_argument(
    #     "--vip-local-address",
    #     metavar="ZMQADDR",
    #     help="ZeroMQ URL to bind for local agent VIP connections",
    # )
    agents.add_argument(
        "--instance-name",
        default=None,
        help="The name of the VOLTTRON instance this command is starting up.",
    )
    agents.add_argument(
        "--msgdebug",
        action="store_true",
        help="Route all messages to an agent while debugging.",
    )
    agents.add_argument(
        "--setup-mode",
        action="store_true",
        help="Setup mode flag for setting up authorization of external platforms.",
    )
    parser.add_argument(
        "--message-bus",
        action="store",
        default="zmq",
        dest="message_bus",
        help="set message to be used. valid values are zmq and rmq",
    )
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

    ipc = "ipc://%s$VOLTTRON_HOME/run/" % ("@" if sys.platform.startswith("linux") else "")

    parser.set_defaults(
        log=None,
        log_config=None,
        monitor=False,
        verboseness=logging.WARNING,
        volttron_home=options.volttron_home,
        autostart=True,
        vip_address=[],
        # vip_local_address=ipc + "vip.socket",
        instance_name=None,
        resource_monitor=True,
        msgdebug=None,
        setup_mode=False
    )

    return parser


def main():
    """
    main entry point for the volttron server.

    :return:
    """
    volttron_home = os.path.normpath(
        config.expandall(os.environ.get("VOLTTRON_HOME", "~/.volttron")))
    server_options = ServerOptions(volttron_home=volttron_home)
    os.environ["VOLTTRON_HOME"] = volttron_home

    parser = build_arg_parser(server_options)
    # Parse and expand options
    args = sys.argv[1:]
    conf = os.path.join(volttron_home, "config")
    if os.path.exists(conf) and "SKIP_VOLTTRON_CONFIG" not in os.environ:
        # command line args get preference over same args in config file
        args = args + ["--config", conf]
    logging.getLogger().setLevel(logging.NOTSET)
    opts = parser.parse_args(args)
    server_runtime = ServerRuntime(opts=server_options)

    start_volttron_process(server_runtime)


def _main():
    """Entry point for scripts."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
