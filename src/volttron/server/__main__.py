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

from gevent import monkey

# monkey.patch_all()
monkey.patch_socket()
monkey.patch_ssl()

import argparse
import logging
from logging import handlers
import logging.config
from urllib.parse import urlparse

import os
from pathlib import Path
import resource
import stat
import sys
import threading

import gevent

# import gevent.monkey
# import gevent.threading as threading
#
from volttron.utils import ClientContext as cc
from volttron.utils.keystore import get_random_key

# gevent.monkey.patch_socket()
# gevent.monkey.patch_ssl()
import zmq
from zmq import green

# Link to the volttron-client library
from volttron.utils import decode_key, encode_key, get_version

# Create a context common to the green and non-green zmq modules.
green.Context._instance = green.Context.shadow(zmq.Context.instance().underlying)

# from .vip.router import *
# from .vip.socket import decode_key, encode_key, Address
# from .vip.tracking import Tracker

from volttron.client.known_identities import (
    PLATFORM_WEB,
    CONFIGURATION_STORE,
    AUTH,
    CONTROL,
    CONTROL_CONNECTION,
    PLATFORM_HEALTH,
    PROXY_ROUTER,
)
from volttron.utils import store_message_bus_config
from volttron.utils.keystore import KeyStore, KnownHostsStore
from volttron.utils.persistance import load_create_store

from .tracking import Tracker

# TODO rmq
# from .vip.rmq_router import RMQRouter

# from volttron.utils.rmq_setup import start_rabbit
# from volttron.utils.rmq_config_params import RMQConfig

from volttron.server.router import Router, GreenRouter
from ..services.health import HealthService
from ..services.peer import ServicePeerNotifier
from ..services.auth import AuthService, AuthFile, AuthEntry
from ..services.control import ControlService
from ..services.config_store import ConfigStoreService

# TODO Key Discovery RPC
# from ..services.external import ExternalRPCService, KeyDiscoveryAgent
from ..services.routing import ZMQProxyRouter

try:
    from services.web import PlatformWebService

    HAS_WEB = True
except ImportError:
    HAS_WEB = False

from .log_actions import log_to_file, configure_logging, LogLevelAction
from . import server_argparser as config, aip

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


def start_volttron_process(opts):
    """Start the main volttron process.

    Typically this function is used from main.py and just uses the argparser's
    Options arguments as inputs.   It also can be called with a dictionary.  In
    that case the dictionaries keys are mapped into a value that acts like the
    args options.
    """
    if isinstance(opts, dict):
        opts = type("Options", (), opts)()
        # vip_address is meant to be a list so make it so.
        if not isinstance(opts.vip_address, list):
            opts.vip_address = [opts.vip_address]
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

    if opts.secure_agent_users == "True":
        _log.info("VOLTTRON starting in secure mode")
        os.umask(0o007)
    else:
        opts.secure_agent_users = "False"

    opts.publish_address = config.expandall(opts.publish_address)
    opts.subscribe_address = config.expandall(opts.subscribe_address)
    opts.vip_address = [config.expandall(addr) for addr in opts.vip_address]
    opts.vip_local_address = config.expandall(opts.vip_local_address)
    opts.message_bus = config.expandall(opts.message_bus)
    if opts.web_ssl_key:
        opts.web_ssl_key = config.expandall(opts.web_ssl_key)
    if opts.web_ssl_cert:
        opts.web_ssl_cert = config.expandall(opts.web_ssl_cert)

    if opts.web_ssl_key and not opts.web_ssl_cert:
        raise Exception("If web-ssl-key is specified web-ssl-cert MUST be specified.")
    if opts.web_ssl_cert and not opts.web_ssl_key:
        raise Exception("If web-ssl-cert is specified web-ssl-key MUST be specified.")

    if opts.web_ca_cert:
        assert os.path.isfile(opts.web_ca_cert), "web_ca_cert does not exist!"
        os.environ["REQUESTS_CA_BUNDLE"] = opts.web_ca_cert

    # Removed the check for opts.web_ca_cert to be the same cert that was used to create web_ssl_key
    # and opts.web_ssl_cert

    os.environ["MESSAGEBUS"] = opts.message_bus
    os.environ["SECURE_AGENT_USERS"] = opts.secure_agent_users
    if opts.instance_name is None:
        if len(opts.vip_address) > 0:
            opts.instance_name = opts.vip_address[0]

    _log.debug("opts.instancename {}".format(opts.instance_name))
    if opts.instance_name:
        store_message_bus_config(opts.message_bus, opts.instance_name)
    else:
        # if there is no instance_name given get_platform_instance_name will
        # try to retrieve from config or default a value and store it in the config
        cc.get_instance_name()

    if opts.bind_web_address:
        os.environ["BIND_WEB_ADDRESS"] = opts.bind_web_address
        parsed = urlparse(opts.bind_web_address)
        if parsed.scheme not in ("http", "https"):
            raise Exception("bind-web-address must begin with http or https.")
        opts.bind_web_address = config.expandall(opts.bind_web_address)
        # zmq with tls is supported
        if opts.message_bus == "zmq" and parsed.scheme == "https":
            if not opts.web_ssl_key or not opts.web_ssl_cert:
                raise Exception("zmq https requires a web-ssl-key and a web-ssl-cert file.")
            if not os.path.isfile(opts.web_ssl_key) or not os.path.isfile(opts.web_ssl_cert):
                raise Exception("zmq https requires a web-ssl-key and a web-ssl-cert file.")
        # zmq without tls is supported through the use of a secret key, if it's None then
        # we want to generate a secret key and set it in the config file.
        elif opts.message_bus == "zmq" and opts.web_secret_key is None:
            opts.web_secret_key = get_random_key()
            _update_config_file(web_secret_key=opts.web_secret_key)

    if opts.volttron_central_address:
        parsed = urlparse(opts.volttron_central_address)
        if parsed.scheme not in ("http", "https", "tcp", "amqp", "amqps"):
            raise Exception(
                "volttron-central-address must begin with tcp, amqp, amqps, http or https.")
        opts.volttron_central_address = config.expandall(opts.volttron_central_address)
    opts.volttron_central_serverkey = opts.volttron_central_serverkey

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

    opts.aip = aip.AIPplatform(opts)
    opts.aip.setup()

    # Check for secure mode/permissions on VOLTTRON_HOME directory
    mode = os.stat(opts.volttron_home).st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        _log.warning("insecure mode on directory: %s", opts.volttron_home)
    # Get or generate encryption key
    keystore = KeyStore()
    _log.debug("using key-store file %s", keystore.filename)
    if not keystore.isvalid():
        _log.warning("key store is invalid; connections may fail")
    st = os.stat(keystore.filename)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        _log.warning("insecure mode on key file")
    publickey = decode_key(keystore.public)
    if publickey:
        # Authorize the platform key:
        entry = AuthEntry(
            credentials=encode_key(publickey),
            user_id="platform",
            capabilities=[{
                "edit_config_store": {
                    "identity": "/.*/"
                }
            }],
            comments="Automatically added by platform on start",
        )
        AuthFile().add(entry, overwrite=True)
        # Add platform key to known-hosts file:
        known_hosts = KnownHostsStore()
        known_hosts.add(opts.vip_local_address, encode_key(publickey))
        for addr in opts.vip_address:
            known_hosts.add(addr, encode_key(publickey))
    secretkey = decode_key(keystore.secret)

    # Add the control.connection so that volttron-ctl can access the bus
    control_conn_path = KeyStore.get_agent_keystore_path(CONTROL_CONNECTION)
    os.makedirs(os.path.dirname(control_conn_path), exist_ok=True)
    ks_control_conn = KeyStore(KeyStore.get_agent_keystore_path(CONTROL_CONNECTION))
    entry = AuthEntry(
        credentials=encode_key(decode_key(ks_control_conn.public)),
        user_id=CONTROL_CONNECTION,
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

    # The following line doesn't appear to do anything, but it creates
    # a context common to the green and non-green zmq modules.
    zmq.Context.instance()    # DO NOT REMOVE LINE!!
    # zmq.Context.instance().set(zmq.MAX_SOCKETS, 2046)

    tracker = Tracker()
    protected_topics_file = os.path.join(opts.volttron_home, "protected_topics.json")
    _log.debug("protected topics file %s", protected_topics_file)
    external_address_file = os.path.join(opts.volttron_home, "external_address.json")
    _log.debug("external_address_file file %s", external_address_file)
    protected_topics = {}
    if opts.agent_monitor_frequency:
        try:
            int(opts.agent_monitor_frequency)
        except ValueError as e:
            raise ValueError("agent-monitor-frequency should be integer "
                             "value. Units - seconds. This determines how "
                             "often the platform checks for any crashed agent "
                             "and attempts to restart. {}".format(e))

    # Allows registration agents to callbacks for peers
    notifier = ServicePeerNotifier()

    # Main loops
    def zmq_router(stop):
        try:
            _log.debug("Running zmq router")
            Router(
                opts.vip_local_address,
                opts.vip_address,
                secretkey=secretkey,
                publickey=publickey,
                default_user_id="vip.service",
                monitor=opts.monitor,
                tracker=tracker,
                volttron_central_address=opts.volttron_central_address,
                volttron_central_serverkey=opts.volttron_central_serverkey,
                instance_name=opts.instance_name,
                bind_web_address=opts.bind_web_address,
                protected_topics=protected_topics,
                external_address_file=external_address_file,
                msgdebug=opts.msgdebug,
                service_notifier=notifier,
            ).run()
        except Exception:
            _log.exception("Unhandled exception in router loop")
            raise
        except KeyboardInterrupt:
            pass
        finally:
            _log.debug("In finally")
            stop(platform_shutdown=True)

    # RMQ router
    def rmq_router(stop):
        try:
            RMQRouter(
                opts.vip_address,
                opts.vip_local_address,
                opts.instance_name,
                opts.vip_address,
                volttron_central_address=opts.volttron_central_address,
                volttron_central_serverkey=opts.volttron_central_serverkey,
                bind_web_address=opts.bind_web_address,
                service_notifier=notifier,
            ).run()
        except Exception:
            _log.exception("Unhandled exception in rmq router loop")
        except KeyboardInterrupt:
            pass
        finally:
            _log.debug("In RMQ router finally")
            stop(platform_shutdown=True)

    address = "inproc://vip"
    pid_file = os.path.join(opts.volttron_home, "VOLTTRON_PID")
    try:

        stop_event = None

        auth_task = None
        protected_topics = {}
        config_store_task = None
        proxy_router = None
        proxy_router_task = None

        _log.debug("********************************************************************")
        _log.debug("VOLTTRON PLATFORM RUNNING ON {} MESSAGEBUS".format(opts.message_bus))
        _log.debug("********************************************************************")
        if opts.message_bus == "zmq":
            # Start the config store before auth so we may one day have auth use it.
            config_store = ConfigStoreService(
                address=address,
                identity=CONFIGURATION_STORE,
                message_bus=opts.message_bus,
            )

            event = gevent.event.Event()
            config_store_task = gevent.spawn(config_store.core.run, event)
            event.wait()
            del event

            # Ensure auth service is running before router
            auth_file = os.path.join(opts.volttron_home, "auth.json")
            auth = AuthService(
                auth_file,
                protected_topics_file,
                opts.setup_mode,
                opts.aip,
                address=address,
                identity=AUTH,
                enable_store=False,
                message_bus="zmq",
            )

            event = gevent.event.Event()
            auth_task = gevent.spawn(auth.core.run, event)
            event.wait()
            del event

            protected_topics = auth.get_protected_topics()
            _log.debug("MAIN: protected topics content {}".format(protected_topics))
            # Start ZMQ router in separate thread to remain responsive
            thread = threading.Thread(target=zmq_router, args=(config_store.core.stop, ))
            thread.daemon = True
            thread.start()

            _log.debug("After thread start!")
            gevent.sleep(0.1)
            if not thread.is_alive():
                sys.exit()
        else:
            pass
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
            config_store = ConfigStoreService(
                address=address,
                identity=CONFIGURATION_STORE,
                message_bus=opts.message_bus,
            )

            thread = threading.Thread(target=rmq_router, args=(config_store.core.stop, ))
            thread.daemon = True
            thread.start()

            gevent.sleep(0.1)
            if not thread.is_alive():
                sys.exit()

            gevent.sleep(1)
            event = gevent.event.Event()
            config_store_task = gevent.spawn(config_store.core.run, event)
            event.wait()
            del event

            # Ensure auth service is running before router
            auth_file = os.path.join(opts.volttron_home, "auth.json")
            auth = AuthService(
                auth_file,
                protected_topics_file,
                opts.setup_mode,
                opts.aip,
                address=address,
                identity=AUTH,
                enable_store=False,
                message_bus="rmq",
            )

            event = gevent.event.Event()
            auth_task = gevent.spawn(auth.core.run, event)
            event.wait()
            del event

            protected_topics = auth.get_protected_topics()

            # Spawn Greenlet friendly ZMQ router
            # Necessary for backward compatibility with ZMQ message bus
            green_router = GreenRouter(
                opts.vip_local_address,
                opts.vip_address,
                secretkey=secretkey,
                publickey=publickey,
                default_user_id="vip.service",
                monitor=opts.monitor,
                tracker=tracker,
                volttron_central_address=opts.volttron_central_address,
                volttron_central_serverkey=opts.volttron_central_serverkey,
                instance_name=opts.instance_name,
                bind_web_address=opts.bind_web_address,
                protected_topics=protected_topics,
                external_address_file=external_address_file,
                msgdebug=opts.msgdebug,
                service_notifier=notifier,
            )

            proxy_router = ZMQProxyRouter(
                address=address,
                identity=PROXY_ROUTER,
                zmq_router=green_router,
                message_bus=opts.message_bus,
            )
            event = gevent.event.Event()
            proxy_router_task = gevent.spawn(proxy_router.core.run, event)
            event.wait()
            del event

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

        # Launch additional services and wait for them to start before
        # auto-starting agents
        services = [
            ControlService(
                opts.aip,
                address=address,
                identity=CONTROL,
                tracker=tracker,
                heartbeat_autostart=True,
                enable_store=False,
                enable_channel=True,
                message_bus=opts.message_bus,
                agent_monitor_frequency=opts.agent_monitor_frequency,
            ),
        # TODO Key discovery agent add in.
        # KeyDiscoveryAgent(
        #     address=address,
        #     serverkey=publickey,
        #     identity=KEY_DISCOVERY,
        #     external_address_config=external_address_file,
        #     setup_mode=opts.setup_mode,
        #     bind_web_address=opts.bind_web_address,
        #     enable_store=False,
        #     message_bus="zmq",
        # ),
        ]

        entry = AuthEntry(
            credentials=services[0].core.publickey,
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

        ks_platformweb = KeyStore(KeyStore.get_agent_keystore_path(PLATFORM_WEB))
        entry = AuthEntry(
            credentials=encode_key(decode_key(ks_platformweb.public)),
            user_id=PLATFORM_WEB,
            capabilities=["allow_auth_modifications"],
            comments="Automatically added by platform on start",
        )
        AuthFile().add(entry, overwrite=True)

        # # PLATFORM_WEB did not work on RMQ. Referred to agent as master
        # # Added this auth to allow RPC calls for credential authentication
        # # when using the RMQ messagebus.
        # ks_platformweb = KeyStore(KeyStore.get_agent_keystore_path('master'))
        # entry = AuthEntry(credentials=encode_key(decode_key(ks_platformweb.public)),
        #                   user_id='master',
        #                   capabilities=['allow_auth_modifications'],
        #                   comments='Automatically added by platform on start')
        # AuthFile().add(entry, overwrite=True)

        health_service = HealthService(
            address=address,
            identity=PLATFORM_HEALTH,
            heartbeat_autostart=True,
            enable_store=False,
            message_bus=opts.message_bus,
        )
        notifier.register_peer_callback(health_service.peer_added, health_service.peer_dropped)
        services.append(health_service)
        events = [gevent.event.Event() for service in services]
        tasks = [gevent.spawn(service.core.run, event) for service, event in zip(services, events)]
        tasks.append(config_store_task)
        tasks.append(auth_task)
        if stop_event:
            tasks.append(stop_event)
        gevent.wait(events)
        del events

        # Auto-start agents now that all services are up
        if opts.autostart:
            for name, error in opts.aip.autostart():
                _log.error("error starting {!r}: {}\n".format(name, error))

        # Done with all start up process write a PID file

        with open(pid_file, "w+") as f:
            f.write(str(os.getpid()))

        # Wait for any service to stop, signaling exit
        try:
            gevent.wait(tasks, count=1)
        except KeyboardInterrupt:
            _log.info("SIGINT received; shutting down")
        finally:
            sys.stderr.write("Shutting down.\n")
            if proxy_router_task:
                proxy_router.core.stop()
            _log.debug("Kill all service agent tasks")
            for task in tasks:
                task.kill(block=False)
            gevent.wait(tasks)
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


def main(argv=sys.argv):
    # Refuse to run as root
    if not getattr(os, "getuid", lambda: -1)():
        sys.stderr.write("%s: error: refusing to run as root to prevent "
                         "potential damage.\n" % os.path.basename(argv[0]))
        sys.exit(77)

    volttron_home = os.path.normpath(
        config.expandall(os.environ.get("VOLTTRON_HOME", "~/.volttron")))
    os.environ["VOLTTRON_HOME"] = volttron_home
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
        "--publish-address",
        metavar="ZMQADDR",
        help="ZeroMQ URL used for pre-3.x agent publishing (deprecated)",
    )
    agents.add_argument(
        "--subscribe-address",
        metavar="ZMQADDR",
        help="ZeroMQ URL used for pre-3.x agent subscriptions (deprecated)",
    )
    agents.add_argument(
        "--vip-address",
        metavar="ZMQADDR",
        action="append",
        default=[],
        help="ZeroMQ URL to bind for VIP connections",
    )
    agents.add_argument(
        "--vip-local-address",
        metavar="ZMQADDR",
        help="ZeroMQ URL to bind for local agent VIP connections",
    )
    agents.add_argument(
        "--bind-web-address",
        metavar="BINDWEBADDR",
        default=None,
        help="Bind a web server to the specified ip:port passed",
    )
    agents.add_argument(
        "--web-ca-cert",
        metavar="CAFILE",
        default=None,
        help=
        "If using self-signed certificates, this variable will be set globally to allow requests"
        "to be able to correctly reach the webserver without having to specify verify in all calls.",
    )
    agents.add_argument(
        "--web-secret-key",
        default=None,
        help="Secret key to be used instead of https based authentication.",
    )
    agents.add_argument(
        "--web-ssl-key",
        metavar="KEYFILE",
        default=None,
        help="ssl key file for using https with the volttron server",
    )
    agents.add_argument(
        "--web-ssl-cert",
        metavar="CERTFILE",
        default=None,
        help="ssl certficate file for using https with the volttron server",
    )
    agents.add_argument(
        "--volttron-central-address",
        default=None,
        help="The web address of a volttron central install instance.",
    )
    agents.add_argument(
        "--volttron-central-serverkey",
        default=None,
        help="The serverkey of volttron central.",
    )
    agents.add_argument(
        "--instance-name",
        default=None,
        help="The name of the instance that will be reported to "
        "VOLTTRON central.",
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
        "--volttron-central-rmq-address",
        default=None,
        help="The AMQP address of a volttron central install instance",
    )
    agents.add_argument(
        "--agent-monitor-frequency",
        default=600,
        help="How often should the platform check for crashed agents and "
        "attempt to restart. Units=seconds. Default=600",
    )
    agents.add_argument(
        "--secure-agent-users",
        default=False,
        help="Require that agents run with their own users (this requires "
        "running scripts/secure_user_permissions.sh as sudo)",
    )

    # XXX: re-implement control options
    # on
    # control.add_argument(
    #    '--allow-root', action='store_true', inverse='--no-allow-root',
    #    help='allow root to connect to control socket')
    # control.add_argument(
    #    '--no-allow-root', action='store_false', dest='allow_root',
    #    help=argparse.SUPPRESS)
    # control.add_argument(
    #    '--allow-users', action='store_list', metavar='LIST',
    #    help='users allowed to connect to control socket')
    # control.add_argument(
    #    '--allow-groups', action='store_list', metavar='LIST',
    #    help='user groups allowed to connect to control socket')

    ipc = "ipc://%s$VOLTTRON_HOME/run/" % ("@" if sys.platform.startswith("linux") else "")

    parser.set_defaults(
        log=None,
        log_config=None,
        monitor=False,
        verboseness=logging.WARNING,
        volttron_home=volttron_home,
        autostart=True,
        publish_address=ipc + "publish",
        subscribe_address=ipc + "subscribe",
        vip_address=[],
        vip_local_address=ipc + "vip.socket",
    # This is used to start the web server from the web module.
        bind_web_address=None,
    # Used to contact volttron central when registering volttron central
    # platform agent.
        volttron_central_address=None,
        volttron_central_serverkey=None,
        instance_name=None,
    # allow_root=False,
    # allow_users=None,
    # allow_groups=None,
        verify_agents=True,
        resource_monitor=True,
    # mobility=True,
        msgdebug=None,
        setup_mode=False,
    # Type of underlying message bus to use - ZeroMQ or RabbitMQ
        message_bus="zmq",
    # Volttron Central in AMQP address format is needed if running on RabbitMQ message bus
        volttron_central_rmq_address=None,
        web_ssl_key=None,
        web_ssl_cert=None,
        web_ca_cert=None,
    # If we aren't using ssl then we need a secret key available for us to use.
        web_secret_key=None,
    )

    # Parse and expand options
    args = argv[1:]
    conf = os.path.join(volttron_home, "config")
    if os.path.exists(conf) and "SKIP_VOLTTRON_CONFIG" not in os.environ:
        # command line args get preference over same args in config file
        args = args + ["--config", conf]
    logging.getLogger().setLevel(logging.NOTSET)
    opts = parser.parse_args(args)

    start_volttron_process(opts)


def _main():
    """Entry point for scripts."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
