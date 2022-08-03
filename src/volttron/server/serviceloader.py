from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from types import ModuleType
from typing import List, Tuple, Dict, Set, KeysView

import sys

#sys.path.append('/repos/volttron-lib-web/src')
from volttron.utils import get_klass
from volttron.utils import get_subclasses, get_module, get_klass

_log = logging.getLogger(__name__)

__discovered_plugins__: Dict[str, Tuple] = {}
__namespaces__: Set[str] = set()
__required_plugins__: Set[str] = set()
__plugin_startup_order__: List[str] = [
    "volttron.services.config_store",
    "volttron.services.auth",
]
__disabled_plugins__: Set[str] = set()

__all__ = ["get_service_names", "start_services", "discover_services"]

__service_interface_class__ = get_klass('volttron.types', 'ServiceInterface')


def get_service_names() -> KeysView[str]:
    return __discovered_plugins__.keys()


def start_service(service_name: str):
    # discover_services('volttron.services')
    # #sys.path.insert(0, '/repos/volttron-lib-web/src')
    # #print(sys.path)
    # #discover_services('volttron.services')
    # #volttron_module = importlib.import_module('volttron')
    # #services_module = importlib.import_module('volttron.services')
    service_interface = get_klass('volttron.types', 'ServiceInterface')
    module = get_module(service_name)
    subclasses = get_subclasses(module, service_interface)
    service = subclasses[0](serverkey=None,
                            identity="platform.web",
                            bind_web_address="http://127.0.0.1:8080")
    greenlet = service.spawn_in_greenlet()
    return greenlet


def start_services():

    # service_interface_class = getattr(__types_module__, 'ServiceInterface')

    klass = None

    found = []
    if not __disabled_plugins__:
        found = __discover_services__("volttron.services")

    for plugin_name in __plugin_startup_order__:
        if plugin_name not in found:
            raise ValueError(f"Invalid plugin specified in plugin_startup_order {plugin_name}")
        _log.info(f"Starting plugin: {plugin_name}, {__discovered_plugins__[plugin_name]}")

    for plugin_name, plugin in __discovered_plugins__.items():
        if plugin_name not in __plugin_startup_order__ and plugin_name not in __disabled_plugins__:
            _log.info(f"Starting plugin {plugin_name}, {plugin}")

            klass = None
            module = get_module("volttron.services")
            subclasses = get_subclasses(module, "ServiceInterface", return_all=True)
            #
            # for single_class in inspect.getmembers(plugin, inspect.isclass):
            #     if service_interface_class in single_class[1].__bases__:
            #     #if issubclass(single_class, service_interface_class):
            #         _log.debug("Found")
            #     else:
            #         _log.error(f"Not found: {single_class}")

            #klass_base_interface = getattr(plugin, 'ServiceInterface')

            #plugin()
            for sub in subclasses:
                sub()


def discover_services(namespace: str) -> List[str]:
    module = importlib.import_module(namespace)
    return __discover_services__(module)


def __iter_namespace__(ns_pkg):
    """
    Uses namespace package to locate all namespaces with the ns_pkg as its root.

    For example in our system any namespace package that starts with volttron.services
    should be detected.

    NOTE: NO __init__.py file should ever be located within any package volttron.services or
            the importing will break

    @param: ns_pkg: Namespace to search for modules in.
    """
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def __discover_services__(namespace: str | ModuleType) -> List[str]:
    """
    Map all of the discovered namespaces to the volttron.services import.  Build
    a dictionary 'package' -> module.
    """
    if isinstance(namespace, str):
        namespace = importlib.import_module(namespace)

    # Add the namespace that is searched in case we need to load others in the future.
    __namespaces__.add(namespace.__name__)
    found: List[str] = []
    for finder, name, ispkg in __iter_namespace__(namespace):
        found.append(name)
        __discovered_plugins__[name] = importlib.import_module(name)
    return found


# """
# Manage the startup order of plugins available.  Note an error will
# be raised and the server will not startup if the plugin doesn't exist.
# The plugins that are within this same codebase hold the "default" services
# that should always be available in the system.  VOLTTRON requires that
# the services be started in a specific order for its processing to work as
# intended.
# """
# plugin_startup_order = [
#     "volttron.services.config_store",
#     "volttron.services.auth",
# ]
#
# plugin_disabled = ["volttron.services.health"]
#
# for p in plugin_startup_order:
#     if p not in __discovered_plugins__:
#         raise ValueError(f"Invalid plugin specified in plugin_startup_order {p}")
#     _log.info(f"Starting plugin: {p}, {__discovered_plugins__[p]}")
#
# for p, v in __discovered_plugins__.items():
#     if p not in plugin_startup_order and p not in plugin_disabled:
#         _log.info(f"Starting plugin {p}, {v}")
