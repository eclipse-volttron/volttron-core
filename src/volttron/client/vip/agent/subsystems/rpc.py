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

import inspect
import logging
import os
import sys
import traceback
import weakref

import gevent.local
from gevent.event import AsyncResult


from volttron.utils import jsonapi, jsonrpc
from volttron.client.known_identities import AUTH, CONTROL, CONTROL_CONNECTION
from ..decorators import annotate, annotations, dualmethod, spawn
from volttron.client.vip.agent.results import ResultsDictionary, counter
from volttron.client.vip.agent.subsystems.base import SubsystemBase
from volttron.client.vip.agent import VIPError

__all__ = ["RPC"]

_ROOT_PACKAGE_PATH = (os.path.dirname(__import__(__name__.split(".", 1)[0]).__path__[-1]) + os.sep)


_log = logging.getLogger(__name__)


def _isregex(obj):
    return (obj is not None and isinstance(obj, str) and len(obj) > 1 and obj[0] == obj[-1] == "/")


class Dispatcher(jsonrpc.Dispatcher):

    def __init__(self, methods, local):
        super(Dispatcher, self).__init__()
        self.methods = methods
        self.local = local
        self._results = ResultsDictionary()

    def serialize(self, json_obj):
        return jsonapi.dumps(json_obj)

    def deserialize(self, json_string):
        return jsonapi.loads(json_string)

    def batch_call(self, requests):
        methods = []
        results = []
        for notify, method, args, kwargs in requests:
            if notify:
                ident = None
            else:
                result = next(self._results)
                ident = result.ident
                results.append(result)
            methods.append((ident, method, args, kwargs))
        return super(Dispatcher, self).batch_call(methods), results

    def call(self, method, args=None, kwargs=None):
        # pylint: disable=arguments-differ
        result = next(self._results)
        return super(Dispatcher, self).call(result.ident, method, args, kwargs), result

    def result(self, response, ident, value, context=None):
        try:
            result = self._results.pop(ident)
        except KeyError:
            return
        result.set(value)

    def error(self, response, ident, code, message, data=None, context=None):
        try:
            result = self._results.pop(ident)
        except KeyError:
            return
        result.set_exception(jsonrpc.exception_from_json(code, message, data))

    def exception(self, response, ident, message, context=None):
        # XXX: Should probably wrap exception in RPC specific error
        #      rather than re-raising.
        (
            _,    # exc_type
            exc,
            _,    # exc_tb
        ) = sys.exc_info()    # pylint: disable=unused-variable
        try:
            result = self._results.pop(ident)
        except KeyError:
            return
        result.set_exception(exc)

    def method(self, request, ident, name, args, kwargs, batch=None, context=None):
        if kwargs:
            try:
                args, kwargs = kwargs["*args"], kwargs["**kwargs"]
            except KeyError:
                pass
        try:
            method = self.methods[name]
        except KeyError:
            if name == "inspect":
                return {"methods": list(self.methods)}
            elif name.endswith(".inspect"):
                try:
                    method = self.methods[name[:-8]]
                except KeyError:
                    pass
                else:
                    return self._inspect(method)
            raise NotImplementedError(name)
        local = self.local
        local.vip_message = context
        local.request = request
        local.batch = batch
        try:
            return method(*args, **kwargs)
        except Exception as exc:    # pylint: disable=broad-except
            exc_tb = traceback.format_exc()
            _log.error("unhandled exception in JSON-RPC method %r: \n%s", name, exc_tb)
            if getattr(method, "traceback", True):
                exc.exc_info = {"exc_tb": exc_tb}
            raise
        finally:
            del local.vip_message
            del local.request
            del local.batch

    @staticmethod
    def _inspect(method):
        response = {"params": {}}
        signature = inspect.signature(method)
        for p in signature.parameters.values():
            response["params"][p.name] = {"kind": p.kind.name}
            if p.default is not inspect.Parameter.empty:
                response["params"][p.name]["default"] = p.default
            if p.annotation is not inspect.Parameter.empty:
                annotation = (p.annotation.__name__ if type(p.annotation) is type else str(p.annotation))
                response["params"][p.name]["annotation"] = annotation
        doc = inspect.getdoc(method)
        if doc:
            response["doc"] = doc
        try:
            source = inspect.getsourcefile(method)
            cut = len(os.path.commonprefix([_ROOT_PACKAGE_PATH, source]))
            source = source[cut:]
            lineno = inspect.getsourcelines(method)[1]
        except Exception:
            pass
        else:
            response["source"] = {"file": source, "line_number": lineno}
        ret = signature.return_annotation
        if ret is not inspect.Signature.empty:
            response["return"] = \
                ret.__name__ if type(ret) is type else str(ret)
        return response


class RPC(SubsystemBase):

    def __init__(self, core, owner, peerlist_subsys):
        self.core = weakref.ref(core)
        self._owner = owner
        self.context = None
        self._exports = {}
        self._dispatcher = None
        self._counter = counter()
        self._outstanding = weakref.WeakValueDictionary()
        core.register("RPC", self._handle_subsystem, self._handle_error)
        core.register(
            "external_rpc",
            self._handle_external_rpc_subsystem,
            self._handle_error,
        )
        self._isconnected = True
        self.peerlist_subsystem = peerlist_subsys
        self.peer_list = {}
        self._protected_rpcs = None

        def export(member):    # pylint: disable=redefined-outer-name
            for name in annotations(member, set, "__rpc__.exports"):
                self._exports[name] = member

        inspect.getmembers(owner, export)

        def setup(sender, **kwargs):
            # pylint: disable=unused-argument
            self.context = gevent.local.local()
            self._dispatcher = Dispatcher(self._exports, self.context)
            self.export(self._add_protected_rpcs, "rpc.add_protected_rpcs")

        core.onsetup.connect(setup, self)
        core.ondisconnected.connect(self._disconnected)
        core.onconnected.connect(self._connected)

    def _connected(self, sender, **kwargs):
        self._isconnected = True
        # Registering to 'onadd' and 'ondrop' signals to get notified
        # whenever new peer is added/removed
        self.peerlist_subsystem.onadd.connect(self._add_new_peer)
        self.peerlist_subsystem.ondrop.connect(self._drop_new_peer)

    def _disconnected(self, sender, **kwargs):
        self._isconnected = False

    def _add_new_peer(self, sender, **kwargs):
        try:
            peer = kwargs.pop("peer")
            message_bus = kwargs.pop("message_bus")
            self.peer_list[peer] = message_bus
        except KeyError:
            pass

    def _drop_new_peer(self, sender, **kwargs):
        try:
            peer = kwargs.pop("peer")
            self.peer_list.pop(peer)
        except KeyError:
            pass

    def _add_auth_check(self, method):
        """
        Adds an authorization check to verify the calling agent has the
        required capabilities.
        """

        def checked_method(*args, **kwargs):
            calling_user = str(self.context.vip_message.user)
            #method_name = method.__name__
            # method.__name__ will give actual method name, but we want the alias used to export this method
            # ex: export("actual_method_name", "alias_exported_which_will_be_used_by_caller")
            method_name = self.context.vip_message.args[0]['method']
            #args_dict = inspect.getcallargs(method, *args, **kwargs)
            signature = inspect.signature(method)
            bound_args = signature.bind(*args, **kwargs)
            bound_args.apply_defaults()
            args_dict = bound_args.arguments
            # Remove self from args_dict if it exists to avoid sending the entire object across.
            # Fixes Issue https://github.com/eclipse-volttron/volttron-core/issues/198
            remove_self = args_dict.pop("self", None)
            from volttron.types.auth import AuthException
            try:
                self.call(AUTH,
                          method="check_rpc_authorization",
                          identity=calling_user,
                          method_name=f"{self.core().identity}.{method_name}",
                          method_args=args_dict).get(timeout=10)
            except AuthException as e:
                # msg = ("method '{}' requires capabilities {}, but capability {} "
                #        "was provided for user {}").format(method.__name__, required_caps,
                #                                           user_capabilites, user)
                raise jsonrpc.exception_from_json(jsonrpc.UNAUTHORIZED, e.args)
            return method(*args, **kwargs)

        return checked_method

    def _wrap_protected_rpcs(self, protected_rpcs):
        """
        Iterates over exported methods and adds authorization checks
        for protected methods
        """
        if protected_rpcs:
            for method_name in self._exports:
                # Don't wrap the method if it is already wrapped by checked_method
                # ideally we shouldn't be here.
                if method_name in protected_rpcs and self._exports[method_name].__name__ !="checked_method":
                    self._exports[method_name] = self._add_auth_check(self._exports[method_name])

    def _add_protected_rpcs(self, updated_list: list[str]):
        if not self._protected_rpcs:
            # nothing was there before so set variable and update all
            self._protected_rpcs = updated_list
            self._wrap_protected_rpcs(self._protected_rpcs)
        else:
            newly_protected = set(updated_list) - set(self._protected_rpcs)
            self._wrap_protected_rpcs(newly_protected)

    def _remove_protected_rpcs(self, remove_list: list[str]):
        if self._protected_rpcs is None:
            self._protected_rpcs = self.get_protected_rpcs()
        if self._protected_rpcs:
            for r in remove_list:
                if r in self._protected_rpcs:
                    method = getattr(self._owner, r, None)
                    # Verify the retrieved method object
                    if method and inspect.ismethod(method):
                        self._exports[r] = method
                    else:
                        raise ValueError(f"Method '{r}' not found in the instance or is not a method.")

    @spawn
    def _handle_external_rpc_subsystem(self, message):
        ret_msg = dict()
        operation = message.args[0]
        rpc_msg = message.args[1]    # jsonapi.loads(message.args[1])
        try:
            method_args = rpc_msg["args"]
            # message.args = [method_args]
            message.args = method_args
            for idx, msg in enumerate(message.args):
                if isinstance(msg, str):
                    message.args[idx] = jsonapi.loads(msg)
            dispatch = self._dispatcher.dispatch
            # _log.debug("External RPC IN message args {}".format(message))

            responses = [response for response in (dispatch(msg, message) for msg in message.args) if response]
            # _log.debug("External RPC Responses {}".format(responses))
            if responses:
                message.user = ""
                try:
                    message.peer = ""
                    message.subsystem = "external_rpc"
                    frames = []
                    operation = "send_platform"
                    frames.append(operation)
                    msg = jsonapi.dumps(
                        dict(
                            to_platform=rpc_msg["from_platform"],
                            to_peer=rpc_msg["from_peer"],
                            from_platform=rpc_msg["to_platform"],
                            from_peer=rpc_msg["to_peer"],
                            args=responses,
                        ))
                    frames.append(msg)
                except KeyError:
                    _log.error("External RPC message did not contain "
                               "proper message format")
                message.args = jsonapi.dumps(ret_msg)
                try:
                    self.core().connection.send_vip(
                        peer="",
                        subsystem="external_rpc",
                        args=frames,
                        msg_id=message.id,
                        user=message.user,
                        copy=False,
                    )
                except OSError as e:
                    # why are we only logging and not throwing the exception
                    # raise VIPError(e.errno, e.strerror, "", "external_rpc")
                    pass
        except KeyError:
            pass

    @spawn
    def _handle_subsystem(self, message):
        dispatch = self._dispatcher.dispatch

        responses = [response for response in (dispatch(msg, message) for msg in message.args) if response]
        if responses:
            message.user = ""
            message.args = responses
            try:
                if self._isconnected:
                    self.core().connection.send_vip_object(message, copy=False)
            except OSError as e:
                # why are we only logging
                pass
                #raise VIPError(e.errno, e.strerror, "", "RPC")

    def _handle_error(self, sender, message, error, **kwargs):
        result = self._outstanding.pop(message.id, None)
        if isinstance(result, AsyncResult):
            result.set_exception(error)
        elif result:
            for result in result:
                result.set_exception(error)

    def get_exports(self):
        """Returns a list copy of all exported methods."""
        return [method for method in self._exports].copy()

    @dualmethod
    def export(self, method, name=None):
        self._exports[name or method.__name__] = method
        return method

    @export.classmethod
    def export(cls, name=None):    # pylint: disable=no-self-argument
        if name is not None and not isinstance(name, str):
            method, name = name, name.__name__
            annotate(method, set, "__rpc__.exports", name)
            return method

        def decorate(method):
            annotate(method, set, "__rpc__.exports", name)
            return method

        return decorate

    def batch(self, peer, requests):
        request, results = self._dispatcher.batch_call(requests)
        if results:
            items = weakref.WeakSet(results)
            ident = "%s.%s" % (next(self._counter), id(items))
            for result in results:
                result._weak_set = items    # pylint: disable=protected-access
            self._outstanding[ident] = items
        else:
            ident = ""
        if request:
            if self._isconnected:
                try:
                    self.core().connection.send_vip(peer, "RPC", [request], msg_id=ident)
                except OSError as e:
                    pass
                    # we were only logging. why?
                    # raise VIPError(e.errno, e.strerror, peer, "RPC")
        return results or None

    def call(self, peer, method, *args, **kwargs):
        if self._protected_rpcs is None and peer not in [AUTH, CONTROL_CONNECTION, CONTROL]:
            # first rpc call
            # TODO: can this be done on onconnect? or on some other event
            self._protected_rpcs = self.get_protected_rpcs()
            self._wrap_protected_rpcs(self._protected_rpcs)
        self_ref = kwargs.pop("self", None)
        platform = kwargs.pop("external_platform", "")
        request, result = self._dispatcher.call(method, args, kwargs)
        ident = f"{next(self._counter)}.{hash(result)}"
        self._outstanding[ident] = result
        subsystem = None
        frames = []

        if not self._isconnected:
            return

        if platform == "":    # local platform
            subsystem = "RPC"
            frames.append(request)
        else:
            frames = []
            operation = "send_platform"
            subsystem = "external_rpc"
            frames.append(operation)
            msg = dict(
                to_platform=platform,
                to_peer=peer,
                from_platform="",
                from_peer="",
                args=[request],
            )
            frames.append(msg)
            peer = ""

        try:
            self.core().connection.send_vip(peer, subsystem, args=frames, msg_id=ident)
        except OSError as e:
            pass
            # we were only logging. why?
            # raise VIPError(e.errno, e.strerror, peer, "RPC")

        return result

    def get_protected_rpcs(self):
        return self.call(AUTH, "get_protected_rpcs", self._owner.core.identity).get(timeout=10)

    __call__ = call

    def notify(self, peer, method, *args, **kwargs):
        platform = kwargs.pop("external_platform", "")
        request = self._dispatcher.notify(method, args, kwargs)
        frames = []
        if not self._isconnected:
            return

        subsystem = None
        if platform == "":
            subsystem = "RPC"
            frames.append(request)
        else:
            operation = "send_platform"
            subsystem = "external_rpc"
            frames.append(operation)
            msg = dict(
                to_platform=platform,
                to_peer=peer,
                from_platform="",
                from_peer="",
                args=[request],
            )
            frames.append(msg)
            peer = ""

        try:
            self.core().connection.send_vip(peer, subsystem, args=frames)
        except OSError as e:
            pass
            # we were only logging. why?
            # raise VIPError(e.errno, e.strerror, peer, "RPC")
