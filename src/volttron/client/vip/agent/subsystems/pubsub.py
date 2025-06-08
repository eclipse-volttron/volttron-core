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
import re
import weakref
from base64 import b64decode, b64encode
from collections import defaultdict
from functools import partial

import gevent
from gevent.queue import Queue

from volttron.client.known_identities import PLATFORM_TAGGING, AUTH
from volttron.client.messaging.health import STATUS_BAD
from volttron.types.auth import AuthException
from volttron.utils import jsonapi
from volttron.utils.scheduling import periodic
from volttron.types.message import Message

from ..decorators import annotate, annotations, dualmethod, spawn
from ..results import ResultsDictionary
from .base import SubsystemBase

__all__ = ["PubSub"]

min_compatible_version = "3.0"
max_compatible_version = ""

_log = logging.getLogger(__name__)


def encode_peer(peer):
    if peer.startswith("\x00"):
        return peer[:1] + b64encode(peer[1:])
    return peer


def decode_peer(peer):
    if peer.startswith("\x00"):
        return peer[:1] + b64decode(peer[1:])
    return peer


class PubSub(SubsystemBase):
    """
    Pubsub subsystem concrete class implementation for ZMQ message bus.
    """

    def __init__(self, core, rpc_subsys, peerlist_subsys, owner, tag_vip_id=PLATFORM_TAGGING, tag_refresh_interval=-1):
        self.__core__ = weakref.ref(core)
        self.__rpc__ = weakref.ref(rpc_subsys)
        self.__peerlist__ = weakref.ref(peerlist_subsys)
        self.__owner__ = owner

        self._create_message_for_router = partial(Message.create_message,
                                                  peer="",
                                                  user=self.__core__().identity,
                                                  subsystem="pubsub")

        def platform_subscriptions():
            return defaultdict(subscriptions)

        def subscriptions():
            return defaultdict(set)

        # d[platform][bus][prefix] = set(callback)
        self._my_subscriptions = defaultdict(platform_subscriptions)

        # d[platform][bus][(topic_source,tag_query_condition)] = set(callback)
        self._my_tag_condition_callbacks = defaultdict(platform_subscriptions)

        # format: # d[platform][bus][prefix] = set(callback)
        # same format as _peer_subscriptions but this is updated periodically by running the
        # tag query condition and update the prefix list
        self._my_subscriptions_by_tags = defaultdict(platform_subscriptions)

        core.register("pubsub", self._handle_subsystem, self._handle_error)
        # self.vip_socket = None
        self._results = ResultsDictionary()
        self._event_queue = Queue()
        self._retry_period = 300.0
        self._processgreenlet = None
        self.tag_refresh_interval = tag_refresh_interval
        self.tag_vip_id = tag_vip_id
        self._connection = core.connection

        def setup(sender, **kwargs):
            # pylint: disable=unused-argument
            self._processgreenlet = gevent.spawn(self._process_loop)
            core.onconnected.connect(self._connected)

            #self.vip_socket = self.core().socket

            def subscribe(member):    # pylint: disable=redefined-outer-name
                for peer, bus, prefix, all_platforms, queue in annotations(member, set, "pubsub.subscriptions"):
                    # XXX: needs updated in light of onconnected signal
                    self._add_subscription("prefix", prefix, member, bus, all_platforms)
                    _log.debug("SYNC ZMQ: all_platforms {}".format(self._my_subscriptions['internal'][bus][prefix]))

                for peer, bus, tag_condition, topic_source, all_platforms, queue in annotations(
                        member, set, "pubsub.subscription_by_tags"):
                    # XXX: needs updated in light of onconnected signal
                    self.subscribe_by_tags(peer='pubsub',
                                           tag_condition=tag_condition,
                                           callback=member,
                                           topic_source=topic_source,
                                           bus=bus,
                                           all_platforms=all_platforms)

            inspect.getmembers(owner, subscribe)

        core.onsetup.connect(setup, self)
        if self.tag_refresh_interval > 0:
            core.schedule(periodic(self.tag_refresh_interval), self.refresh_tag_subscriptions)

    def _connected(self, sender, **kwargs):
        """
        Synchronize local subscriptions with PubSubService upon receiving connected signal.
        param sender: identity of sender
        type sender: str
        param kwargs: optional arguments
        type kwargs: pointer to arguments
        """
        self.synchronize()

    def _process_callback(self, sender, bus, topic, headers, message):
        """Handle incoming subscription pushes from PubSubService. It iterates over all subscriptions to find the
        subscription matching the topic and bus. It then calls the corresponding callback on finding a match.
        param sender: identity of the publisher
        type sender: str
        param bus: bus
        type bus: str
        param topic: publishing topic
        type topic: str
        param headers: header information for the incoming message
        type headers: dict
        param message: actual message
        type message: dict
        """
        peer = "pubsub"

        handled = dict()
        for platform in self._my_subscriptions:
            # _log.debug("SYNC: process callback subscriptions: {}".format(self._my_subscriptions[platform][bus]))
            buses = self._my_subscriptions[platform]
            for bus in buses:
                subscriptions = buses[bus]
                for prefix, callbacks in subscriptions.items():
                    if topic.startswith(prefix):
                        handled[prefix] = callbacks
                        for callback in callbacks:
                            callback(peer, sender, bus, topic, headers, message)
        for platform in self._my_subscriptions_by_tags:
            buses = self._my_subscriptions_by_tags[platform]
            for bus in buses:
                subscriptions = buses[bus]
                for prefix, callbacks in subscriptions.items():
                    if topic.startswith(prefix):
                        for callback in callbacks:
                            # don't call same callback function twice for the same topic
                            handled_callbacks = handled.get(prefix, set())
                            if callback not in handled_callbacks:
                                callback(peer, sender, bus, topic, headers, message)
                                handled[prefix] = callbacks

        if not handled:
            # No callbacks for topic; synchronize with sender
            self.synchronize()

    def get_topics_by_tag(self, condition):
        topics = self.rpc().call(self.tag_vip_id, "get_topics_by_tags", condition=condition).get(timeout=10)
        return topics

    @spawn
    def refresh_tag_subscriptions(self):

        def platform_subscriptions():
            return defaultdict(subscriptions)

        def subscriptions():
            return defaultdict(set)

        # format d[platform][bus][prefix] = set(callbacks)
        subscriptions_by_tag = defaultdict(platform_subscriptions)
        for platform, bus_subscriptions in self._my_tag_condition_callbacks.items():
            for bus, tag_conditions in bus_subscriptions.items():
                for (source, condition), callbacks in tag_conditions.items():
                    for prefix in self.get_topics_by_tag(condition):
                        if source:
                            prefix = source + "/" + prefix
                        subscriptions_by_tag[platform][bus][prefix] = callbacks
        self._my_subscriptions_by_tags = subscriptions_by_tag
        self.synchronize()

    def synchronize(self):
        """Synchronize local subscriptions with the PubSubService."""
        result = next(self._results)

        subscriptions_prefix_and_tag = {
            platform: {
                bus: list(subscriptions.keys())
            }
            for platform, bus_subscriptions in self._my_subscriptions.items()
            for bus, subscriptions in bus_subscriptions.items()
        }

        # extend subscriptions dict to be sent to server with the subscriptions derived from tag based subscriptions
        for platform, bus_subscriptions in self._my_subscriptions_by_tags.items():
            if not subscriptions_prefix_and_tag.get(platform):
                subscriptions_prefix_and_tag[platform] = dict()
            for bus, _subscriptions in bus_subscriptions.items():
                if not subscriptions_prefix_and_tag[platform].get(bus):
                    subscriptions_prefix_and_tag[platform][bus] = list()
                for subscription in _subscriptions.keys():
                    if subscription not in subscriptions_prefix_and_tag[platform][bus]:
                        subscriptions_prefix_and_tag[platform][bus].append(subscription)

        sync_msg = jsonapi.dumpb(dict(subscriptions=subscriptions_prefix_and_tag))
        frames = ["synchronize", "connected", sync_msg]

        message = self._create_message_for_router(msg_id=result.ident, args=frames)
        self.__core__().send_vip_message(message)

    def list(
        self,
        peer,
        prefix="",
        bus="",
        subscribed=True,
        reverse=False,
        all_platforms=False,
    ):
        """Gets list of subscriptions matching the prefix and bus for the specified peer.
        param peer: peer
        type peer: str
        param prefix: prefix of a topic
        type prefix: str
        param bus: bus
        type bus: bus
        param subscribed: subscribed or not
        type subscribed: boolean
        param reverse: reverse
        type reverse:
        :returns: List of subscriptions, i.e, list of tuples of bus, topic and
        flag to indicate if peer is a subscriber or not
        :rtype: list of tuples
        :Return Values:
        List of tuples [(topic, bus, flag to indicate if peer is a subscriber or not)]
        """
        result = next(self._results)
        list_msg = jsonapi.dumpb(
            dict(
                prefix=prefix,
                all_platforms=all_platforms,
                subscribed=subscribed,
                reverse=reverse,
                bus=bus,
            ))

        frames = ["list", list_msg]

        message = self._create_message_for_router(msg_id=result.ident, args=frames)
        self.__core__().send_vip_message(message=message)
        return result

    def _add_subscription(self, subscription_type, prefix, callback, bus="", all_platforms=False):
        # _log.debug(f"Adding subscription prefix: {prefix} allplatforms: {all_platforms}")
        if subscription_type == "prefix":
            subscription_dict = self._my_subscriptions
        elif subscription_type == "tags":
            subscription_dict = self._my_subscriptions_by_tags
        else:
            raise ValueError(f"Invalid subscription type {subscription_type}")

        if not callable(callback):
            raise ValueError("callback %r is not callable" % (callback, ))

        if not all_platforms:
            subscription_dict["internal"][bus][prefix].add(callback)
        else:
            subscription_dict["all"][bus][prefix].add(callback)
            # _log.debug("SYNC: add subscriptions: {}".format(self._my_subscriptions['internal'][bus][prefix]))

    def call_server_subscribe(self, all_platforms, bus, prefix):
        result = next(self._results)
        sub_msg = jsonapi.dumpb(dict(prefix=prefix, bus=bus, all_platforms=all_platforms))
        frames = ["subscribe", sub_msg]
        message = self._create_message_for_router(msg_id=result.ident, args=frames)
        self.__core__().connection.send_vip_message(message=message)
        #
        # self._connection.send_vip_message(message=message)
        return result

    @dualmethod
    @spawn
    def subscribe(self, peer, prefix, callback, bus="", all_platforms=False, **kwargs):
        """Subscribe to topic and register callback.

        Subscribes to topics beginning with prefix. If callback is
        supplied, it should be a function taking four arguments,
        callback(peer, sender, bus, topic, headers, message), where peer
        is the ZMQ identity of the bus owner sender is identity of the
        publishing peer, topic is the full message topic, headers is a
        case-insensitive dictionary (mapping) of message headers, and
        message is a possibly empty list of message parts
        :param peer
        :type peer str
        :param prefix topic prefix
        :type prefix str
        :param callback method to callback
        :type callback method
        :param bus message bus
        :type bus str
        :param all_platforms
        :type all_platforms boolean
        :returns: Subscribe is successful or not
        :rtype: boolean
        :Return Values:
        Success or Failure
        """
        authorized = True
        identity = self.__core__().identity
        if AUTH in self.__peerlist__().list().get():
            authorized = self.__rpc__().call("platform.auth",
                                             "check_pubsub_authorization",
                                             identity=identity,
                                             topic_pattern=prefix,
                                             access="subscribe").get()
        if authorized:
            self._add_subscription("prefix", prefix, callback, bus, all_platforms)
            return self.call_server_subscribe(all_platforms, bus, prefix)
        else:
            self.__owner__.health.set_status(STATUS_BAD, f"{identity} is not authorized to subscribe to {prefix}")
            # no harm in publishing so we don't wait till next heart beat for status update
            self.__owner__.health.publish()
            _log.error(f"{identity} is not authorized to subscribe to protected topic {prefix}")

    @dualmethod
    @spawn
    def subscribe_by_tags(self,
                          peer,
                          tag_condition,
                          callback,
                          bus="",
                          all_platforms=False,
                          topic_source="devices",
                          **kwargs):
        """Subscribe to topic based on given tags and register callback.

        Subscribes to topics that match a given combination of tags. tag_condition is a condition string using which
        tagging service can be queried for topic prefix that match the condition.
        For example - "campusRef=building1 and equip and ahu"
        If callback is supplied, it should be a function taking four arguments,
        callback(peer, sender, bus, topic, headers, message), where peer is the ZMQ identity of the bus owner sender
        is identity of the publishing peer, topic is the full message topic, headers is a case-insensitive dictionary
        (mapping) of message headers, and message is a possibly empty list of message parts
        :param peer
        :type peer
        :param tag_condition query string/condition containing tags that need be matched
        :type tag_condition str
        :param callback method to callback
        :type callback method
        :param bus message bus
        :type bus str
        :param all_platforms
        :type all_platforms boolean
        :param topic_source message bus topic source. Will get added to beginning of each of the topics that matches the
         given tag condition. defaults to "devices"
        :type topic_source str
        :returns: success_list, failure_list
        :rtype: list, list

        :Return Values:
        [List of matched prefix successfully subscribed to], [list of matched prefix we couldn't subscribe to]
        """
        if all_platforms:
            platform = "all"
        else:
            platform = "internal"

        # Query tagging service to topic prefix that match the given tag search condition
        topic_prefixes = self.get_topics_by_tag(tag_condition)
        if not topic_prefixes:
            raise ValueError(f"No topics match given tag condition {tag_condition}")
        success_list = []
        failure_list = []
        for prefix in topic_prefixes:
            if topic_source:
                prefix = topic_source + "/" + prefix
            self._add_subscription("tags", prefix, callback, bus, all_platforms)
            if self.call_server_subscribe(all_platforms, bus, prefix):
                success_list.append(prefix)
            else:
                failure_list.append(prefix)

        if success_list:
            # even if there was one successful subscription save tag_condition for periodic updates
            self._my_tag_condition_callbacks[platform][bus][(topic_source, tag_condition)].add(callback)
        return success_list, failure_list

    @subscribe.classmethod
    def subscribe(cls, peer, prefix, bus="", all_platforms=False, persistent_queue=None):

        def decorate(method):
            annotate(
                method,
                set,
                "pubsub.subscriptions",
                (peer, bus, prefix, all_platforms, persistent_queue),
            )
            return method

        return decorate

    @subscribe_by_tags.classmethod
    def subscribe_by_tags(cls,
                          peer,
                          tag_condition,
                          bus="",
                          all_platforms=False,
                          persistent_queue=None,
                          topic_source="devices"):

        def decorate(method):
            annotate(
                method,
                set,
                "pubsub.subscription_by_tags",
                (peer, bus, tag_condition, topic_source, all_platforms, persistent_queue),
            )
            return method

        return decorate

    def _drop_subscription(self, subscription_type, prefix, callback, bus="", platform="internal"):
        """
        Drop the subscription for the specified prefix, callback and bus.
        param prefix: prefix to be removed
        type prefix: str
        param callback: callback method
        type callback: method
        param bus: bus
        type bus: bus
        return: list of topics/prefixes
        :rtype: list
        :Return Values:
        List of prefixes
        """
        if subscription_type == "prefix":
            subscription_dict = self._my_subscriptions
        elif subscription_type == "tags":
            subscription_dict = self._my_subscriptions_by_tags
        else:
            raise ValueError(f"Invalid subscription type {subscription_type}")

        topics = []
        bus_subscriptions = dict()
        if prefix is None:
            if callback is None:
                if len(subscription_dict) and platform in subscription_dict:
                    bus_subscriptions = subscription_dict[platform]
                    if bus in bus_subscriptions:
                        topics.extend(bus_subscriptions[bus].keys())
                if not len(topics):
                    return []
            else:
                if platform in subscription_dict:
                    bus_subscriptions = subscription_dict[platform]
                if bus in bus_subscriptions:
                    subscriptions = bus_subscriptions[bus]
                    remove = []
                    for topic, callbacks in subscriptions.items():
                        try:
                            callbacks.remove(callback)
                        except KeyError:
                            pass
                        else:
                            topics.append(topic)
                        if not callbacks:
                            remove.append(topic)
                    for topic in remove:
                        del subscriptions[topic]
                    if not subscriptions:
                        del bus_subscriptions[bus]
                    if not bus_subscriptions:
                        del subscription_dict[platform]
            if not topics:
                raise KeyError("no such subscription")
        else:
            _log.debug(f"BEFORE: {subscription_dict}")
            if platform in subscription_dict:
                bus_subscriptions = subscription_dict[platform]
                if bus in bus_subscriptions:
                    _log.debug(f"BUS: {bus}")
                    subscriptions = bus_subscriptions[bus]
                    _log.debug(f"subscriptions: {subscriptions}")
                    if callback is None:
                        try:
                            del subscriptions[prefix]
                        except KeyError:
                            return []
                    else:
                        try:
                            callbacks = subscriptions[prefix]
                            _log.debug(f"callbacks: {callbacks}")
                        except KeyError:
                            return []
                        try:
                            callbacks.remove(callback)
                        except KeyError as e:
                            _log.debug(f"KeyError: {e}")
                            pass
                        if not callbacks:
                            try:
                                del subscriptions[prefix]
                                _log.debug(f"subscriptions: {subscriptions}")
                            except KeyError:
                                return []
                    topics = [prefix]
                    if not subscriptions:
                        del bus_subscriptions[bus]
                    if not bus_subscriptions:
                        del subscription_dict[platform]
        _log.debug(f"AFTER: {subscription_dict}")
        return topics

    def call_server_unsubscribe(self, bus, platform, subscriptions, topics):
        result = next(self._results)
        subscriptions[platform] = dict(prefix=topics, bus=bus)
        unsub_msg = jsonapi.dumpb(subscriptions)
        frames = ["unsubscribe", unsub_msg]

        message = self._create_message_for_router(msg_id=result.ident, args=frames)
        self._connection.send_vip_message(message=message)
        return result

    def unsubscribe(self, peer, prefix, callback, bus="", all_platforms=False, **kwargs):
        """Unsubscribe and remove callback(s).

        Remove all handlers matching the given info - peer, callback and bus, which was used earlier to subscribe as
        well. If all handlers for a topic prefix are removed, the topic is also unsubscribed.
        param peer: peer
        type peer: str
        param prefix: prefix that needs to be unsubscribed
        type prefix: str
        param callback: callback method
        type callback: method
        param bus: bus
        type bus: bus
        return: success or not
        :rtype: boolean
        :Return Values:
        success or not
        """
        subscriptions = dict()

        if not all_platforms:
            platform = "internal"
        else:
            platform = "all"

        topics = self._drop_subscription("prefix", prefix, callback, bus, platform)
        return self.call_server_unsubscribe(bus, platform, subscriptions, topics)

    @spawn
    def unsubscribe_by_tags(self,
                            peer,
                            tag_condition,
                            callback,
                            bus="",
                            all_platforms=False,
                            topic_source="devices",
                            **kwargs):
        """Unsubscribe to topic based on given tags and register callback.

        Subscribes to topics that match a given combination of tags. tag_condition is a condition string using which
        tagging service can be queried for topic prefix that match the condition.
        For example - "campusRef=building1 and equip and ahu"
        If callback is supplied, it should be a function taking four arguments,
        callback(peer, sender, bus, topic, headers, message), where peer is the ZMQ identity of the bus owner sender
        is identity of the publishing peer, topic is the full message topic, headers is a case-insensitive dictionary
        (mapping) of message headers, and message is a possibly empty list of message parts
        :param peer
        :type peer
        :param tag_condition query string/condition containing tags that need be matched
        :type tag_condition str
        :param callback method to callback
        :type callback method
        :param bus message bus
        :type bus str
        :param all_platforms
        :type all_platforms boolean
        :param topic_source message bus topic source. Will get added to beginning of each of the topics that matches the
         given tag condition. defaults to "devices"
        :type topic_source str
        :returns: success_list, failure_list
        :rtype: list, list

        :Return Values:
        [List of matched prefix successfully unsubscribed], [list of matched prefix we couldn't unsubscribe]
        """
        subscriptions = dict()

        if all_platforms:
            platform = "all"
        else:
            platform = "internal"

        if not tag_condition:
            raise KeyError("tag_condition is mandatory")

        # Query tagging service to topic prefix that match the given tag search condition
        topic_prefixes = self.get_topics_by_tag(tag_condition)

        if not topic_prefixes:
            raise KeyError(f"Not topics match given tag condition {tag_condition}")
        success_list = []
        failure_list = []
        for prefix in topic_prefixes:
            if topic_source:
                prefix = topic_source + "/" + prefix
            topics = self._drop_subscription("tags", prefix, callback, bus, platform)
            if self.call_server_unsubscribe(bus, platform, subscriptions, topics):
                success_list.extend(topics)
            else:
                failure_list.extend(topics)

        if not failure_list:
            # remove tag_condition only if there were no failures. if there are failures leave tag condition in place
            # so that user could call unsubscribe again
            remove = []
            for platform, bus_subscriptions in self._my_tag_condition_callbacks.items():
                for bus, tag_subscriptions in bus_subscriptions.items():
                    for t, callbacks in tag_subscriptions.items():
                        if t == (topic_source, tag_condition):
                            if callback:
                                try:
                                    callbacks.remove(callback)
                                except KeyError:
                                    pass
                            # if passed callback is none or if no callbacks left after last callbacks.remove()
                            if not callback or not callbacks:
                                remove.append((platform, bus, (topic_source, tag_condition)))

            for platform, bus, condition in remove:
                subscriptions = self._my_tag_condition_callbacks[platform][bus]
                subscriptions.pop(condition)
        return success_list, failure_list

    def publish(self, peer: str, topic: str, headers=None, message=None, bus="", **kwargs):
        """
        Publish a message to a given topic via a peer.

        Publish headers and message to all subscribers of topic on bus.
        If peer is None, use self. Adds volttron platform version
        compatibility information to header as variables
        min_compatible_version and max_compatible version
        param peer: peer
        type peer: str
        param topic: topic to publish to
        type topic: str
        param headers: header info for the message
        type headers: None or dict
        param message: actual message
        type message: None or any
        param bus: bus
        type bus: str
        return: async result - contains Number of subscribers the message was sent to.
        :rtype: AsyncResult
        """
        if headers is None:
            headers = {}
        headers["min_compatible_version"] = min_compatible_version
        headers["max_compatible_version"] = max_compatible_version

        if peer is None:
            peer = "pubsub"
        authorized = True
        identity = self.__core__().identity
        if AUTH in self.__peerlist__().list().get():
            authorized = self.__rpc__().call("platform.auth",
                                             "check_pubsub_authorization",
                                             identity=identity,
                                             topic_pattern=topic,
                                             access="publish").get()
        result = next(self._results)
        if authorized:
            args = ["publish", topic, dict(bus=bus, headers=headers, message=message)]
            message = self._create_message_for_router(msg_id=result.ident, args=args)
            _log.debug(f"sending pubsub message created for router is: {message}")
            self.__core__().connection.send_vip_message(message=message)
        else:
            self.__owner__.health.set_status(STATUS_BAD, f"{identity} is not authorized to subscribe to {topic}")
            self.__owner__.health.publish()
            _log.error(f"{identity} is not authorized to subscribe to protected topic {topic}")

        return result

    def publish_by_tags(self,
                        peer: str,
                        tag_condition: str,
                        headers=None,
                        message=None,
                        bus="",
                        max_publish_count=1,
                        topic_source="devices",
                        **kwargs):
        """Publish a message to a topic that matches the give tag_condition via a peer. If tag_condition resolves to
        more than one topic then throw an error if publish_multiple is False. Publish to multiple matching topics if
        publish_multiple parameter is True

        Publish headers and message to all subscribers of topic on bus.
        If peer is None, use self. Adds volttron platform version
        compatibility information to header as variables
        min_compatible_version and max_compatible version
        :param peer: peer
        :type peer: str
        :param tag_condition: tag_condition to find topics to publish to
        :type tag_condition: str
        :param headers: header info for the message
        :type headers: None or dict
        :param message: actual message
        :type message: None or any
        :param bus: bus
        :type bus: str
        :param max_publish_count: maximum number of publish that can be done. By default expects the tag_condition
         to match a single topic.
        :type max_publish_count: int
        :param topic_source message bus topic source. Will get added to beginning of each of the topics that matches the
         given tag condition. defaults to "devices"
        :type topic_source str

        """
        if not tag_condition:
            raise KeyError("tag_condition is mandatory")
        number_of_subscribers = 0

        topic_prefixes = []
        # Query tagging service to topic prefix that match the given tag search condition
        topic_prefixes = self.get_topics_by_tag(tag_condition)
        if not topic_prefixes:
            raise ValueError(f"Not topics match given tag condition {tag_condition}")
        count = len(topic_prefixes)
        if count > max_publish_count:
            raise ValueError(f"tag condition {tag_condition} matched {count} topics "
                             f"but max_publish_count is set to {max_publish_count}")
        for topic in topic_prefixes:
            if topic_source:
                topic = topic_source + "/" + topic
            self.publish(peer, topic, headers, message, bus)

    def _handle_subsystem(self, message):
        """Handler for incoming messages
        param message: VIP message from PubSubService
        type message: dict
        """
        _log.debug(f"Putting message in event queue for {self.__core__().identity} {message}")
        self._event_queue.put(message)

    @spawn
    def _process_incoming_message(self, message):
        """Process incoming messages
        param message: VIP message from PubSubService
        type message: dict
        """
        op = message.args[0]

        _log.debug(f"Processing {self.__core__().identity}: op: {op}, message: {message}")
        response = None
        if op == "request_response":
            result = None
            try:
                result = self._results.pop(message.id)
            except KeyError:
                pass
            _log.debug(f"Result is: {result}")
            response = message.args[1]

            if result:
                result.set(response)

        elif op == "publish":
            try:
                topic = message.args[1]
                msg = message.args[2]
            except IndexError:
                return
            try:
                headers = msg["headers"]
                message = msg["message"]
                sender = msg["sender"]
                bus = msg["bus"]
            except KeyError as exc:
                _log.error("Missing keys in pubsub message: {}".format(exc))
            else:
                response = message
                self._process_callback(sender, bus, topic, headers, message)

        elif op == "list_response":
            result = None
            try:
                result = self._results.pop(message.id)
                response = message.args[1]
                if result:
                    result.set(response)
            except KeyError:
                pass
        else:
            _log.error("Unknown operation ({})".format(op))

        if response is not None:
            _log.debug(f"Processed {op} response was {response}")

    def _process_loop(self):
        """Incoming message processing loop"""
        for msg in self._event_queue:
            _log.debug(f"Handling pubsub message: {msg}")
            self._process_incoming_message(msg)

    def _handle_error(self, sender, message, error, **kwargs):
        """Error handler. If UnknownSubsystem error is received, it implies that agent is connected to platform that has
        OLD pubsub implementation. So messages are resent using RPC method.
        :param message: Error message
        :type message: dict
        :param error: indicates error type
        :type error: error class
        :param **kwargs: variable arguments
        :type **kwargs: dict
        """
        try:
            result = self._results.pop(message.id)
        except KeyError:
            return
        result.set_exception(error)
