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
    "VolttronHomeFileReloader",
    "AbsolutePathFileReloader",
    "watch_file",
    "watch_file_with_fullpath",
]

import logging
import os

from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

from volttron.utils import ClientContext as cc

_log = logging.getLogger(__name__)


class VolttronHomeFileReloader(PatternMatchingEventHandler):
    """
    Extends PatternMatchingEvent handler to watch changes to a singlefile/file pattern within volttron home.
    filetowatch should be path relative to volttron home.
    For example filetowatch auth.json with watch file <volttron_home>/auth.json.
    filetowatch *.json will watch all json files in <volttron_home>
    """

    def __init__(self, filetowatch, callback):
        super(VolttronHomeFileReloader, self).__init__([f"{cc.get_volttron_home()}/{filetowatch}"])
        _log.debug(f"patterns is {cc.get_volttron_home()}/{filetowatch}")
        self._callback = callback

    def on_any_event(self, event):
        _log.debug("Calling callback on event {}. Calling {}".format(event, self._callback))
        try:
            self._callback()
        except BaseException as e:
            _log.error("Exception in callback: {}".format(e))
        _log.debug("After callback on event {}".format(event))


class AbsolutePathFileReloader(PatternMatchingEventHandler):
    """
    Extends PatternMatchingEvent handler to watch changes to a singlefile/file pattern within volttron home.
    filetowatch should be path relative to volttron home.
    For example filetowatch auth.json with watch file <volttron_home>/auth.json.
    filetowatch *.json will watch all json files in <volttron_home>
    """

    def __init__(self, filetowatch, callback):
        super(AbsolutePathFileReloader, self).__init__([filetowatch])
        self._callback = callback
        self._filetowatch = filetowatch

    @property
    def watchfile(self):
        return self._filetowatch

    def on_any_event(self, event):
        _log.debug("Calling callback on event {}. Calling {}".format(event, self._callback))
        try:
            self._callback(self._filetowatch)
        except BaseException as e:
            _log.error("Exception in callback: {}".format(e))
        _log.debug("After callback on event {}".format(event))


def watch_file(fullpath, callback):
    """Run callback method whenever the file changes

    Not available on OS X/MacOS.
    """

    dirname, filename = os.path.split(fullpath)
    _log.info(
        "Adding file watch for %s dirname=%s, filename=%s",
        fullpath,
        cc.get_volttron_home(),
        filename,
    )
    observer = Observer()
    observer.schedule(
        VolttronHomeFileReloader(filename, callback),
        path=cc.get_volttron_home(),
    )
    observer.start()
    _log.info("Added file watch for %s", fullpath)


def watch_file_with_fullpath(fullpath, callback):
    """Run callback method whenever the file changes

    Not available on OS X/MacOS.
    """
    dirname, filename = os.path.split(fullpath)
    _log.info("Adding file watch for %s", fullpath)
    _observer = Observer()
    _observer.schedule(AbsolutePathFileReloader(fullpath, callback), dirname)
    _log.info("Added file watch for %s", fullpath)
    _observer.start()
