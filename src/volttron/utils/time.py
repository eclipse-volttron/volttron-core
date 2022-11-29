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
    "format_timestamp",
    "parse_timestamp_string",
    "get_aware_utc_now",
    "get_utc_seconds_from_epoch",
    "process_timestamp",
    "fix_sqlite3_datetime",
]

import calendar
from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzutc, tzoffset
import logging
import pytz
from tzlocal import get_localzone

_log = logging.getLogger(__name__)


def format_timestamp(time_stamp):
    """Create a consistent datetime string representation based on
    ISO 8601 format.

    YYYY-MM-DDTHH:MM:SS.mmmmmm for unaware datetime objects.
    YYYY-MM-DDTHH:MM:SS.mmmmmm+HH:MM for aware datetime objects

    :param time_stamp: value to convert
    :type time_stamp: datetime
    :returns: datetime in string format
    :rtype: str
    """

    time_str = time_stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")

    if time_stamp.tzinfo is not None:
        sign = "+"
        td = time_stamp.tzinfo.utcoffset(time_stamp)
        if td.days < 0:
            sign = "-"
            td = -td

        seconds = td.seconds
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        time_str += "{sign}{HH:02}:{MM:02}".format(sign=sign, HH=hours, MM=minutes)

    return time_str


def parse_timestamp_string(time_stamp_str):
    """
    Create a datetime object from the supplied date/time string.
    Uses dateutil.parse with no extra parameters.

    For performance reasons we try
    YYYY-MM-DDTHH:MM:SS.mmmmmm
    or
    YYYY-MM-DDTHH:MM:SS.mmmmmm+HH:MM
    based on the string length before falling back to dateutil.parse.

    @param time_stamp_str:
    @return: value to convert
    """

    if len(time_stamp_str) == 26:
        try:
            return datetime.strptime(time_stamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass

    elif len(time_stamp_str) == 32:
        try:
            base_time_stamp_str = time_stamp_str[:26]
            time_zone_str = time_stamp_str[26:]
            time_stamp = datetime.strptime(base_time_stamp_str, "%Y-%m-%dT%H:%M:%S.%f")
            # Handle most common case.
            if time_zone_str == "+00:00":
                return time_stamp.replace(tzinfo=pytz.UTC)

            hours_offset = int(time_zone_str[1:3])
            minutes_offset = int(time_zone_str[4:6])

            seconds_offset = hours_offset * 3600 + minutes_offset * 60
            if time_zone_str[0] == "-":
                seconds_offset = -seconds_offset

            return time_stamp.replace(tzinfo=tzoffset("", seconds_offset))

        except ValueError:
            pass

    return parse(time_stamp_str)


def get_aware_utc_now():
    """Create a timezone aware UTC datetime object from the system time.

    :returns: an aware UTC datetime object
    :rtype: datetime
    """
    utcnow = datetime.utcnow()
    utcnow = pytz.UTC.localize(utcnow)
    return utcnow


def get_utc_seconds_from_epoch(timestamp=None):
    """
    convert a given time stamp to seconds from epoch based on utc time. If
    given time is naive datetime it is considered be local to where this
    code is running.
    @param timestamp: datetime object
    @return: seconds from epoch
    """

    if timestamp is None:
        timestamp = datetime.now(tz=tzutc())

    if timestamp.tzinfo is None:
        local_tz = get_localzone()

        # Note:
        # We replace the time zone here which allows us to get the timezone and set it to the
        # current local timezone.  This may have an issue when we are in the daylight savings time
        # era.  See using fold on the timestamp for fixing this.
        #
        # https://pytz-deprecation-shim.readthedocs.io/en/latest/migration.html#acquiring-a-tzinfo-object
        #
        # TODO: Handle timestamp without using localize for migration.
        timestamp = timestamp.replace(tzinfo=local_tz)

    # utctimetuple can be called on aware timestamps and it will
    # convert to UTC first.
    seconds_from_epoch = calendar.timegm(timestamp.utctimetuple())
    # timetuple loses microsecond accuracy so we have to put it back.
    seconds_from_epoch += timestamp.microsecond / 1000000.0
    return seconds_from_epoch


def process_timestamp(timestamp_string, topic=""):
    """
    Convert timestamp string timezone aware utc timestamp
    @param timestamp_string: datetime string to parse
    @param topic: topic to which parse errors are published
    @return: UTC datetime object and the original timezone of input datetime
    """
    if timestamp_string is None:
        _log.error("message for {topic} missing timetamp".format(topic=topic))
        return

    try:
        timestamp = parse_timestamp_string(timestamp_string)
    except (ValueError, TypeError):
        _log.error("message for {topic} bad timetamp string: {ts_string}".format(
            topic=topic, ts_string=timestamp_string))
        return

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=pytz.UTC)
        original_tz = None
    else:
        original_tz = timestamp.tzinfo
        timestamp = timestamp.astimezone(pytz.UTC)
    return timestamp, original_tz


def fix_sqlite3_datetime(sql=None):
    """Primarily for fixing the base historian cache on certain versions
    of python.

    Registers a new datetime converter to that uses dateutil parse. This
    should
    better resolve #216, #174, and #91 without the goofy workarounds that
    change data.

    Optional sql argument is for testing only.
    """
    if sql is None:
        import sqlite3 as sql

    def parse(time_stamp_bytes):
        return parse_timestamp_string(time_stamp_bytes.decode("utf-8"))

    sql.register_adapter(datetime, format_timestamp)
    sql.register_converter("timestamp", parse)
