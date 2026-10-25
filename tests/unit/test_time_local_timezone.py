import logging
import warnings
from datetime import datetime, timezone

import pytest

from volttron.utils import time as vtime


def test_naive_timestamp_uses_the_local_zone_when_it_is_known(monkeypatch):
    monkeypatch.setattr(vtime, "get_localzone", lambda: timezone.utc)
    assert vtime.get_utc_seconds_from_epoch(datetime(2026, 1, 1, 0, 0, 0)) == 1767225600.0


def test_unknown_local_zone_falls_back_to_utc_and_warns_once(monkeypatch, caplog):
    def broken():
        raise RuntimeError("Multiple conflicting time zone configurations found")
    monkeypatch.setattr(vtime, "get_localzone", broken)
    monkeypatch.setattr(vtime, "_local_timezone_warned", False)
    with caplog.at_level(logging.WARNING, logger=vtime.__name__):
        first = vtime.get_utc_seconds_from_epoch(datetime(2026, 1, 1, 0, 0, 0))
        second = vtime.get_utc_seconds_from_epoch(datetime(2026, 1, 1, 0, 0, 1))
    assert first == 1767225600.0 and second == 1767225601.0          # read as UTC, no exception
    assert caplog.text.count("Unable to determine the local time zone") == 1


def test_tzlocal_warnings_go_to_the_log_not_the_terminal(monkeypatch, caplog, recwarn):
    def noisy():
        warnings.warn("tzlocal: /etc/timezone is deprecated", UserWarning)
        return timezone.utc
    monkeypatch.setattr(vtime, "get_localzone", noisy)
    monkeypatch.setattr(vtime, "_local_timezone_warned", False)
    with caplog.at_level(logging.WARNING, logger=vtime.__name__):
        assert vtime.get_utc_seconds_from_epoch(datetime(2026, 1, 1)) == 1767225600.0
    assert "tzlocal: /etc/timezone is deprecated" in caplog.text
    assert not [w for w in recwarn if "tzlocal" in str(w.message)]   # swallowed, not re-emitted
