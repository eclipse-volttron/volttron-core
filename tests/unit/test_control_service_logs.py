import logging
from logging.handlers import RotatingFileHandler
import os
import pytest
from pathlib import Path

from volttron.server.logs import (
    get_available_logs,
    read_log_file,
    _hash_file_identity,
    _hash_log_id,
)


def test_log_file_discovery_and_retention(tmp_path):
    log_dir = tmp_path / "volttron_home"
    log_dir.mkdir()
    log_file = log_dir / "volttron.log"
    log_rotated = log_dir / "volttron.log.1"

    log_file.write_text("line 1\nline 2\n")
    log_rotated.write_text("old line 1\nold line 2\n")

    logger = logging.getLogger()
    handler = RotatingFileHandler(str(log_file), maxBytes=1048576, backupCount=3)
    logger.addHandler(handler)

    try:
        result = get_available_logs(volttron_home=str(log_dir))
        logs = result["logs"]
        retention = result["retention"]

        assert len(logs) == 2
        log_names = {item["name"] for item in logs}
        assert "volttron.log" in log_names
        assert "volttron.log.1" in log_names

        for item in logs:
            assert "id" in item
            assert len(item["id"]) == 16
            assert "file_id" in item
            assert len(item["file_id"]) == 16
            assert "size_bytes" in item
            assert "modified" in item

        assert retention is not None
        assert retention["max_file_bytes"] == 1048576
        assert retention["backup_count"] == 3
        assert retention["max_total_bytes"] == 1048576 * 4
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_read_log_tail_and_offset(tmp_path):
    log_dir = tmp_path / "volttron_home"
    log_dir.mkdir()
    log_file = log_dir / "volttron.log"

    lines = [f"2026-08-31 INFO message {i}" for i in range(50)]
    log_file.write_text("\n".join(lines) + "\n")

    logger = logging.getLogger()
    handler = RotatingFileHandler(str(log_file), maxBytes=1048576, backupCount=3)
    logger.addHandler(handler)

    try:
        discovered = get_available_logs(volttron_home=str(log_dir))
        log_id = discovered["logs"][0]["id"]

        # 1. Tail reading
        tail_res = read_log_file(log_id=log_id, tail=5, volttron_home=str(log_dir))
        assert len(tail_res["lines"]) == 5
        assert tail_res["lines"][-1] == "2026-08-31 INFO message 49"
        assert tail_res["lines"][0] == "2026-08-31 INFO message 45"
        assert tail_res["next_offset"] == log_file.stat().st_size

        # 2. Forward offset reading from beginning
        fwd_res = read_log_file(log_id=log_id, offset=0, max_bytes=200, volttron_home=str(log_dir))
        assert len(fwd_res["lines"]) > 0
        assert fwd_res["lines"][0] == "2026-08-31 INFO message 0"
        assert fwd_res["has_newer"] is True

        # Read next chunk using returned next_offset
        next_chunk = read_log_file(log_id=log_id, offset=fwd_res["next_offset"], max_bytes=200, volttron_home=str(log_dir))
        assert len(next_chunk["lines"]) > 0
        assert next_chunk["lines"][0] == lines[len(fwd_res["lines"])]

        # 3. Reverse pagination with `before`
        file_size = log_file.stat().st_size
        rev_res = read_log_file(log_id=log_id, before=file_size, max_bytes=200, volttron_home=str(log_dir))
        assert len(rev_res["lines"]) > 0
        assert rev_res["lines"][-1] == "2026-08-31 INFO message 49"
        assert rev_res["has_older"] is True
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_read_log_file_not_found(tmp_path):
    log_dir = tmp_path / "volttron_home"
    log_dir.mkdir()

    with pytest.raises(FileNotFoundError):
        read_log_file(log_id="nonexistent_id", volttron_home=str(log_dir))
