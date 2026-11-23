"""vctl subscribe's output: the text banner by default, one JSON object per message with --json (#390)."""
import json

import pytest

from volttron.client.commands import subscribe_parser
from volttron.client.commands.control import build_parser, parse_args


@pytest.fixture
def parser(tmp_path, monkeypatch):
    monkeypatch.setenv("VOLTTRON_HOME", str(tmp_path))
    return build_parser(str(tmp_path))


@pytest.mark.parametrize("args, expected", [
    (["subscribe", "devices"], False),
    (["subscribe", "devices", "--json"], True),
    (["--json", "subscribe", "devices"], True),
])
def test_json_before_or_after_the_command(parser, args, expected):
    opts = parse_args(parser, args)
    assert opts.func is subscribe_parser.subscribe_to_bus and opts.topic == "devices" and opts.json is expected


def test_json_prints_one_object_per_line(capsys):
    printer = subscribe_parser.message_printer(as_json=True)
    printer("pubsub", "some.agent", "", "devices/a/all", {"Date": "now"}, [{"SetPoint": 72.5}, {}])
    printer("pubsub", "some.agent", "", "devices/a/b", None, "72.5")
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line) for line in lines] == [
        {"peer": "pubsub", "sender": "some.agent", "bus": "", "topic": "devices/a/all", "headers": {"Date": "now"},
         "message": [{"SetPoint": 72.5}, {}]},
        {"peer": "pubsub", "sender": "some.agent", "bus": "", "topic": "devices/a/b", "headers": None,
         "message": "72.5"},                                  # a string stays a string
    ]


def test_text_output_is_unchanged(capsys):
    subscribe_parser.message_printer(as_json=False)("pubsub", "s", "", "t", {}, 1)
    out = capsys.readouterr().out
    assert "Received:" in out and "\tmessage=1" in out
