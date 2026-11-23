"""vctl rpc call: converting command-line values for an RPC method (volttron-core#386)."""
import json
from types import SimpleNamespace
from typing import Any, Sequence, Set

import pytest

from volttron.client.commands.control import build_parser, parse_args
from volttron.client.commands.rpc_parser import annotation_kind, call_agent_rpc, convert_args
from volttron.client.vip.agent.subsystems.rpc import Dispatcher


def driver_like_set(value: Any, topic: str | Sequence[str] | Set[str] = None, regex: str = None,
                    confirm: bool = False, **kwargs):
    """Shaped like the Platform Driver's set."""


def typed(count: int, ratio: float, enabled: bool, name: str, items: list[str], options: dict, untyped, *rest):
    """Every conversion case."""


def params_of(func):
    """The params payload an agent's '<method>.inspect' returns, from core's own inspection."""
    return Dispatcher._inspect(func)["params"]


@pytest.mark.parametrize("annotation, kind", [
    ("str", "str"), ("int", "int"), ("float", "float"), ("bool", "bool"),
    ("list", "json"), ("list[str]", "json"), ("typing.List[int]", "json"), ("dict", "json"),
    ("Sequence[str]", "json"), ("str | Sequence[str] | Set[str]", None), ("Any", None),
    ("Optional[int]", None), ("typing.Union[int, str]", None), (None, None), ("", None),
])
def test_annotation_kind(annotation, kind):
    assert annotation_kind(annotation) == kind


def test_simple_annotations_convert_strictly():
    args, kwargs = convert_args(params_of(typed), ["3", "0.5", "true", "5", '["a"]', '{"k": 1}', "7", "x", "[1]"], {})
    assert args == [3, 0.5, True, "5", ["a"], {"k": 1}, 7, "x", [1]]


def test_bad_values_name_the_parameter():
    with pytest.raises(ValueError, match="count: expected an integer"):
        convert_args(params_of(typed), ["three"], {})
    with pytest.raises(ValueError, match="enabled: expected true or false"):
        convert_args(params_of(typed), ["1", "1", "maybe"], {})
    with pytest.raises(ValueError, match="items: expected JSON"):
        convert_args(params_of(typed), ["1", "1", "1", "n", "a,b"], {})


def test_unions_and_any_read_json_or_keep_the_string():
    params = params_of(driver_like_set)
    args, kwargs = convert_args(params, ["72.5", "campus/b/rtu/SetPoint"], {"confirm": "true", "extra": "[1, 2]"})
    assert args == [72.5, "campus/b/rtu/SetPoint"]
    assert kwargs == {"confirm": True, "extra": [1, 2]}
    args, _ = convert_args(params, ['"72.5"', '["a/b", "c/d"]'], {})
    assert args == ["72.5", ["a/b", "c/d"]]


def test_nan_and_infinity_stay_strings():
    assert convert_args({}, ["NaN", "Infinity"], {})[0] == ["NaN", "Infinity"]


def test_raw_sends_strings_and_no_inspection_falls_back_to_json_or_string():
    assert convert_args(params_of(typed), ["3"], {}, raw=True) == (["3"], {})
    assert convert_args({}, ["3", "x", "true"], {"k": "null"}) == ([3, "x", True], {"k": None})


def test_parser_accepts_the_command(tmp_path, monkeypatch):
    monkeypatch.setenv("VOLTTRON_HOME", str(tmp_path))
    opts = parse_args(build_parser(str(tmp_path)),
                      ["rpc", "call", "platform.driver", "set", "72.5", "a/b/c", "--kw", "confirm=true"])
    assert (opts.identity, opts.method, opts.args, opts.kw) == ("platform.driver", "set", ["72.5", "a/b/c"],
                                                                ["confirm=true"])
    assert opts.func is call_agent_rpc and opts.timeout == 120.0


class _Pending:
    def __init__(self, value):
        self.value = value

    def get(self, timeout=None):
        return self.value


def _opts(connection, **kw):
    base = dict(identity="agent", method="m", args=[], kw=None, json_args=None, json_kwargs=None, raw=False,
                timeout=5.0, json=True, connection=connection)
    base.update(kw)
    return SimpleNamespace(**base)


def _connection(params, result="done"):
    calls = []

    def call(identity, method, *args, **kwargs):
        calls.append((identity, method, args, kwargs))
        if method.endswith(".inspect"):
            return _Pending({"params": params})
        return _Pending(result)
    return _conn(call), calls


def _conn(call, peers=("agent",)):
    """A connection whose peerlist holds ``peers`` and whose RPC calls go to ``call``."""
    return SimpleNamespace(call=lambda name: list(peers),
                           server=SimpleNamespace(vip=SimpleNamespace(rpc=SimpleNamespace(call=call))))


def test_call_converts_with_the_inspection_and_prints_json(capsys):
    connection, calls = _connection(params_of(typed), result={"ok": [1]})
    assert call_agent_rpc(_opts(connection, args=["3", "0.5"], kw=["name=5"])) == 0
    assert calls[0][1] == "m.inspect"
    assert calls[1] == ("agent", "m", (3, 0.5), {"name": "5"})
    assert json.loads(capsys.readouterr().out) == {"ok": [1]}


def test_json_args_are_sent_as_given_without_inspection():
    connection, calls = _connection(params_of(typed))
    assert call_agent_rpc(_opts(connection, json_args='["3", 4]', json_kwargs='{"k": [1]}')) == 0
    assert [c[1] for c in calls] == ["m"] and calls[0][2:] == (("3", 4), {"k": [1]})


def test_json_args_cannot_be_mixed_with_values(capsys):
    connection, calls = _connection({})
    assert call_agent_rpc(_opts(connection, args=["1"], json_args="[2]")) == 2
    assert calls == [] and "cannot be combined" in capsys.readouterr().err


def test_bad_value_is_a_usage_error_before_any_call(capsys):
    connection, calls = _connection(params_of(typed))
    assert call_agent_rpc(_opts(connection, args=["three"])) == 2
    assert [c[1] for c in calls] == ["m.inspect"]
    assert "count: expected an integer" in capsys.readouterr().err


def test_failed_inspection_still_calls():
    calls = []

    def call(identity, method, *args, **kwargs):
        calls.append(method)
        if method.endswith(".inspect"):
            raise RuntimeError("no inspection")
        return _Pending("ok")
    connection = _conn(call)
    assert call_agent_rpc(_opts(connection, args=["3"], json=False)) == 0
    assert calls == ["m.inspect", "m"]


@pytest.mark.parametrize("args", [["--json", "rpc", "call", "a", "m"], ["rpc", "call", "a", "m", "--json"]])
def test_json_before_or_after_the_command(tmp_path, monkeypatch, args):
    monkeypatch.setenv("VOLTTRON_HOME", str(tmp_path))
    assert parse_args(build_parser(str(tmp_path)), args).json is True


def test_unknown_method_and_unreachable_agent_are_short_errors(capsys):
    from volttron.client.vip.agent.errors import Unreachable
    from volttron.utils.jsonrpc import MethodNotFound

    cases = ((MethodNotFound(-32601, "method not found"), "has no RPC method 'm'"),
             (Unreachable(113, "unreachable", "agent", ""), "is not connected"))
    for error, text in cases:
        def call(identity, method, *args, error=error, **kwargs):
            if method.endswith(".inspect"):
                return _Pending({"params": {}})
            raise error
        assert call_agent_rpc(_opts(_conn(call))) == 1
        assert text in capsys.readouterr().err


def test_an_identity_not_in_the_peerlist_fails_without_calling(capsys):
    calls = []
    connection = _conn(lambda *a, **k: calls.append(a), peers=("platform.control",))
    assert call_agent_rpc(_opts(connection, identity="no.such.agent")) == 1
    assert calls == [] and "is not connected" in capsys.readouterr().err


def test_an_inspection_timeout_still_calls():
    import gevent
    calls = []

    def call(identity, method, *args, **kwargs):
        calls.append(method)
        if method.endswith(".inspect"):
            raise gevent.Timeout()
        return _Pending("ok")
    assert call_agent_rpc(_opts(_conn(call), args=["3"], json=False)) == 0
    assert calls == ["m.inspect", "m"]
