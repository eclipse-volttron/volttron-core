"""get_core_builder caches one builder per name and chooses unnamed lookups by the platform's bus (volttron-core#361).

It used to cache a single builder for the process, so once any builder was cached an explicit name was ignored
(get_core_builder(name="mock") returned the zmq builder, or the reverse), and with two builders registered an
unnamed lookup raised. Separately ClientContext.get_messagebus() read Monolithic's "message-bus" key, so it was
always None on modular.
"""
import pytest

from volttron.client import decorators
from volttron.utils import ClientContext


class ZmqLikeBuilder:
    messagebus = "zmq"


class MockBuilder:
    pass


class ArgsBuilder:
    def __init__(self, flavour="plain"):
        self.flavour = flavour


@pytest.fixture
def registry(monkeypatch):
    """An empty builder registry and cache for the test, restored afterwards."""
    monkeypatch.setattr(decorators.core_builder, "registry", {})
    monkeypatch.setattr(decorators, "__core_builders__", {})
    monkeypatch.setattr(decorators, "__core_builder__", None)
    return decorators.core_builder.registry


def _bus(monkeypatch, value):
    monkeypatch.setattr(ClientContext, "get_messagebus", classmethod(lambda cls: value))


def test_an_explicit_name_returns_that_builder_whatever_is_cached(registry):
    registry.update(ZmqCoreBuilder=ZmqLikeBuilder, mock=MockBuilder)
    zmq = decorators.get_core_builder(name="ZmqCoreBuilder")
    assert isinstance(decorators.get_core_builder(name="mock"), MockBuilder)
    assert decorators.get_core_builder(name="ZmqCoreBuilder") is zmq


def test_one_builder_per_name_until_reset(registry):
    registry.update(args=ArgsBuilder)
    first = decorators.get_core_builder(name="args", flavour="spicy")
    assert first.flavour == "spicy"
    assert decorators.get_core_builder(name="args", flavour="ignored") is first
    decorators.reset_core_builder()
    assert decorators.get_core_builder(name="args") is not first


def test_unnamed_with_one_builder_uses_it(registry, monkeypatch):
    _bus(monkeypatch, None)
    registry.update(mock=MockBuilder)
    builder = decorators.get_core_builder()
    assert isinstance(builder, MockBuilder)
    assert decorators.get_core_builder(name="mock") is builder    # the same instance either way


def test_unnamed_with_several_builders_follows_the_platform_bus(registry, monkeypatch):
    registry.update(ZmqCoreBuilder=ZmqLikeBuilder, mock=MockBuilder)
    _bus(monkeypatch, "zmq")
    assert isinstance(decorators.get_core_builder(), ZmqLikeBuilder)    # by the messagebus attribute
    decorators.reset_core_builder()
    _bus(monkeypatch, "mock")
    assert isinstance(decorators.get_core_builder(), MockBuilder)       # by the registry name


def test_unnamed_lookup_that_cannot_choose_says_why(registry, monkeypatch):
    registry.update(one=MockBuilder, two=ArgsBuilder)
    _bus(monkeypatch, "zmq")
    with pytest.raises(ValueError, match="registered \\['one', 'two'\\].*Pass name="):
        decorators.get_core_builder()


def test_get_messagebus_reads_the_modular_key(monkeypatch):
    config = {"messagebus": "zmq"}
    monkeypatch.setattr(ClientContext, "get_config_param",
                        classmethod(lambda cls, key, default=None: config.get(key, default)))
    assert ClientContext.get_messagebus() == "zmq"
    config.clear()
    config["message-bus"] = "zmq"    # a Monolithic config
    assert ClientContext.get_messagebus() == "zmq"
    config.clear()
    assert ClientContext.get_messagebus() is None
