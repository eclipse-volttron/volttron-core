import pytest

from volttron.client.vip.agent import Agent


def test_subsystems_available():
    agent = Agent(enable_channel=True)
    assert agent.vip.auth
    assert agent.vip.channel
    assert agent.vip.config
    assert agent.vip.health
    assert agent.vip.heartbeat
    assert agent.vip.hello
    assert agent.vip.peerlist
    assert agent.vip.ping
    assert agent.vip.pubsub
    assert agent.vip.rpc

    # TODO: Add tests for enable/disable options.

    # agent = Agent(enable_store=False)

    # with pytest.raises(AttributeError):
    #     agent.vip.channel
    # with pytest.raises(NameError):
    #     getattr(agent.vip, "web")

    # with pytest.raises(AttributeError):
    #     assert not agent.vip.config

    # assert agent.vip.auth
    # assert agent.vip.health
    # assert agent.vip.heartbeat
    # assert agent.vip.hello
    # assert agent.vip.peerlist
    # assert agent.vip.ping
    # assert agent.vip.pubsub
    # assert agent.vip.rpc
