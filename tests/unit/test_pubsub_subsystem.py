import pytest
from unittest.mock import MagicMock
from volttron.client.vip.agent.subsystems.pubsub import PubSub


@pytest.fixture()
def mypubsub():
    core = MagicMock()
    rpc_subsys = MagicMock()
    peerlist_subsys = MagicMock()
    p = PubSub(core, rpc_subsys, peerlist_subsys, MagicMock())
    return p


def test_add_subscription_invalid_callback(mypubsub):
    with pytest.raises(ValueError) as error:
        mypubsub._add_subscription("tags", "heartbeat", "invalid_callback")
    assert str(error.value) == "callback 'invalid_callback' is not callable"


def test_add_tag_subscription_success(mypubsub):
    def callback(peer, sender, bus, topic, headers, message):
        print("Called")

    def new_callback(peer, sender, bus, topic, headers, message):
        print("Called")

    test_condition = {"prefix": mypubsub._my_subscriptions, "tags": mypubsub._my_subscriptions_by_tags}
    for subscription_type, var in test_condition.items():
        expected = set()
        expected.add(callback)
        mypubsub._add_subscription(subscription_type, "heartbeat", callback)
        assert var["internal"][""]["heartbeat"] == expected

        mypubsub._add_subscription(subscription_type, "heartbeat", callback)
        assert var["internal"][""]["heartbeat"] == expected

        expected.add(new_callback)
        mypubsub._add_subscription(subscription_type, "heartbeat", new_callback)
        assert var["internal"][""]["heartbeat"] == expected


def test_drop_subscription_error(mypubsub):
    def callback(peer, sender, bus, topic, headers, message):
        print("Called")

    def new_callback(peer, sender, bus, topic, headers, message):
        print("Called")

    test_condition = {"prefix": mypubsub._my_subscriptions, "tags": mypubsub._my_subscriptions_by_tags}
    for subscription_type, var in test_condition.items():
        var["internal"][""]["heartbeat"] = set()
        var["internal"][""]["heartbeat"].add(new_callback)

        # why is this not consistent. Both below cases should throw exception or both should return empty
        assert [] == mypubsub._drop_subscription(subscription_type, None, None, bus="rmq")
        with pytest.raises(KeyError, match="no such subscription"):
            mypubsub._drop_subscription(subscription_type, None, callback, bus="rmq")


def test_drop_subscription_success(mypubsub):
    def callback(peer, sender, bus, topic, headers, message):
        print("Called")

    def new_callback(peer, sender, bus, topic, headers, message):
        print("Called")

    test_condition = {"prefix": mypubsub._my_subscriptions, "tags": mypubsub._my_subscriptions_by_tags}
    for subscription_type, var in test_condition.items():
        var["internal"][""]["heartbeat"] = set()
        var["internal"][""]["heartbeat"].add(callback)
        var["internal"][""]["heartbeat"].add(new_callback)

        assert ['heartbeat'] == mypubsub._drop_subscription(subscription_type, None, None)

        # assert var["internal"][""] == dict() # why is local variable not cleared. server is always updated.

        assert ['heartbeat'] == mypubsub._drop_subscription(subscription_type, "heartbeat", callback)
        assert var["internal"][""]['heartbeat'] == {new_callback}  # variable cleared when callback is sent


def test_unsubscribe_sends_through_the_cores_current_connection():
    """The core swaps its connection object when it connects (zmq_core builds a new one and opens its socket). Both
    subscribe and unsubscribe must send through the connection the core holds at send time, not one captured when the
    subsystem was built: that one is never opened and its send fails an assertion, so no unsubscribe ever reached the
    router."""
    core = MagicMock()
    stale = core.connection
    p = PubSub(core, MagicMock(), MagicMock(), MagicMock())
    core.connection = MagicMock(name='live connection')         # what zmq_core does on connect

    def callback(peer, sender, bus, topic, headers, message):
        pass
    p._add_subscription("prefix", "devices/x", callback)
    p.unsubscribe("pubsub", "devices/x", callback)
    assert core.connection.send_vip_message.called
    assert not stale.send_vip_message.called
    assert "devices/x" not in p._my_subscriptions.get("internal", {}).get("", {})
