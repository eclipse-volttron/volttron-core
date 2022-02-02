from volttron.utils import is_ip_private


def test_is_private_vip_address():
    assert is_ip_private("tcp://127.0.0.1")
    assert is_ip_private("tcp://172.16.2.2")
    assert is_ip_private("tcp://192.168.1.1")
    assert not is_ip_private("tcp://8.8.8.8")
    assert not is_ip_private("tcp://5.4.3.2")
