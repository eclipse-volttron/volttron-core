
import volttron.types.auth.authz_types as authz
import pytest

rpc_cap1 = authz.RPCCapability("id.rpc1")
rpc_cap2 = authz.RPCCapability("id2.rpc2", {"id": "id2", "param2": "v2"})


def test_rpc_capability():
    assert rpc_cap1.resource == "id.rpc1"
    assert rpc_cap1.param_restrictions is None
    assert rpc_cap2.param_restrictions == {"id": "id2", "param2": "v2"}
    r3 = authz.RPCCapability("id2.rpc2", {"param2": "v2", "id": "id2"})
    assert rpc_cap2 == r3


def test_rpc_capabilities():
    global rpc_cap1
    rpc_obj_list = authz.RPCCapabilities()
    rpc_obj_list.add_rpc_capability(rpc_cap1)
    rpc_compact_list = authz.authz_converter.unstructure(rpc_obj_list)
    assert rpc_compact_list == ['id.rpc1']

    # test add
    rpc_obj_list.add_rpc_capability(rpc_cap2)
    assert len(rpc_obj_list.rpc_capabilities) == 2
    print(rpc_obj_list)
    # no duplicate
    rpc_cap3 = authz.RPCCapability("id2.rpc2")
    print(rpc_obj_list)
    rpc_cap3.add_param_restrictions("p2", "v2")
    print(rpc_obj_list)
    rpc_cap3.add_param_restrictions("id", "id2")
    #rpc_cap3.add_param_restrictions("param3", None)
    print(rpc_obj_list)
    rpc_obj_list.add_rpc_capability(rpc_cap3)
    print(rpc_obj_list)
    assert len(rpc_obj_list.rpc_capabilities) == 2

    rpc_compact_list = authz.authz_converter.unstructure(rpc_obj_list)
    assert rpc_compact_list == ['id.rpc1', {'id2.rpc2': {'id': 'id2', 'p2': 'v2'}}]

    # test remove
    rpc_obj_list.remove_rpc_capability(rpc_cap2)
    assert len(rpc_obj_list.rpc_capabilities) == 1

    rpc_obj_list.remove_rpc_capability(authz.RPCCapability("id4.rpc4"))
    assert len(rpc_obj_list.rpc_capabilities) == 1
    
    
