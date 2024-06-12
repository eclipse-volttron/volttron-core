
import volttron.types.auth.authz_types as authz
import pytest
import json


def test_rpc_capability():
    rpc_cap1 = authz.RPCCapability("id.rpc1")
    rpc_cap2 = authz.RPCCapability("id2.rpc2", {"id": "id2", "param2": "v2"})
    assert rpc_cap1.resource == "id.rpc1"
    assert not rpc_cap1.param_restrictions
    assert rpc_cap2.param_restrictions == {"id": "id2", "param2": "v2"}
    r3 = authz.RPCCapability("id2.rpc2", {"param2": "v2", "id": "id2"})
    assert rpc_cap2 == r3


def test_rpc_capabilities():
    rpc_cap1 = authz.RPCCapability("id.rpc1")
    rpc_cap2 = authz.RPCCapability("id2.rpc2", {"id": "id2", "param2": "v2"})
    rpc_obj_list = authz.RPCCapabilities()
    rpc_obj_list.add_rpc_capability(rpc_cap1)
    rpc_compact_list = authz.authz_converter.unstructure(rpc_obj_list)
    assert rpc_compact_list == ['id.rpc1']

    # test add
    rpc_obj_list.add_rpc_capability(rpc_cap2)
    assert len(rpc_obj_list.rpc_capabilities) == 2
    print(rpc_obj_list)

    # no duplicates
    rpc_cap3 = authz.RPCCapability("id2.rpc2")
    print(rpc_obj_list)
    rpc_cap3.add_param_restrictions("param2", "v2")
    print(rpc_obj_list)
    rpc_cap3.add_param_restrictions("id", "id2")
    print(rpc_obj_list)
    rpc_obj_list.add_rpc_capability(rpc_cap3)
    print(rpc_obj_list)
    assert len(rpc_obj_list.rpc_capabilities) == 2

    rpc_compact_list = authz.authz_converter.unstructure(rpc_obj_list)
    # param restrictions should get merged
    assert rpc_compact_list == ['id.rpc1', {'id2.rpc2': {'id': 'id2',  "param2": "v2"}}]

    # merge params
    rpc_cap4 = authz.RPCCapability("id2.rpc2")
    print(rpc_obj_list)
    rpc_cap4.add_param_restrictions("p2", "v2")
    print(rpc_obj_list)
    rpc_cap4.add_param_restrictions("id", "id2")
    print(rpc_obj_list)
    rpc_obj_list.add_rpc_capability(rpc_cap4)
    print(rpc_obj_list)
    assert len(rpc_obj_list.rpc_capabilities) == 2

    rpc_compact_list = authz.authz_converter.unstructure(rpc_obj_list)
    # param restrictions should get merged
    assert rpc_compact_list == ['id.rpc1', {'id2.rpc2': {'id': 'id2', 'p2': 'v2', "param2": "v2"}}]

    # test remove
    rpc_obj_list.remove_rpc_capability(rpc_cap2)
    assert len(rpc_obj_list.rpc_capabilities) == 1

    rpc_obj_list.remove_rpc_capability(authz.RPCCapability("id4.rpc4"))
    assert len(rpc_obj_list.rpc_capabilities) == 1

def test_expand_user_capabilities():

    with open("input.json") as f:
        input_dict = json.load(f)

    volttron_authz_map = authz.VolttronAuthzMap.from_unstructured_dict(input_dict)
    assert volttron_authz_map.compact_dict == input_dict

    # verify group permissions are applied right
    # user historian1 is part of user_group historian_users
    # Relevant Input json entries
    # "historian_users": {
    #     "identities": [
    #         "historian1"
    #     ],
    #     "rpc_capabilities": [
    #         "agent1.rpc1"
    #     ],
    #     "pubsub_capabilities": {
    #         "historian_stats/*": "publish"
    #     }
    # }
    # "historian1": {
    #     "pubsub_capabilities": {
    #            "user_pubsub_topic": "pubsub"
    #        },
    #     "roles": [
    #         {
    #             "edit_config_store": {
    #                 "id": "historian1"
    #             }
    #         }
    #     ]
    assert (volttron_authz_map.user_capabilities["historian1"]["pubsub_capabilities"] ==
            {'historian_stats/*': 'publish', 'user_pubsub_topic': 'pubsub'})

    # rpc capabilities must have both user groups' capabilities and role's capabilities
    # role 'edit_config_store' in input json is
    # "edit_config_store": {
    #     "rpc_capabilities": [
    #         "config.store.add_config",
    #         "config.store.delete_config",
    #         "config.store.edit_config"
    #     ]
    # }
    # above should have got applied with param restriction

    assert (volttron_authz_map.user_capabilities["historian1"]["rpc_capabilities"] ==
            ["agent1.rpc1",
             {'config.store.add_config': {'id': 'historian1'}},
             {'config.store.delete_config': {'id': 'historian1'}},
             {'config.store.edit_config': {'id': 'historian1'}}
             ]
            )

