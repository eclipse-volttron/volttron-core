import pytest
import json
import volttron.types.auth.authz_types as authz


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
    assert rpc_compact_list == ['id.rpc1', {'id2.rpc2': {'id': 'id2', "param2": "v2"}}]

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


def test_expand_user_capabilities_on_init():
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


def test_create_user_simple():
    authz_map = authz.VolttronAuthzMap()
    # create user with above role
    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test"}


def test_create_role_simple():
    authz_map = authz.VolttronAuthzMap()
    try:
        authz_map.create_or_merge_role(name="new_role")
        assert False
    except ValueError as e:
        assert e.args[0] == ("Role new_role should have non empty capabilities - rpc capabilities, "
                             "pubsub capabilities or both")

    authz_map.create_or_merge_role(name="new_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )
    assert authz_map.compact_dict.get("roles").get("new_role") == {"rpc_capabilities": ["id.rpc1"]}


def test_create_user_groups_simple():
    authz_map = authz.VolttronAuthzMap()
    # create group no user
    try:
        authz_map.create_or_merge_user_group(name="group1", identities=[])
        assert False
    except ValueError as e:
        assert e.args[0] == "Empty user group"

    # group with no capabilities or roles
    try:
        # test for invalid user id once check is done
        authz_map.create_or_merge_user_group(name="group1", identities=["test_agent"])
        assert False
    except ValueError as e:
        assert e.args[0] == ("User group group1 should have non empty capabilities. Please pass non empty values "
                             "for at least one of the three parameters - roles, rpc_capabilities, pubsub_capabilities")

    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    authz_map.create_or_merge_role(name="test_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )

    # todo test invalid role name
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]))
    # compact_dict which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1"]}


def test_update_role():
    authz_map = authz.VolttronAuthzMap()
    authz_map.create_or_merge_role(name="new_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )
    assert authz_map.compact_dict.get("roles").get("new_role") == {"rpc_capabilities": ["id.rpc1"]}

    # create user with above role
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         roles=authz.UserRoles(user_roles=[authz.UserRole(role_name="new_role")])
                                         )
    # add pubsub_cap to existing role
    authz_map.create_or_merge_role(name="new_role",
                                   pubsub_capabilities=authz.PubsubCapabilities(
                                       [authz.PubsubCapability(topic_pattern="test/topic/*", topic_access="pubsub")])
                                   )

    assert authz_map.compact_dict.get("roles").get("new_role") == {"rpc_capabilities": ["id.rpc1"],
                                                                   "pubsub_capabilities": {"test/topic/*": "pubsub"}}

    # update existing role's pubsub cap
    authz_map.create_or_merge_role(name="new_role",
                                   pubsub_capabilities=authz.PubsubCapabilities(
                                       [authz.PubsubCapability(topic_pattern="test/topic/*", topic_access="publish")])
                                   )
    assert authz_map.compact_dict.get("roles").get("new_role") == {"rpc_capabilities": ["id.rpc1"],
                                                                   "pubsub_capabilities": {"test/topic/*": "publish"}}

    # update existing role's rpc cap
    authz_map.create_or_merge_role(name="new_role",
                                   rpc_capabilities=authz.RPCCapabilities(
                                       [authz.RPCCapability(resource="id.rpc1", param_restrictions={"param1": "val1"})])
                                   )
    assert authz_map.compact_dict.get("roles")["new_role"]["rpc_capabilities"] == [{"id.rpc1": {"param1": "val1"}}]
    assert authz_map.compact_dict.get("roles")["new_role"]["pubsub_capabilities"] == {"test/topic/*": "publish"}

    # test if the expanded user_capabilities has been updated based on the new role updates
    assert authz_map.user_capabilities["test_agent"]["rpc_capabilities"] == [{"id.rpc1": {"param1": "val1"}}]
    assert authz_map.user_capabilities["test_agent"]["pubsub_capabilities"] == {"test/topic/*": "publish"}


def test_update_user_groups():
    ################
    # Pre-requisites
    ################
    authz_map = authz.VolttronAuthzMap()

    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    authz_map.create_or_merge_user_authz(identity="test_agent2", comments="Created as part of test")

    authz_map.create_or_merge_role(name="test_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )

    # create user group with users and role
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]))
    # compact_dict which gets persisted shouldn't get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"]}
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1"]}

    ##############
    # test updates
    ##############

    # #1. Update user group add rpc_capabilities
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]),
                                         rpc_capabilities=authz.RPCCapabilities(
                                             [authz.RPCCapability(resource="id2.rpc2")]
                                         ))
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"],
                                                               "rpc_capabilities": ["id2.rpc2"]
                                                               }
    # compact_dict users which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1", "id2.rpc2"]}

    # #2. Update user group add pubsub_capabilities
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]),
                                         rpc_capabilities=authz.RPCCapabilities(
                                             [authz.RPCCapability(resource="id2.rpc2")]
                                         ),
                                         pubsub_capabilities=authz.PubsubCapabilities(
                                             [authz.PubsubCapability(topic_access="publish", topic_pattern="devices/")]
                                         ))
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"],
                                                               "rpc_capabilities": ["id2.rpc2"],
                                                               "pubsub_capabilities": {"devices/": "publish"}
                                                               }
    # compact_dict which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1", "id2.rpc2"],
                                                         "pubsub_capabilities": {"devices/": "publish"}}

    # #3. Update user group current pubsub_capabilities
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]),
                                         rpc_capabilities=authz.RPCCapabilities(
                                             [authz.RPCCapability(resource="id2.rpc2")]
                                         ),
                                         pubsub_capabilities=authz.PubsubCapabilities(
                                             [authz.PubsubCapability(topic_access="subscribe",
                                                                     topic_pattern="devices/")]
                                         ))
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"],
                                                               "rpc_capabilities": ["id2.rpc2"],
                                                               "pubsub_capabilities": {"devices/": "subscribe"}
                                                               }
    # compact_dict which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1", "id2.rpc2"],
                                                         "pubsub_capabilities": {"devices/": "subscribe"}}

    # #4. Update user group current rpc_capabilities
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]),
                                         rpc_capabilities=authz.RPCCapabilities(
                                             [authz.RPCCapability(resource="id2.rpc2", param_restrictions={"p1": "v1"})]
                                         ))
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"],
                                                               "rpc_capabilities": [{"id2.rpc2": {"p1": "v1"}}],
                                                               "pubsub_capabilities": {"devices/": "subscribe"}
                                                               }
    # compact_dict users which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1",
                                                                              {"id2.rpc2": {"p1": "v1"}}],
                                                         "pubsub_capabilities": {"devices/": "subscribe"}
                                                         }

    # #5. Update user group current roles
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role",
                                                                               param_restrictions={"p1": "v1"})]),
                                         rpc_capabilities=authz.RPCCapabilities(
                                             [authz.RPCCapability(resource="id2.rpc2", param_restrictions={"p1": "v1"})]
                                         ))
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": [{"test_role": {"p1": "v1"}}],
                                                               "rpc_capabilities": [{"id2.rpc2": {"p1": "v1"}}],
                                                               "pubsub_capabilities": {"devices/": "subscribe"}
                                                               }
    # compact_dict users which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": [{"test_role": {"p1": "v1"}}],
                                                         "rpc_capabilities": [{"id.rpc1": {"p1": "v1"}},
                                                                              {"id2.rpc2": {"p1": "v1"}}],
                                                         "pubsub_capabilities": {"devices/": "subscribe"}
                                                         }

    # #6. Update user group current identities
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent", "test_agent2"])
    # compact_dict user_groups should get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent2", "test_agent"],
                                                               "roles": [{"test_role": {"p1": "v1"}}],
                                                               "rpc_capabilities": [{"id2.rpc2": {"p1": "v1"}}],
                                                               "pubsub_capabilities": {"devices/": "subscribe"}
                                                               }
    # compact_dict users which gets persisted shouldn't get updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    assert authz_map.compact_dict["users"]["test_agent2"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": [{"test_role": {"p1": "v1"}}],
                                                         "rpc_capabilities": [{"id.rpc1": {"p1": "v1"}},
                                                                              {"id2.rpc2": {"p1": "v1"}}],
                                                         "pubsub_capabilities": {"devices/": "subscribe"}
                                                         }

    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent2"] == {"comments": "Created as part of test",
                                                          "roles": [{"test_role": {"p1": "v1"}}],
                                                          "rpc_capabilities": [{"id2.rpc2": {"p1": "v1"}},
                                                                               {"id.rpc1": {"p1": "v1"}}],
                                                          "pubsub_capabilities": {"devices/": "subscribe"}
                                                          }


def test_update_user():
    ################
    # Pre-requisites
    ################
    authz_map = authz.VolttronAuthzMap()

    # #1. create user
    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    # #2. create role
    authz_map.create_or_merge_role(name="test_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )
    authz_map.create_or_merge_role(name="test_role2",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id3.rpc3")])
                                   )

    # #3. create user group with users and role
    authz_map.create_or_merge_user_group(name="group2", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]))

    # compact_dict which gets persisted shouldn't get updated
    assert authz_map.compact_dict["user_groups"]["group2"] == {"identities": ["test_agent"],
                                                               "roles": ["test_role"]}
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}
    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1"]}

    # Test updates to user test_agent

    # #1. add new role to user
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role2")]))

    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test",
                                                             "roles": ["test_role2"]}

    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role2", "test_role"],
                                                         "rpc_capabilities": ["id3.rpc3", "id.rpc1"]}

    # #2. add new rpc_capability to user
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         rpc_capabilities=authz.RPCCapabilities([
                                             authz.RPCCapability(resource="agent2.rpc2",
                                                                 param_restrictions={'param1': 'value2'})]))

    # persisted dict should be updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test",
                                                             "roles": ["test_role2"],
                                                             "rpc_capabilities": [
                                                                 {"agent2.rpc2": {'param1': 'value2'}}]}

    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role2", "test_role"],
                                                         "rpc_capabilities": [
                                                             {"agent2.rpc2": {'param1': 'value2'}},
                                                             "id3.rpc3",
                                                             "id.rpc1"]
                                                         }

    # #3. add new pubsub_capability to user
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         pubsub_capabilities=authz.PubsubCapabilities([
                                             authz.PubsubCapability(topic_pattern="mytopic/*",
                                                                    topic_access="subscribe")
                                         ])
                                         )

    # persisted dict should be updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test",
                                                             "roles": ["test_role2"],
                                                             "rpc_capabilities": [
                                                                 {"agent2.rpc2": {'param1': 'value2'}}],
                                                             "pubsub_capabilities": {"mytopic/*": "subscribe"}
                                                             }

    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role2", "test_role"],
                                                         "rpc_capabilities": [
                                                             {"agent2.rpc2": {'param1': 'value2'}},
                                                             "id3.rpc3",
                                                             "id.rpc1"],
                                                         "pubsub_capabilities": {"mytopic/*": "subscribe"}
                                                         }

    # #4. add new protected_rpcs to user
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         protected_rpcs={"method_1", "method_3"},
                                         pubsub_capabilities=authz.PubsubCapabilities([
                                             authz.PubsubCapability(topic_pattern="mytopic/*",
                                                                    topic_access="subscribe")
                                         ])
                                         )

    # persisted dict should be updated
    assert set(authz_map.compact_dict["users"]["test_agent"]["protected_rpcs"]) == {"method_1", "method_3"}

    # user_capabilities used in memory should be updated
    assert set(authz_map.user_capabilities["test_agent"]["protected_rpcs"]) == {"method_1", "method_3"}

    # #5. update protected_topics, comments
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         protected_rpcs={"method_4"},
                                         comments="new comments"
                                         )

    # persisted dict should be updated
    assert set(authz_map.compact_dict["users"]["test_agent"]["protected_rpcs"]) == {"method_1", "method_3", "method_4"}

    # user_capabilities used in memory should be updated
    assert set(authz_map.user_capabilities["test_agent"]["protected_rpcs"]) == {"method_1", "method_3", "method_4"}

    # assert str values
    assert (authz_map.compact_dict["users"]["test_agent"]["comments"] ==
            authz_map.user_capabilities["test_agent"]["comments"] == "new comments")

    # #6. update existing rpc_capability
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         rpc_capabilities=authz.RPCCapabilities([
                                             authz.RPCCapability(resource="agent2.rpc2")]))

    # persisted dict should be updated
    rpcs = authz_map.compact_dict["users"]["test_agent"].pop("protected_rpcs")
    assert set(rpcs) == {"method_1", "method_3", "method_4"}
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "new comments",
                                                             "roles": ["test_role2"],
                                                             "rpc_capabilities": ["agent2.rpc2"],
                                                             "pubsub_capabilities": {"mytopic/*": "subscribe"}}

    # user_capabilities used in memory should be updated
    rpcs = authz_map.user_capabilities["test_agent"].pop("protected_rpcs")
    assert set(rpcs) == {"method_1", "method_3", "method_4"}
    assert authz_map.user_capabilities["test_agent"] == {"comments": "new comments",
                                                         "roles": ["test_role2", "test_role"],
                                                         "rpc_capabilities": [
                                                             "agent2.rpc2",
                                                             "id3.rpc3",
                                                             "id.rpc1"],
                                                         "pubsub_capabilities": {"mytopic/*": "subscribe"}
                                                         }

    # #7. update users existing pubsub_capability
    authz_map.create_or_merge_user_authz(identity="test_agent",
                                         pubsub_capabilities=authz.PubsubCapabilities([
                                             authz.PubsubCapability(topic_pattern="mytopic/*",
                                                                    topic_access="pubsub")
                                         ])
                                         )

    # persisted dict should be updated
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "new comments",
                                                             "roles": ["test_role2"],
                                                             "rpc_capabilities": ["agent2.rpc2"],
                                                             "pubsub_capabilities": {"mytopic/*": "pubsub"}
                                                             }

    # user_capabilities used in memory should be updated
    assert authz_map.user_capabilities["test_agent"] == {"comments": "new comments",
                                                         "roles": ["test_role2", "test_role"],
                                                         "rpc_capabilities": [
                                                             "agent2.rpc2",
                                                             "id3.rpc3",
                                                             "id.rpc1"],
                                                         "pubsub_capabilities": {"mytopic/*": "pubsub"}
                                                         }


def test_add_users_to_group():
    ################
    # Pre-requisites
    ################
    authz_map = authz.VolttronAuthzMap()

    # #1. create users
    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    authz_map.create_or_merge_user_authz(identity="test_agent2", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    # #2. create role
    authz_map.create_or_merge_role(name="test_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )

    # #3. create user group with users and role
    authz_map.create_or_merge_user_group(name="group1", identities=["test_agent"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]))

    # ####Now test
    authz_map.add_users_to_group("group1", {"test_agent2", })

    assert set(authz_map.compact_dict["user_groups"]["group1"]["identities"]) == {"test_agent2", "test_agent"}
    assert authz_map.compact_dict["user_groups"]["group1"]["roles"] == ["test_role"]

    assert authz_map.user_capabilities["test_agent2"] == {"comments": "Created as part of test",
                                                          "roles": ["test_role"],
                                                          "rpc_capabilities": ["id.rpc1"]
                                                          }


def test_remove_users_from_group():
    ################
    # Pre-requisites
    ################
    authz_map = authz.VolttronAuthzMap()

    # #1. create users
    authz_map.create_or_merge_user_authz(identity="test_agent", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    authz_map.create_or_merge_user_authz(identity="test_agent2", comments="Created as part of test")
    assert authz_map.compact_dict["users"]["test_agent"] == {"comments": "Created as part of test"}

    # #2. create role
    authz_map.create_or_merge_role(name="test_role",
                                   rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability("id.rpc1")])
                                   )

    # #3. create user group with users and role
    authz_map.create_or_merge_user_group(name="group1", identities=["test_agent", "test_agent2"],
                                         roles=authz.UserRoles([authz.UserRole(role_name="test_role")]))

    assert set(authz_map.compact_dict["user_groups"]["group1"]["identities"]) == {"test_agent2", "test_agent"}
    assert authz_map.compact_dict["user_groups"]["group1"]["roles"] == ["test_role"]

    assert (authz_map.user_capabilities["test_agent2"] == authz_map.user_capabilities["test_agent"] ==
            {"comments": "Created as part of test",
             "roles": ["test_role"],
             "rpc_capabilities": ["id.rpc1"]
             })

    # ####Now test
    authz_map.remove_users_from_group("group1", {"test_agent2", })

    assert set(authz_map.compact_dict["user_groups"]["group1"]["identities"]) == {"test_agent", }
    assert authz_map.compact_dict["user_groups"]["group1"]["roles"] == ["test_role"]

    assert authz_map.user_capabilities["test_agent2"] == {"comments": "Created as part of test"}

    assert authz_map.user_capabilities["test_agent"] == {"comments": "Created as part of test",
                                                         "roles": ["test_role"],
                                                         "rpc_capabilities": ["id.rpc1"]
                                                         }
