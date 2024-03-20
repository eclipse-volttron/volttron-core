from volttron.platform.auth.authz_manager import (Role, RoleMap, VolttronAuthManager)


def test_can_create_role_for_config_store():
    authm = VolttronAuthManager(role_map=RoleMap())

    resource = {}

    # resource is config_store
    resource["config_store"] = {}
    # action is edit
    resource["config_store"]["edit"] = {}

    resource["config_store"]["edit"]["admin"] = lambda x: x == 5
    resource["config_store"]["edit"]["bob"] = lambda x: x == "bob"

    resource["pubsub"]["publish"]["platform.driver"] = lambda x: x.startswith("devices")
