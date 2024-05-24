from typing import Set, Any

from attrs import validators, define, field, fields
from cattrs import Converter

vipid_dot_rpc_method = str


@define
class RPCCapability:
    resource = field(type=vipid_dot_rpc_method)
    param_restrictions = field(type=dict, default=None)

    def add_param_restrictions(self, param: str, value: Any):
        if self.param_restrictions is None:
            self.param_restrictions = dict()
        self.param_restrictions[param] = value

@define
class RPCCapabilities:
    rpc_capabilities = field(type=list[RPCCapability], default=[])
    _rpc_resources = field(type=Set[str], init=False, default=set())

    def __attrs_post_init__(self):
        for c in self.rpc_capabilities:
            self._rpc_resources.add(c.resource)

    def add_rpc_capability(self, c: RPCCapability):
        if c.resource not in self._rpc_resources:
            self.rpc_capabilities.append(c)
            self._rpc_resources.add(c.resource)

    def remove_rpc_capability(self, c: RPCCapability):
        if c.resource not in self._rpc_resources:
            self.rpc_capabilities.remove(c)
            self._rpc_resources.remove(c.resource)


def unstructure_rpc_capabilities(instance: RPCCapabilities):
    """
    Convert from:

        RPCCapabilities(
        rpc_capabilities=[RPCCapability(resource='id.rpc1', param_restrictions={}),
                          RPCCapability(resource='id2.rpc2', param_restrictions={'id': 'id2', 'p2': 'v2'})])

    TO:
        ['id.rpc1', {'id2.rpc2': {'id': 'id2', 'p2': 'v2'}}]
        i.e. instead of the default unstructure/asdict behavior - list of {resource:value, param_restrictions:value}
        generate single List with just resource str if param_restrictions is None or dict(resource, param_restriction)

    """
    rpc_capabilities_list = []
    for c in instance.rpc_capabilities:
        if c.param_restrictions:
            rpc_capabilities_list.append({c.resource: c.param_restrictions})
        else:
            rpc_capabilities_list.append(c.resource)
    return rpc_capabilities_list


@define
class PubsubCapability:
    topic_pattern = field(type=str)
    topic_access = field(validator=validators.in_(["publish", "subscribe", "pubsub"]))


@define
class PubsubCapabilities:
    # todo check for duplicates
    pubsub_capabilities = field(type=list[PubsubCapability])

    def add_pubsub_capability(self, c: PubsubCapability):
        self.pubsub_capabilities.append(c)

    def remove_pubsub_capability(self, c: PubsubCapability):
        self.pubsub_capabilities.remove(c)


def unstructure_pubsub_capabilities(instance: PubsubCapabilities):
    """
    Convert from:
        PubsubCapabilities(
        pubsub_capabilities=[PubsubCapability(topic_pattern='device/*', topic_access='pubsub'),
                             PubsubCapability(topic_pattern='*', topic_access='pubsub')])
    TO:
        {'device/*': 'pubsub', '*': 'pubsub'}
        i.e. instead of the default - list of dict with topic_pattern:<value>, topic_access: <value>
             generate single dict with key as topic_pattern and values topic_access
    """
    pubsub_capabilities_dict = dict()
    for c in instance.pubsub_capabilities:
        pubsub_capabilities_dict[c.topic_pattern] = c.topic_access
    return pubsub_capabilities_dict


@define
class Role:
    name = field(type=str)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)

    def add_rpc_capability(self, c: RPCCapability):
        self.rpc_capabilities.add_rpc_capability(c)

    def remove_rpc_capability(self, c: RPCCapability):
        self.rpc_capabilities.remove_rpc_capability(c)

@define
class Roles:
    roles = field(type=list[Role])


def unstructure_roles(instance: Roles):
    """
    Convert from:
        Roles(roles=[
          Role(name='admin',
               rpc_capabilities=RPCCapabilities(rpc_capabilities=[
                                 RPCCapability(resource='id.rpc1', param_restrictions={}),
                                 RPCCapability(resource='id2.rpc2', param_restrictions={'id': 'id2', 'p2': 'v2'})]),
               pubsub_capabilities=None),
          Role(name='new_role',
               rpc_capabilities=None,
               pubsub_capabilities=PubsubCapabilities(pubsub_capabilities=[
                                     PubsubCapability(topic_pattern='device/*', topic_access='pubsub'),
                                     PubsubCapability(topic_pattern='*', topic_access='pubsub')]))
          ])

    TO:
        {'admin': {'rpc_capabilities': ['id.rpc1', {'id2.rpc2': {'id': 'id2', 'p2': 'v2'}}]},
         'new_role': {'pubsub_capabilities': {'device/*': 'pubsub', '*': 'pubsub'}}}

        i.e. instead of list of dict with name:<value>, rpc_capabilities: <list>, pubsub_capabilities: <list>
             generate dict with key as role name and values as rpc and pubsub capabilities and skip none values
    """
    roles_dict = dict()
    for _r in instance.roles:
        roles_dict[_r.name] = dict()
        if _r.rpc_capabilities:
            roles_dict[_r.name]['rpc_capabilities'] = authz_converter.unstructure(_r.rpc_capabilities)
        if _r.pubsub_capabilities:
            roles_dict[_r.name]['pubsub_capabilities'] = authz_converter.unstructure(_r.pubsub_capabilities)
    return roles_dict


role_name = str
Identity = str


@define
class UserGroup:
    name = field(type=str)
    users = field(type=set[Identity])
    roles = field(type=set[role_name], default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)


@define
class UserGroups:
    user_groups = field(type=list[UserGroup])


def unstructure_user_groups(instance: UserGroups):
    """
    Convert
      UserGroups(user_groups=[
        UserGroup(name='admin_users',
                  users=['volttron.ctl', 'config.store'],
                  roles=['admin'],
                  rpc_capabilities=None,
                  pubsub_capabilities=PubsubCapabilities(pubsub_capabilities=[
                    PubsubCapability(topic_pattern='device/*', topic_access='pubsub'),
                    PubsubCapability(topic_pattern='*', topic_access='pubsub')])
                  )
        ])

    TO:
    {'admin_users':
        {'users': ['volttron.ctl', 'config.store'],
         'roles': ['admin'],
         'pubsub_capabilities': {'device/*': 'pubsub', '*': 'pubsub'}
         }
    }
    i.e. instead of list of dict with
                  name:<value>, users:<list>, roles:<list>, rpc_capabilities: <list>, pubsub_capabilities: <list>
    generate dict with key as group name and values as users, roles, rpc, pubsub capabilities and skipping none
    """
    groups_dict = dict()
    for _g in instance.user_groups:
        groups_dict[_g.name] = {'users': _g.users}
        if _g.roles:
            groups_dict[_g.name]['roles'] = authz_converter.unstructure(_g.roles)
        if _g.rpc_capabilities:
            groups_dict[_g.name]['rpc_capabilities'] = authz_converter.unstructure(_g.rpc_capabilities)
        if _g.pubsub_capabilities:
            groups_dict[_g.name]['pubsub_capabilities'] = authz_converter.unstructure(_g.pubsub_capabilities)

    return groups_dict


@define
class ProtectedTopics:
    protected_topics = field(type=list[str], default=None)


@define
class User:
    name = field(type=str)
    protected_rpcs = field(type=set[vipid_dot_rpc_method], default=None)
    roles = field(type=set[role_name], default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)
    comments = field(type=str, default=None)
    domain = field(type=str, default=None)
    address = field(type=str, default=None)


@define
class Users:
    users = field(type=list[User])


def unstructure_users(instance: Users):
    users_dict = dict()
    # make a dict with key as user name and value as dict of all other attributes. In the inner dict, values are
    # converted from attrs objects to primitives based on its own custom unstructure methods
    for _user in instance.users:
        users_dict[_user.name] = dict()
        for attribute in fields(_user.__class__):
            if attribute.name != "name" and _user.__getattribute__(attribute.name):
                users_dict[_user.name][attribute.name] = (
                    authz_converter.unstructure(_user.__getattribute__(attribute.name)))
    return users_dict


@define
class VolttronAuthzMap:
    protected_topics: field(type=ProtectedTopics)
    roles: field(type=Roles)
    # user_groups: field(type=UserGroups, default=None)
    # users: field(type=Users, default=None)


authz_converter = Converter()
authz_converter.register_unstructure_hook(RPCCapabilities, unstructure_rpc_capabilities)
authz_converter.register_unstructure_hook(PubsubCapabilities, unstructure_pubsub_capabilities)
authz_converter.register_unstructure_hook(Roles, unstructure_roles)
authz_converter.register_unstructure_hook(UserGroups, unstructure_user_groups)
authz_converter.register_unstructure_hook(Users, unstructure_users)

###############
# test
###############
if __name__ == "__main__":
    r1 = RPCCapability("id.rpc1")
    r2 = RPCCapability("id2.rpc2", {"id": "id2", "p2": "v2"})
    rpc_list = RPCCapabilities([r1, r2])
    print(rpc_list)
    rpc_dict = authz_converter.unstructure(rpc_list)
    print(rpc_dict)
    pubsub_list = PubsubCapabilities([PubsubCapability(topic_pattern="device/*", topic_access="pubsub"),
                                      PubsubCapability(topic_pattern="*", topic_access="pubsub")])
    print(pubsub_list)
    pubsub_dict = authz_converter.unstructure(pubsub_list)
    print(pubsub_dict)

    r = Role("admin", rpc_list, pubsub_list)
    print(r)
    r_dict = authz_converter.unstructure(r)
    print(r_dict)
    roles = Roles([Role("admin", rpc_list), Role("new_role", pubsub_capabilities=pubsub_list)])
    print(roles)
    roles_dict = authz_converter.unstructure(roles)
    print(roles_dict)

    g = UserGroups([UserGroup("admin_users", ["volttron.ctl", "config.store"], roles=["admin"],
                              pubsub_capabilities=pubsub_list)])
    print(g)
    g_dict = authz_converter.unstructure(g)
    print(g_dict)

    p = ProtectedTopics(["devices/*", "health/*"])
    print(p)
    p_dict = authz_converter.unstructure(p)
    print(p_dict)

    u = Users([User("volttron.ctl", roles=["admin"]), User("hist1", rpc_capabilities=rpc_list)])
    print(u)
    u_dict = authz_converter.unstructure(u)
    print(u_dict)
