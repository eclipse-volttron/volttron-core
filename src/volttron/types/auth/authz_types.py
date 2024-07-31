import copy
import logging
from typing import Any, TYPE_CHECKING

from attrs import validators, define, field, fields
from cattrs import Converter

from volttron.types import Identity

vipid_dot_rpc_method = str
RPC_CAPABILITIES = "rpc_capabilities"
PUBSUB_CAPABILITIES = "pubsub_capabilities"
ROLES = "roles"
USERS = "users"
USER_GROUPS = "user_groups"
IDENTITIES = "identities"
authz_converter = Converter()
_log = logging.getLogger(__name__)


@define
class RPCCapability:
    resource = field(type=vipid_dot_rpc_method)
    param_restrictions = field(type=dict, default=None)

    def __attrs_post_init__(self):
        if self.param_restrictions is None:
            self.param_restrictions = dict()

    def add_param_restrictions(self, param: str, value: Any):
        self.param_restrictions[param] = value


@define
class RPCCapabilities:
    rpc_capabilities = field(type=list[RPCCapability], default=None)
    _rpc_dict = field(type=dict, default=None, init=False)

    def __attrs_post_init__(self):
        if self.rpc_capabilities is None:
            self.rpc_capabilities = []
        self._rpc_dict = dict()
        for r in self.rpc_capabilities:
            self._rpc_dict[r.resource] = r.param_restrictions

    def add_rpc_capability(self, c: RPCCapability):
        if c.resource not in self._rpc_dict:
            self.rpc_capabilities.append(c)
            self._rpc_dict[c.resource] = c.param_restrictions
        else:
            for r in self.rpc_capabilities:
                if r.resource == c.resource:
                    r.param_restrictions.update(c.param_restrictions)
                    self._rpc_dict[r.resource] = r.param_restrictions
                    break

    def remove_rpc_capability(self, c: RPCCapability):
        try:
            self.rpc_capabilities.remove(c)
        except ValueError:
            if c.resource in self._rpc_dict:
                # difference is in param_restriction
                for r in self.rpc_capabilities:
                    if r.resource == c.resource:
                        for k in c.param_restrictions:
                            r.param_restrictions.pop(k, None)
        else:
            self._rpc_dict.pop(c.resource)

    def __len__(self):
        return len(self.rpc_capabilities)


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
    pubsub_capabilities = field(type=list[PubsubCapability], default=None)

    def __attrs_post_init__(self):
        if self.pubsub_capabilities is None:
            self.pubsub_capabilities = []

    def add_pubsub_capability(self, c: PubsubCapability):
        if c not in self.pubsub_capabilities:
            self.pubsub_capabilities.append(c)

    def remove_pubsub_capability(self, c: PubsubCapability):
        try:
            self.pubsub_capabilities.remove(c)
        except ValueError:
            pass

    def __len__(self):
        return len(self.pubsub_capabilities)


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
    roles = field(type=list[Role], default=None)

    def __attrs_post_init__(self):
        if self.roles is None:
            self.roles = []

    def __len__(self):
        return len(self.roles)


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
    _roles_dict = dict()
    for _r in instance.roles:
        _roles_dict[_r.name] = dict()
        if _r.rpc_capabilities:
            _roles_dict[_r.name][RPC_CAPABILITIES] = authz_converter.unstructure(
                _r.rpc_capabilities)
        if _r.pubsub_capabilities:
            _roles_dict[_r.name][PUBSUB_CAPABILITIES] = authz_converter.unstructure(
                _r.pubsub_capabilities)
    return _roles_dict


role_name = str
PubKey = str


@define
class UserRole:
    role_name = field(type=role_name)
    param_restrictions = field(type=dict, default=None)

    def __attrs_post_init__(self):
        if self.param_restrictions is None:
            self.param_restrictions = dict()

    def add_param_restrictions(self, param: str, value: Any):
        self.param_restrictions[param] = value


@define
class UserRoles:
    user_roles = field(type=list[UserRole], default=None)
    _user_roles_dict = field(type=dict, default=None, init=False)

    def __attrs_post_init__(self):
        if self.user_roles is None:
            self.user_roles = []
        self._user_roles_dict = dict()
        for r in self.user_roles:
            self._user_roles_dict[r.role_name] = r.param_restrictions

    def add_role(self, c: UserRole):
        if c.role_name not in self._user_roles_dict:
            self.user_roles.append(c)
            self._user_roles_dict[c.role_name] = c.param_restrictions
        else:
            for r in self.user_roles:
                if r.role_name == c.role_name:
                    r.param_restrictions.update(c.param_restrictions)
                    self._user_roles_dict[r.role_name] = r.param_restrictions
                    break

    def remove_role(self, c: UserRole):
        try:
            self.user_roles.remove(c)
        except ValueError:
            if c.role_name in self._user_roles_dict:
                # difference is in param_restriction
                for r in self.user_roles:
                    if r.role_name == c.role_name:
                        for k in c.param_restrictions:
                            r.param_restrictions.pop(k, None)
        else:
            self._user_roles_dict.pop(c.role_name)

    def __len__(self):
        return len(self.user_roles)


def unstructure_user_roles(instance: UserRoles):
    """
    Convert from:

        UserRoles(
        user_roles=[UserRole(role_name='role1', param_restrictions={}),
                    UserRole(role_name='role2', param_restrictions={'id': 'id2', 'p2': 'v2'})])

    TO:
        ['role1', {'role2': {'id': 'id2', 'p2': 'v2'}}]
        i.e. instead of the default unstructure/asdict behavior - list of {role_name:value, param_restrictions:value}
        generate single List with just role_name str if param_restrictions is None or dict(role_name, param_restriction)

    """
    user_roles_list = []
    for c in instance.user_roles:
        if c.param_restrictions:
            user_roles_list.append({c.role_name: c.param_restrictions})
        else:
            user_roles_list.append(c.role_name)
    return user_roles_list


@define
class UserGroup:
    name = field(type=str)
    identities = field(type=list[Identity], default=None)
    roles = field(type=UserRoles, default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)

    def __attrs_post_init__(self):
        if self.identities is None:
            self.identities = list()

        if self.roles is None:
            self.roles = UserRoles()


@define
class UserGroups:
    user_groups = field(type=list[UserGroup], default=None)

    def __attrs_post_init__(self):
        if self.user_groups is None:
            self.user_groups = []

    def __len__(self):
        return len(self.user_groups)


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
    generate dict with key as group name and values as users, roles, __rpc__, pubsub capabilities and skipping none
    """
    _groups_dict = dict()
    for _g in instance.user_groups:
        _groups_dict[_g.name] = {'identities': _g.identities}
        if _g.roles:
            _groups_dict[_g.name]['roles'] = authz_converter.unstructure(_g.roles)
        if _g.rpc_capabilities:
            _groups_dict[_g.name][RPC_CAPABILITIES] = authz_converter.unstructure(
                _g.rpc_capabilities)
        if _g.pubsub_capabilities:
            _groups_dict[_g.name][PUBSUB_CAPABILITIES] = authz_converter.unstructure(
                _g.pubsub_capabilities)

    return _groups_dict


@define
class User:
    identity = field(type=Identity)
    protected_rpcs = field(type=set[vipid_dot_rpc_method], default=None)
    roles = field(type=UserRoles, default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)
    comments = field(type=str, default=None)


@define
class Users:
    users = field(type=list[User], default=None)

    def __attrs_post_init__(self):
        if self.users is None:
            self.users = []

    def __len__(self):
        return len(self.users)


def unstructure_users(instance: Users):
    _users_dict = dict()
    # make a dict with key as user name and value as dict of all other attributes. In the inner dict, values are
    # converted from attrs objects to primitives based on its own custom unstructure methods
    for _user in instance.users:
        _users_dict[_user.identity] = dict()
        for attribute in fields(_user.__class__):
            if attribute.name != "identity" and _user.__getattribute__(attribute.name):
                _users_dict[_user.identity][attribute.name] = (authz_converter.unstructure(
                    _user.__getattribute__(attribute.name)))
    return _users_dict


@define
class VolttronAuthzMap:
    protected_topics = field(type=set[str], default=None)
    roles = field(type=Roles, default=None)
    user_groups = field(type=UserGroups, default=None)
    users = field(type=Users, default=None)
    compact_dict = field(type=dict, init=False, default=None)
    user_capabilities = field(type=dict, init=False, default=None)

    def __attrs_post_init__(self):
        self.compact_dict = authz_converter.unstructure(self)
        self.user_capabilities = copy.deepcopy(self.compact_dict.get(USERS))
        VolttronAuthzMap.expand_user_capabilities(user_capabilities=self.user_capabilities,
                                                  user_groups=self.compact_dict.get(USER_GROUPS),
                                                  roles=self.compact_dict.get(ROLES))

    @classmethod
    def from_unstructured_dict(cls, input_dict: dict):
        """
        Method to create VolttronAuthzMap instance from json.load(authz.json file)
        :param input_dict: json.load(authz.json file created by unstructure(VolttronAuthzMap))
        :return: instance of VolttronAuthzMap
        """
        protected_topics = input_dict.get("protected_topics")

        # Build Roles
        _roles = list()
        for name, value in input_dict.get(ROLES, dict()).items():
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(
                value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(
                value.get(PUBSUB_CAPABILITIES))

            r_obj = Role(name, rpc_capabilities=rpc_obj_list, pubsub_capabilities=pubsub_obj_list)
            _roles.append(r_obj)

        # Build user groups
        groups = list()
        for group_name, value in input_dict.get(USER_GROUPS, dict()).items():
            vip_ids = value.get(IDENTITIES, list())
            role_names = value.get(ROLES, list())
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(
                value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(
                value.get(PUBSUB_CAPABILITIES))
            groups.append(
                UserGroup(name=group_name,
                          identities=vip_ids,
                          roles=role_names,
                          rpc_capabilities=rpc_obj_list,
                          pubsub_capabilities=pubsub_obj_list))

        # Build users
        users = list()
        for identity, value in input_dict.get(USERS, dict()).items():
            protected_rpcs = value.get("protected_rpcs", list())
            role_names = value.get(ROLES, list())
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(
                value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(
                value.get(PUBSUB_CAPABILITIES))
            comments = value.get("comments")
            users.append(
                User(identity=identity,
                     protected_rpcs=protected_rpcs,
                     roles=role_names,
                     rpc_capabilities=rpc_obj_list,
                     pubsub_capabilities=pubsub_obj_list,
                     comments=comments))

        authz_roles = Roles(_roles)
        authz_user_groups = UserGroups(groups)
        authz_users = Users(users)
        instance = cls(protected_topics=protected_topics,
                       roles=authz_roles,
                       user_groups=authz_user_groups,
                       users=authz_users)
        # print(json.dumps(authz.authz_converter.unstructure(instance), indent=4))
        instance.compact_dict = input_dict
        return instance

    @classmethod
    def create_rpc_capabilities_obj(cls, rpc_cap_list: list = None) -> RPCCapabilities:
        if rpc_cap_list is None:
            rpc_cap_list = list()
        obj_list = RPCCapabilities(
            [])    # I don't get a new instance of list in obj if I don't pass []  ?!
        for rpc_cap in rpc_cap_list:
            if isinstance(rpc_cap, str):
                obj_list.add_rpc_capability(RPCCapability(rpc_cap))
            elif isinstance(rpc_cap, dict):
                vip_id_rpc_method = list(rpc_cap.keys())[0]
                param_restrict = rpc_cap[vip_id_rpc_method]
                obj_list.add_rpc_capability(RPCCapability(vip_id_rpc_method, param_restrict))
        return obj_list

    @classmethod
    def create_pubsub_capabilities_obj(cls, pubsub_cap_dict: dict = None) -> PubsubCapabilities:
        if pubsub_cap_dict is None:
            pubsub_cap_dict = dict()
        obj_list = PubsubCapabilities(
            [])    # I don't get a new instance of list in obj if I don't pass []  ?!
        for topic_pattern, access in pubsub_cap_dict.items():
            obj_list.add_pubsub_capability(PubsubCapability(topic_pattern, access))
        return obj_list

    @classmethod
    def expand_user_capabilities(cls,
                                 *,
                                 user_capabilities: dict,
                                 user_groups: dict = None,
                                 roles: dict = None):
        if not user_capabilities:
            return
        apply_role_capabilities = False
        if user_groups:
            # Apply rules of the group to each group member
            for _name, group_details in user_groups.items():
                for vip in group_details[IDENTITIES]:
                    cls.update_roles(user_capabilities[vip], group_details.get(ROLES))
                    cls.update_rpc_capabilities(user_capabilities[vip],
                                                group_details.get(RPC_CAPABILITIES))
                    cls.update_pubsub_capabilities(user_capabilities[vip],
                                                   group_details.get(PUBSUB_CAPABILITIES))
        if roles or apply_role_capabilities:
            # Apply role's capabilities to user_capabilities.
            for vip, user_authz in user_capabilities.items():
                for user_role in user_authz.get(ROLES, []):
                    if isinstance(user_role, dict):
                        user_role_name = list(user_role.keys())[0]
                        if not roles.get(user_role_name):
                            # not a role that is currently updated, skip to next role
                            continue
                        param_restriction = user_role[user_role_name]
                        # add param restriction dict to role's __rpc__ capbailities before merging with
                        # user capabilities
                        role_rpc_caps = copy.deepcopy(
                            roles.get(user_role_name).get(RPC_CAPABILITIES))
                        role_rpc_caps_params = []
                        for role_rpc_cap in role_rpc_caps:
                            if isinstance(role_rpc_cap, str):
                                d = {role_rpc_cap: param_restriction}
                            else:
                                key = list(role_rpc_cap.keys())[0]
                                value = role_rpc_cap[key]
                                d = {key: value}
                                value.update(param_restriction)
                            role_rpc_caps_params.append(d)
                        # Update user authz with role's __rpc__ cap
                        cls.update_rpc_capabilities(user_authz, role_rpc_caps_params)
                    else:
                        user_role_name = user_role
                        if not roles.get(user_role_name):
                            # not a role that is currently updated, skip to next role
                            continue
                        # Update user authz with role's __rpc__ cap
                        cls.update_rpc_capabilities(
                            user_authz,
                            roles.get(user_role_name).get(RPC_CAPABILITIES))

                    # update user authz with role's pubsub cap
                    cls.update_pubsub_capabilities(
                        user_authz,
                        roles.get(user_role_name).get(PUBSUB_CAPABILITIES))

    @classmethod
    def update_rpc_capabilities_or_roles(cls, authz_dict: dict, new_caps_list: list,
                                         list_type: str):

        if not new_caps_list:
            return
        current_caps_list = authz_dict.get(list_type)
        if not current_caps_list:
            authz_dict[list_type] = copy.deepcopy(new_caps_list)
            return

        # Both current and new __rpc__ capabilities are not empty.
        # Merge
        for new_cap in new_caps_list:
            if isinstance(new_cap, dict):
                new_cap_name = next(iter(new_cap))
            else:
                new_cap_name = new_cap
            for i, cur_cap in enumerate(current_caps_list):
                if isinstance(cur_cap, dict) and new_cap_name == next(iter(cur_cap)):
                    if isinstance(new_cap, dict):
                        new_param_restrict_value = copy.deepcopy(new_cap[new_cap_name])
                        new_param_restrict_value.update(cur_cap[new_cap_name])
                        current_caps_list[i] = {new_cap_name: new_param_restrict_value}
                        break
                    else:
                        current_caps_list[i] = new_cap_name
                        break
                elif cur_cap == new_cap_name:
                    if isinstance(new_cap, dict):
                        current_caps_list[i] = {cur_cap: copy.deepcopy(new_cap[cur_cap])}
                        break
                    else:
                        # both are string and capability already exists do nothing
                        break
            else:
                # for loop completed and didn't do anything so new cap is not in current. so append
                current_caps_list.append(copy.deepcopy(new_cap))

    @classmethod
    def update_rpc_capabilities(cls, authz_dict: dict, new_rpc_caps: list):
        cls.update_rpc_capabilities_or_roles(authz_dict, new_rpc_caps, RPC_CAPABILITIES)

    @classmethod
    def update_roles(cls, authz_dict: dict, new_roles: list):
        cls.update_rpc_capabilities_or_roles(authz_dict, new_roles, ROLES)

    @classmethod
    def update_pubsub_capabilities(cls, authz_dict, new_pubsub_caps):
        if new_pubsub_caps:
            user_pubsub_caps = authz_dict.get(PUBSUB_CAPABILITIES, dict())
            user_pubsub_caps.update(new_pubsub_caps)
            authz_dict[PUBSUB_CAPABILITIES] = user_pubsub_caps

    def create_or_merge_role(self,
                             *,
                             name: str,
                             rpc_capabilities: RPCCapabilities = None,
                             pubsub_capabilities: PubsubCapabilities = None) -> bool:
        if not rpc_capabilities and not pubsub_capabilities:
            raise ValueError(f"Role {name} should have non empty capabilities - rpc capabilities, "
                             "pubsub capabilities or both")
        if not self.compact_dict.get(ROLES):
            self.compact_dict[ROLES] = dict()
        if name not in self.compact_dict.get(ROLES):
            self.compact_dict.get(ROLES)[name] = dict()

        expand_user_caps = False
        role_dict = self.compact_dict.get(ROLES).get(name)
        if role_dict:
            expand_user_caps = True    # existing role so might have users associated it, updated user_caps
        VolttronAuthzMap.update_rpc_capabilities(role_dict,
                                                 authz_converter.unstructure(rpc_capabilities))
        VolttronAuthzMap.update_pubsub_capabilities(
            role_dict, authz_converter.unstructure(pubsub_capabilities))

        if expand_user_caps:
            self.expand_user_capabilities(user_capabilities=self.user_capabilities,
                                          roles={name: role_dict})
        return True

    def create_or_merge_user_group(self,
                                   *,
                                   name: str,
                                   identities: list[Identity],
                                   roles: UserRoles = None,
                                   rpc_capabilities: RPCCapabilities = None,
                                   pubsub_capabilities: PubsubCapabilities = None,
                                   **kwargs) -> bool:
        new_group = False
        if not self.compact_dict.get(USER_GROUPS):
            self.compact_dict[USER_GROUPS] = dict()
        if name not in self.compact_dict.get(USER_GROUPS):
            self.compact_dict.get(USER_GROUPS)[name] = dict()
            new_group = True

        if new_group and not identities:
            self.compact_dict.get(USER_GROUPS).pop(name)
            raise ValueError("Empty user group")
        if new_group and not roles and not rpc_capabilities and not pubsub_capabilities:
            self.compact_dict.get(USER_GROUPS).pop(name)
            raise ValueError(
                f"User group {name} should have non empty capabilities. Please pass non empty values "
                "for at least one of the three parameters - roles, rpc_capabilities, pubsub_capabilities"
            )

        group_dict = self.compact_dict.get(USER_GROUPS).get(name)
        # todo validate ids
        current_ids_set = set(group_dict.get('identities', []))
        current_ids_set.update(identities)
        group_dict[IDENTITIES] = list(current_ids_set)

        if roles:
            # todo validate roles
            VolttronAuthzMap.update_roles(group_dict, authz_converter.unstructure(roles))

        VolttronAuthzMap.update_rpc_capabilities(group_dict,
                                                 authz_converter.unstructure(rpc_capabilities))
        VolttronAuthzMap.update_pubsub_capabilities(
            group_dict, authz_converter.unstructure(pubsub_capabilities))

        if group_dict.get(ROLES):
            self.expand_user_capabilities(user_capabilities=self.user_capabilities,
                                          user_groups={name: group_dict},
                                          roles=self.compact_dict.get(ROLES))
        else:
            self.expand_user_capabilities(user_capabilities=self.user_capabilities,
                                          user_groups={name: group_dict})
        return True

    def remove_users_from_group(self, name: str, identities: set[Identity]) -> bool:
        if not self.compact_dict.get(USER_GROUPS) or name not in self.compact_dict[USER_GROUPS]:
            return False
        s = set(self.compact_dict[USER_GROUPS][name][IDENTITIES])
        self.compact_dict[USER_GROUPS][name][IDENTITIES] = list(s - identities)
        # expand will only create or merge so reset user_capabilities to compact_dict value and then expand
        for _id in identities:
            self.user_capabilities[_id] = copy.deepcopy(self.compact_dict[USERS][_id])
        VolttronAuthzMap.expand_user_capabilities(
            user_capabilities=self.user_capabilities,
            user_groups={name: self.compact_dict[USER_GROUPS][name]},
            roles=self.compact_dict[ROLES])
        return True

    def add_users_to_group(self, name: str, identities: set[Identity]):
        if not self.compact_dict.get(USER_GROUPS) or name not in self.compact_dict[USER_GROUPS]:
            return False
        # TODO validate identity
        s = set(self.compact_dict[USER_GROUPS][name][IDENTITIES])
        s.update(identities)
        self.compact_dict[USER_GROUPS][name][IDENTITIES] = list(s)
        VolttronAuthzMap.expand_user_capabilities(
            user_capabilities=self.user_capabilities,
            user_groups={name: self.compact_dict[USER_GROUPS][name]},
            roles=self.compact_dict[ROLES])
        return True

    def create_or_merge_user_authz(self,
                                   *,
                                   identity: str,
                                   protected_rpcs: set[str] = None,
                                   roles: UserRoles = None,
                                   rpc_capabilities: RPCCapabilities = None,
                                   pubsub_capabilities: PubsubCapabilities = None,
                                   comments: str = None,
                                   **kwargs) -> bool:

        if not identity:
            raise ValueError("User identity is mandatory")

        if not self.compact_dict.get(USERS):
            self.compact_dict[USERS] = dict()
            self.user_capabilities = dict()
        if identity not in self.compact_dict.get(USERS):
            self.compact_dict.get(USERS)[identity] = dict()

        user_dict = self.compact_dict.get(USERS).get(identity)

        if protected_rpcs:
            current_rpc_set = set(user_dict.get("protected_rpcs", list()))
            current_rpc_set.update(protected_rpcs)
            user_dict["protected_rpcs"] = list(current_rpc_set)

        if roles:
            VolttronAuthzMap.update_roles(user_dict, authz_converter.unstructure(roles))
        if rpc_capabilities:
            VolttronAuthzMap.update_rpc_capabilities(user_dict,
                                                     authz_converter.unstructure(rpc_capabilities))
        if pubsub_capabilities:
            VolttronAuthzMap.update_pubsub_capabilities(
                user_dict, authz_converter.unstructure(pubsub_capabilities))
        if comments:
            user_dict["comments"] = comments

        self.user_capabilities[identity] = copy.deepcopy(user_dict)
        VolttronAuthzMap.expand_user_capabilities(user_capabilities=self.user_capabilities,
                                                  user_groups=self.compact_dict.get(USER_GROUPS),
                                                  roles=self.compact_dict.get(ROLES))
        return True

    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        _topics = self.compact_dict.get("protected_topics", [])
        if topic_name_pattern in _topics:
            return False
        else:
            _topics.append(topic_name_pattern)
            return True

    def remove_protected_topic(self, *, topic_name_pattern: str) -> bool:
        if not self.compact_dict.get("protected_topics"):
            return False
        try:
            self.compact_dict.get("protected_topics").remove(topic_name_pattern)
            return True
        except KeyError:
            return False

    def remove_user_authorization(self, identity: Identity):
        if not self.compact_dict.get(USERS) or identity not in self.compact_dict.get(USERS):
            return False
        else:
            del self.compact_dict.get(USERS)[identity]
            return True

    def remove_user_group(self, name: str):
        if not self.compact_dict.get(USER_GROUPS) or name not in self.compact_dict.get(
                USER_GROUPS):
            return False
        else:
            del self.compact_dict.get(USER_GROUPS)[name]
            return True

    def remove_role(self, name: str):
        if not self.compact_dict.get(ROLES) or name not in self.compact_dict.get(ROLES):
            return False
        else:
            del self.compact_dict.get(ROLES)[name]
            return True


def unstructure_authz_map(instance: VolttronAuthzMap):
    authz_map_dict = dict()
    if instance.protected_topics:
        authz_map_dict["protected_topics"] = instance.protected_topics
    if instance.roles:
        authz_map_dict[ROLES] = authz_converter.unstructure(instance.roles)
    if instance.user_groups:
        authz_map_dict[USER_GROUPS] = authz_converter.unstructure(instance.user_groups)
    if instance.users:
        authz_map_dict[USERS] = authz_converter.unstructure(instance.users)
    return authz_map_dict


authz_converter.register_unstructure_hook(RPCCapabilities, unstructure_rpc_capabilities)
authz_converter.register_unstructure_hook(PubsubCapabilities, unstructure_pubsub_capabilities)
authz_converter.register_unstructure_hook(Roles, unstructure_roles)
authz_converter.register_unstructure_hook(UserGroups, unstructure_user_groups)
authz_converter.register_unstructure_hook(UserRoles, unstructure_user_roles)
authz_converter.register_unstructure_hook(Users, unstructure_users)
authz_converter.register_unstructure_hook(VolttronAuthzMap, unstructure_authz_map)

###############
# test
###############
if __name__ == "__main__":
    # test unstructure hooks
    test_r1 = RPCCapability("id.rpc1")
    test_r2 = RPCCapability("id2.rpc2", {"id": "id2", "p2": "v2"})
    test_rpc_list = RPCCapabilities([test_r1, test_r2])
    print(test_rpc_list)
    test_rpc_dict = authz_converter.unstructure(test_rpc_list)
    print(test_rpc_dict)
    test_pubsub_list = PubsubCapabilities([
        PubsubCapability(topic_pattern="device/*", topic_access="pubsub"),
        PubsubCapability(topic_pattern="*", topic_access="pubsub")
    ])
    print(test_pubsub_list)
    pubsub_dict = authz_converter.unstructure(test_pubsub_list)
    print(pubsub_dict)

    test_role = Role("admin", test_rpc_list, test_pubsub_list)
    print(test_role)
    test_role_dict = authz_converter.unstructure(test_role)
    print(test_role_dict)
    test_roles = Roles(
        [Role("admin", test_rpc_list),
         Role("new_role", pubsub_capabilities=test_pubsub_list)])
    print(test_roles)
    test_roles_dict = authz_converter.unstructure(test_roles)
    print(test_roles_dict)

    test_group = UserGroups([
        UserGroup("admin_users", ["volttron.ctl", "config.store"],
                  roles=UserRoles([UserRole(role_name="admin")]),
                  pubsub_capabilities=test_pubsub_list)
    ])
    print(test_group)
    test_group_dict = authz_converter.unstructure(test_group)
    print(test_group_dict)

    test_users = Users([
        User("volttron.ctl", roles=UserRoles([UserRole("admin")])),
    # User("hist1", rpc_capabilities=test_rpc_list),
        User("listener1",
             roles=UserRoles(
                 [UserRole(role_name="role1", param_restrictions={"param1": "value1"})]))
    ])
    print(test_users)
    test_users_dict = authz_converter.unstructure(test_users)
    print(test_users_dict)

    # # Test rpc capabilities update
    # current_rpc_caps = ["string value", {"p1": {"param1": "value1", "param2": "value3", "param3": "value3"}}]
    # element = {"p1": {"param1": "value1", "param2": "value2"}}
    # ## element = {"p3": {1: "12"}}
    # ## element = "sasdf"
    # if isinstance(element, dict):
    #     for i, cur_cap in enumerate(current_rpc_caps):
    #         if isinstance(cur_cap, dict) and next(iter(element)) == next(iter(cur_cap)):
    #             new_param_restrict_value = element[next(iter(element))]
    #             new_param_restrict_value.update(cur_cap[next(iter(cur_cap))])
    #             current_rpc_caps[i] = element
    #             break
    #     else:
    #         current_rpc_caps.append(element)
    # elif element not in current_rpc_caps:
    #     current_rpc_caps.append(element)
    # print(current_rpc_caps)

    # #test expand user caps
