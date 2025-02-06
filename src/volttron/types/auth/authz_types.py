import copy
import logging
import re
from typing import Any, TYPE_CHECKING

from attrs import validators, define, field, fields
from cattrs import Converter

from volttron.types import Identity

vipid_dot_rpc_method = str
RPC_CAPABILITIES = "rpc_capabilities"
PUBSUB_CAPABILITIES = "pubsub_capabilities"
ROLES = "roles"
AGENTS = "agents"
GROUPS = "agent_groups"
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
            _roles_dict[_r.name][RPC_CAPABILITIES] = authz_converter.unstructure(_r.rpc_capabilities)
        if _r.pubsub_capabilities:
            _roles_dict[_r.name][PUBSUB_CAPABILITIES] = authz_converter.unstructure(_r.pubsub_capabilities)
    return _roles_dict


role_name = str
PubKey = str


@define
class AgentRole:
    role_name = field(type=role_name)
    param_restrictions = field(type=dict, default=None)

    def __attrs_post_init__(self):
        if self.param_restrictions is None:
            self.param_restrictions = dict()

    def add_param_restrictions(self, param: str, value: Any):
        self.param_restrictions[param] = value


@define
class AgentRoles:
    agent_roles = field(type=list[AgentRole], default=None)
    _agent_roles_dict = field(type=dict, default=None, init=False)

    def __attrs_post_init__(self):
        if self.agent_roles is None:
            self.agent_roles = []
        self._agent_roles_dict = dict()
        for r in self.agent_roles:
            self._agent_roles_dict[r.role_name] = r.param_restrictions

    def add_agent_role(self, c: AgentRole):
        if c.role_name not in self._agent_roles_dict:
            self.agent_roles.append(c)
            self._agent_roles_dict[c.role_name] = c.param_restrictions
        else:
            for r in self.agent_roles:
                if r.role_name == c.role_name:
                    r.param_restrictions.update(c.param_restrictions)
                    self._agent_roles_dict[r.role_name] = r.param_restrictions
                    break

    def remove_agent_role(self, c: AgentRole):
        try:
            self.agent_roles.remove(c)
        except ValueError:
            if c.role_name in self._agent_roles_dict:
                # difference is in param_restriction
                for r in self.agent_roles:
                    if r.role_name == c.role_name:
                        for k in c.param_restrictions:
                            r.param_restrictions.pop(k, None)
        else:
            self._agent_roles_dict.pop(c.role_name)

    def __len__(self):
        return len(self.agent_roles)


def unstructure_agent_roles(instance: AgentRoles):
    """
    Convert from:

        AgentRoles(
        agent_roles=[AgentRole(role_name='role1', param_restrictions={}),
                    AgentRole(role_name='role2', param_restrictions={'id': 'id2', 'p2': 'v2'})])

    TO:
        ['role1', {'role2': {'id': 'id2', 'p2': 'v2'}}]
        i.e. instead of the default unstructure/asdict behavior - list of {role_name:value, param_restrictions:value}
        generate single List with just role_name str if param_restrictions is None or dict(role_name, param_restriction)

    """
    agent_roles_list = []
    for c in instance.agent_roles:
        if c.param_restrictions:
            agent_roles_list.append({c.role_name: c.param_restrictions})
        else:
            agent_roles_list.append(c.role_name)
    return agent_roles_list


@define
class AgentGroup:
    name = field(type=str)
    identities = field(type=list[Identity], default=None)
    agent_roles = field(type=AgentRoles, default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)

    def __attrs_post_init__(self):
        if self.identities is None:
            self.identities = list()

        if self.agent_roles is None:
            self.agent_roles = AgentRoles()


@define
class AgentGroups:
    agent_groups = field(type=list[AgentGroup], default=None)

    def __attrs_post_init__(self):
        if self.agent_groups is None:
            self.agent_groups = []

    def __len__(self):
        return len(self.agent_groups)


def unstructure_agent_groups(instance: AgentGroups):
    """
    Convert
      AgentGroups(agent_groups=[
        AgentGroup(name='admin_agents',
                  identities=['volttron.ctl', 'config.store'],
                  agent_roles=['admin'],
                  rpc_capabilities=None,
                  pubsub_capabilities=PubsubCapabilities(pubsub_capabilities=[
                    PubsubCapability(topic_pattern='device/*', topic_access='pubsub'),
                    PubsubCapability(topic_pattern='*', topic_access='pubsub')])
                  )
        ])

    TO:
    {'admin_agents':
        {'agents': ['volttron.ctl', 'config.store'],
         'agent_roles': ['admin'],
         'pubsub_capabilities': {'device/*': 'pubsub', '*': 'pubsub'}
         }
    }
    i.e. instead of list of dict with
                  name:<value>, identities:<list>, agent_roles:<list>, rpc_capabilities: <list>, pubsub_capabilities: <list>
    generate dict with key as group name and values as identities, agent_roles, __rpc__, pubsub capabilities and skipping none
    """
    _groups_dict = dict()
    for _g in instance.agent_groups:
        _groups_dict[_g.name] = {'identities': _g.identities}
        if _g.agent_roles:
            _groups_dict[_g.name]['agent_roles'] = authz_converter.unstructure(_g.agent_roles)
        if _g.rpc_capabilities:
            _groups_dict[_g.name][RPC_CAPABILITIES] = authz_converter.unstructure(_g.rpc_capabilities)
        if _g.pubsub_capabilities:
            _groups_dict[_g.name][PUBSUB_CAPABILITIES] = authz_converter.unstructure(_g.pubsub_capabilities)

    return _groups_dict


@define
class Agent:
    identity = field(type=Identity)
    protected_rpcs = field(type=set[vipid_dot_rpc_method], default=None)
    agent_roles = field(type=AgentRoles, default=None)
    rpc_capabilities = field(type=RPCCapabilities, default=None)
    pubsub_capabilities = field(type=PubsubCapabilities, default=None)
    comments = field(type=str, default=None)


@define
class Agents:
    agents = field(type=list[Agent], default=None)

    def __attrs_post_init__(self):
        if self.agents is None:
            self.agents = []

    def __len__(self):
        return len(self.agents)


def unstructure_agents(instance: Agents):
    _agents_dict = dict()
    # make a dict with key as identity and value as dict of all other attributes. In the inner dict, values are
    # converted from attrs objects to primitives based on its own custom unstructure methods
    for _agent in instance.agents:
        _agents_dict[_agent.identity] = dict()
        for attribute in fields(_agent.__class__):
            if attribute.name != "identity" and _agent.__getattribute__(attribute.name):
                _agents_dict[_agent.identity][attribute.name] = (authz_converter.unstructure(
                    _agent.__getattribute__(attribute.name)))
    return _agents_dict


@define
class VolttronAuthzMap:
    protected_topics = field(type=list[str], default=None)
    roles = field(type=Roles, default=None)
    agent_groups = field(type=AgentGroups, default=None)
    agents = field(type=Agents, default=None)
    compact_dict = field(type=dict, init=False, default=None)
    agent_capabilities = field(type=dict, init=False, default=None)

    def __attrs_post_init__(self):
        self.compact_dict = authz_converter.unstructure(self)
        self.agent_capabilities = copy.deepcopy(self.compact_dict.get(AGENTS))
        VolttronAuthzMap.expand_agent_capabilities(agent_capabilities=self.agent_capabilities,
                                                   agent_groups=self.compact_dict.get(GROUPS),
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
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(value.get(PUBSUB_CAPABILITIES))

            r_obj = Role(name, rpc_capabilities=rpc_obj_list, pubsub_capabilities=pubsub_obj_list)
            _roles.append(r_obj)

        # Build agent groups
        groups = list()
        for group_name, value in input_dict.get(GROUPS, dict()).items():
            vip_ids = value.get(IDENTITIES, list())
            role_names = value.get(ROLES, list())
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(value.get(PUBSUB_CAPABILITIES))
            groups.append(
                AgentGroup(name=group_name,
                           identities=vip_ids,
                           agent_roles=role_names,
                           rpc_capabilities=rpc_obj_list,
                           pubsub_capabilities=pubsub_obj_list))

        # Build agents
        agents = list()
        for identity, value in input_dict.get(AGENTS, dict()).items():
            protected_rpcs = value.get("protected_rpcs", list())
            role_names = value.get('agent_roles', list())
            rpc_obj_list = VolttronAuthzMap.create_rpc_capabilities_obj(value.get(RPC_CAPABILITIES))
            pubsub_obj_list = VolttronAuthzMap.create_pubsub_capabilities_obj(value.get(PUBSUB_CAPABILITIES))
            comments = value.get("comments")
            agents.append(
                Agent(identity=identity,
                      protected_rpcs=protected_rpcs,
                      agent_roles=role_names,
                      rpc_capabilities=rpc_obj_list,
                      pubsub_capabilities=pubsub_obj_list,
                      comments=comments))

        authz_roles = Roles(_roles)
        authz_agent_groups = AgentGroups(groups)
        authz_agents = Agents(agents)
        instance = cls(protected_topics=protected_topics,
                       roles=authz_roles,
                       agent_groups=authz_agent_groups,
                       agents=authz_agents)
        # print(json.dumps(authz.authz_converter.unstructure(instance), indent=4))
        instance.compact_dict = input_dict
        return instance

    @classmethod
    def create_rpc_capabilities_obj(cls, rpc_cap_list: list = None) -> RPCCapabilities:
        if rpc_cap_list is None:
            rpc_cap_list = list()
        obj_list = RPCCapabilities([])    # I don't get a new instance of list in obj if I don't pass []  ?!
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
        obj_list = PubsubCapabilities([])    # I don't get a new instance of list in obj if I don't pass []  ?!
        for topic_pattern, access in pubsub_cap_dict.items():
            obj_list.add_pubsub_capability(PubsubCapability(topic_pattern, access))
        return obj_list

    @classmethod
    def expand_agent_capabilities(cls, *, agent_capabilities: dict, agent_groups: dict = None, roles: dict = None):
        if not agent_capabilities:
            return
        apply_role_capabilities = False
        if agent_groups:
            # Apply rules of the group to each group member
            for _name, group_details in agent_groups.items():
                for vip in group_details[IDENTITIES]:
                    cls.update_agent_roles(agent_capabilities[vip], group_details.get("agent_roles"))
                    cls.update_rpc_capabilities(agent_capabilities[vip], group_details.get(RPC_CAPABILITIES))
                    cls.update_pubsub_capabilities(agent_capabilities[vip], group_details.get(PUBSUB_CAPABILITIES))
        if roles or apply_role_capabilities:
            # Apply agent_role's capabilities to agent_capabilities.
            for vip, agent_authz in agent_capabilities.items():
                for agent_role in agent_authz.get("agent_roles", []):
                    if isinstance(agent_role, dict):
                        agent_role_name = list(agent_role.keys())[0]
                        if not roles.get(agent_role_name):
                            # not an agent_role that is currently updated, skip to next agent_role
                            continue
                        param_restriction = agent_role[agent_role_name]
                        # add param restriction dict to role's __rpc__ capbailities before merging with
                        # agent capabilities
                        role_rpc_caps = copy.deepcopy(roles.get(agent_role_name).get(RPC_CAPABILITIES))
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
                        # Update agent authz with role's __rpc__ cap
                        cls.update_rpc_capabilities(agent_authz, role_rpc_caps_params)
                    else:
                        agent_role_name = agent_role
                        if not roles.get(agent_role_name):
                            # not a role that is currently updated, skip to next role
                            continue
                        # Update agent authz with role's __rpc__ cap
                        cls.update_rpc_capabilities(agent_authz, roles.get(agent_role_name).get(RPC_CAPABILITIES))

                    # update agent authz with role's pubsub cap
                    cls.update_pubsub_capabilities(agent_authz, roles.get(agent_role_name).get(PUBSUB_CAPABILITIES))

    @classmethod
    def update_rpc_capabilities_or_roles(cls, authz_dict: dict, new_caps_list: list, list_type: str):

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
    def update_agent_roles(cls, authz_dict: dict, new_roles: list):
        cls.update_rpc_capabilities_or_roles(authz_dict, new_roles, 'agent_roles')

    @classmethod
    def update_pubsub_capabilities(cls, authz_dict, new_pubsub_caps):
        if new_pubsub_caps:
            agent_pubsub_caps = authz_dict.get(PUBSUB_CAPABILITIES, dict())
            agent_pubsub_caps.update(new_pubsub_caps)
            authz_dict[PUBSUB_CAPABILITIES] = agent_pubsub_caps

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

        expand_agent_caps = False
        role_dict = self.compact_dict.get(ROLES).get(name)
        if role_dict:
            expand_agent_caps = True    # existing role so might have agents associated it, updated agent_caps
        VolttronAuthzMap.update_rpc_capabilities(role_dict, authz_converter.unstructure(rpc_capabilities))
        VolttronAuthzMap.update_pubsub_capabilities(role_dict, authz_converter.unstructure(pubsub_capabilities))

        if expand_agent_caps:
            self.expand_agent_capabilities(agent_capabilities=self.agent_capabilities, roles={name: role_dict})
        return True

    def create_or_merge_agent_group(self,
                                    *,
                                    name: str,
                                    identities: list[Identity],
                                    agent_roles: AgentRoles = None,
                                    rpc_capabilities: RPCCapabilities = None,
                                    pubsub_capabilities: PubsubCapabilities = None,
                                    **kwargs) -> bool:
        new_group = False
        if not self.compact_dict.get(GROUPS):
            self.compact_dict[GROUPS] = dict()
        if name not in self.compact_dict.get(GROUPS):
            self.compact_dict.get(GROUPS)[name] = dict()
            new_group = True

        if new_group and not identities:
            self.compact_dict.get(GROUPS).pop(name)
            raise ValueError("Empty agent group")
        if new_group and not agent_roles and not rpc_capabilities and not pubsub_capabilities:
            self.compact_dict.get(GROUPS).pop(name)
            raise ValueError(
                f"agent group {name} should have non empty capabilities. Please pass non empty values "
                "for at least one of the three parameters - agent_roles, rpc_capabilities, pubsub_capabilities")

        group_dict = self.compact_dict.get(GROUPS).get(name)
        # todo validate ids
        current_ids_set = set(group_dict.get('identities', []))
        current_ids_set.update(identities)
        group_dict[IDENTITIES] = list(current_ids_set)

        if agent_roles:
            # todo validate agent_roles
            VolttronAuthzMap.update_agent_roles(group_dict, authz_converter.unstructure(agent_roles))

        VolttronAuthzMap.update_rpc_capabilities(group_dict, authz_converter.unstructure(rpc_capabilities))
        VolttronAuthzMap.update_pubsub_capabilities(group_dict, authz_converter.unstructure(pubsub_capabilities))

        if group_dict.get("agent_roles"):
            self.expand_agent_capabilities(agent_capabilities=self.agent_capabilities,
                                           agent_groups={name: group_dict},
                                           roles=self.compact_dict.get(ROLES))
        else:
            self.expand_agent_capabilities(agent_capabilities=self.agent_capabilities, agent_groups={name: group_dict})
        return True

    def remove_agents_from_group(self, name: str, identities: list[Identity]) -> bool:
        if not self.compact_dict.get(GROUPS) or name not in self.compact_dict[GROUPS]:
            return False
        s = set(self.compact_dict[GROUPS][name][IDENTITIES])
        self.compact_dict[GROUPS][name][IDENTITIES] = list(s - set(identities))
        # expand will only create or merge so reset agent_capabilities to compact_dict value and then expand
        for _id in identities:
            self.agent_capabilities[_id] = copy.deepcopy(self.compact_dict[AGENTS][_id])
        VolttronAuthzMap.expand_agent_capabilities(agent_capabilities=self.agent_capabilities,
                                                   agent_groups={name: self.compact_dict[GROUPS][name]},
                                                   roles=self.compact_dict[ROLES])
        return True

    def add_agents_to_group(self, name: str, identities: list[Identity]):
        if not self.compact_dict.get(GROUPS) or name not in self.compact_dict[GROUPS]:
            return False
        # TODO validate identity
        s = set(self.compact_dict[GROUPS][name][IDENTITIES])
        s.update(identities)
        self.compact_dict[GROUPS][name][IDENTITIES] = list(s)
        VolttronAuthzMap.expand_agent_capabilities(agent_capabilities=self.agent_capabilities,
                                                   agent_groups={name: self.compact_dict[GROUPS][name]},
                                                   roles=self.compact_dict[ROLES])
        return True

    def create_or_merge_agent_authz(self,
                                    *,
                                    identity: str,
                                    protected_rpcs: list[str] = None,
                                    agent_roles: AgentRoles = None,
                                    rpc_capabilities: RPCCapabilities = None,
                                    pubsub_capabilities: PubsubCapabilities = None,
                                    comments: str = None,
                                    **kwargs) -> bool:

        if not identity:
            raise ValueError("agent identity is mandatory")

        if not self.compact_dict.get(AGENTS):
            self.compact_dict[AGENTS] = dict()
            self.agent_capabilities = dict()
        if identity not in self.compact_dict.get(AGENTS):
            self.compact_dict.get(AGENTS)[identity] = dict()

        agent_dict = self.compact_dict.get(AGENTS).get(identity)

        if protected_rpcs:
            current_rpc_set = set(agent_dict.get("protected_rpcs", list()))
            current_rpc_set.update(protected_rpcs)
            agent_dict["protected_rpcs"] = list(current_rpc_set)

        if agent_roles:
            VolttronAuthzMap.update_agent_roles(agent_dict, authz_converter.unstructure(agent_roles))
        if rpc_capabilities:
            VolttronAuthzMap.update_rpc_capabilities(agent_dict, authz_converter.unstructure(rpc_capabilities))
        if pubsub_capabilities:
            VolttronAuthzMap.update_pubsub_capabilities(agent_dict, authz_converter.unstructure(pubsub_capabilities))
        if comments:
            agent_dict["comments"] = comments

        self.agent_capabilities[identity] = copy.deepcopy(agent_dict)
        VolttronAuthzMap.expand_agent_capabilities(agent_capabilities=self.agent_capabilities,
                                                   agent_groups=self.compact_dict.get(GROUPS),
                                                   roles=self.compact_dict.get(ROLES))
        return True

    def get_protected_rpcs(self, identity) -> list[str]:
        id_authz = self.agent_capabilities.get(identity)
        if not id_authz:
            raise ValueError(f"Invalid agent identity {identity}")
        return id_authz.get("protected_rpcs", [])

    def create_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        _topics = self.compact_dict.get("protected_topics", [])
        if not _topics:
            self.compact_dict["protected_topics"] = topic_name_patterns
            return True

        return_value = False
        for topic_name_pattern in topic_name_patterns:
            if topic_name_pattern not in _topics:
                _topics.append(topic_name_pattern)
                return_value = True
        return return_value

    def remove_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        _topics = self.compact_dict.get("protected_topics")
        if not _topics:
            return False

        return_value = False
        for topic_name_pattern in topic_name_patterns:
            if topic_name_pattern in _topics:
                _topics.remove(topic_name_pattern)
                return_value = True
        return return_value

    def is_protected_topic(self, *, topic_name_pattern: str) -> bool:
        from volttron.utils import is_regex

        # 1. Check that we have any protected topics.
        if not self.compact_dict.get('protected_topics'):
            return False

        # TODO make the compile a part of the create and merge rather than having it as a loop here.
        # 2. Determine if the topic_name_pattern is a regex or not.  If not then
        #    the string is a topic prefix so we add a .* to the end so that it
        #    becomes a regular expression.
        for tp in self.compact_dict["protected_topics"]:
            if is_regex(tp):
                compiled = re.compile(tp[1:-1])
            else:
                compiled = re.compile(tp + ".*")
            if compiled.match(topic_name_pattern):
                return True

        return False

    def remove_agent_authorization(self, identity: Identity):
        if not self.compact_dict.get(AGENTS) or identity not in self.compact_dict.get(AGENTS):
            return False
        else:
            del self.compact_dict.get(AGENTS)[identity]
            return True

    def remove_agent_group(self, name: str):
        if not self.compact_dict.get(GROUPS) or name not in self.compact_dict.get(GROUPS):
            return False
        else:
            del self.compact_dict.get(GROUPS)[name]
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
    if instance.agent_groups:
        authz_map_dict[GROUPS] = authz_converter.unstructure(instance.agent_groups)
    if instance.agents:
        authz_map_dict[AGENTS] = authz_converter.unstructure(instance.agents)
    return authz_map_dict


authz_converter.register_unstructure_hook(RPCCapabilities, unstructure_rpc_capabilities)
authz_converter.register_unstructure_hook(PubsubCapabilities, unstructure_pubsub_capabilities)
authz_converter.register_unstructure_hook(Roles, unstructure_roles)
authz_converter.register_unstructure_hook(AgentGroups, unstructure_agent_groups)
authz_converter.register_unstructure_hook(AgentRoles, unstructure_agent_roles)
authz_converter.register_unstructure_hook(Agents, unstructure_agents)
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
    test_roles = Roles([Role("admin", test_rpc_list), Role("new_role", pubsub_capabilities=test_pubsub_list)])
    print(test_roles)
    test_roles_dict = authz_converter.unstructure(test_roles)
    print(test_roles_dict)

    test_group = AgentGroups([
        AgentGroup("admin_agents", ["volttron.ctl", "config.store"],
                   agent_roles=AgentRoles([AgentRole(role_name="admin")]),
                   pubsub_capabilities=test_pubsub_list)
    ])
    print(test_group)
    test_group_dict = authz_converter.unstructure(test_group)
    print(test_group_dict)

    test_agents = Agents([
        Agent("volttron.ctl", agent_roles=AgentRoles([AgentRole("admin")])),
    # Agent("hist1", rpc_capabilities=test_rpc_list),
        Agent("listener1",
              agent_roles=AgentRoles([AgentRole(role_name="role1", param_restrictions={"param1": "value1"})]))
    ])
    print(test_agents)
    test_agents_dict = authz_converter.unstructure(test_agents)
    print(test_agents_dict)

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

    # #test expand agent caps
