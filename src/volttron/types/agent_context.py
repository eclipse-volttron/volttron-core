import functools
from dataclasses import dataclass, field
from dataclass_wizard import JSONSerializable

from volttron.types.auth.auth_credentials import Credentials
from volttron.types import Identity, Tag


@dataclass
class AgentOptions:
    heartbeat_autostart: bool = False
    '''If True, the heartbeat will start automatically'''

    heartbeat_period: int = 60
    '''If the heartbeat is started, this is the period in seconds between heartbeats'''

    volttron_home: str = None
    '''A setting for the volttron home directory, set by the platform if not set'''

    agent_uuid: str = None
    '''An installed agent's uuid'''

    enable_store: bool = True
    '''If True, the agent will have a config store and be able to store configurations'''

    reconnect_interval: int = None

    version: str = "0.1"
    volttron_central_address: str = None,
    volttron_central_instance_name: str = None,
    tag_vip_id: str = None,
    tag_refresh_interval: int = -1
    custom_options: dict[str, any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentContext:
    credentials: Credentials
    address: str | list[str]
    options: AgentOptions = field(default_factory=lambda: AgentOptions())

    # Use functools rather than try to modify the property of
    # frozen class
    @functools.cached_property
    def address(self):
        if isinstance(self.address, str):
            return [self.address]
        else:
            return self.address


@dataclass
class AgentInstallOptions(JSONSerializable):
    """ A metaclass for controling the installation of an agent onto the platform.

    Parameters
    ----------
    source : str
        The name of the agent to install from pypi or the name of the
        wheel file.  If the wheel file, then data parameter must be included.  If a wheel
        file the source MUST end with whl.
    start : bool = False
        Should the agent be started after installing successfully.
    data : str | None
        If source is specified as a .whl file, the data associated with the wheel file
        MUST be set in this variable.
    identity : Identity | None
        The identity of the installed agent.  If identity is not specified, then the
        name of the source will be used to create the agent.
    tag : Tag | None
        A tag associated with the agent
    editable: bool = False
       should be installed as editable package
    force : bool = False
        If the identity is already on the platform, should we overwrite it or not
    allow_prerelease: bool = False
        Should the platform allow pre-release artifacts or only releases from pypi.
    agent_config : dict = {}
        A default configuration for the agent to be installed.  This will be stored
        so that it is passed to the agent on startup.
    credentials : Credentials | None
        A set of credentials that should be used for this agent.  In general, the platform
        will generate credentials as the agent is installed, but this method allows the
        calling platform to specify them externally.  Make sure the passed credentials are
        available on the platform from the CredentialsFactory or this method will fail.
    enabled : bool = False
        An enabled agent will start when the platform is started.  If enabled and priority
        is not set then a 50 priority will be set.
    priority: int | None
        A priority specified means the agent is enabled.  The number should be between
        1-99 where lower numbers start first.

    Raises
    ------
    ValueError if there is an issue with any of the arguments passed to the class.

    Returns
    -------
    An agent uuid if the agent is successful
    """
    source: str
    start: bool = False
    data: str | None = None
    identity: Identity | None = None
    tag: Tag | None = None
    editable: bool = False
    force: bool = False
    allow_prerelease: bool = False
    agent_config: dict = field(default_factory=dict)
    credentials: Credentials | None = None
    enabled: bool = False
    priority: int | None = None

    def __post_init__(self):

        if self.priority is not None:
            if self.priority < 0 or self.priority > 99:
                raise ValueError(f"Invalid priority specified!")
            self.enabled = True

        if self.enabled and self.priority is None:
            self.priority = 50
