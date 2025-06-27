import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import gevent
import httpx
from httpx import HTTPError

from volttron.server.decorators import service
from volttron.client.known_identities import PLATFORM_FEDERATION, PLATFORM
from volttron.client.vip.agent import Agent, Core
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_service import AuthService
from volttron.types import MessageBus
from volttron.utils import set_agent_identity

_log = logging.getLogger(__name__)

DEFAULT_GROUP = "default"
DEFAULT_RETRY_PERIOD = 30  # seconds
logging.getLogger("httpcore.http11").setLevel(logging.WARNING)
logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
class _PlatformInstance:
    """Represents a connected remote VOLTTRON platform"""
    
    def __init__(self, platform_id: str, address: str, public_credentials: str, group: str = DEFAULT_GROUP):
        self.platform_id = platform_id
        self.address = address
        self.public_credentials = public_credentials
        self.group = group
        self.connected = False
        self.last_heartbeat = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "id": self.platform_id,
            "address": self.address,
            "public_credentials": self.public_credentials,
            "group": self.group,
            "connected": self.connected,
            "last_heartbeat": self.last_heartbeat
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> '_PlatformInstance':
        """Create instance from dictionary"""
        instance = cls(
            platform_id=data["id"],
            address=data["address"],
            public_credentials=data["public_credentials"],
            group=data.get("group", DEFAULT_GROUP)
        )
        instance.connected = data.get("connected", False)
        instance.last_heartbeat = data.get("last_heartbeat")
        return instance

@service
class FederationService(Agent):
    """
    Service that manages connections between multiple VOLTTRON platforms.
    Enables cross-platform message routing and RPC calls.
    """
    class Meta:
        identity = PLATFORM_FEDERATION
    
    def __init__(self, options: ServerOptions, auth_service: AuthService, messagebus: MessageBus, **kwargs):
        
        kwargs["identity"] = self.Meta.identity
        with set_agent_identity(self.Meta.identity):
            super().__init__(address=options.service_address, **kwargs)
        
        self._options = options
        self._auth_service = auth_service
        self._messagebus = messagebus
        self._connected_platforms: Dict[str, _PlatformInstance] = {}
        self._is_running = False
        self._registry_url = None
        self._httpx_client = httpx.Client(timeout=10.0)
        self._federation_config_path = Path(self._options.volttron_home) / "federation_config.json"
        self._federation_bridge = None 
        self._federation_enabled = self._options.enable_federation
        self._retry_period = DEFAULT_RETRY_PERIOD
        self._registry_connection_successful = False
        self._registry_last_attempt = 0
        
        # Load any existing federation configuration
        self._load_config()
        
        # If federation is enabled and URL is set in options, register at startup
        if options.enable_federation and options.federation_url:
            self._registry_url = options.federation_url.split('#')[0]
            
    def _load_config(self):
        """Load federation configuration from file"""
        if not self._federation_config_path.exists():
            _log.info("No federation configuration file found, creating new configuration")
            self._save_config()
            return
            
        try:
            config = json.loads(self._federation_config_path.read_text())
            self._registry_url = config.get('registry_url')
            
            # Load platforms from config
            platforms_data = config.get('platforms', [])
            for platform_data in platforms_data:
                try:
                    platform = _PlatformInstance.from_dict(platform_data)
                    self._connected_platforms[platform.platform_id] = platform
                except Exception as e:
                    _log.error(f"Error loading platform from config: {e}")
                    
            _log.info(f"Loaded federation configuration with {len(self._connected_platforms)} platforms")
        except Exception as e:
            _log.error(f"Error loading federation config: {e}")
            # Create a new config file if loading fails
            self._save_config()
    
    def _save_config(self):
        """Save federation configuration to file"""
        try:
            config = {
                'registry_url': self._registry_url,
                'platforms': [platform.to_dict() for platform in self._connected_platforms.values() if platform.platform_id != self._options.instance_name]
            }
            
            self._federation_config_path.write_text(json.dumps(config, indent=2))
            _log.debug("Saved federation configuration")
        except Exception as e:
            _log.error(f"Error saving federation config: {e}")

    def _start_federation(self):

        if self._federation_enabled:
            self._federation_bridge = self._messagebus.create_federation_bridge()
            if not self._federation_bridge:
                _log.error("Federation bridge not available, cannot start federation service")
                return
            
            # If we have a registry URL, register and discover platforms
            if self._registry_url:
                # Schedule registration with retry mechanism
                self._registry_greenlet = gevent.spawn(self._registry_connection_loop)
            else:
                # If no registry, just connect to platforms from config
                self._connect_to_stored_platforms()
                

    
    @Core.receiver("onstart")
    def _on_start(self, sender, **kwargs):
        """Handle startup tasks"""
        _log.info(f"Starting Federation Service with identity {self.core.identity}")
        self._is_running = True
        self._start_federation()        

    def _registry_connection_loop(self):
        """Periodically try to register and get platforms from the registry"""
        while self._is_running:
            try:
                if not self._registry_connection_successful:
                    # Handle registration only if not successful yet
                    self._registry_connection_successful = self._attempt_registration()
                else:
                    # If already registered, just update platform list
                    self._discover_platforms()
            except Exception as e:
                _log.error(f"Error in registry connection loop: {e}")
                self._registry_connection_successful = False
                    
            # Sleep before next attempt
            self._registry_last_attempt = time.time()
            gevent.sleep(self._retry_period)

    def _attempt_registration(self) -> bool:
        """Try to register with federation registry"""
        if not self._registry_url:
            return False
            
        _log.debug(f"Attempting to register with federation registry at {self._registry_url}")
        success = self.register_with_federation(self._registry_url)
        
        if success:
            _log.info("Successfully registered with federation registry")
            # Do an initial platform discovery
            self._discover_platforms()
        else:
            _log.warning(f"Failed to register with registry, will retry in {self._retry_period} seconds")
        
        return success

    def _discover_platforms(self):
        """Discover platforms and manage connections"""
        connected_count = self.discover_and_connect_platforms()
        _log.debug(f"Platform discovery found {connected_count} platforms")
    
    
    def _connect_to_stored_platforms(self):
        """Connect to platforms stored in configuration"""
        for platform_id, platform in list(self._connected_platforms.items()):
            try:
                _log.info(f"Connecting to stored platform {platform_id} at {platform.address}")
                self._connect_platform(platform)
            except Exception as e:
                _log.error(f"Failed to connect to stored platform {platform_id}: {e}")
            
    @Core.receiver("onstop")
    def _on_stop(self, sender, **kwargs):
        """Handle shutdown tasks"""
        _log.info(f"Stopping Federation Service")
        self._is_running = False
        
        # Stop connection loop greenlet
        if hasattr(self, '_registry_greenlet'):
            self._registry_greenlet.kill()
        
        # If registered with a federation registry, attempt to unregister
        if self._registry_url and self._options.instance_name and self._registry_connection_successful:
            try:
                self._httpx_client.delete(
                    f"{self._registry_url}/platform/{self._options.instance_name}",
                    headers={"accept": "application/json"}
                )
                _log.info(f"Unregistered from federation registry at {self._registry_url}")
            except Exception as e:
                _log.error(f"Failed to unregister from federation registry: {e}")
        
        # Close httpx client
        self._httpx_client.close()
        
        # Disconnect from all platforms
        self._disconnect_all_platforms()
        
        # Save final state to configuration
        self._save_config()
    
    def register_with_federation(self, registry_url: str) -> bool:
        """
        Register this platform with a federation registry.
        
        :param registry_url: URL of the federation registry service
        :return: True if registration was successful
        """
        self._registry_url = registry_url
        
        # Determine platform ID
        local_platform_id = self._options.instance_name
        if not local_platform_id:
            _log.error("Cannot register with federation: no platform ID available")
            return False
            
        # Get our platform's address
        if not self._options.address or len(self._options.address) == 0:
            _log.error("Cannot register with federation: no platform address available")
            return False
            
        # Use the first address as our externally reachable address
        platform_address = self._options.address[0]
        
        # Simple validation of the address format
        if not (platform_address.startswith('tcp://') or 
                platform_address.startswith('ipc://') or 
                platform_address.startswith('inproc://')):
            _log.error(f"Invalid address format for federation: {platform_address}")
            _log.error("Address should start with tcp://, ipc://, or inproc://")
            return False
        
        # Get our platform's public credentials using auth service
        public_credentials = None
        try:
            # Use auth_service directly instead of VIP
            public_credentials = self._auth_service.get_credentials(identity=PLATFORM).get_public_part()
            if not public_credentials:
                _log.error("Auth service returned empty platform public key")
        except Exception as e:
            _log.error(f"Error getting platform public key from auth service: {e}")
            
        if not public_credentials:
            _log.error("Cannot register with federation: no public credential available")
            return False
            
        # Register our platform with the federation registry
        _log.info(f"Registering platform {local_platform_id} with federation registry at {registry_url}")
        registration_data = {
            "address": platform_address,
            "group": DEFAULT_GROUP,  # Default group can be customized
            "id": local_platform_id,
            "public_credentials": public_credentials  # Match API field name
        }
        
        try:
            # Post our platform to the registry
            response = self._httpx_client.post(
                f"{registry_url}/platform", 
                headers={"accept": "application/json", "Content-Type": "application/json"},
                json=registration_data,
                timeout=5.0  # Short timeout for responsiveness
            )
            response.raise_for_status()
            _log.info(f"Successfully registered with federation registry: {response.text}")
            
            # Save the configuration with registry URL
            self._save_config()
            
            # Discover and connect to other platforms
            return self.discover_and_connect_platforms() >= 0
            
        except HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') else "unknown"
            _log.error(f"HTTP error registering with federation registry (status {status_code}): {e}")
            return False
        except Exception as e:
            _log.error(f"Failed to register with federation registry: {e}")
            return False
    
    def discover_and_connect_platforms(self) -> int:
        """
        Discover platforms from the registry and connect to them.
        
        :return: Number of platforms connected, -1 if error
        """
        if not self._registry_url:
            _log.error("Cannot discover platforms: no registry URL configured")
            return -1
            
        try:
            # Get list of platforms from registry
            response = self._httpx_client.get(
                f"{self._registry_url}/platforms", 
                headers={"accept": "application/json"},
                timeout=5.0  # Short timeout for responsiveness
            )
            response.raise_for_status()
            platforms_data = response.json()
            
            connected_count = 0
            local_platform_id = self._options.instance_name
            
            # Process each platform
            for platform_data in platforms_data:
                # Skip ourselves
                if platform_data["id"] == local_platform_id:
                    continue
                    
                platform_id = platform_data["id"]
                
                try:
                    # Check if we already have this platform
                    if platform_id in self._connected_platforms:
                        existing_platform = self._connected_platforms[platform_id]
                        
                        # Check if anything has changed that requires reconnection
                        if (existing_platform.address != platform_data["address"] or 
                            existing_platform.public_credentials != platform_data["public_credentials"]):
                            
                            _log.info(f"Platform {platform_id} details changed, reconnecting")
                            # Disconnect existing connection
                            try:
                                self._disconnect_platform(existing_platform)
                            except:
                                _log.warning(f"Error disconnecting from platform {platform_id} before update")
                                
                            # Create updated platform instance
                            platform = _PlatformInstance(
                                platform_id=platform_id,
                                address=platform_data["address"],
                                public_credential=platform_data["public_credentials"],
                                group=platform_data.get("group", DEFAULT_GROUP)
                            )
                            
                            # Store updated platform
                            self._connected_platforms[platform_id] = platform
                            
                            # Connect to updated platform
                            self._connect_platform(platform)
                            connected_count += 1
                        else:
                            # Platform exists with same details, just count it
                            connected_count += 1 if existing_platform.connected else 0
                    else:
                        # New platform discovered
                        _log.info(f"Discovered new platform: {platform_id}")
                        
                        # Create _PlatformInstance object
                        platform = _PlatformInstance(
                            platform_id=platform_id,
                            address=platform_data["address"],
                            public_credentials=platform_data["public_credentials"],
                            group=platform_data.get("group", DEFAULT_GROUP)
                        )
                        
                        # Store in our registry
                        self._connected_platforms[platform_id] = platform
                        
                        # Connect to the platform
                        _log.info(f"Connecting to federated platform: {platform_id} at {platform.address}")
                        self._connect_platform(platform)
                        connected_count += 1
                except Exception as e:
                    _log.error(f"Error processing platform {platform_id}: {e}")
                    
            # Save updated configuration
            self._save_config()
            
            return connected_count
            
        except HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') else "unknown"
            _log.error(f"HTTP error discovering platforms (status {status_code}): {e}")
            return -1
        except Exception as e:
            _log.error(f"Failed to discover platforms: {e}")
            return -1
    
    def _connect_platform(self, platform: _PlatformInstance):
        """
        Establish connection to a platform
        
        :param platform: _PlatformInstance object containing connection details
        """
        try:
            if not self._federation_bridge:
                _log.error(f"Cannot connect to platform {platform.platform_id}: federation bridge not initialized")
                return False
            
            _log.debug(f"Attempting connection to platform {platform.platform_id} at {platform.address}")
            
            # Use the existing connect method from ZmqFederationBridge
            success = self._federation_bridge.connect(
                platform_id=platform.platform_id,
                platform_address=platform.address,
                credentials=platform.public_credentials
            )
            
            if success:
                _log.info(f"Successfully established connection to platform {platform.platform_id}")
                platform.connected = True
                platform.last_heartbeat = time.time()
            else:
                _log.error(f"Failed to connect to platform {platform.platform_id}")
                platform.connected = False
                
            return success
                
        except Exception as e:
            _log.error(f"Error connecting to platform {platform.platform_id}: {e}", exc_info=True)
            platform.connected = False
            return False
    
    def _is_platform_connected(self, platform_id: str) -> bool:
        """Check if a platform is currently connected"""
        if not self._federation_bridge:
            return False
            
        try:
            # Use the federation bridge's ping method to check connection health
            return self._federation_bridge.ping(platform_id)
        except Exception as e:
            _log.error(f"Error checking connection to platform {platform_id}: {e}")
            return False
    
    def _disconnect_platform(self, platform: _PlatformInstance):
        """Disconnect from a specific platform"""
        if not self._federation_bridge:
            _log.error(f"Cannot disconnect platform {platform.platform_id}: federation bridge not initialized")
            return False
            
        try:
            # Use the federation bridge's disconnect method
            success = self._federation_bridge.disconnect(platform.platform_id)
            
            if success:
                platform.connected = False
                platform.last_heartbeat = None
                _log.info(f"Disconnected from platform {platform.platform_id}")
            else:
                _log.warning(f"Failed to disconnect from platform {platform.platform_id}")
                
            return success
        except Exception as e:
            _log.error(f"Error disconnecting from platform {platform.platform_id}: {e}", exc_info=True)
            return False
    
    def _disconnect_all_platforms(self):
        """Disconnect from all connected platforms"""
        for platform_id, platform in list(self._connected_platforms.items()):
            try:
                if platform.connected:
                    self._disconnect_platform(platform)
            except Exception as e:
                _log.error(f"Error disconnecting from platform {platform_id}: {e}")