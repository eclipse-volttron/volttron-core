from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable

class FederationBridge(ABC):
    """
    Abstract interface for platform federation bridges.
    
    A FederationBridge enables communication between separate VOLTTRON platforms.
    It handles the details of establishing connections, routing messages, and
    monitoring connection health between federated platforms.
    
    Each message bus implementation (ZMQ, RMQ, etc.) provides its own 
    implementation of this interface, allowing the Federation Service to work with
    any message bus without knowing the implementation details.
    """
    
    @abstractmethod
    def connect(self, platform_id: str, platform_address: str, credentials: Any) -> bool:
        """
        Connect to a remote platform
        
        :param platform_id: ID of the remote platform
        :param platform_address: Address of the remote platform
        :param credentials: Authentication credentials for the platform
        :return: True if connection was successful
        """
        pass
        
    @abstractmethod
    def disconnect(self, platform_id: str) -> bool:
        """
        Disconnect from a remote platform
        
        :param platform_id: ID of the remote platform
        :return: True if disconnection was successful
        """
        pass
        
    @abstractmethod
    def get_status(self, platform_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get status of federation bridges
        
        :param platform_id: Optional ID to get status for a specific platform
        :return: Dictionary with status information
        """
        pass
        
    @abstractmethod
    def ping(self, platform_id: str, timeout: int = 5) -> bool:
        """
        Ping a remote platform to check connection health
        
        :param platform_id: ID of the remote platform
        :param timeout: Timeout in seconds
        :return: True if ping was successful
        """
        pass
        
    @abstractmethod
    def send_message(self, platform_id: str, topic: str, message: Any) -> bool:
        """
        Send a message to a specific platform
        
        :param platform_id: ID of the target platform
        :param topic: Message topic
        :param message: Message content
        :return: True if message was sent successfully
        """
        pass
        
    @abstractmethod
    def register_message_handler(self, handler: Callable[[str, str, Any], None]) -> None:
        """
        Register a handler for incoming federation messages
        
        :param handler: Callback function(platform_id, topic, message)
                        - platform_id: ID of the source platform
                        - topic: Message topic
                        - message: Message content
        """
        pass
        
    @abstractmethod
    def forward_vip_message(self, platform_id: str, sender: str, recipient: str, 
                           subsystem: str, args: Optional[List] = None) -> bool:
        """
        Forward a VIP message to a federated platform
        
        :param platform_id: ID of the target platform
        :param sender: Sender identity 
        :param recipient: Recipient identity on the target platform
        :param subsystem: VIP subsystem
        :param args: Message arguments
        :return: True if the message was forwarded successfully
        """
        pass