from typing import Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

 
@dataclass
class Message:
    content: str
    role: str = "user"
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class Agent:
    def __init__(
        self,
        agent_id: str = "agent",
        name: str = "Agent",
        capabilities: List[str] = None
    ):
        self.agent_id = agent_id
        self.name = name
        self.capabilities = capabilities or []
        self.model = None
        self.model_name = None
        self.model_loaded = False
        self.conversation_history: List[Message] = []
        self.knowledge: Dict[str, Any] = {}
    
    def add_capability(self, capability: str):
        if capability not in self.capabilities:
            self.capabilities.append(capability)
    
    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities
    
    async def think(self, prompt: str) -> str:
        raise NotImplementedError("Subclass must implement think()")
    
    def load_model(self, model_path: str = None) -> bool:
        raise NotImplementedError("Subclass must implement load_model()")
