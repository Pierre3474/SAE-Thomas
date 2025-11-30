"""
Modèles de données partagés entre client et serveur
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json
from datetime import datetime

class UserRole(Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    READER = "reader"

class FirewallStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"

@dataclass
class User:
    username: str
    password_hash: str
    role: UserRole
    enabled: bool = True
    firewalls: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "role": self.role.value,
            "enabled": self.enabled,
            "firewalls": self.firewalls,
            "created_at": self.created_at
        }
    
    @staticmethod
    def from_dict(data):
        return User(
            username=data["username"],
            password_hash=data["password_hash"],
            role=UserRole(data["role"]),
            enabled=data.get("enabled", True),
            firewalls=data.get("firewalls", []),
            created_at=data.get("created_at", datetime.now().isoformat())
        )
    
    def has_access(self, firewall_name: str) -> bool:
        """Vérifie si l'utilisateur a accès à un pare-feu"""
        if self.role == UserRole.ADMIN:
            return True
        return firewall_name in self.firewalls

@dataclass
class IptablesRule:
    chain: str  # INPUT, OUTPUT, FORWARD
    protocol: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    sport: Optional[str] = None
    dport: Optional[str] = None
    state: Optional[str] = None
    interface: Optional[str] = None
    target: str = "ACCEPT"
    
    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v is not None}
    
    @staticmethod
    def from_dict(data):
        return IptablesRule(**data)
    
    def to_iptables_command(self, table: str = "filter", action: str = "A") -> str:
        """Génère la commande iptables correspondante"""
        cmd = f"iptables -t {table} -{action} {self.chain}"
        
        if self.protocol:
            cmd += f" -p {self.protocol}"
        if self.source:
            cmd += f" -s {self.source}"
        if self.destination:
            cmd += f" -d {self.destination}"
        if self.sport:
            cmd += f" --sport {self.sport}"
        if self.dport:
            cmd += f" --dport {self.dport}"
        if self.state:
            cmd += f" -m state --state {self.state}"
        if self.interface:
            cmd += f" -i {self.interface}"
        
        cmd += f" -j {self.target}"
        return cmd

@dataclass
class Firewall:
    name: str
    status: FirewallStatus = FirewallStatus.INACTIVE
    tables: Dict[str, Dict[str, List[IptablesRule]]] = field(default_factory=dict)
    interfaces: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        if not self.tables:
            self.tables = {
                "filter": {
                    "INPUT": [],
                    "OUTPUT": [],
                    "FORWARD": []
                },
                "nat": {
                    "PREROUTING": [],
                    "POSTROUTING": [],
                    "OUTPUT": []
                }
            }
    
    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status.value,
            "tables": {
                table_name: {
                    chain_name: [rule.to_dict() for rule in rules]
                    for chain_name, rules in chains.items()
                }
                for table_name, chains in self.tables.items()
            },
            "interfaces": self.interfaces,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @staticmethod
    def from_dict(data):
        tables = {}
        for table_name, chains in data.get("tables", {}).items():
            tables[table_name] = {}
            for chain_name, rules in chains.items():
                tables[table_name][chain_name] = [
                    IptablesRule.from_dict(rule) for rule in rules
                ]
        
        return Firewall(
            name=data["name"],
            status=FirewallStatus(data.get("status", "inactive")),
            tables=tables,
            interfaces=data.get("interfaces", []),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat())
        )

@dataclass
class Message:
    """Message échangé entre client et serveur"""
    type: str  # command, response, error
    data: Dict
    session_token: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_json(self) -> str:
        return json.dumps({
            "type": self.type,
            "data": self.data,
            "session_token": self.session_token,
            "timestamp": self.timestamp
        })
    
    @staticmethod
    def from_json(json_str: str) -> 'Message':
        data = json.loads(json_str)
        return Message(
            type=data["type"],
            data=data["data"],
            session_token=data.get("session_token"),
            timestamp=data.get("timestamp", datetime.now().isoformat())
        )

@dataclass
class LogEntry:
    """Entrée de log"""
    timestamp: str
    level: str  # INFO, ERROR, WARNING, CMD
    username: str
    message: str
    firewall: Optional[str] = None
    
    def to_string(self) -> str:
        fw = f"@{self.firewall}" if self.firewall else ""
        return f"[{self.timestamp}] [{self.level}] [{self.username}{fw}] {self.message}"
    
    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "username": self.username,
            "message": self.message,
            "firewall": self.firewall
        }