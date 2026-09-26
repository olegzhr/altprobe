from dataclasses import dataclass, field
from typing import Any, Optional


class GreetingLanguage:
    EN = "en"
    ES = "es"
    FR = "fr"

    GREETINGS = {
        EN: "Hello, {name}!",
        ES: "\u00a1Hola, {name}!",
        FR: "Bonjour, {name}!",
    }


@dataclass
class MCPRequest:
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse:
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            d["error"] = self.error
        else:
            d["result"] = self.result
        return d
