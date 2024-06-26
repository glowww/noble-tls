from typing import Dict, List, Optional

import msgspec


class LibraryResponse(msgspec.Struct):
    id: str
    sessionId: str
    target: str
    usedProtocol: str
    status: int = 0
    body: str = ""
    cookies: Optional[Dict[str, str]] = {}
    headers: Optional[Dict[str, List[str]]] = {}


json_encoder = msgspec.json.Encoder()
lib_response_decoder = msgspec.json.Decoder(type=LibraryResponse)
