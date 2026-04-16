import json
from typing import Optional
from typing import Union, Dict

from requests.exceptions import HTTPError

from .encoding import LibraryResponse
from noble_tls.utils.structures import CaseInsensitiveDict
from .cookies import cookiejar_from_dict


class Protocol(Enum):
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2.0"
    HTTP_3 = "HTTP/3.0"

    @classmethod
    def from_string(cls, value: str) -> "Protocol | None":
        if not value:
            return None
        for member in cls:
            if member.value == value:
                return member
        return None


class Response:

    def __init__(self):
        self.url: Optional[str] = None
        self.status_code: Optional[int] = None
        self.text: Optional[str] = None
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.cookies = cookiejar_from_dict({})
        self._content: Optional[bytes] = None
        self._content_consumed: bool = False
        self.history = []
        self.used_protocol: Optional[Protocol] = None

    def __enter__(self):
        return self

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def json(self, **kwargs) -> Union[Dict, list]:
        return json.loads(self.text, **kwargs)

    def raise_for_status(self):
        if 400 <= self.status_code < 500:
            raise HTTPError(f'Client Error: {self.status_code} for url: {self.url}')
        elif 500 <= self.status_code < 600:
            raise HTTPError(f'Server Error: {self.status_code} for url: {self.url}')

    @property
    def content(self) -> bytes:
        if self._content is None:
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed.")
            self._content = self.text.encode() if self.status_code != 0 else b""
            self._content_consumed = True
        return self._content


def build_response(res: LibraryResponse, res_cookies) -> Response:
    """Builds and returns a Response object from given data."""
    response = Response()
    response.url = res.target  # Extract the target URL from the response data.
    response.status_code = res.status  # Default to 0 if status is not provided.
    response.text = res.body  # Default to empty string if body is not provided.

    response_headers = CaseInsensitiveDict()
    for key, value in res.headers.items():
        response_headers[key] = value[0] if len(value) == 1 else value
    response.headers = response_headers

    response.cookies = res_cookies
    response.used_protocol = Protocol.from_string(res.get("usedProtocol"))
    return response
