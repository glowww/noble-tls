import asyncio
import base64
import urllib.parse
import random
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional, Union

from .encoding import lib_response_decoder, json_encoder
from .__version__ import __version__
from .c.cffi import request, free_memory
from .cookies import cookiejar_from_dict, merge_cookies, extract_cookies_to_jar
from .exceptions.exceptions import TLSClientException
from .response import build_response
from .utils.identifiers import Client
from .utils.session_utils import random_session_id
from .utils.structures import CaseInsensitiveDict


class Session:
    def __init__(
            self,
            client: Optional[Client] = None,
            ja3_string: Optional[str] = None,
            h2_settings: Optional[dict] = None,
            h2_settings_order: Optional[list] = None,
            supported_signature_algorithms: Optional[list] = None,
            supported_delegated_credentials_algorithms: Optional[list] = None,
            supported_versions: Optional[list] = None,
            key_share_curves: Optional[list] = None,
            cert_compression_algo: str = None,
            additional_decode: str = None,
            pseudo_header_order: Optional[list] = None,
            connection_flow: Optional[int] = None,
            priority_frames: Optional[list] = None,
            header_priority: Optional[dict] = None,  # Optional[list[str]]
            random_tls_extension_order: Optional[bool] = False,
            force_http1: Optional[bool] = False,
            catch_panics: Optional[bool] = False,
            debug: Optional[bool] = False,
            transportOptions: Optional[dict] = None,
            connectHeaders: Optional[dict] = None,
            executor: ThreadPoolExecutor = None
    ) -> None:
        self.client_identifier = client.value if client else None
        self._session_id = random_session_id()


        self.proxies = {}
        self.params = {}
        self.cookies = cookiejar_from_dict({})
        self.timeout_seconds = 30

        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algo = cert_compression_algo
        self.additional_decode = additional_decode
        self.pseudo_header_order = pseudo_header_order
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames

        # Order of your headers
        # Example:
        # [
        #   "key1",
        #   "key2"
        # ]

        # Header Priority
        # Example:
        # {
        #   "streamDep": 1,
        #   "exclusive": true,
        #   "weight": 1
        # }
        self.header_priority = header_priority
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.transportOptions = transportOptions
        self.connectHeaders = connectHeaders
        self.catch_panics = catch_panics
        self.debug = debug

        # loop
        self.loop = asyncio.get_event_loop()
        
        self.executor = executor or ThreadPoolExecutor()

    @property
    def timeout(self):
        return self.timeout_seconds

    @timeout.setter
    def timeout(self, seconds):
        self.timeout_seconds = seconds

    async def close(self):
        """Destroy this session in the Go library, freeing connections and memory."""
        payload = dumps({"sessionId": self._session_id}).encode('utf-8')
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, destroy_session, payload)
        response_bytes = ctypes.string_at(response)
        response_object = loads(response_bytes.decode('utf-8'))
        await loop.run_in_executor(None, free_memory, response_object['id'].encode('utf-8'))
        return response_object.get("success", False)

    @staticmethod
    async def close_all():
        """Destroy all sessions in the Go library."""
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, destroy_all)
        response_bytes = ctypes.string_at(response)
        response_object = loads(response_bytes.decode('utf-8'))
        await loop.run_in_executor(None, free_memory, response_object['id'].encode('utf-8'))
        return response_object.get("success", False)

    async def get_cookies(self, url: str) -> list:
        """Get cookies stored in the Go session for a given URL."""
        payload = dumps({"sessionId": self._session_id, "url": url}).encode('utf-8')
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, get_cookies_from_session, payload)
        response_bytes = ctypes.string_at(response)
        response_object = loads(response_bytes.decode('utf-8'))
        await loop.run_in_executor(None, free_memory, response_object['id'].encode('utf-8'))
        return response_object.get("cookies", [])

    async def add_cookies(self, url: str, cookies: list[dict]) -> list:
        """Add cookies to the Go session for a given URL.
        Each cookie dict: {name, value, domain, path, expires, maxAge, secure, httpOnly}
        """
        payload = dumps({
            "sessionId": self._session_id,
            "url": url,
            "cookies": cookies,
        }).encode('utf-8')
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, add_cookies_to_session, payload)
        response_bytes = ctypes.string_at(response)
        response_object = loads(response_bytes.decode('utf-8'))
        await loop.run_in_executor(None, free_memory, response_object['id'].encode('utf-8'))
        return response_object.get("cookies", [])

    async def execute_request(
            self,
            method: str,
            url: str,
            params: Optional[dict] = None,
            data: Optional[Union[str, dict]] = None,
            headers: Optional[dict] = None,
            cookies: Optional[dict] = None,
            json: Optional[dict] = None,
            allow_redirects: Optional[bool] = True,
            insecure_skip_verify: Optional[bool] = False,
            timeout_seconds: Optional[int] = None,
            timeout: Optional[int] = None,
            timeout_milliseconds: Optional[int] = None,
            proxy: Optional[dict] = None,
            is_byte_response: Optional[bool] = False,
            request_host_override: Optional[str] = None,
            stream_output_path: Optional[str] = None,
            stream_output_block_size: Optional[int] = None,
            stream_output_eof_symbol: Optional[str] = None,
    ):
        timeout_seconds = timeout or timeout_seconds or self.timeout_seconds
        del timeout

        history = []

        if params is not None:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"

        # --- Request Body ---------------------------------------------------------------------------------------------
        # Prepare request body - build request body
        # Data has priority. JSON is only used if data is None.


        
        if data is None and json is not None:
            if type(json) in [dict, list]:
                json = json_encoder.encode(json)
            request_body = json
            content_type = "application/json"
        elif data is not None and type(data) not in [str, bytes]:
            request_body = urllib.parse.urlencode(data, doseq=True)
            content_type = "application/x-www-form-urlencoded"
        else:
            request_body = data
            content_type = None

        # --- Headers --------------------------------------------------------------------------------------------------
        
        # This is unnecessary imo
        ci_headers = CaseInsensitiveDict(headers)

        if content_type is not None:
            ci_headers["content-type"] = content_type

        headers_result = {}
        header_order = []

        # Set headers like cookie, content-length to None to set their header order
        for key, value in ci_headers.lower_items():
            header_order.append(key)
            if value is not None:
                headers_result[key] = value
        # --- Cookies --------------------------------------------------------------------------------------------------
        cookies = cookies or {}
        cookies = merge_cookies(self.cookies, cookies)
        # Strip quotes from cookie values — fhttp in Go doesn't accept them
        request_cookies = [
            {'domain': c.domain, 'expires': c.expires, 'name': c.name, 'path': c.path,
             'value': c.value.replace('"', "")}
            for c in cookies
        ]

        proxy = proxy or self.proxies
        if type(proxy) is dict and "http" in proxy:
            proxy = proxy["http"]
        elif type(proxy) is str:
            proxy = proxy
        else:
            proxy = ""

        while True:
            is_byte_request = isinstance(request_body, (bytes, bytearray))
            request_payload = {
                "sessionId": self._session_id,
                "followRedirects": allow_redirects,
                "forceHttp1": self.force_http1,
                "withDebug": self.debug,
                "catchPanics": self.catch_panics,
                "headers": headers_result,
                "headerOrder": header_order,
                "insecureSkipVerify": insecure_skip_verify,
                "isByteRequest": is_byte_request,
                "isByteResponse": is_byte_response,
                "additionalDecode": self.additional_decode,
                "proxyUrl": proxy,
                "requestUrl": url,
                "requestMethod": method,
                "requestBody": base64.b64encode(request_body).decode() if is_byte_request else request_body,
                "requestCookies": request_cookies,
                "timeoutSeconds": timeout_seconds,
                "transportOptions": self.transportOptions,
                "connectHeaders": self.connectHeaders,
                "disableIPV6": self.disable_ipv6,
                "disableIPV4": self.disable_ipv4,
                "isRotatingProxy": self.is_rotating_proxy,
                "withoutCookieJar": self.without_cookie_jar,
                "disableHttp3": self.disable_http3,
                "withProtocolRacing": self.protocol_racing,
            }

            if timeout_milliseconds is not None:
                request_payload["timeoutMilliseconds"] = timeout_milliseconds
                request_payload.pop("timeoutSeconds", None)

            if request_host_override is not None:
                request_payload["requestHostOverride"] = request_host_override
            if self.server_name_overwrite is not None:
                request_payload["serverNameOverwrite"] = self.server_name_overwrite
            if self.local_address is not None:
                request_payload["localAddress"] = self.local_address
            if self.certificate_pinning is not None:
                request_payload["certificatePinningHosts"] = self.certificate_pinning
            if self.default_headers is not None:
                request_payload["defaultHeaders"] = self.default_headers

            if stream_output_path is not None:
                request_payload["streamOutputPath"] = stream_output_path
            if stream_output_block_size is not None:
                request_payload["streamOutputBlockSize"] = stream_output_block_size
            if stream_output_eof_symbol is not None:
                request_payload["streamOutputEOFSymbol"] = stream_output_eof_symbol

            if self.client_identifier is None:
                custom_tls = {
                    "ja3String": self.ja3_string,
                    "h2Settings": self.h2_settings,
                    "h2SettingsOrder": self.h2_settings_order,
                    "pseudoHeaderOrder": self.pseudo_header_order,
                    "connectionFlow": self.connection_flow,
                    "priorityFrames": self.priority_frames,
                    "headerPriority": self.header_priority,
                    "certCompressionAlgos": [self.cert_compression_algo] if self.cert_compression_algo else None,
                    "alpnProtocols": ["h2", "http/1.1"],
                    "supportedVersions": self.supported_versions,
                    "supportedSignatureAlgorithms": self.supported_signature_algorithms,
                    "supportedDelegatedCredentialsAlgorithms": self.supported_delegated_credentials_algorithms,
                    "keyShareCurves": self.key_share_curves,
                }

                if self.alps_protocols is not None:
                    custom_tls["alpsProtocols"] = self.alps_protocols
                if self.ech_candidate_payloads is not None:
                    custom_tls["eCHCandidatePayloads"] = self.ech_candidate_payloads
                if self.ech_candidate_cipher_suites is not None:
                    custom_tls["eCHCandidateCipherSuites"] = self.ech_candidate_cipher_suites
                if self.allow_http is not None:
                    custom_tls["allowHttp"] = self.allow_http
                if self.record_size_limit is not None:
                    custom_tls["recordSizeLimit"] = self.record_size_limit
                if self.stream_id is not None:
                    custom_tls["streamId"] = self.stream_id

                if self.h3_settings is not None:
                    custom_tls["h3Settings"] = self.h3_settings
                if self.h3_settings_order is not None:
                    custom_tls["h3SettingsOrder"] = self.h3_settings_order
                if self.h3_pseudo_header_order is not None:
                    custom_tls["h3PseudoHeaderOrder"] = self.h3_pseudo_header_order
                if self.h3_priority_param is not None:
                    custom_tls["h3PriorityParam"] = self.h3_priority_param
                if self.h3_send_grease_frames is not None:
                    custom_tls["h3SendGreaseFrames"] = self.h3_send_grease_frames

                request_payload["customTlsClient"] = custom_tls
            else:
                request_payload["tlsClientIdentifier"] = self.client_identifier
                request_payload["withRandomTLSExtensionOrder"] = self.random_tls_extension_order

            loop = asyncio.get_event_loop()
            # this is a pointer to the response
            response = await loop.run_in_executor(self.executor, request, json_encoder.encode(request_payload))
            # convert response bytes to json
            response_object = lib_response_decoder.decode(response)
            # free the memory
            loop.run_in_executor(self.executor, free_memory, response_object.id.encode('utf-8'))

            # --- Response -------------------------------------------------------------------------------------------------
            # Error handling
            if response_object.status == 0:
                raise TLSClientException(response_object.body)
            # Set response cookies
            response_cookie_jar = extract_cookies_to_jar(
                request_url=url,
                request_headers=CaseInsensitiveDict(headers_result),
                cookie_jar=cookies,
                response_headers=response_object.headers
            )

            current_response = build_response(response_object, response_cookie_jar)

            if allow_redirects:
                if 'Location' in (headers := current_response.headers) and current_response.status_code in (
                        300, 301, 302, 303, 307, 308
                ):
                    history.append(current_response)
                    url = headers['Location']
                else:
                    break
            else:
                break

        current_response.history = history
        return current_response

    async def get(self, url: str, **kwargs: Any):
        return await self.execute_request(method="GET", url=url, **kwargs)

    async def options(self, url: str, **kwargs: Any):
        return await self.execute_request(method="OPTIONS", url=url, **kwargs)

    async def head(self, url: str, **kwargs: Any):
        return await self.execute_request(method="HEAD", url=url, **kwargs)

    async def post(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any):
        return await self.execute_request(method="POST", url=url, data=data, json=json, **kwargs)

    async def put(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any):
        return await self.execute_request(method="PUT", url=url, data=data, json=json, **kwargs)

    async def patch(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any):
        return await self.execute_request(method="PATCH", url=url, data=data, json=json, **kwargs)

    async def delete(self, url: str, **kwargs: Any):
        return await self.execute_request(method="DELETE", url=url, **kwargs)
