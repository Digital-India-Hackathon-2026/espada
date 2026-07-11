# runtime/core/request.py
"""
HTTP Request Model for Secure Runtime

This module defines the Request model used throughout the runtime pipeline.
It represents incoming HTTP requests with comprehensive metadata and helper
methods for accessing request data in various formats.
"""

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union, BinaryIO, Iterator
from datetime import datetime
from enum import Enum
from io import BytesIO
from urllib.parse import parse_qs, urlparse, unquote

from pydantic import BaseModel, Field, ConfigDict, validator, field_validator
from pydantic import ValidationError


class RequestMethod(str, Enum):
    """HTTP request methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


class RequestProtocol(str, Enum):
    """HTTP protocol versions"""
    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2.0"
    HTTP_3 = "HTTP/3.0"


class RequestEncoding(str, Enum):
    """Request body encoding types"""
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    TEXT = "text/plain"
    XML = "application/xml"
    OCTET_STREAM = "application/octet-stream"
    HTML = "text/html"
    EVENT_STREAM = "text/event-stream"
    GRAPHQL = "application/graphql"


class Request(BaseModel):
    """
    HTTP Request model for the Secure Runtime
    
    Represents an incoming HTTP request with all standard components and
    provides convenient methods for accessing request data. Designed to
    be compatible with FastAPI and other ASGI frameworks.
    """
    
    # Core request identifiers
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique request identifier"
    )
    correlation_id: Optional[str] = Field(
        default=None,
        description="Correlation ID for distributed tracing"
    )
    
    # Request line
    method: RequestMethod = Field(
        description="HTTP method (GET, POST, PUT, etc.)"
    )
    path: str = Field(
        description="Request path (e.g., /api/users/123)"
    )
    protocol: RequestProtocol = Field(
        default=RequestProtocol.HTTP_1_1,
        description="HTTP protocol version"
    )
    
    # HTTP version as string for compatibility
    http_version: str = Field(
        default="1.1",
        description="HTTP version as string (e.g., '1.1', '2.0')"
    )
    
    # Host and addressing
    host: str = Field(
        description="Host header value (e.g., example.com:8080)"
    )
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address"
    )
    client_port: Optional[int] = Field(
        default=None,
        description="Client port"
    )
    server_name: Optional[str] = Field(
        default=None,
        description="Server name from forwarding headers"
    )
    
    # Headers
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="HTTP headers (lowercase keys)"
    )
    
    # Query parameters
    query_params: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description="Query string parameters"
    )
    
    # Path parameters (from route matching)
    path_params: Dict[str, str] = Field(
        default_factory=dict,
        description="Path parameters from route matching"
    )
    
    # Cookies
    cookies: Dict[str, str] = Field(
        default_factory=dict,
        description="Request cookies"
    )
    
    # Body
    body: Optional[bytes] = Field(
        default=None,
        description="Raw request body bytes"
    )
    body_encoding: Optional[RequestEncoding] = Field(
        default=None,
        description="Detected or specified body encoding"
    )
    
    # Content information
    content_type: Optional[str] = Field(
        default=None,
        description="Content-Type header value"
    )
    content_length: Optional[int] = Field(
        default=None,
        description="Content-Length header value"
    )
    
    # Timestamps
    created_at: float = Field(
        default_factory=time.time,
        description="Timestamp when request was created"
    )
    received_at: Optional[float] = Field(
        default=None,
        description="Timestamp when request was received"
    )
    processed_at: Optional[float] = Field(
        default=None,
        description="Timestamp when request processing started"
    )
    
    # Metadata - extensible field for additional data
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional request metadata"
    )
    
    # Security context
    security_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Security-related context data"
    )
    
    # State
    is_secure: bool = Field(
        default=False,
        description="Whether request was made over HTTPS"
    )
    is_websocket: bool = Field(
        default=False,
        description="Whether this is a WebSocket upgrade request"
    )
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
        json_encoders={
            datetime: lambda dt: dt.isoformat(),
            bytes: lambda b: b.hex(),
        }
    )
    
    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Ensure headers keys are lowercase for consistency"""
        if v:
            return {k.lower(): v for k, v in v.items()}
        return v
    
    @field_validator("query_params")
    @classmethod
    def validate_query_params(cls, v: Dict[str, Union[str, List[str]]]) -> Dict[str, Union[str, List[str]]]:
        """Ensure query params are properly decoded"""
        if v:
            return {k: v[k] if isinstance(v[k], list) else v[k] for k in v}
        return v
    
    def get_header(
        self,
        name: str,
        default: Optional[str] = None,
        case_insensitive: bool = True
    ) -> Optional[str]:
        """
        Get a header value by name
        
        Args:
            name: Header name (case-insensitive by default)
            default: Default value if header not found
            case_insensitive: Whether to match case-insensitively
            
        Returns:
            Optional[str]: Header value or default
        """
        if case_insensitive:
            name = name.lower()
            for key, value in self.headers.items():
                if key.lower() == name:
                    return value
            return default
        return self.headers.get(name, default)
    
    def get_cookie(
        self,
        name: str,
        default: Optional[str] = None
    ) -> Optional[str]:
        """
        Get a cookie value by name
        
        Args:
            name: Cookie name
            default: Default value if cookie not found
            
        Returns:
            Optional[str]: Cookie value or default
        """
        return self.cookies.get(name, default)
    
    def get_query(
        self,
        name: str,
        default: Optional[Union[str, List[str]]] = None
    ) -> Optional[Union[str, List[str]]]:
        """
        Get a query parameter value by name
        
        Args:
            name: Parameter name
            default: Default value if parameter not found
            
        Returns:
            Optional[Union[str, List[str]]]: Parameter value(s) or default
        """
        return self.query_params.get(name, default)
    
    def get_query_string(self, include_question_mark: bool = True) -> str:
        """
        Get the full query string
        
        Args:
            include_question_mark: Whether to include '?' prefix
            
        Returns:
            str: Query string
        """
        if not self.query_params:
            return ""
        
        parts = []
        for key, value in self.query_params.items():
            if isinstance(value, list):
                for v in value:
                    parts.append(f"{key}={v}")
            else:
                parts.append(f"{key}={value}")
        
        if not parts:
            return ""
        
        query = "&".join(parts)
        return f"?{query}" if include_question_mark else query
    
    def get_path_with_query(self) -> str:
        """
        Get the full path with query string
        
        Returns:
            str: Path + query string
        """
        query = self.get_query_string(include_question_mark=True)
        return f"{self.path}{query}"
    
    async def json(
        self,
        *,
        encoding: str = "utf-8",
        strict: bool = True
    ) -> Union[Dict[str, Any], List[Any]]:
        """
        Parse request body as JSON
        
        Args:
            encoding: Character encoding
            strict: Whether to use strict JSON parsing
            
        Returns:
            Union[Dict[str, Any], List[Any]]: Parsed JSON data
            
        Raises:
            json.JSONDecodeError: If body is not valid JSON
            ValueError: If body is empty
        """
        if not self.body:
            raise ValueError("Request body is empty")
        
        data = self.body.decode(encoding)
        return json.loads(data, strict=strict)
    
    async def text(self, encoding: str = "utf-8") -> str:
        """
        Get request body as text
        
        Args:
            encoding: Character encoding
            
        Returns:
            str: Request body as string
            
        Raises:
            ValueError: If body is empty
        """
        if not self.body:
            return ""
        return self.body.decode(encoding)
    
    async def bytes(self) -> bytes:
        """
        Get raw request body bytes
        
        Returns:
            bytes: Request body as bytes
        """
        return self.body or b""
    
    async def stream(self, chunk_size: int = 8192) -> Iterator[bytes]:
        """
        Stream the request body in chunks
        
        Args:
            chunk_size: Size of each chunk
            
        Yields:
            bytes: Chunks of body data
        """
        if not self.body:
            return
        
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i:i + chunk_size]
    
    def is_json(self) -> bool:
        """
        Check if request has JSON content type
        
        Returns:
            bool: True if Content-Type is JSON
        """
        content_type = self.content_type or self.get_header("content-type", "")
        return content_type.startswith("application/json")
    
    def is_form(self) -> bool:
        """
        Check if request has form URL-encoded content type
        
        Returns:
            bool: True if Content-Type is form URL-encoded
        """
        content_type = self.content_type or self.get_header("content-type", "")
        return content_type.startswith("application/x-www-form-urlencoded")
    
    def is_multipart(self) -> bool:
        """
        Check if request has multipart content type
        
        Returns:
            bool: True if Content-Type is multipart
        """
        content_type = self.content_type or self.get_header("content-type", "")
        return content_type.startswith("multipart/form-data")
    
    def is_xml(self) -> bool:
        """
        Check if request has XML content type
        
        Returns:
            bool: True if Content-Type is XML
        """
        content_type = self.content_type or self.get_header("content-type", "")
        return content_type.startswith("application/xml") or content_type.startswith("text/xml")
    
    def is_text(self) -> bool:
        """
        Check if request has text content type
        
        Returns:
            bool: True if Content-Type is text
        """
        content_type = self.content_type or self.get_header("content-type", "")
        return content_type.startswith("text/")
    
    def size(self) -> int:
        """
        Get size of request body in bytes
        
        Returns:
            int: Size in bytes
        """
        return len(self.body) if self.body else 0
    
    def is_empty(self) -> bool:
        """
        Check if request has empty body
        
        Returns:
            bool: True if body is empty or None
        """
        return not self.body
    
    def get_client_address(self) -> Optional[str]:
        """
        Get client address from headers (X-Forwarded-For, X-Real-IP) or client_ip
        
        Returns:
            Optional[str]: Client IP address
        """
        # Check X-Forwarded-For header
        forwarded_for = self.get_header("x-forwarded-for")
        if forwarded_for:
            # Get the first IP in the list
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = self.get_header("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to client_ip
        return self.client_ip
    
    def get_forwarded_proto(self) -> Optional[str]:
        """
        Get forwarded protocol from X-Forwarded-Proto header
        
        Returns:
            Optional[str]: Protocol (http/https)
        """
        return self.get_header("x-forwarded-proto")
    
    def is_ajax(self) -> bool:
        """
        Check if request is an AJAX request
        
        Returns:
            bool: True if X-Requested-With header is XMLHttpRequest
        """
        return self.get_header("x-requested-with") == "XMLHttpRequest"
    
    def get_accept_languages(self) -> List[str]:
        """
        Parse Accept-Language header into list of languages
        
        Returns:
            List[str]: List of accepted languages in order of preference
        """
        accept_language = self.get_header("accept-language")
        if not accept_language:
            return []
        
        # Parse Accept-Language header
        languages = []
        for part in accept_language.split(","):
            part = part.strip()
            if not part:
                continue
            # Split quality value if present
            if ";" in part:
                lang, quality = part.split(";", 1)
                quality = quality.replace("q=", "")
                try:
                    q = float(quality)
                except ValueError:
                    q = 1.0
            else:
                lang = part
                q = 1.0
            
            # Split language variants
            for lang_part in lang.split(";"):
                lang_part = lang_part.strip()
                if lang_part:
                    languages.append((lang_part, q))
        
        # Sort by quality (highest first)
        languages.sort(key=lambda x: x[1], reverse=True)
        return [lang for lang, _ in languages]
    
    def get_accept_encodings(self) -> List[str]:
        """
        Parse Accept-Encoding header into list of encodings
        
        Returns:
            List[str]: List of accepted encodings
        """
        accept_encoding = self.get_header("accept-encoding")
        if not accept_encoding:
            return []
        
        encodings = []
        for part in accept_encoding.split(","):
            part = part.strip()
            if part and not part.startswith(";"):
                # Remove quality values
                if ";" in part:
                    part = part.split(";")[0]
                encodings.append(part)
        
        return encodings
    
    def get_auth_header(self) -> Optional[str]:
        """
        Get Authorization header value
        
        Returns:
            Optional[str]: Authorization header value
        """
        return self.get_header("authorization")
    
    def get_bearer_token(self) -> Optional[str]:
        """
        Extract Bearer token from Authorization header
        
        Returns:
            Optional[str]: Bearer token or None
        """
        auth = self.get_auth_header()
        if not auth:
            return None
        
        if auth.startswith("Bearer "):
            return auth[7:]
        
        return None
    
    def get_basic_auth(self) -> Optional[Dict[str, str]]:
        """
        Parse Basic Auth from Authorization header
        
        Returns:
            Optional[Dict[str, str]]: Dict with 'username' and 'password' keys
        """
        import base64
        
        auth = self.get_auth_header()
        if not auth:
            return None
        
        if not auth.startswith("Basic "):
            return None
        
        try:
            encoded = auth[6:]
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            return {"username": username, "password": password}
        except Exception:
            return None
    
    def get_origin(self) -> Optional[str]:
        """
        Get Origin header value (for CORS checks)
        
        Returns:
            Optional[str]: Origin header value
        """
        return self.get_header("origin")
    
    def get_referer(self) -> Optional[str]:
        """
        Get Referer header value
        
        Returns:
            Optional[str]: Referer header value
        """
        return self.get_header("referer")
    
    def get_user_agent(self) -> Optional[str]:
        """
        Get User-Agent header value
        
        Returns:
            Optional[str]: User-Agent header value
        """
        return self.get_header("user-agent")
    
    def parse_multipart(self) -> Dict[str, Any]:
        """
        Parse multipart form data (simplified)
        
        Returns:
            Dict[str, Any]: Parsed form data
            
        Raises:
            ValueError: If not multipart or body is empty
        """
        # This is a simplified parser - real implementation would use a proper library
        # like python-multipart for production use
        if not self.is_multipart():
            raise ValueError("Request is not multipart")
        
        if not self.body:
            raise ValueError("Request body is empty")
        
        # Get boundary
        content_type = self.content_type or self.get_header("content-type", "")
        boundary_prefix = "boundary="
        if boundary_prefix not in content_type:
            raise ValueError("No boundary found in Content-Type")
        
        boundary = "--" + content_type.split(boundary_prefix)[1].split(";")[0].strip()
        
        # Parse multipart body (simplified)
        # In production, use a proper library
        return {"_warning": "Simplified parser used - use proper library for production"}
    
    def add_metadata(self, key: str, value: Any) -> "Request":
        """
        Add metadata to the request
        
        Args:
            key: Metadata key
            value: Metadata value
            
        Returns:
            Request: Self for method chaining
        """
        self.metadata[key] = value
        return self
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata from the request
        
        Args:
            key: Metadata key
            default: Default value if key not found
            
        Returns:
            Any: Metadata value or default
        """
        return self.metadata.get(key, default)
    
    def add_security_context(self, key: str, value: Any) -> "Request":
        """
        Add security context to the request
        
        Args:
            key: Security context key
            value: Security context value
            
        Returns:
            Request: Self for method chaining
        """
        self.security_context[key] = value
        return self
    
    def get_security_context(self, key: str, default: Any = None) -> Any:
        """
        Get security context from the request
        
        Args:
            key: Security context key
            default: Default value if key not found
            
        Returns:
            Any: Security context value or default
        """
        return self.security_context.get(key, default)
    
    def set_processed(self) -> "Request":
        """
        Mark the request as being processed
        
        Returns:
            Request: Self for method chaining
        """
        self.processed_at = time.time()
        return self
    
    def get_elapsed(self) -> float:
        """
        Get elapsed time since request was created
        
        Returns:
            float: Elapsed time in seconds
        """
        return time.time() - self.created_at
    
    def get_elapsed_from_received(self) -> Optional[float]:
        """
        Get elapsed time since request was received
        
        Returns:
            Optional[float]: Elapsed time in seconds or None if not received
        """
        if self.received_at is None:
            return None
        return time.time() - self.received_at
    
    def clone(self) -> "Request":
        """
        Create a deep clone of the request
        
        Returns:
            Request: Cloned request
        """
        return self.model_copy(deep=True)
    
    def to_dict(self, include_body: bool = True) -> Dict[str, Any]:
        """
        Convert request to dictionary
        
        Args:
            include_body: Whether to include body data
            
        Returns:
            Dict[str, Any]: Request dictionary
        """
        data = self.model_dump(exclude={"body" if not include_body else None})
        if include_body and self.body:
            data["body_size"] = len(self.body)
        return data
    
    def __repr__(self) -> str:
        """String representation"""
        return f"<Request id={self.id} {self.method.value} {self.path}>"
    
    def __str__(self) -> str:
        """Human-readable representation"""
        return f"{self.method.value} {self.path} (HTTP {self.http_version})"


# Helper functions for request creation
def create_request(
    method: Union[RequestMethod, str],
    path: str,
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
    body: Optional[bytes] = None,
    client_ip: Optional[str] = None,
    host: Optional[str] = None,
    **kwargs
) -> Request:
    """
    Create a Request instance with defaults filled in
    
    Args:
        method: HTTP method
        path: Request path
        headers: HTTP headers
        query_params: Query parameters
        body: Request body
        client_ip: Client IP address
        host: Host header
        **kwargs: Additional request fields
        
    Returns:
        Request: Request instance
    """
    # Handle method as string
    if isinstance(method, str):
        method = RequestMethod(method.upper())
    
    # Get host from headers if not provided
    if not host and headers:
        host = headers.get("host")
    
    # Parse content type from headers
    content_type = None
    content_length = None
    if headers:
        content_type = headers.get("content-type")
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError:
                pass
    
    # Parse cookies from headers
    cookies = {}
    if headers and "cookie" in headers:
        cookie_header = headers["cookie"]
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, value = cookie.split("=", 1)
                cookies[key] = value
    
    # Parse query params from path if needed
    if query_params is None and "?" in path:
        path_parts = path.split("?", 1)
        path = path_parts[0]
        query_string = path_parts[1]
        query_params = parse_qs(query_string)
    
    # Create request
    return Request(
        method=method,
        path=path,
        headers=headers or {},
        query_params=query_params or {},
        body=body,
        content_type=content_type,
        content_length=content_length,
        client_ip=client_ip,
        host=host,
        cookies=cookies,
        **kwargs
    )


def request_from_fastapi(fastapi_request, body: Optional[bytes] = None) -> Request:
    """
    Convert a FastAPI request to our Request model
    
    Args:
        fastapi_request: FastAPI Request object
        body: Pre-read body (optional)
        
    Returns:
        Request: Runtime Request model
    """
    from fastapi import Request as FastAPIRequest
    
    # Get headers
    headers = dict(fastapi_request.headers)
    
    # Get query params
    query_params = dict(fastapi_request.query_params)
    
    # Get path params (from route)
    path_params = dict(fastapi_request.path_params)
    
    # Get client info
    client = fastapi_request.client
    client_ip = client.host if client else None
    client_port = client.port if client else None
    
    # Get method and path
    method = RequestMethod(fastapi_request.method)
    path = fastapi_request.url.path
    
    # Get host
    host = fastapi_request.headers.get("host")
    
    # Get protocol
    http_version = fastapi_request.scope.get("http_version", "1.1")
    protocol = RequestProtocol(f"HTTP/{http_version}")
    
    # Parse cookies
    cookies = dict(fastapi_request.cookies)
    
    # Get content type and length
    content_type = fastapi_request.headers.get("content-type")
    content_length = fastapi_request.headers.get("content-length")
    if content_length:
        try:
            content_length = int(content_length)
        except ValueError:
            content_length = None
    
    # Create request
    return Request(
        id=str(uuid.uuid4()),
        method=method,
        path=path,
        path_params=path_params,
        headers=headers,
        query_params=query_params,
        cookies=cookies,
        body=body,
        content_type=content_type,
        content_length=content_length,
        client_ip=client_ip,
        client_port=client_port,
        host=host,
        http_version=http_version,
        protocol=protocol,
        received_at=time.time(),
        metadata={
            "fastapi_scope": fastapi_request.scope,
        }
    )