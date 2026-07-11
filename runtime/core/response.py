# runtime/core/response.py
"""
HTTP Response Model for Secure Runtime

This module defines the Response model used throughout the runtime pipeline.
It represents outgoing HTTP responses with comprehensive features for
security headers, content encoding, and common response patterns.
"""

import json
import time
import re
from typing import Any, Dict, List, Optional, Union, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import quote

from pydantic import BaseModel, Field, ConfigDict, field_validator, validator


class ResponseStatus(int, Enum):
    """HTTP status codes"""
    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    
    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    ALREADY_REPORTED = 208
    IM_USED = 226
    
    # 3xx Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308
    
    # 4xx Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    PAYLOAD_TOO_LARGE = 413
    URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    TOO_EARLY = 425
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451
    
    # 5xx Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    VARIANT_ALSO_NEGOTIATES = 506
    INSUFFICIENT_STORAGE = 507
    LOOP_DETECTED = 508
    NOT_EXTENDED = 510
    NETWORK_AUTHENTICATION_REQUIRED = 511


class ContentType(str, Enum):
    """Common content types"""
    JSON = "application/json"
    TEXT = "text/plain"
    HTML = "text/html"
    XML = "application/xml"
    CSS = "text/css"
    JAVASCRIPT = "application/javascript"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    OCTET_STREAM = "application/octet-stream"
    PNG = "image/png"
    JPEG = "image/jpeg"
    GIF = "image/gif"
    SVG = "image/svg+xml"
    PDF = "application/pdf"
    CSV = "text/csv"
    EVENT_STREAM = "text/event-stream"
    GRAPHQL = "application/graphql"
    YAML = "application/x-yaml"
    TOML = "application/toml"
    PROTOBUF = "application/protobuf"
    MSGPACK = "application/msgpack"


class ResponseSecurityHeaders(BaseModel):
    """Security headers for HTTP responses"""
    content_security_policy: Optional[str] = None
    strict_transport_security: Optional[str] = None
    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    x_xss_protection: str = "1; mode=block"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: Optional[str] = None
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_resource_policy: str = "same-origin"
    
    model_config = ConfigDict(extra="allow")


class Cookie(BaseModel):
    """HTTP Cookie model"""
    name: str
    value: str
    expires: Optional[Union[datetime, int]] = None
    max_age: Optional[int] = None
    domain: Optional[str] = None
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None  # Strict, Lax, None
    
    model_config = ConfigDict(extra="allow")


class ErrorDetail(BaseModel):
    """Structured error detail for error responses"""
    code: str
    message: str
    field: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(extra="allow")


class Response(BaseModel):
    """
    HTTP Response model for the Secure Runtime
    
    Represents an outgoing HTTP response with comprehensive features for
    security headers, content encoding, and common response patterns.
    Designed to be compatible with FastAPI and other ASGI frameworks.
    """
    
    # Response basics
    status_code: ResponseStatus = Field(
        default=ResponseStatus.OK,
        description="HTTP status code"
    )
    status_code_int: int = Field(
        default=200,
        description="HTTP status code as integer"
    )
    
    # Content
    body: Optional[Union[str, bytes, Dict, List]] = Field(
        default=None,
        description="Response body content"
    )
    content_type: ContentType = Field(
        default=ContentType.JSON,
        description="Content-Type header value"
    )
    charset: str = Field(
        default="utf-8",
        description="Character encoding"
    )
    
    # Headers and cookies
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Additional response headers"
    )
    cookies: List[Cookie] = Field(
        default_factory=list,
        description="Cookies to set in response"
    )
    
    # Metadata
    timestamp: float = Field(
        default_factory=time.time,
        description="Response creation timestamp"
    )
    response_time: Optional[float] = Field(
        default=None,
        description="Response processing time in seconds"
    )
    
    # Security
    security_headers: ResponseSecurityHeaders = Field(
        default_factory=ResponseSecurityHeaders,
        description="Security headers to include"
    )
    
    # Blocking information
    is_blocked: bool = Field(
        default=False,
        description="Whether this response represents a blocked request"
    )
    block_reason: Optional[str] = Field(
        default=None,
        description="Reason for blocking the request"
    )
    block_type: Optional[str] = Field(
        default=None,
        description="Type of block (threat, policy, rate_limit, etc.)"
    )
    
    # Status messages
    status_message: Optional[str] = Field(
        default=None,
        description="Human-readable status message"
    )
    
    # Error details
    error_details: Optional[List[ErrorDetail]] = Field(
        default=None,
        description="Structured error details"
    )
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional response metadata"
    )
    
    # CORS
    allow_origin: Optional[str] = Field(
        default=None,
        description="Access-Control-Allow-Origin header"
    )
    allow_credentials: bool = Field(
        default=False,
        description="Access-Control-Allow-Credentials"
    )
    allow_methods: Optional[List[str]] = Field(
        default=None,
        description="Access-Control-Allow-Methods"
    )
    allow_headers: Optional[List[str]] = Field(
        default=None,
        description="Access-Control-Allow-Headers"
    )
    expose_headers: Optional[List[str]] = Field(
        default=None,
        description="Access-Control-Expose-Headers"
    )
    max_age: Optional[int] = Field(
        default=None,
        description="Access-Control-Max-Age"
    )
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
        json_encoders={
            datetime: lambda dt: dt.isoformat(),
            bytes: lambda b: b.hex(),
        }
    )
    
    @field_validator("status_code_int")
    @classmethod
    def validate_status_code_int(cls, v: int) -> int:
        """Validate status code integer"""
        if not 100 <= v <= 599:
            raise ValueError("Status code must be between 100 and 599")
        return v
    
    def __init__(self, **data):
        """Initialize with automatic status code sync"""
        if "status_code" in data:
            status = data["status_code"]
            if isinstance(status, int):
                data["status_code_int"] = status
                try:
                    data["status_code"] = ResponseStatus(status)
                except ValueError:
                    data["status_code"] = ResponseStatus.OK
                    data["status_code_int"] = status
            elif isinstance(status, ResponseStatus):
                data["status_code_int"] = status.value
        
        if "status_code_int" in data and "status_code" not in data:
            try:
                data["status_code"] = ResponseStatus(data["status_code_int"])
            except ValueError:
                data["status_code"] = ResponseStatus.OK
        
        super().__init__(**data)
    
    def json(
        self,
        data: Optional[Any] = None,
        indent: Optional[int] = None,
        **kwargs
    ) -> "Response":
        """
        Set response body as JSON
        
        Args:
            data: Data to serialize as JSON
            indent: JSON indentation
            **kwargs: Additional JSON serialization arguments
            
        Returns:
            Response: Self for method chaining
        """
        if data is not None:
            self.body = data
        
        self.content_type = ContentType.JSON
        
        # If body is already a string, assume it's JSON
        if isinstance(self.body, str):
            return self
        
        # Serialize to JSON on access
        self._json_indent = indent
        self._json_kwargs = kwargs
        return self
    
    def text(
        self,
        text: Optional[str] = None,
        content_type: ContentType = ContentType.TEXT
    ) -> "Response":
        """
        Set response body as text
        
        Args:
            text: Text content
            content_type: Content type (default: text/plain)
            
        Returns:
            Response: Self for method chaining
        """
        if text is not None:
            self.body = text
        self.content_type = content_type
        return self
    
    def html(self, html: Optional[str] = None) -> "Response":
        """
        Set response body as HTML
        
        Args:
            html: HTML content
            
        Returns:
            Response: Self for method chaining
        """
        return self.text(html or self.body, ContentType.HTML)
    
    def bytes(self, data: Optional[bytes] = None, content_type: ContentType = ContentType.OCTET_STREAM) -> "Response":
        """
        Set response body as bytes
        
        Args:
            data: Binary data
            content_type: Content type
            
        Returns:
            Response: Self for method chaining
        """
        if data is not None:
            self.body = data
        self.content_type = content_type
        return self
    
    def redirect(
        self,
        url: str,
        status_code: int = 302,
        permanent: bool = False
    ) -> "Response":
        """
        Create a redirect response
        
        Args:
            url: Redirect URL
            status_code: HTTP status code (301, 302, 307, 308)
            permanent: Whether redirect is permanent (301/308)
            
        Returns:
            Response: Self for method chaining
        """
        if permanent:
            status_code = 301 if status_code == 302 else 308
        self.status_code_int = status_code
        try:
            self.status_code = ResponseStatus(status_code)
        except ValueError:
            pass
        self.headers["Location"] = url
        self.body = None
        return self
    
    def error(
        self,
        message: str,
        status_code: int = 500,
        error_code: Optional[str] = None,
        details: Optional[List[ErrorDetail]] = None,
        **kwargs
    ) -> "Response":
        """
        Create an error response
        
        Args:
            message: Error message
            status_code: HTTP status code
            error_code: Application error code
            details: Additional error details
            **kwargs: Additional error data
            
        Returns:
            Response: Self for method chaining
        """
        self.status_code_int = status_code
        try:
            self.status_code = ResponseStatus(status_code)
        except ValueError:
            pass
        
        self.status_message = message
        
        error_data = {
            "error": message,
            "status_code": status_code,
            "timestamp": datetime.utcnow().isoformat(),
            **kwargs
        }
        
        if error_code:
            error_data["code"] = error_code
        
        if details:
            error_data["details"] = [d.model_dump() for d in details]
            self.error_details = details
        
        self.body = error_data
        self.content_type = ContentType.JSON
        return self
    
    def success(
        self,
        data: Optional[Any] = None,
        message: Optional[str] = None,
        status_code: int = 200,
        **kwargs
    ) -> "Response":
        """
        Create a success response
        
        Args:
            data: Response data
            message: Success message
            status_code: HTTP status code
            **kwargs: Additional data
            
        Returns:
            Response: Self for method chaining
        """
        self.status_code_int = status_code
        try:
            self.status_code = ResponseStatus(status_code)
        except ValueError:
            pass
        
        response_data = {"success": True}
        if message:
            response_data["message"] = message
            self.status_message = message
        if data is not None:
            response_data["data"] = data
        response_data.update(kwargs)
        
        self.body = response_data
        self.content_type = ContentType.JSON
        return self
    
    def forbidden(self, message: str = "Access forbidden", **kwargs) -> "Response":
        """Create a 403 Forbidden response"""
        return self.error(message, 403, **kwargs)
    
    def unauthorized(self, message: str = "Unauthorized", **kwargs) -> "Response":
        """Create a 401 Unauthorized response"""
        return self.error(message, 401, **kwargs)
    
    def bad_request(self, message: str = "Bad request", **kwargs) -> "Response":
        """Create a 400 Bad Request response"""
        return self.error(message, 400, **kwargs)
    
    def not_found(self, message: str = "Not found", **kwargs) -> "Response":
        """Create a 404 Not Found response"""
        return self.error(message, 404, **kwargs)
    
    def rate_limited(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs
    ) -> "Response":
        """Create a 429 Too Many Requests response"""
        response = self.error(message, 429, **kwargs)
        if retry_after:
            response.headers["Retry-After"] = str(retry_after)
        return response
    
    def internal_error(self, message: str = "Internal server error", **kwargs) -> "Response":
        """Create a 500 Internal Server Error response"""
        return self.error(message, 500, **kwargs)
    
    def conflict(self, message: str = "Conflict", **kwargs) -> "Response":
        """Create a 409 Conflict response"""
        return self.error(message, 409, **kwargs)
    
    def unprocessable_entity(self, message: str = "Unprocessable entity", **kwargs) -> "Response":
        """Create a 422 Unprocessable Entity response"""
        return self.error(message, 422, **kwargs)
    
    def not_implemented(self, message: str = "Not implemented", **kwargs) -> "Response":
        """Create a 501 Not Implemented response"""
        return self.error(message, 501, **kwargs)
    
    def service_unavailable(self, message: str = "Service unavailable", **kwargs) -> "Response":
        """Create a 503 Service Unavailable response"""
        return self.error(message, 503, **kwargs)
    
    def add_cookie(
        self,
        name: str,
        value: str,
        max_age: Optional[int] = None,
        expires: Optional[Union[datetime, int]] = None,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        http_only: bool = False,
        same_site: Optional[str] = None,
    ) -> "Response":
        """
        Add a cookie to the response
        
        Args:
            name: Cookie name
            value: Cookie value
            max_age: Max age in seconds
            expires: Expiration time
            path: Cookie path
            domain: Cookie domain
            secure: Secure flag
            http_only: HTTP only flag
            same_site: SameSite policy (Strict, Lax, None)
            
        Returns:
            Response: Self for method chaining
        """
        cookie = Cookie(
            name=name,
            value=value,
            max_age=max_age,
            expires=expires,
            path=path,
            domain=domain,
            secure=secure,
            http_only=http_only,
            same_site=same_site,
        )
        self.cookies.append(cookie)
        return self
    
    def delete_cookie(
        self,
        name: str,
        path: str = "/",
        domain: Optional[str] = None
    ) -> "Response":
        """
        Delete a cookie by setting it with expired max_age
        
        Args:
            name: Cookie name
            path: Cookie path
            domain: Cookie domain
            
        Returns:
            Response: Self for method chaining
        """
        self.add_cookie(
            name=name,
            value="",
            max_age=0,
            expires=datetime.utcnow() - timedelta(days=1),
            path=path,
            domain=domain,
        )
        return self
    
    def add_header(self, key: str, value: str) -> "Response":
        """
        Add a header to the response
        
        Args:
            key: Header name
            value: Header value
            
        Returns:
            Response: Self for method chaining
        """
        self.headers[key] = value
        return self
    
    def add_headers(self, headers: Dict[str, str]) -> "Response":
        """
        Add multiple headers to the response
        
        Args:
            headers: Dictionary of headers
            
        Returns:
            Response: Self for method chaining
        """
        self.headers.update(headers)
        return self
    
    def set_cors(
        self,
        origin: str = "*",
        credentials: bool = False,
        methods: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        expose: Optional[List[str]] = None,
        max_age: Optional[int] = None
    ) -> "Response":
        """
        Set CORS headers on the response
        
        Args:
            origin: Allowed origin
            credentials: Allow credentials
            methods: Allowed methods
            headers: Allowed headers
            expose: Exposed headers
            max_age: Max age
            
        Returns:
            Response: Self for method chaining
        """
        self.allow_origin = origin
        self.allow_credentials = credentials
        self.allow_methods = methods
        self.allow_headers = headers
        self.expose_headers = expose
        self.max_age = max_age
        return self
    
    def block(
        self,
        reason: str,
        block_type: str = "blocked",
        status_code: int = 403,
        message: Optional[str] = None
    ) -> "Response":
        """
        Mark this response as a blocked request
        
        Args:
            reason: Reason for blocking
            block_type: Type of block
            status_code: HTTP status code
            message: Custom message
            
        Returns:
            Response: Self for method chaining
        """
        self.is_blocked = True
        self.block_reason = reason
        self.block_type = block_type
        self.status_code_int = status_code
        try:
            self.status_code = ResponseStatus(status_code)
        except ValueError:
            pass
        
        if message:
            self.status_message = message
        else:
            self.status_message = f"Request blocked: {reason}"
        
        return self
    
    def with_security_headers(self, **kwargs) -> "Response":
        """
        Apply security headers to the response
        
        Args:
            **kwargs: Security header overrides
            
        Returns:
            Response: Self for method chaining
        """
        # Update security headers with overrides
        for key, value in kwargs.items():
            if hasattr(self.security_headers, key):
                setattr(self.security_headers, key, value)
        
        return self
    
    def to_headers(self, include_cookies: bool = True) -> Dict[str, str]:
        """
        Convert response to headers dictionary
        
        Args:
            include_cookies: Whether to include cookie headers
            
        Returns:
            Dict[str, str]: Headers dictionary
        """
        headers = dict(self.headers)
        
        # Content-Type
        content_type = self.content_type.value
        if self.charset and "text" in content_type:
            content_type += f"; charset={self.charset}"
        headers["Content-Type"] = content_type
        
        # Security headers
        security = self.security_headers
        if security.content_security_policy:
            headers["Content-Security-Policy"] = security.content_security_policy
        if security.strict_transport_security:
            headers["Strict-Transport-Security"] = security.strict_transport_security
        headers["X-Content-Type-Options"] = security.x_content_type_options
        headers["X-Frame-Options"] = security.x_frame_options
        headers["X-XSS-Protection"] = security.x_xss_protection
        headers["Referrer-Policy"] = security.referrer_policy
        if security.permissions_policy:
            headers["Permissions-Policy"] = security.permissions_policy
        headers["Cross-Origin-Opener-Policy"] = security.cross_origin_opener_policy
        headers["Cross-Origin-Embedder-Policy"] = security.cross_origin_embedder_policy
        headers["Cross-Origin-Resource-Policy"] = security.cross_origin_resource_policy
        
        # CORS headers
        if self.allow_origin:
            headers["Access-Control-Allow-Origin"] = self.allow_origin
        if self.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        if self.allow_methods:
            headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
        if self.allow_headers:
            headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)
        if self.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)
        if self.max_age is not None:
            headers["Access-Control-Max-Age"] = str(self.max_age)
        
        # Cookies
        if include_cookies and self.cookies:
            cookie_headers = self._build_cookie_headers()
            for cookie_header in cookie_headers:
                headers["Set-Cookie"] = cookie_header
        
        return headers
    
    def _build_cookie_headers(self) -> List[str]:
        """Build Set-Cookie headers from cookies"""
        cookie_headers = []
        
        for cookie in self.cookies:
            parts = [f"{cookie.name}={cookie.value}"]
            
            if cookie.max_age is not None:
                parts.append(f"Max-Age={cookie.max_age}")
            elif cookie.expires:
                if isinstance(cookie.expires, datetime):
                    expires = cookie.expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
                else:
                    expires = cookie.expires
                parts.append(f"Expires={expires}")
            
            if cookie.domain:
                parts.append(f"Domain={cookie.domain}")
            if cookie.path:
                parts.append(f"Path={cookie.path}")
            if cookie.secure:
                parts.append("Secure")
            if cookie.http_only:
                parts.append("HttpOnly")
            if cookie.same_site:
                parts.append(f"SameSite={cookie.same_site}")
            
            cookie_headers.append("; ".join(parts))
        
        return cookie_headers
    
    def render_body(self) -> Optional[bytes]:
        """
        Render the response body as bytes
        
        Returns:
            Optional[bytes]: Rendered body bytes
        """
        if self.body is None:
            return None
        
        # Already bytes
        if isinstance(self.body, bytes):
            return self.body
        
        # String
        if isinstance(self.body, str):
            return self.body.encode(self.charset)
        
        # Dict/List - JSON
        if isinstance(self.body, (dict, list)):
            indent = getattr(self, '_json_indent', None)
            kwargs = getattr(self, '_json_kwargs', {})
            json_str = json.dumps(self.body, indent=indent, default=str, **kwargs)
            return json_str.encode(self.charset)
        
        # Other types - convert to string
        return str(self.body).encode(self.charset)
    
    def get_elapsed(self) -> Optional[float]:
        """
        Get response time
        
        Returns:
            Optional[float]: Response time in seconds
        """
        return self.response_time
    
    def set_response_time(self, start_time: float) -> "Response":
        """
        Set response time based on start time
        
        Args:
            start_time: Start time in seconds
            
        Returns:
            Response: Self for method chaining
        """
        self.response_time = time.time() - start_time
        return self
    
    def clone(self) -> "Response":
        """Create a deep clone of the response"""
        return self.model_copy(deep=True)
    
    def to_dict(self, include_body: bool = True) -> Dict[str, Any]:
        """
        Convert response to dictionary
        
        Args:
            include_body: Whether to include body content
            
        Returns:
            Dict[str, Any]: Response dictionary
        """
        data = self.model_dump(exclude={"body" if not include_body else None})
        
        if include_body and self.body is not None:
            if isinstance(self.body, bytes):
                data["body"] = self.body.hex()
            elif isinstance(self.body, (dict, list)):
                # For dict/list, leave as is (will be JSON serialized)
                data["body"] = self.body
            else:
                data["body"] = str(self.body)
        
        return data
    
    def __repr__(self) -> str:
        """String representation"""
        return f"<Response status={self.status_code_int} type={self.content_type.value} blocked={self.is_blocked}>"
    
    def __str__(self) -> str:
        """Human-readable representation"""
        status_message = ResponseStatus(self.status_code_int).name if hasattr(ResponseStatus, self.status_code_int.__str__()) else self.status_code_int
        return f"{self.status_code_int} {status_message} (blocked={self.is_blocked})"


# Helper functions for common responses
def json_response(
    data: Any,
    status_code: int = 200,
    **kwargs
) -> Response:
    """
    Create a JSON response
    
    Args:
        data: Response data
        status_code: HTTP status code
        **kwargs: Additional response arguments
        
    Returns:
        Response: Response instance
    """
    response = Response(status_code_int=status_code, **kwargs)
    return response.json(data)


def text_response(
    text: str,
    status_code: int = 200,
    content_type: ContentType = ContentType.TEXT,
    **kwargs
) -> Response:
    """
    Create a text response
    
    Args:
        text: Response text
        status_code: HTTP status code
        content_type: Content type
        **kwargs: Additional response arguments
        
    Returns:
        Response: Response instance
    """
    response = Response(status_code_int=status_code, **kwargs)
    return response.text(text, content_type)


def html_response(
    html: str,
    status_code: int = 200,
    **kwargs
) -> Response:
    """
    Create an HTML response
    
    Args:
        html: HTML content
        status_code: HTTP status code
        **kwargs: Additional response arguments
        
    Returns:
        Response: Response instance
    """
    response = Response(status_code_int=status_code, **kwargs)
    return response.html(html)


def redirect_response(
    url: str,
    status_code: int = 302,
    **kwargs
) -> Response:
    """
    Create a redirect response
    
    Args:
        url: Redirect URL
        status_code: HTTP status code
        **kwargs: Additional response arguments
        
    Returns:
        Response: Response instance
    """
    response = Response(**kwargs)
    return response.redirect(url, status_code)


def error_response(
    message: str,
    status_code: int = 500,
    **kwargs
) -> Response:
    """
    Create an error response
    
    Args:
        message: Error message
        status_code: HTTP status code
        **kwargs: Additional response arguments
        
    Returns:
        Response: Response instance
    """
    response = Response(**kwargs)
    return response.error(message, status_code)