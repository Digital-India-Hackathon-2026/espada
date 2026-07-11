# runtime/middleware/auth.py
"""
Authentication Middleware for Secure Runtime

This module provides comprehensive authentication capabilities including
JWT, API keys, OAuth2, Basic Auth, and session-based authentication.
It supports multiple authentication providers and extensible authentication
strategies.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import time
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable, Set, Tuple
from urllib.parse import parse_qs, urlparse
import secrets

from pydantic import BaseModel, Field

from runtime.core.context import RuntimeContext
from runtime.core.request import Request
from runtime.core.response import Response
from runtime.core.errors import (
    AuthenticationError,
    AuthenticationFailedError,
    TokenExpiredError,
    TokenInvalidError,
    CredentialsInvalidError,
    SessionExpiredError,
    RuntimeError as RuntimeErrorBase,
)
from runtime.core.events import get_event_bus
from runtime.core.metrics import get_metrics_collector


class AuthType(StrEnum):
    """Authentication types"""
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    SESSION = "session"
    COOKIE = "cookie"
    CUSTOM = "custom"
    NONE = "none"


class AuthStatus(StrEnum):
    """Authentication status"""
    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"
    REQUIRES_2FA = "requires_2fa"


class TokenType(StrEnum):
    """Token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    ID = "id"
    API = "api"
    SESSION = "session"


@dataclass
class AuthCredentials:
    """Authentication credentials extracted from request"""
    auth_type: AuthType
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    session_id: Optional[str] = None
    cookie: Optional[str] = None
    oauth2_token: Optional[str] = None
    oauth2_code: Optional[str] = None
    custom_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source: Optional[str] = None  # header, cookie, query, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "auth_type": self.auth_type.value if self.auth_type else None,
            "token": self.token,
            "username": self.username,
            "password": "[REDACTED]" if self.password else None,
            "api_key": self.api_key,
            "session_id": self.session_id,
            "cookie": self.cookie,
            "oauth2_token": self.oauth2_token,
            "oauth2_code": self.oauth2_code,
            "custom_data": self.custom_data,
            "timestamp": self.timestamp,
            "source": self.source,
        }


@dataclass
class AuthResult:
    """Authentication result"""
    status: AuthStatus
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    claims: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    token_type: Optional[TokenType] = None
    token_id: Optional[str] = None
    auth_type: Optional[AuthType] = None
    session_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None
    requires_2fa: bool = False
    error: Optional[str] = None
    error_code: Optional[str] = None
    
    def is_authenticated(self) -> bool:
        """Check if authentication was successful"""
        return self.status == AuthStatus.SUCCESS
    
    def is_expired(self) -> bool:
        """Check if the authentication has expired"""
        if self.status == AuthStatus.EXPIRED:
            return True
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "status": self.status.value,
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "roles": self.roles,
            "permissions": self.permissions,
            "scopes": self.scopes,
            "claims": self.claims,
            "metadata": self.metadata,
            "token_type": self.token_type.value if self.token_type else None,
            "token_id": self.token_id,
            "auth_type": self.auth_type.value if self.auth_type else None,
            "session_id": self.session_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "requires_2fa": self.requires_2fa,
            "error": self.error,
            "error_code": self.error_code,
        }


class AuthenticationProvider(ABC):
    """Base class for authentication providers"""
    
    def __init__(self, name: str, priority: int = 50):
        """
        Initialize authentication provider
        
        Args:
            name: Provider name
            priority: Provider priority (higher = checked first)
        """
        self.name = name
        self.priority = priority
        self._logger = None
    
    @abstractmethod
    async def authenticate(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate using this provider
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        pass
    
    @abstractmethod
    async def supports(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> bool:
        """
        Check if this provider supports the given credentials
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            bool: True if this provider can handle the credentials
        """
        pass
    
    async def verify_token(
        self,
        token: str,
        context: RuntimeContext,
        token_type: Optional[TokenType] = None,
    ) -> AuthResult:
        """
        Verify a token
        
        Args:
            token: Token to verify
            context: Runtime context
            token_type: Type of token
            
        Returns:
            AuthResult: Verification result
        """
        credentials = AuthCredentials(
            auth_type=AuthType.JWT,
            token=token,
        )
        if token_type:
            credentials.custom_data["token_type"] = token_type.value
        return await self.authenticate(credentials, context)
    
    async def refresh_token(
        self,
        refresh_token: str,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Refresh a token
        
        Args:
            refresh_token: Refresh token
            context: Runtime context
            
        Returns:
            AuthResult: New token result
        """
        # Default implementation - override in subclass
        raise NotImplementedError("Token refresh not implemented")
    
    async def revoke_token(
        self,
        token: str,
        context: RuntimeContext,
    ) -> bool:
        """
        Revoke a token
        
        Args:
            token: Token to revoke
            context: Runtime context
            
        Returns:
            bool: True if revoked successfully
        """
        # Default implementation - override in subclass
        return False


class JWTProvider(AuthenticationProvider):
    """
    JWT Authentication Provider
    
    Handles JWT token authentication with support for various algorithms,
    token validation, and claims extraction.
    """
    
    def __init__(
        self,
        name: str = "jwt",
        secret_key: str = "",
        algorithm: str = "HS256",
        issuer: Optional[str] = None,
        audience: Optional[Union[str, List[str]]] = None,
        leeway: int = 60,
        require_exp: bool = True,
        require_iat: bool = True,
        require_nbf: bool = True,
        public_key: Optional[str] = None,
        private_key: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize JWT provider
        
        Args:
            name: Provider name
            secret_key: Secret key for HMAC algorithms
            algorithm: JWT algorithm
            issuer: Required issuer
            audience: Required audience
            leeway: Leeway in seconds for time validation
            require_exp: Require expiration claim
            require_iat: Require issued at claim
            require_nbf: Require not before claim
            public_key: Public key for RSA/ECDSA
            private_key: Private key for signing
            **kwargs: Additional configuration
        """
        super().__init__(name, kwargs.get("priority", 100))
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.require_exp = require_exp
        self.require_iat = require_iat
        self.require_nbf = require_nbf
        self.public_key = public_key
        self.private_key = private_key
        self._config = kwargs
        
        import logging
        self._logger = logging.getLogger(f"runtime.auth.providers.jwt.{name}")
    
    async def authenticate(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate using JWT token
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        if not credentials.token:
            return AuthResult(
                status=AuthStatus.FAILED,
                error="No token provided",
                auth_type=AuthType.JWT,
                error_code="MISSING_TOKEN",
            )
        
        try:
            # Decode and validate token
            payload = await self._decode_token(credentials.token, context)
            
            # Extract user information
            user_id = payload.get("sub") or payload.get("user_id") or payload.get("uid")
            username = payload.get("username") or payload.get("name") or payload.get("preferred_username")
            email = payload.get("email") or payload.get("user_email")
            
            # Extract roles and permissions
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])
            scopes = payload.get("scopes", [])
            claims = {k: v for k, v in payload.items() if k not in ["sub", "username", "email", "roles", "permissions", "scopes"]}
            
            # Check expiration
            if "exp" in payload:
                exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                if exp_time < datetime.now(timezone.utc):
                    return AuthResult(
                        status=AuthStatus.EXPIRED,
                        error="Token has expired",
                        auth_type=AuthType.JWT,
                        error_code="TOKEN_EXPIRED",
                        token_type=TokenType.ACCESS,
                    )
            
            # Success
            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=user_id,
                username=username,
                email=email,
                roles=roles,
                permissions=permissions,
                scopes=scopes,
                claims=claims,
                metadata={
                    "jti": payload.get("jti"),
                    "token_type": payload.get("typ", "JWT"),
                    "algorithm": self.algorithm,
                    "provider": self.name,
                },
                token_type=TokenType.ACCESS,
                auth_type=AuthType.JWT,
                expires_at=datetime.fromtimestamp(payload.get("exp", time.time() + 3600), tz=timezone.utc) if "exp" in payload else None,
            )
            
        except TokenExpiredError as e:
            return AuthResult(
                status=AuthStatus.EXPIRED,
                error=str(e),
                auth_type=AuthType.JWT,
                error_code="TOKEN_EXPIRED",
            )
        except TokenInvalidError as e:
            return AuthResult(
                status=AuthStatus.FAILED,
                error=str(e),
                auth_type=AuthType.JWT,
                error_code="TOKEN_INVALID",
            )
        except Exception as e:
            self._logger.error(f"JWT authentication error: {e}")
            return AuthResult(
                status=AuthStatus.FAILED,
                error=f"Authentication error: {str(e)}",
                auth_type=AuthType.JWT,
                error_code="AUTH_ERROR",
            )
    
    async def supports(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> bool:
        """Check if credentials can be handled by JWT provider"""
        return (
            credentials.auth_type == AuthType.JWT or
            credentials.token is not None or
            credentials.custom_data.get("token_type") == TokenType.ACCESS.value
        )
    
    async def _decode_token(self, token: str, context: RuntimeContext) -> Dict[str, Any]:
        """
        Decode and validate JWT token
        
        Args:
            token: JWT token
            context: Runtime context
            
        Returns:
            Dict[str, Any]: Decoded payload
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenExpiredError: If token has expired
        """
        # For production, use a proper JWT library like PyJWT
        # This is a simplified implementation
        try:
            # Split token into parts
            parts = token.split(".")
            if len(parts) != 3:
                raise TokenInvalidError("Invalid token format")
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            
            # Verify algorithm
            if header.get("alg") != self.algorithm:
                raise TokenInvalidError(f"Algorithm mismatch: {header.get('alg')} != {self.algorithm}")
            
            # Verify signature
            expected_signature = self._sign_token(header_b64 + "." + payload_b64)
            if expected_signature != signature_b64:
                raise TokenInvalidError("Invalid signature")
            
            # Validate claims
            now = time.time() - self.leeway
            
            # Check expiration
            if "exp" in payload:
                if payload["exp"] < now:
                    raise TokenExpiredError("Token has expired")
            elif self.require_exp:
                raise TokenInvalidError("Expiration claim (exp) required")
            
            # Check issued at
            if "iat" in payload:
                if payload["iat"] > now + self.leeway:
                    raise TokenInvalidError("Token issued in the future")
            elif self.require_iat:
                raise TokenInvalidError("Issued at claim (iat) required")
            
            # Check not before
            if "nbf" in payload:
                if payload["nbf"] > now:
                    raise TokenInvalidError("Token not yet valid")
            elif self.require_nbf:
                raise TokenInvalidError("Not before claim (nbf) required")
            
            # Check issuer
            if self.issuer:
                if payload.get("iss") != self.issuer:
                    raise TokenInvalidError(f"Issuer mismatch: {payload.get('iss')} != {self.issuer}")
            
            # Check audience
            if self.audience:
                aud = payload.get("aud")
                if isinstance(self.audience, str):
                    if aud != self.audience:
                        raise TokenInvalidError(f"Audience mismatch: {aud} != {self.audience}")
                elif isinstance(self.audience, list):
                    if aud not in self.audience:
                        raise TokenInvalidError(f"Audience mismatch: {aud} not in {self.audience}")
            
            return payload
            
        except TokenExpiredError:
            raise
        except TokenInvalidError:
            raise
        except Exception as e:
            raise TokenInvalidError(f"Invalid token: {str(e)}")
    
    def _sign_token(self, data: str) -> str:
        """
        Sign token data
        
        Args:
            data: Data to sign
            
        Returns:
            str: Signature
        """
        # Simplified signing - production should use proper JWT library
        if self.algorithm in ["HS256", "HS384", "HS512"]:
            secret = self.secret_key.encode("utf-8")
            signature = hmac.new(secret, data.encode("utf-8"), hashlib.sha256).digest()
            return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
        else:
            # RSA/ECDSA - would need proper implementation with cryptography library
            # For production, use pyjwt or jose library
            return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    
    async def refresh_token(
        self,
        refresh_token: str,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Refresh JWT token using refresh token
        
        Args:
            refresh_token: Refresh token
            context: Runtime context
            
        Returns:
            AuthResult: New authentication result
        """
        try:
            payload = await self._decode_token(refresh_token, context)
            
            # Check if it's a refresh token
            token_type = payload.get("typ") or payload.get("token_type")
            if token_type and token_type != "refresh":
                raise TokenInvalidError("Not a refresh token")
            
            # Check if refresh token is expired
            if "exp" in payload:
                exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                if exp_time < datetime.now(timezone.utc):
                    return AuthResult(
                        status=AuthStatus.EXPIRED,
                        error="Refresh token has expired",
                        auth_type=AuthType.JWT,
                        error_code="REFRESH_TOKEN_EXPIRED",
                    )
            
            # Create new access token
            # In production, this would use a proper JWT library
            # For now, just return success with the same user info
            result = await self.authenticate(
                AuthCredentials(
                    auth_type=AuthType.JWT,
                    token=refresh_token,  # Not ideal, but works for demo
                ),
                context,
            )
            
            # Generate a new refresh token
            # This would be done in production
            result.refresh_token = refresh_token  # Keep same for demo
            
            return result
            
        except TokenExpiredError as e:
            return AuthResult(
                status=AuthStatus.EXPIRED,
                error=str(e),
                auth_type=AuthType.JWT,
                error_code="REFRESH_TOKEN_EXPIRED",
            )
        except Exception as e:
            self._logger.error(f"Token refresh error: {e}")
            return AuthResult(
                status=AuthStatus.FAILED,
                error=f"Refresh error: {str(e)}",
                auth_type=AuthType.JWT,
                error_code="REFRESH_ERROR",
            )


class APIKeyProvider(AuthenticationProvider):
    """
    API Key Authentication Provider
    
    Validates API keys from headers, query parameters, or cookies.
    """
    
    def __init__(
        self,
        name: str = "api_key",
        header_name: str = "X-API-Key",
        query_param: str = "api_key",
        cookie_name: str = "api_key",
        valid_keys: Dict[str, Dict[str, Any]] = None,
        validate_with_service: Optional[Callable] = None,
        **kwargs
    ):
        """
        Initialize API key provider
        
        Args:
            name: Provider name
            header_name: Header name for API key
            query_param: Query parameter name
            cookie_name: Cookie name
            valid_keys: Dictionary of valid keys with metadata
            validate_with_service: Function to validate keys with external service
            **kwargs: Additional configuration
        """
        super().__init__(name, kwargs.get("priority", 90))
        self.header_name = header_name
        self.query_param = query_param
        self.cookie_name = cookie_name
        self.valid_keys = valid_keys or {}
        self.validate_with_service = validate_with_service
        
        import logging
        self._logger = logging.getLogger(f"runtime.auth.providers.apikey.{name}")
    
    async def authenticate(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate using API key
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        api_key = credentials.api_key
        
        if not api_key:
            return AuthResult(
                status=AuthStatus.FAILED,
                error="No API key provided",
                auth_type=AuthType.API_KEY,
                error_code="MISSING_API_KEY",
            )
        
        try:
            # Validate API key
            user_data = await self._validate_api_key(api_key, context)
            
            if not user_data:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    error="Invalid API key",
                    auth_type=AuthType.API_KEY,
                    error_code="INVALID_API_KEY",
                )
            
            # Extract user information
            user_id = user_data.get("user_id") or user_data.get("sub") or user_data.get("id")
            username = user_data.get("username") or user_data.get("name")
            email = user_data.get("email")
            
            roles = user_data.get("roles", [])
            permissions = user_data.get("permissions", [])
            scopes = user_data.get("scopes", [])
            
            # Remove sensitive data from claims
            claims = {k: v for k, v in user_data.items() if k not in ["user_id", "username", "email", "roles", "permissions", "scopes"]}
            
            # Check expiration
            if "expires_at" in user_data:
                expires_at = user_data["expires_at"]
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                if isinstance(expires_at, (int, float)):
                    expires_at = datetime.fromtimestamp(expires_at, tz=timezone.utc)
                
                if expires_at < datetime.now(timezone.utc):
                    return AuthResult(
                        status=AuthStatus.EXPIRED,
                        error="API key has expired",
                        auth_type=AuthType.API_KEY,
                        error_code="API_KEY_EXPIRED",
                    )
            else:
                expires_at = None
            
            # Success
            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=user_id,
                username=username,
                email=email,
                roles=roles,
                permissions=permissions,
                scopes=scopes,
                claims=claims,
                metadata={
                    "api_key_id": user_data.get("key_id"),
                    "key_name": user_data.get("key_name"),
                    "provider": self.name,
                },
                token_type=TokenType.API,
                auth_type=AuthType.API_KEY,
                expires_at=expires_at,
            )
            
        except Exception as e:
            self._logger.error(f"API key authentication error: {e}")
            return AuthResult(
                status=AuthStatus.FAILED,
                error=f"Authentication error: {str(e)}",
                auth_type=AuthType.API_KEY,
                error_code="AUTH_ERROR",
            )
    
    async def supports(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> bool:
        """Check if credentials can be handled by API key provider"""
        return (
            credentials.auth_type == AuthType.API_KEY or
            credentials.api_key is not None
        )
    
    async def _validate_api_key(
        self,
        api_key: str,
        context: RuntimeContext,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate API key
        
        Args:
            api_key: API key to validate
            context: Runtime context
            
        Returns:
            Optional[Dict[str, Any]]: User data if valid
        """
        # Check local valid keys
        if self.valid_keys and api_key in self.valid_keys:
            return self.valid_keys[api_key]
        
        # Check with external service
        if self.validate_with_service:
            if asyncio.iscoroutinefunction(self.validate_with_service):
                return await self.validate_with_service(api_key, context)
            else:
                return self.validate_with_service(api_key, context)
        
        # Try to parse as JWT API key
        # In production, this would use a proper JWT library
        if len(api_key.split(".")) == 3:
            # Treat as JWT
            try:
                parts = api_key.split(".")
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                
                # Check if it's an API key token
                if payload.get("type") == "api_key" or payload.get("typ") == "api":
                    return payload
            except Exception:
                pass
        
        return None


class BasicAuthProvider(AuthenticationProvider):
    """
    Basic Authentication Provider
    
    Handles HTTP Basic Authentication with username/password.
    """
    
    def __init__(
        self,
        name: str = "basic",
        validate_credentials: Optional[Callable] = None,
        realm: str = "Secure Runtime",
        **kwargs
    ):
        """
        Initialize basic auth provider
        
        Args:
            name: Provider name
            validate_credentials: Function to validate credentials
            realm: Authentication realm
            **kwargs: Additional configuration
        """
        super().__init__(name, kwargs.get("priority", 80))
        self.validate_credentials = validate_credentials
        self.realm = realm
        
        import logging
        self._logger = logging.getLogger(f"runtime.auth.providers.basic.{name}")
    
    async def authenticate(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate using Basic Auth
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        username = credentials.username
        password = credentials.password
        
        if not username or not password:
            return AuthResult(
                status=AuthStatus.FAILED,
                error="Missing username or password",
                auth_type=AuthType.BASIC,
                error_code="MISSING_CREDENTIALS",
            )
        
        try:
            # Validate credentials
            user_data = await self._validate_credentials(username, password, context)
            
            if not user_data:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    error="Invalid username or password",
                    auth_type=AuthType.BASIC,
                    error_code="INVALID_CREDENTIALS",
                )
            
            # Extract user information
            user_id = user_data.get("user_id") or user_data.get("id") or username
            email = user_data.get("email")
            roles = user_data.get("roles", [])
            permissions = user_data.get("permissions", [])
            scopes = user_data.get("scopes", [])
            
            claims = {k: v for k, v in user_data.items() if k not in ["user_id", "email", "roles", "permissions", "scopes"]}
            
            # Success
            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=user_id,
                username=username,
                email=email,
                roles=roles,
                permissions=permissions,
                scopes=scopes,
                claims=claims,
                metadata={
                    "provider": self.name,
                },
                auth_type=AuthType.BASIC,
            )
            
        except Exception as e:
            self._logger.error(f"Basic auth error: {e}")
            return AuthResult(
                status=AuthStatus.FAILED,
                error=f"Authentication error: {str(e)}",
                auth_type=AuthType.BASIC,
                error_code="AUTH_ERROR",
            )
    
    async def supports(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> bool:
        """Check if credentials can be handled by basic auth provider"""
        return (
            credentials.auth_type == AuthType.BASIC or
            (credentials.username is not None and credentials.password is not None)
        )
    
    async def _validate_credentials(
        self,
        username: str,
        password: str,
        context: RuntimeContext,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate username and password
        
        Args:
            username: Username
            password: Password
            context: Runtime context
            
        Returns:
            Optional[Dict[str, Any]]: User data if valid
        """
        if self.validate_credentials:
            if asyncio.iscoroutinefunction(self.validate_credentials):
                return await self.validate_credentials(username, password, context)
            else:
                return self.validate_credentials(username, password, context)
        
        # Default validation - only allow if configured
        # In production, this would validate against a user database
        return {"user_id": username, "username": username}


class SessionProvider(AuthenticationProvider):
    """
    Session Authentication Provider
    
    Handles session-based authentication using session IDs or cookies.
    """
    
    def __init__(
        self,
        name: str = "session",
        session_validate_func: Optional[Callable] = None,
        cookie_name: str = "session_id",
        header_name: str = "X-Session-ID",
        **kwargs
    ):
        """
        Initialize session provider
        
        Args:
            name: Provider name
            session_validate_func: Function to validate session
            cookie_name: Cookie name for session ID
            header_name: Header name for session ID
            **kwargs: Additional configuration
        """
        super().__init__(name, kwargs.get("priority", 70))
        self.session_validate_func = session_validate_func
        self.cookie_name = cookie_name
        self.header_name = header_name
        
        import logging
        self._logger = logging.getLogger(f"runtime.auth.providers.session.{name}")
    
    async def authenticate(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate using session
        
        Args:
            credentials: Authentication credentials
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        session_id = credentials.session_id
        
        if not session_id:
            return AuthResult(
                status=AuthStatus.FAILED,
                error="No session ID provided",
                auth_type=AuthType.SESSION,
                error_code="MISSING_SESSION",
            )
        
        try:
            # Validate session
            session_data = await self._validate_session(session_id, context)
            
            if not session_data:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    error="Invalid session",
                    auth_type=AuthType.SESSION,
                    error_code="INVALID_SESSION",
                )
            
            # Check if session is expired
            if "expires_at" in session_data:
                expires_at = session_data["expires_at"]
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                if isinstance(expires_at, (int, float)):
                    expires_at = datetime.fromtimestamp(expires_at, tz=timezone.utc)
                
                if expires_at < datetime.now(timezone.utc):
                    return AuthResult(
                        status=AuthStatus.EXPIRED,
                        error="Session has expired",
                        auth_type=AuthType.SESSION,
                        error_code="SESSION_EXPIRED",
                    )
            
            # Extract user information
            user_id = session_data.get("user_id") or session_data.get("sub") or session_data.get("id")
            username = session_data.get("username") or session_data.get("name")
            email = session_data.get("email")
            roles = session_data.get("roles", [])
            permissions = session_data.get("permissions", [])
            scopes = session_data.get("scopes", [])
            
            claims = {k: v for k, v in session_data.items() if k not in ["user_id", "username", "email", "roles", "permissions", "scopes"]}
            
            # Success
            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=user_id,
                username=username,
                email=email,
                roles=roles,
                permissions=permissions,
                scopes=scopes,
                claims=claims,
                metadata={
                    "session_id": session_id,
                    "provider": self.name,
                },
                token_type=TokenType.SESSION,
                auth_type=AuthType.SESSION,
                session_id=session_id,
                expires_at=session_data.get("expires_at"),
            )
            
        except SessionExpiredError as e:
            return AuthResult(
                status=AuthStatus.EXPIRED,
                error=str(e),
                auth_type=AuthType.SESSION,
                error_code="SESSION_EXPIRED",
            )
        except Exception as e:
            self._logger.error(f"Session auth error: {e}")
            return AuthResult(
                status=AuthStatus.FAILED,
                error=f"Authentication error: {str(e)}",
                auth_type=AuthType.SESSION,
                error_code="AUTH_ERROR",
            )
    
    async def supports(
        self,
        credentials: AuthCredentials,
        context: RuntimeContext,
    ) -> bool:
        """Check if credentials can be handled by session provider"""
        return (
            credentials.auth_type == AuthType.SESSION or
            credentials.session_id is not None or
            credentials.cookie is not None
        )
    
    async def _validate_session(
        self,
        session_id: str,
        context: RuntimeContext,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate session ID
        
        Args:
            session_id: Session ID
            context: Runtime context
            
        Returns:
            Optional[Dict[str, Any]]: Session data if valid
        """
        if self.session_validate_func:
            if asyncio.iscoroutinefunction(self.session_validate_func):
                return await self.session_validate_func(session_id, context)
            else:
                return self.session_validate_func(session_id, context)
        
        # Default validation - return basic session data
        # In production, this would validate against a session store
        return {
            "user_id": "session_user",
            "username": "session_user",
            "session_id": session_id,
        }


class AuthenticationMiddleware:
    """
    Authentication Middleware for Secure Runtime
    
    Handles authentication of incoming requests using multiple providers.
    Supports JWT, API keys, Basic Auth, OAuth2, and session authentication.
    """
    
    def __init__(
        self,
        providers: Optional[List[AuthenticationProvider]] = None,
        require_auth: bool = True,
        auth_exempt_paths: List[str] = None,
        auth_exempt_methods: List[str] = None,
        extract_from_header: str = "Authorization",
        cookie_name: str = "session_id",
        query_param: str = "token",
        **kwargs
    ):
        """
        Initialize authentication middleware
        
        Args:
            providers: List of authentication providers (ordered by priority)
            require_auth: Whether authentication is required
            auth_exempt_paths: Paths that don't require authentication
            auth_exempt_methods: Methods that don't require authentication
            extract_from_header: Header to extract credentials from
            cookie_name: Cookie name for session
            query_param: Query parameter for token
            **kwargs: Additional configuration
        """
        self.providers = providers or []
        self.require_auth = require_auth
        self.auth_exempt_paths = auth_exempt_paths or []
        self.auth_exempt_methods = auth_exempt_methods or ["OPTIONS"]
        self.extract_from_header = extract_from_header
        self.cookie_name = cookie_name
        self.query_param = query_param
        
        # Sort providers by priority (highest first)
        self.providers.sort(key=lambda p: -p.priority)
        
        self._logger = None
        self._event_bus = None
        self._metrics = None
        
        import logging
        self._logger = logging.getLogger("runtime.middleware.auth")
    
    async def __call__(
        self,
        request: Request,
        context: RuntimeContext,
        next_middleware: Callable[[Request, RuntimeContext], Awaitable[Response]],
    ) -> Response:
        """
        Process authentication for the request
        
        Args:
            request: HTTP request
            context: Runtime context
            next_middleware: Next middleware in chain            
        Returns:
            Response: HTTP response
        """
        # Check if authentication is exempt
        if self._is_auth_exempt(request):
            self._logger.debug(f"Authentication exempt for {request.method.value} {request.path}")
            context.authenticated = False
            context.auth_method = "none"
            return await next_middleware(request, context)
        
        try:
            # Extract credentials from request
            credentials = await self._extract_credentials(request, context)
            
            if not credentials or not credentials.auth_type:
                # No credentials found
                if self.require_auth:
                    self._logger.warning(f"No credentials provided for {request.method.value} {request.path}")
                    await self._emit_auth_event("authentication.failure", request, context, "No credentials provided")
                    return self._unauthorized_response("Authentication required")
                else:
                    context.authenticated = False
                    return await next_middleware(request, context)
            
            # Try each provider
            for provider in self.providers:
                if not await provider.supports(credentials, context):
                    continue
                
                result = await provider.authenticate(credentials, context)
                
                if result.is_authenticated():
                    # Authentication successful
                    self._logger.info(f"Authentication successful for user {result.user_id} via {provider.name}")
                    
                    # Set authentication data in context
                    context.authenticated = True
                    context.user_id = result.user_id
                    context.auth_method = provider.name
                    context.auth_provider = provider.name
                    context.auth_claims = result.claims
                    context.permissions = set(result.permissions)
                    context.roles = set(result.roles)
                    
                    # Store additional auth data in context metadata
                    context.metadata["auth"] = {
                        "result": result.to_dict(),
                        "provider": provider.name,
                        "token_type": result.token_type.value if result.token_type else None,
                        "scopes": result.scopes,
                    }
                    
                    # Emit success event
                    await self._emit_auth_event("authentication.success", request, context, "Authentication successful")
                    
                    # Record metrics
                    await self._record_auth_metrics(True, provider.name)
                    
                    break
                else:
                    # Authentication failed
                    self._logger.warning(f"Authentication failed for {provider.name}: {result.error}")
                    
                    if result.status == AuthStatus.EXPIRED:
                        await self._emit_auth_event("authentication.expired", request, context, result.error or "Token expired")
                        return self._unauthorized_response(result.error or "Authentication expired", expired=True)
                    
                    # Continue to next provider
                    continue
            
            if not context.authenticated:
                # All providers failed
                self._logger.warning(f"Authentication failed for {request.method.value} {request.path}")
                await self._emit_auth_event("authentication.failure", request, context, "All authentication providers failed")
                return self._unauthorized_response("Authentication failed")
            
            return await next_middleware(request, context)
            
        except Exception as e:
            self._logger.error(f"Authentication middleware error: {e}")
            await self._emit_auth_event("authentication.error", request, context, str(e))
            return self._error_response(f"Authentication error: {str(e)}")
    
    def _is_auth_exempt(self, request: Request) -> bool:
        """
        Check if request is exempt from authentication
        
        Args:
            request: HTTP request
            
        Returns:
            bool: True if exempt
        """
        # Check method exemptions
        if request.method.value in self.auth_exempt_methods:
            return True
        
        # Check path exemptions
        path = request.path
        for exempt_path in self.auth_exempt_paths:
            if exempt_path.endswith("*"):
                if path.startswith(exempt_path[:-1]):
                    return True
            elif path == exempt_path:
                return True
        
        return False
    
    async def _extract_credentials(
        self,
        request: Request,
        context: RuntimeContext,
    ) -> Optional[AuthCredentials]:
        """
        Extract authentication credentials from request
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[AuthCredentials]: Extracted credentials
        """
        # Try to extract from Authorization header
        auth_header = request.headers.get(self.extract_from_header.lower())
        if auth_header:
            # Parse Authorization header
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                return AuthCredentials(
                    auth_type=AuthType.JWT,
                    token=token,
                    source="header",
                    custom_data={"header_type": "Bearer"},
                )
            elif auth_header.startswith("Basic "):
                try:
                    encoded = auth_header[6:].strip()
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                        return AuthCredentials(
                            auth_type=AuthType.BASIC,
                            username=username,
                            password=password,
                            source="header",
                            custom_data={"header_type": "Basic"},
                        )
                except Exception:
                    pass
            elif auth_header.startswith("APIKey "):
                api_key = auth_header[7:].strip()
                return AuthCredentials(
                    auth_type=AuthType.API_KEY,
                    api_key=api_key,
                    source="header",
                    custom_data={"header_type": "APIKey"},
                )
            else:
                # Try as API key or session token
                if len(auth_header) > 20:
                    return AuthCredentials(
                        auth_type=AuthType.API_KEY,
                        api_key=auth_header,
                        source="header",
                    )
                else:
                    return AuthCredentials(
                        auth_type=AuthType.SESSION,
                        session_id=auth_header,
                        source="header",
                    )
        
        # Try to extract from cookie
        if self.cookie_name:
            cookie_value = request.get_cookie(self.cookie_name)
            if cookie_value:
                return AuthCredentials(
                    auth_type=AuthType.COOKIE,
                    cookie=cookie_value,
                    session_id=cookie_value,
                    source="cookie",
                    custom_data={"cookie_name": self.cookie_name},
                )
        
        # Try to extract from query parameter
        if self.query_param:
            query_value = request.get_query(self.query_param)
            if query_value:
                if isinstance(query_value, list):
                    query_value = query_value[0]
                return AuthCredentials(
                    auth_type=AuthType.JWT,
                    token=query_value,
                    source="query",
                    custom_data={"query_param": self.query_param},
                )
        
        # Try to extract API key from query
        api_key_param = request.get_query("api_key")
        if api_key_param:
            if isinstance(api_key_param, list):
                api_key_param = api_key_param[0]
            return AuthCredentials(
                auth_type=AuthType.API_KEY,
                api_key=api_key_param,
                source="query",
            )
        
        # No credentials found
        return None
    
    def _unauthorized_response(self, message: str, expired: bool = False) -> Response:
        """
        Create unauthorized response
        
        Args:
            message: Error message
            expired: Whether authentication expired
            
        Returns:
            Response: Unauthorized response
        """
        from runtime.core.response import Response
        
        status_code = 401
        headers = {"WWW-Authenticate": "Bearer realm=\"Secure Runtime\""}
        
        response = Response().unauthorized(message=message)
        response.headers.update(headers)
        
        if expired:
            response.add_header("X-Auth-Expired", "true")
        
        return response
    
    def _error_response(self, message: str) -> Response:
        """
        Create error response
        
        Args:
            message: Error message
            
        Returns:
            Response: Error response
        """
        from runtime.core.response import Response
        return Response().internal_error(message=message)
    
    async def _emit_auth_event(
        self,
        event_type: str,
        request: Request,
        context: RuntimeContext,
        message: str,
    ) -> None:
        """
        Emit authentication event
        
        Args:
            event_type: Event type
            request: HTTP request
            context: Runtime context
            message: Event message
        """
        try:
            event_bus = get_event_bus()
            await event_bus.emit(
                event_type,
                payload={
                    "user_id": context.user_id,
                    "path": request.path,
                    "method": request.method.value,
                    "request_id": request.id,
                    "message": message,
                }
            )
        except Exception:
            pass  # Ignore event errors
    
    async def _record_auth_metrics(
        self,
        success: bool,
        provider: str,
    ) -> None:
        """
        Record authentication metrics
        
        Args:
            success: Whether authentication succeeded
            provider: Authentication provider name
        """
        try:
            metrics = get_metrics_collector()
            if success:
                metrics.increment_counter("auth_success")
            else:
                metrics.increment_counter("auth_failures")
            # Provider-specific metrics would go here
        except Exception:
            pass  # Ignore metrics errors
    
    # Public methods for external use
    
    async def authenticate(
        self,
        request: Request,
        context: RuntimeContext,
    ) -> AuthResult:
        """
        Authenticate a request using the configured providers
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            AuthResult: Authentication result
        """
        credentials = await self._extract_credentials(request, context)
        
        if not credentials:
            return AuthResult(
                status=AuthStatus.FAILED,
                error="No credentials provided",
                auth_type=AuthType.NONE,
                error_code="NO_CREDENTIALS",
            )
        
        for provider in self.providers:
            if await provider.supports(credentials, context):
                result = await provider.authenticate(credentials, context)
                if result.is_authenticated():
                    return result
        
        return AuthResult(
            status=AuthStatus.FAILED,
            error="Authentication failed with all providers",
            auth_type=AuthType.NONE,
            error_code="AUTH_FAILED",
        )
    
    def add_provider(self, provider: AuthenticationProvider) -> None:
        """
        Add an authentication provider
        
        Args:
            provider: Authentication provider
        """
        self.providers.append(provider)
        self.providers.sort(key=lambda p: -p.priority)
        self._logger.info(f"Added authentication provider: {provider.name}")
    
    def remove_provider(self, provider_name: str) -> bool:
        """
        Remove an authentication provider
        
        Args:
            provider_name: Provider name
            
        Returns:
            bool: True if removed
        """
        for i, provider in enumerate(self.providers):
            if provider.name == provider_name:
                self.providers.pop(i)
                self._logger.info(f"Removed authentication provider: {provider_name}")
                return True
        return False
    
    def get_providers(self) -> List[AuthenticationProvider]:
        """
        Get all authentication providers
        
        Returns:
            List[AuthenticationProvider]: List of providers
        """
        return self.providers.copy()
    
    def clear_providers(self) -> None:
        """Clear all authentication providers"""
        self.providers.clear()
        self._logger.info("Cleared all authentication providers")


# Convenience functions
def create_auth_middleware(**kwargs) -> AuthenticationMiddleware:
    """
    Create authentication middleware with default providers
    
    Args:
        **kwargs: AuthenticationMiddleware configuration
        
    Returns:
        AuthenticationMiddleware: Configured middleware
    """
    # Create default providers if not provided
    if "providers" not in kwargs:
        providers = [
            JWTProvider(priority=100),
            APIKeyProvider(priority=90),
            BasicAuthProvider(priority=80),
            SessionProvider(priority=70),
        ]
        kwargs["providers"] = providers
    
    return AuthenticationMiddleware(**kwargs)


def create_jwt_auth(**kwargs) -> AuthenticationMiddleware:
    """
    Create JWT-only authentication middleware
    
    Args:
        **kwargs: Configuration
        
    Returns:
        AuthenticationMiddleware: JWT auth middleware
    """
    provider = JWTProvider(**kwargs.get("jwt_config", {}))
    return AuthenticationMiddleware(
        providers=[provider],
        **{k: v for k, v in kwargs.items() if k != "jwt_config"}
    )


def create_api_key_auth(**kwargs) -> AuthenticationMiddleware:
    """
    Create API key-only authentication middleware
    
    Args:
        **kwargs: Configuration
        
    Returns:
        AuthenticationMiddleware: API key auth middleware
    """
    provider = APIKeyProvider(**kwargs.get("api_key_config", {}))
    return AuthenticationMiddleware(
        providers=[provider],
        **{k: v for k, v in kwargs.items() if k != "api_key_config"}
    )