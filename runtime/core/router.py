# runtime/core/router.py
"""
Internal Request Router for Secure Runtime

This module provides internal routing capabilities for dispatching requests
through the Secure Runtime pipeline. It manages route registration, matching,
and dispatching with support for middleware chains and various routing patterns.
"""

import re
import time
import asyncio
import inspect
from typing import (
    Any, Callable, Dict, List, Optional, Set, Union, Type, Tuple,
    Awaitable, Coroutine, TypeVar, Generic
)
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps
from urllib.parse import unquote

from pydantic import BaseModel, Field, ConfigDict

from runtime.core.request import Request, RequestMethod
from runtime.core.response import Response
from runtime.core.context import RuntimeContext
from runtime.core.errors import (
    RouterError,
    RouteNotFoundError,
    RouteMethodNotAllowedError,
    MiddlewareError,
    MiddlewareChainError,
)
from runtime.core.events import get_event_bus, publish, Event
from runtime.core.metrics import get_metrics_collector


# Type variables
Handler = Callable[[Request, RuntimeContext], Awaitable[Response]]
Middleware = Callable[[Request, RuntimeContext, Callable], Awaitable[Response]]
RouteHandler = Union[Handler, Callable[[Request], Awaitable[Response]], Callable[..., Awaitable[Response]]]


class RoutePriority(int, Enum):
    """Route priority levels"""
    LOWEST = 0
    LOW = 25
    NORMAL = 50
    HIGH = 75
    HIGHEST = 100


class RouteMatchType(str, Enum):
    """Route matching types"""
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"
    WILDCARD = "wildcard"


@dataclass
class Route:
    """Route definition"""
    path: str
    method: RequestMethod
    handler: RouteHandler
    priority: int = RoutePriority.NORMAL
    middlewares: List[Middleware] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    timeout: Optional[float] = None
    security_policy: Optional[str] = None
    caching_rules: Optional[Dict[str, Any]] = None
    match_type: RouteMatchType = RouteMatchType.EXACT
    is_regex: bool = False
    regex_pattern: Optional[re.Pattern] = None
    version: Optional[str] = None
    
    def __post_init__(self):
        """Initialize route and compile regex if needed"""
        if self.is_regex:
            self.regex_pattern = re.compile(self.path)
        elif self.path.endswith("*"):
            self.match_type = RouteMatchType.WILDCARD
        elif any(c in self.path for c in "{}:<>") or self.path.startswith("^"):
            self.match_type = RouteMatchType.REGEX
            self.is_regex = True
            pattern = self.path.replace("{", "(?P<").replace("}", ">)")
            pattern = pattern.replace(":str", "[^/]+")
            pattern = pattern.replace(":int", "\\d+")
            pattern = pattern.replace(":float", "\\d+\\.\\d+")
            pattern = pattern.replace(":uuid", "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            self.regex_pattern = re.compile(f"^{pattern}$")
    
    def matches(self, path: str, method: RequestMethod) -> Tuple[bool, Dict[str, str]]:
        """
        Check if route matches the given path and method
        
        Args:
            path: Request path
            method: Request method
            
        Returns:
            Tuple[bool, Dict[str, str]]: (matches, path_params)
        """
        # Check method
        if method != self.method:
            return False, {}
        
        path_params = {}
        
        # Exact match
        if self.match_type == RouteMatchType.EXACT:
            return path == self.path, {}
        
        # Wildcard match
        if self.match_type == RouteMatchType.WILDCARD:
            prefix = self.path[:-1]
            if prefix and path.startswith(prefix):
                suffix = path[len(prefix):]
                if suffix:
                    path_params = {"wildcard": suffix}
                return True, path_params
            return False, {}
        
        # Regex match
        if self.is_regex and self.regex_pattern:
            match = self.regex_pattern.match(path)
            if match:
                # Extract named groups as path parameters
                path_params = match.groupdict()
                # Also add unnamed groups
                for i, group in enumerate(match.groups()):
                    if f"group_{i}" not in path_params:
                        path_params[f"param_{i}"] = group
                return True, path_params
        
        # Prefix match (for nested routes)
        if self.match_type == RouteMatchType.PREFIX:
            if self.path and path.startswith(self.path):
                return True, {}
        
        return False, {}
    
    def __repr__(self) -> str:
        return f"<Route {self.method.value} {self.path} priority={self.priority}>"


@dataclass
class RouteMatch:
    """Result of route matching"""
    route: Route
    path_params: Dict[str, str]
    matched_path: str
    priority: int


class RouteRegistry:
    """Registry for managing routes"""
    
    def __init__(self):
        self._routes: List[Route] = []
        self._routes_by_method: Dict[RequestMethod, List[Route]] = {}
        self._route_by_id: Dict[str, Route] = {}
        self._route_id_counter = 0
        self._logger = logging.getLogger("runtime.router.registry")
    
    def register(self, route: Route) -> str:
        """
        Register a route
        
        Args:
            route: Route to register
            
        Returns:
            str: Route ID
        """
        # Generate route ID
        route_id = f"route_{self._route_id_counter}"
        self._route_id_counter += 1
        
        # Add metadata
        route.metadata["route_id"] = route_id
        route.metadata["registered_at"] = time.time()
        
        # Add to route list
        self._routes.append(route)
        
        # Add to method index
        if route.method not in self._routes_by_method:
            self._routes_by_method[route.method] = []
        self._routes_by_method[route.method].append(route)
        
        # Sort by priority
        self._routes.sort(key=lambda r: -r.priority)
        for method in self._routes_by_method:
            self._routes_by_method[method].sort(key=lambda r: -r.priority)
        
        self._route_by_id[route_id] = route
        
        self._logger.debug(f"Registered route {route.method.value} {route.path} (id: {route_id})")
        return route_id
    
    def unregister(self, route_id: str) -> bool:
        """
        Unregister a route by ID
        
        Args:
            route_id: Route ID
            
        Returns:
            bool: True if removed
        """
        route = self._route_by_id.pop(route_id, None)
        if not route:
            return False
        
        # Remove from main list
        self._routes = [r for r in self._routes if r.metadata.get("route_id") != route_id]
        
        # Remove from method index
        if route.method in self._routes_by_method:
            self._routes_by_method[route.method] = [
                r for r in self._routes_by_method[route.method]
                if r.metadata.get("route_id") != route_id
            ]
        
        self._logger.debug(f"Unregistered route {route.method.value} {route.path}")
        return True
    
    def find_route(
        self,
        path: str,
        method: RequestMethod
    ) -> Optional[RouteMatch]:
        """
        Find a route matching the given path and method
        
        Args:
            path: Request path
            method: Request method
            
        Returns:
            Optional[RouteMatch]: Route match if found
        """
        # Normalize path
        path = unquote(path)
        if not path.startswith("/"):
            path = f"/{path}"
        
        # First check exact matches
        for route in self._routes:
            if route.method == method:
                matches, params = route.matches(path, method)
                if matches:
                    return RouteMatch(
                        route=route,
                        path_params=params,
                        matched_path=path,
                        priority=route.priority
                    )
        
        # Check wildcard/prefix matches with lower priority
        for route in self._routes:
            if route.method == method and route.match_type in [RouteMatchType.WILDCARD, RouteMatchType.PREFIX]:
                matches, params = route.matches(path, method)
                if matches:
                    return RouteMatch(
                        route=route,
                        path_params=params,
                        matched_path=path,
                        priority=route.priority - 1
                    )
        
        return None
    
    def find_by_method(self, method: RequestMethod) -> List[Route]:
        """Get all routes for a specific method"""
        return self._routes_by_method.get(method, [])
    
    def get_all_routes(self) -> List[Route]:
        """Get all registered routes"""
        return self._routes.copy()
    
    def get_route(self, route_id: str) -> Optional[Route]:
        """Get route by ID"""
        return self._route_by_id.get(route_id)
    
    def count(self) -> int:
        """Get total number of routes"""
        return len(self._routes)
    
    def exists(self, path: str, method: RequestMethod) -> bool:
        """Check if a route exists"""
        return self.find_route(path, method) is not None
    
    def clear(self) -> None:
        """Clear all routes"""
        self._routes.clear()
        self._routes_by_method.clear()
        self._route_by_id.clear()
        self._logger.info("Cleared all routes")
    
    def __repr__(self) -> str:
        return f"<RouteRegistry routes={self.count()}>"


class RouteMatcher:
    """Route matching and validation utilities"""
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize path for consistent matching"""
        # Remove trailing slash if not root
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        # Ensure leading slash
        if not path.startswith("/"):
            path = f"/{path}"
        return unquote(path)
    
    @staticmethod
    def extract_path_params(pattern: str, path: str) -> Dict[str, str]:
        """Extract path parameters from a path"""
        params = {}
        pattern_parts = pattern.split("/")
        path_parts = path.split("/")
        
        for i, part in enumerate(pattern_parts):
            if i < len(path_parts) and part.startswith("{") and part.endswith("}"):
                param_name = part[1:-1]
                param_value = path_parts[i]
                params[param_name] = param_value
        
        return params
    
    @staticmethod
    def validate_path(path: str) -> bool:
        """Validate that a path is valid"""
        if not path:
            return False
        if not path.startswith("/"):
            return False
        # Prevent path traversal
        if ".." in path or "//" in path:
            return False
        return True
    
    @staticmethod
    def route_matches_path(route: Route, path: str) -> bool:
        """Check if a route's path matches a given path"""
        if route.match_type == RouteMatchType.EXACT:
            return path == route.path
        elif route.match_type == RouteMatchType.WILDCARD:
            prefix = route.path[:-1]
            return path.startswith(prefix) if prefix else True
        elif route.match_type in [RouteMatchType.REGEX]:
            if route.regex_pattern:
                return bool(route.regex_pattern.match(path))
        return False


class RouterMiddleware:
    """Middleware chain management"""
    
    def __init__(self):
        self._middlewares: List[Middleware] = []
        self._before_middlewares: List[Middleware] = []
        self._after_middlewares: List[Middleware] = []
        self._exception_middlewares: List[Callable[[Exception, Request, RuntimeContext], Awaitable[Response]]] = []
        self._logger = logging.getLogger("runtime.router.middleware")
    
    def add(self, middleware: Middleware, position: str = "before") -> None:
        """
        Add a middleware to the chain
        
        Args:
            middleware: Middleware function
            position: Position in chain (before, after, exception)
        """
        if position == "before":
            self._before_middlewares.append(middleware)
        elif position == "after":
            self._after_middlewares.append(middleware)
        elif position == "exception":
            self._exception_middlewares.append(middleware)
        else:
            self._middlewares.append(middleware)
        
        self._logger.debug(f"Added {position} middleware: {middleware.__name__}")
    
    def remove(self, middleware: Middleware) -> bool:
        """Remove a middleware from the chain"""
        for collection in [self._before_middlewares, self._after_middlewares, self._middlewares]:
            if middleware in collection:
                collection.remove(middleware)
                self._logger.debug(f"Removed middleware: {middleware.__name__}")
                return True
        return False
    
    async def execute_chain(
        self,
        request: Request,
        context: RuntimeContext,
        handler: Handler
    ) -> Response:
        """
        Execute the full middleware chain and handler
        
        Args:
            request: Request object
            context: Runtime context
            handler: Final handler
            
        Returns:
            Response: Response object
        """
        # Build the chain
        chain = self._build_chain(handler)
        
        # Execute before middlewares
        for middleware in self._before_middlewares:
            try:
                chain = self._wrap_with_middleware(middleware, chain, "before")
            except Exception as e:
                self._logger.error(f"Error in before middleware {middleware.__name__}: {e}")
                raise MiddlewareError(f"Before middleware error: {e}", middleware_name=middleware.__name__)
        
        # Execute middlewares
        try:
            response = await chain(request, context)
        except Exception as e:
            # Exception handling
            for exc_middleware in self._exception_middlewares:
                try:
                    response = await exc_middleware(e, request, context)
                    if response:
                        break
                except Exception as middleware_error:
                    self._logger.error(f"Error in exception middleware: {middleware_error}")
            else:
                # No exception middleware handled it
                raise
        
        # Execute after middlewares
        for middleware in self._after_middlewares:
            try:
                response = await self._wrap_with_middleware(middleware, lambda req, ctx: asyncio.coroutine(lambda: response), "after")(request, context)
            except Exception as e:
                self._logger.error(f"Error in after middleware {middleware.__name__}: {e}")
                raise MiddlewareError(f"After middleware error: {e}", middleware_name=middleware.__name__)
        
        return response
    
    def _build_chain(self, handler: Handler) -> Handler:
        """Build the middleware chain"""
        chain = handler
        
        # Wrap with middlewares in reverse order
        for middleware in reversed(self._middlewares):
            chain = self._wrap_with_middleware(middleware, chain, "chain")
        
        return chain
    
    def _wrap_with_middleware(self, middleware: Middleware, handler: Handler, position: str) -> Handler:
        """Wrap a handler with a middleware"""
        @wraps(handler)
        async def wrapper(request: Request, context: RuntimeContext) -> Response:
            return await middleware(request, context, handler)
        return wrapper


class RuntimeRouter:
    """
    Internal Request Router for Secure Runtime
    
    Routes incoming requests through the Secure Runtime pipeline with
    support for middleware chains, route registration, and dispatching.
    """
    
    def __init__(
        self,
        name: str = "secure-runtime-router",
        enable_metrics: bool = True,
        enable_events: bool = True,
        default_timeout: float = 30.0,
    ):
        """
        Initialize the router
        
        Args:
            name: Router name
            enable_metrics: Enable metrics collection
            enable_events: Enable event publishing
            default_timeout: Default route timeout in seconds
        """
        self.name = name
        self.enable_metrics = enable_metrics
        self.enable_events = enable_events
        self.default_timeout = default_timeout
        
        self.registry = RouteRegistry()
        self.matcher = RouteMatcher()
        self.middleware = RouterMiddleware()
        
        self._logger = logging.getLogger(f"runtime.router.{name}")
        self._event_bus = None
        self._metrics = None
        
        # Route handlers cache
        self._handler_cache: Dict[str, Handler] = {}
        
        # Stats
        self._stats = {
            "total_requests": 0,
            "matched_routes": 0,
            "unmatched_requests": 0,
            "errors": 0,
        }
    
    @property
    def event_bus(self):
        """Get event bus instance"""
        if self._event_bus is None and self.enable_events:
            self._event_bus = get_event_bus()
        return self._event_bus
    
    @property
    def metrics(self):
        """Get metrics collector instance"""
        if self._metrics is None and self.enable_metrics:
            self._metrics = get_metrics_collector()
        return self._metrics
    
    def register(
        self,
        path: str,
        method: Union[RequestMethod, str],
        handler: RouteHandler,
        **kwargs
    ) -> str:
        """
        Register a route
        
        Args:
            path: Route path
            method: HTTP method
            handler: Route handler
            **kwargs: Additional route configuration
            
        Returns:
            str: Route ID
        """
        # Normalize method
        if isinstance(method, str):
            method = RequestMethod(method.upper())
        
        # Normalize path
        path = self.matcher.normalize_path(path)
        
        # Validate path
        if not self.matcher.validate_path(path):
            raise ValueError(f"Invalid path: {path}")
        
        # Extract route configuration
        route = Route(
            path=path,
            method=method,
            handler=handler,
            priority=kwargs.get("priority", RoutePriority.NORMAL),
            middlewares=kwargs.get("middlewares", []),
            permissions=kwargs.get("permissions", set()),
            metadata=kwargs.get("metadata", {}),
            description=kwargs.get("description", ""),
            tags=kwargs.get("tags", []),
            timeout=kwargs.get("timeout", self.default_timeout),
            security_policy=kwargs.get("security_policy"),
            caching_rules=kwargs.get("caching_rules"),
            match_type=kwargs.get("match_type", RouteMatchType.EXACT),
            is_regex=kwargs.get("is_regex", False),
            version=kwargs.get("version"),
        )
        
        # Register route
        route_id = self.registry.register(route)
        
        # Clear handler cache
        self._handler_cache.clear()
        
        # Log registration
        self._logger.info(f"Registered route: {method.value} {path} (id: {route_id})")
        
        # Emit event
        if self.event_bus:
            asyncio.create_task(self.event_bus.emit(
                "route.registered",
                payload={
                    "route_id": route_id,
                    "path": path,
                    "method": method.value,
                    "description": route.description,
                }
            ))
        
        return route_id
    
    def unregister(self, route_id: str) -> bool:
        """
        Unregister a route
        
        Args:
            route_id: Route ID
            
        Returns:
            bool: True if removed
        """
        route = self.registry.get_route(route_id)
        if not route:
            return False
        
        result = self.registry.unregister(route_id)
        if result:
            self._handler_cache.clear()
            self._logger.info(f"Unregistered route: {route.method.value} {route.path}")
            
            if self.event_bus:
                asyncio.create_task(self.event_bus.emit(
                    "route.unregistered",
                    payload={
                        "route_id": route_id,
                        "path": route.path,
                        "method": route.method.value,
                    }
                ))
        
        return result
    
    def resolve(
        self,
        path: str,
        method: Union[RequestMethod, str]
    ) -> Optional[RouteMatch]:
        """
        Resolve a route for the given path and method
        
        Args:
            path: Request path
            method: HTTP method
            
        Returns:
            Optional[RouteMatch]: Route match if found
        """
        # Normalize method
        if isinstance(method, str):
            method = RequestMethod(method.upper())
        
        # Normalize path
        path = self.matcher.normalize_path(path)
        
        return self.registry.find_route(path, method)
    
    async def dispatch(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Response:
        """
        Dispatch a request through the routing pipeline
        
        Args:
            request: Request object
            context: Runtime context
            
        Returns:
            Response: Response object
            
        Raises:
            RouteNotFoundError: If no route matches
            RouteMethodNotAllowedError: If method not allowed
            MiddlewareError: If middleware fails
        """
        start_time = time.time()
        self._stats["total_requests"] += 1
        
        # Resolve route
        route_match = self.resolve(request.path, request.method)
        
        if not route_match:
            self._stats["unmatched_requests"] += 1
            self._logger.warning(f"Route not found: {request.method.value} {request.path}")
            
            # Emit event
            if self.event_bus:
                await self.event_bus.emit(
                    "route.not_found",
                    payload={
                        "path": request.path,
                        "method": request.method.value,
                        "request_id": request.id,
                    }
                )
            
            raise RouteNotFoundError(path=request.path, method=request.method.value)
        
        route = route_match.route
        self._stats["matched_routes"] += 1
        
        # Add path parameters to request
        if route_match.path_params:
            request.path_params.update(route_match.path_params)
        
        # Add route metadata to context
        context.metadata["route"] = {
            "id": route.metadata.get("route_id"),
            "path": route.path,
            "method": route.method.value,
            "description": route.description,
            "tags": route.tags,
            "version": route.version,
            "timeout": route.timeout,
        }
        
        # Build handler with middlewares
        handler = self._build_handler(route, context)
        
        # Execute with timeout if specified
        try:
            if route.timeout:
                response = await asyncio.wait_for(
                    self.middleware.execute_chain(request, context, handler),
                    timeout=route.timeout
                )
            else:
                response = await self.middleware.execute_chain(request, context, handler)
            
            # Set response time
            response.set_response_time(start_time)
            
            # Record metrics
            if self.metrics:
                self.metrics.record_request(
                    allowed=not response.is_blocked,
                    duration=(time.time() - start_time) * 1000  # Convert to ms
                )
            
            # Emit event
            if self.event_bus:
                await self.event_bus.emit(
                    "request.completed",
                    payload={
                        "path": request.path,
                        "method": request.method.value,
                        "status_code": response.status_code_int,
                        "blocked": response.is_blocked,
                        "duration": time.time() - start_time,
                        "request_id": request.id,
                    }
                )
            
            return response
            
        except asyncio.TimeoutError:
            self._logger.error(f"Route timeout: {route.method.value} {route.path}")
            if self.metrics:
                self.metrics.record_error("route_timeout", "error")
            
            if self.event_bus:
                await self.event_bus.emit(
                    "route.timeout",
                    payload={
                        "path": request.path,
                        "method": request.method.value,
                        "request_id": request.id,
                    }
                )
            
            # Return a timeout response
            from runtime.core.response import Response
            return Response(
                status_code=504,
                body={"error": "Request timeout", "timeout": route.timeout},
                content_type="application/json"
            ).block(
                reason="Request timeout",
                block_type="timeout",
                status_code=504
            )
        
        except RouteNotFoundError:
            raise
        except Exception as e:
            self._stats["errors"] += 1
            self._logger.error(f"Error dispatching request: {e}")
            
            if self.metrics:
                self.metrics.record_error(str(e), "error")
            
            if self.event_bus:
                await self.event_bus.emit(
                    "route.error",
                    payload={
                        "path": request.path,
                        "method": request.method.value,
                        "error": str(e),
                        "request_id": request.id,
                    }
                )
            
            # Re-raise as router error
            if not isinstance(e, RouterError):
                raise RouterError(f"Route dispatch error: {e}", route=request.path) from e
            raise
    
    def _build_handler(self, route: Route, context: RuntimeContext) -> Handler:
        """Build the complete handler with route-specific middlewares"""
        async def handler(request: Request, ctx: RuntimeContext) -> Response:
            # Add route middlewares to context
            if route.middlewares:
                # Execute route-specific middlewares
                chain = route.handler
                for middleware in reversed(route.middlewares):
                    chain = self._wrap_middleware(middleware, chain)
                return await chain(request, ctx)
            else:
                # Direct handler execution
                return await self._execute_handler(route.handler, request, ctx)
        
        return handler
    
    def _wrap_middleware(self, middleware: Middleware, handler: Handler) -> Handler:
        """Wrap a handler with a middleware"""
        @wraps(handler)
        async def wrapper(request: Request, context: RuntimeContext) -> Response:
            return await middleware(request, context, handler)
        return wrapper
    
    async def _execute_handler(
        self,
        handler: RouteHandler,
        request: Request,
        context: RuntimeContext
    ) -> Response:
        """
        Execute the route handler with proper signature handling
        
        Args:
            handler: Route handler
            request: Request object
            context: Runtime context
            
        Returns:
            Response: Response object
        """
        # Check if handler is already a proper Handler signature
        sig = inspect.signature(handler)
        params = list(sig.parameters.keys())
        
        # Build arguments based on handler signature
        kwargs = {}
        
        if "request" in params:
            kwargs["request"] = request
        if "context" in params or "ctx" in params:
            key = "context" if "context" in params else "ctx"
            kwargs[key] = context
        if "req" in params and "request" not in kwargs:
            kwargs["req"] = request
        
        # Execute handler
        if asyncio.iscoroutinefunction(handler):
            result = await handler(**kwargs)
        else:
            # Run sync handler in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, handler, **kwargs)
        
        # Ensure result is a Response
        if isinstance(result, Response):
            return result
        elif isinstance(result, dict):
            # Convert dict to JSON response
            from runtime.core.response import Response
            return Response(body=result, content_type="application/json")
        elif isinstance(result, str):
            # Convert string to text response
            from runtime.core.response import Response
            return Response(body=result, content_type="text/plain")
        else:
            # Wrap in default response
            from runtime.core.response import Response
            return Response(body=result)
    
    def use(self, middleware: Middleware, position: str = "before") -> None:
        """
        Add global middleware
        
        Args:
            middleware: Middleware function
            position: Position (before, after, exception)
        """
        self.middleware.add(middleware, position)
        self._logger.info(f"Added global middleware: {middleware.__name__} ({position})")
    
    def remove_middleware(self, middleware: Middleware) -> bool:
        """
        Remove global middleware
        
        Args:
            middleware: Middleware to remove
            
        Returns:
            bool: True if removed
        """
        return self.middleware.remove(middleware)
    
    def list_routes(self) -> List[Dict[str, Any]]:
        """
        List all registered routes
        
        Returns:
            List[Dict[str, Any]]: Route information
        """
        routes = []
        for route in self.registry.get_all_routes():
            route_info = {
                "id": route.metadata.get("route_id"),
                "path": route.path,
                "method": route.method.value,
                "priority": route.priority,
                "description": route.description,
                "tags": route.tags,
                "version": route.version,
                "match_type": route.match_type.value,
                "middlewares": len(route.middlewares),
                "permissions": list(route.permissions),
                "timeout": route.timeout,
                "has_security_policy": route.security_policy is not None,
                "registered_at": route.metadata.get("registered_at"),
            }
            routes.append(route_info)
        
        return routes
    
    def exists(self, path: str, method: Union[RequestMethod, str]) -> bool:
        """
        Check if a route exists
        
        Args:
            path: Route path
            method: HTTP method
            
        Returns:
            bool: True if route exists
        """
        return self.registry.exists(path, method)
    
    def validate_route(self, path: str, method: Union[RequestMethod, str]) -> bool:
        """
        Validate a route configuration
        
        Args:
            path: Route path
            method: HTTP method
            
        Returns:
            bool: True if valid
        """
        # Normalize
        path = self.matcher.normalize_path(path)
        if isinstance(method, str):
            method = RequestMethod(method.upper())
        
        return self.matcher.validate_path(path) and method in RequestMethod
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get router statistics
        
        Returns:
            Dict[str, Any]: Statistics
        """
        return {
            **self._stats,
            "total_routes": self.registry.count(),
            "routes_by_method": {
                method.value: len(routes)
                for method, routes in self.registry._routes_by_method.items()
            },
            "handler_cache_size": len(self._handler_cache),
            "middleware_count": len(self.middleware._middlewares) +
                               len(self.middleware._before_middlewares) +
                               len(self.middleware._after_middlewares),
        }
    
    def reset_stats(self) -> None:
        """Reset router statistics"""
        self._stats = {
            "total_requests": 0,
            "matched_routes": 0,
            "unmatched_requests": 0,
            "errors": 0,
        }
    
    def clear(self) -> None:
        """Clear all routes and middleware"""
        self.registry.clear()
        self.middleware = RouterMiddleware()
        self._handler_cache.clear()
        self._logger.info("Router cleared")
    
    def __repr__(self) -> str:
        return f"<RuntimeRouter name={self.name} routes={self.registry.count()}>"


# Convenience functions and decorators
def router(name: str = "secure-runtime-router", **kwargs) -> RuntimeRouter:
    """
    Create a new router instance
    
    Args:
        name: Router name
        **kwargs: Additional arguments
        
    Returns:
        RuntimeRouter: Router instance
    """
    return RuntimeRouter(name=name, **kwargs)


def route(
    path: str,
    method: Union[RequestMethod, str],
    **kwargs
):
    """
    Decorator for registering routes
    
    Args:
        path: Route path
        method: HTTP method
        **kwargs: Additional route configuration
        
    Returns:
        Decorator function
    """
    def decorator(handler: RouteHandler):
        router_instance = kwargs.pop("router", None)
        if router_instance is None:
            from runtime.core.lifecycle import get_lifecycle_manager
            lifecycle = get_lifecycle_manager()
            router_instance = lifecycle.get_component("router")
        
        if router_instance:
            route_id = router_instance.register(path, method, handler, **kwargs)
            handler._route_id = route_id
            handler._route_path = path
            handler._route_method = method
        return handler
    return decorator


def get(path: str, **kwargs):
    """GET route decorator"""
    return route(path, RequestMethod.GET, **kwargs)


def post(path: str, **kwargs):
    """POST route decorator"""
    return route(path, RequestMethod.POST, **kwargs)


def put(path: str, **kwargs):
    """PUT route decorator"""
    return route(path, RequestMethod.PUT, **kwargs)


def delete(path: str, **kwargs):
    """DELETE route decorator"""
    return route(path, RequestMethod.DELETE, **kwargs)


def patch(path: str, **kwargs):
    """PATCH route decorator"""
    return route(path, RequestMethod.PATCH, **kwargs)


def options(path: str, **kwargs):
    """OPTIONS route decorator"""
    return route(path, RequestMethod.OPTIONS, **kwargs)


def head(path: str, **kwargs):
    """HEAD route decorator"""
    return route(path, RequestMethod.HEAD, **kwargs)