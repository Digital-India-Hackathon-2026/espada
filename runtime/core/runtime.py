# runtime/core/runtime.py
"""
Secure Runtime - Heart of the Security Platform

This module orchestrates the entire request processing pipeline by coordinating
all security, policy, AI, and routing components. It acts as the central
controller that delegates to specialized modules without implementing
business logic itself.
"""

import asyncio
import time
import signal
import sys
import uuid
from typing import Any, Dict, List, Optional, Callable, Awaitable, Union
from datetime import datetime

from runtime.core.config import get_config, RuntimeConfig
from runtime.core.context import RuntimeContext, create_context, get_current_context, set_current_context
from runtime.core.errors import (
    RuntimeError as RuntimeErrorBase,
    InitializationError,
    ShutdownError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ThreatDetectedError,
    SecretDetectedError,
    PromptInjectionError,
    PolicyViolationError,
    AIEngineError,
    RouterError,
    MiddlewareError,
    ValidationError,
    TimeoutError,
    HealthCheckFailedError,
)
from runtime.core.events import EventBus, get_event_bus, publish, Event
from runtime.core.lifecycle import (
    LifecycleManager,
    LifecycleStatus,
    LifecycleEvent,
    get_lifecycle_manager,
)
from runtime.core.metrics import MetricsCollector, get_metrics_collector, record_request
from runtime.core.request import Request
from runtime.core.response import Response
from runtime.core.router import RuntimeRouter, get, post, put, delete, patch, options, head

# Import security modules (these will be created separately)
# from runtime.security.auth import Authenticator, Authorizer
# from runtime.security.threat import ThreatDetector
# from runtime.security.secrets import SecretDetector
# from runtime.security.injection import PromptInjectionDetector
# from runtime.policy.engine import PolicyEngine
# from runtime.ai.decision import AIDecisionEngine


class Runtime:
    """
    Secure Runtime - Central Orchestrator
    
    This class is the heart of the Secure Runtime platform. It orchestrates
    the complete request processing pipeline by coordinating all security,
    policy, AI, and routing components. It delegates to specialized modules
    without implementing business logic itself.
    
    The runtime follows a strict pipeline pattern:
    1. Request received
    2. Context created
    3. Middleware executed
    4. Authentication
    5. Authorization
    6. Rate limiting
    7. Validation
    8. Threat detection
    9. Secret detection
    10. Prompt injection detection
    11. Policy evaluation
    12. AI decision
    13. Routing
    14. Response generation
    15. Metrics & Events
    """
    
    def __init__(
        self,
        name: str = "secure-runtime",
        config_path: Optional[str] = None,
        enable_metrics: bool = True,
        enable_events: bool = True,
        enable_security: bool = True,
        enable_policy: bool = True,
        enable_ai: bool = True,
    ):
        """
        Initialize the Secure Runtime
        
        Args:
            name: Runtime instance name
            config_path: Optional path to configuration file
            enable_metrics: Enable metrics collection
            enable_events: Enable event publishing
            enable_security: Enable security features
            enable_policy: Enable policy engine
            enable_ai: Enable AI decision engine
        """
        self.name = name
        self._config_path = config_path
        
        # Feature flags
        self.enable_metrics = enable_metrics
        self.enable_events = enable_events
        self.enable_security = enable_security
        self.enable_policy = enable_policy
        self.enable_ai = enable_ai
        
        # Core components (initialized in _initialize_components)
        self._config: Optional[RuntimeConfig] = None
        self._lifecycle: Optional[LifecycleManager] = None
        self._event_bus: Optional[EventBus] = None
        self._metrics: Optional[MetricsCollector] = None
        self._router: Optional[RuntimeRouter] = None
        
        # Security components (to be injected)
        self._authenticator: Optional[Any] = None
        self._authorizer: Optional[Any] = None
        self._threat_detector: Optional[Any] = None
        self._secret_detector: Optional[Any] = None
        self._injection_detector: Optional[Any] = None
        self._policy_engine: Optional[Any] = None
        self._ai_engine: Optional[Any] = None
        
        # Middleware
        self._middleware: List[Callable] = []
        
        # Internal state
        self._initialized = False
        self._running = False
        self._shutting_down = False
        self._start_time: Optional[float] = None
        self._request_counter = 0
        self._active_requests = 0
        self._lock = asyncio.Lock()
        
        # Signal handling
        self._signal_handlers_setup = False
        
        # Logger
        import logging
        self._logger = logging.getLogger(f"runtime.core.runtime.{name}")
    
    async def initialize(self) -> "Runtime":
        """
        Initialize the runtime and all components
        
        Returns:
            Runtime: Self for method chaining
            
        Raises:
            InitializationError: If initialization fails
        """
        if self._initialized:
            self._logger.warning("Runtime already initialized")
            return self
        
        self._logger.info(f"Initializing Secure Runtime: {self.name}")
        
        try:
            # Load configuration
            self._config = get_config()
            if self._config_path:
                self._config.load(self._config_path)
            
            # Initialize components
            await self._initialize_components()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            self._initialized = True
            self._logger.info("Secure Runtime initialized successfully")
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.initialized", payload={
                    "name": self.name,
                    "version": self._config.runtime_version if self._config else "unknown",
                })
            
            return self
            
        except Exception as e:
            self._logger.error(f"Initialization failed: {e}")
            raise InitializationError(f"Runtime initialization failed: {e}") from e
    
    async def _initialize_components(self) -> None:
        """Initialize all runtime components"""
        # Lifecycle Manager
        self._lifecycle = get_lifecycle_manager(name=self.name)
        self._lifecycle.add_component("runtime", self)
        
        # Event Bus
        if self.enable_events:
            self._event_bus = get_event_bus(name=f"{self.name}.events")
            await self._event_bus.start()
            self._lifecycle.add_component("event_bus", self._event_bus)
        
        # Metrics Collector
        if self.enable_metrics:
            self._metrics = get_metrics_collector(name=self.name)
            await self._metrics.start_collecting()
            self._lifecycle.add_component("metrics", self._metrics)
        
        # Router
        self._router = RuntimeRouter(
            name=f"{self.name}.router",
            enable_metrics=self.enable_metrics,
            enable_events=self.enable_events,
        )
        self._lifecycle.add_component("router", self._router)
        
        # Security components will be initialized when available
        # This allows for dependency injection of security modules
        
        # Register health check components
        self._lifecycle.register_hook(
            LifecycleEvent.ON_HEALTH_CHECK,
            self._health_check_hook
        )
    
    async def start(self) -> "Runtime":
        """
        Start the runtime
        
        Returns:
            Runtime: Self for method chaining
            
        Raises:
            RuntimeError: If runtime is not initialized
        """
        if not self._initialized:
            raise RuntimeError("Runtime must be initialized before starting")
        
        if self._running:
            self._logger.warning("Runtime already running")
            return self
        
        self._logger.info(f"Starting Secure Runtime: {self.name}")
        
        try:
            # Start lifecycle
            await self._lifecycle.start()
            
            # Start event bus if enabled
            if self._event_bus and not self._event_bus._is_running:
                await self._event_bus.start()
            
            # Start metrics if enabled
            if self._metrics:
                await self._metrics.start_collecting()
            
            self._running = True
            self._start_time = time.time()
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.started", payload={
                    "name": self.name,
                    "start_time": self._start_time,
                })
            
            self._logger.info("Secure Runtime started successfully")
            return self
            
        except Exception as e:
            self._logger.error(f"Start failed: {e}")
            raise RuntimeError(f"Runtime start failed: {e}") from e
    
    async def shutdown(self, graceful: bool = True) -> None:
        """
        Shutdown the runtime
        
        Args:
            graceful: Whether to perform graceful shutdown
            
        Raises:
            ShutdownError: If shutdown fails
        """
        if self._shutting_down:
            self._logger.warning("Shutdown already in progress")
            return
        
        self._shutting_down = True
        self._logger.info(f"Shutting down Secure Runtime: {self.name} (graceful={graceful})")
        
        try:
            # Stop accepting new requests
            await self._stop_accepting_requests()
            
            # Wait for active requests to complete (graceful only)
            if graceful:
                await self._wait_for_active_requests()
            
            # Stop metrics
            if self._metrics:
                await self._metrics.stop_collecting()
            
            # Stop event bus
            if self._event_bus:
                await self._event_bus.stop()
            
            # Shutdown lifecycle
            await self._lifecycle.shutdown(graceful=graceful)
            
            self._running = False
            self._shutting_down = False
            
            self._logger.info("Secure Runtime shutdown successfully")
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.stopped", payload={
                    "name": self.name,
                    "uptime": self.uptime(),
                })
            
        except Exception as e:
            self._shutting_down = False
            self._logger.error(f"Shutdown failed: {e}")
            raise ShutdownError(f"Runtime shutdown failed: {e}") from e
    
    async def reload(self) -> None:
        """
        Reload the runtime configuration and components
        
        Raises:
            RuntimeError: If runtime is not running
        """
        if not self._running:
            raise RuntimeError("Runtime must be running to reload")
        
        self._logger.info("Reloading Secure Runtime...")
        
        try:
            # Reload configuration
            if self._config:
                self._config.reload()
            
            # Reload router
            if self._router:
                # Clear and re-register routes (handlers should be re-registered)
                self._router.clear()
            
            # Reload lifecycle
            await self._lifecycle.reload()
            
            self._logger.info("Secure Runtime reloaded successfully")
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.reloaded", payload={
                    "name": self.name,
                    "timestamp": time.time(),
                })
            
        except Exception as e:
            self._logger.error(f"Reload failed: {e}")
            raise RuntimeError(f"Runtime reload failed: {e}") from e
    
    async def pause(self) -> None:
        """
        Pause the runtime
        
        Raises:
            RuntimeError: If runtime is not running
        """
        if not self._running:
            raise RuntimeError("Runtime must be running to pause")
        
        self._logger.info("Pausing Secure Runtime...")
        
        try:
            await self._lifecycle.pause()
            self._running = False
            
            self._logger.info("Secure Runtime paused")
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.paused", payload={
                    "name": self.name,
                })
            
        except Exception as e:
            self._logger.error(f"Pause failed: {e}")
            raise RuntimeError(f"Runtime pause failed: {e}") from e
    
    async def resume(self) -> None:
        """
        Resume the runtime from paused state
        
        Raises:
            RuntimeError: If runtime is not paused
        """
        if self._running:
            self._logger.warning("Runtime is already running")
            return
        
        self._logger.info("Resuming Secure Runtime...")
        
        try:
            await self._lifecycle.resume()
            self._running = True
            
            self._logger.info("Secure Runtime resumed")
            
            # Emit event
            if self._event_bus:
                await self._event_bus.emit("runtime.resumed", payload={
                    "name": self.name,
                })
            
        except Exception as e:
            self._logger.error(f"Resume failed: {e}")
            raise RuntimeError(f"Runtime resume failed: {e}") from e
    
    async def _stop_accepting_requests(self) -> None:
        """Stop accepting new requests"""
        self._logger.debug("Stopping acceptance of new requests")
        # Signal to the application that it should stop accepting requests
        # This could be implemented by setting a flag or using a server hook
    
    async def _wait_for_active_requests(self, timeout: int = 30) -> None:
        """
        Wait for active requests to complete
        
        Args:
            timeout: Maximum time to wait in seconds
        """
        if self._active_requests == 0:
            return
        
        self._logger.info(f"Waiting for {self._active_requests} active requests to complete...")
        
        start_time = time.time()
        while self._active_requests > 0 and (time.time() - start_time) < timeout:
            await asyncio.sleep(0.1)
        
        if self._active_requests > 0:
            self._logger.warning(f"{self._active_requests} requests still active after {timeout}s")
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        if self._signal_handlers_setup:
            return
        
        loop = asyncio.get_event_loop()
        
        def signal_handler(signum, frame):
            self._logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.shutdown(graceful=True))
        
        try:
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            self._signal_handlers_setup = True
            self._logger.debug("Signal handlers setup complete")
        except ValueError:
            # Not in main thread, skip signal handling
            self._logger.debug("Signal handling not available in this context")
    
    async def process_request(
        self,
        request: Request,
        context: Optional[RuntimeContext] = None
    ) -> Response:
        """
        Process a request through the complete runtime pipeline
        
        This is the main entry point for processing HTTP requests. It orchestrates
        the entire pipeline including security checks, policy evaluation, AI
        decisions, and routing.
        
        Args:
            request: HTTP request object
            context: Optional runtime context (created if not provided)
            
        Returns:
            Response: HTTP response object
            
        Raises:
            Various exceptions for security violations, errors, etc.
        """
        # Track active request
        self._active_requests += 1
        self._request_counter += 1
        
        # Create or use provided context
        if context is None:
            context = create_context(
                request_id=request.id,
                session_id=request.get_cookie("session_id"),
            )
        else:
            # Ensure request ID matches
            if context.request_id != request.id:
                context.request_id = request.id
        
        # Set current context
        set_current_context(context)
        
        # Add request to context
        context.request = request
        
        # Start timing
        start_time = time.time()
        context.start_time = start_time
        
        try:
            # Execute pipeline
            response = await self._execute_pipeline(request, context)
            
            # Record metrics
            if self._metrics:
                duration = time.time() - start_time
                self._metrics.record_request(
                    allowed=not response.is_blocked,
                    duration=duration * 1000  # Convert to milliseconds
                )
                self._metrics.increment_counter("total_requests")
                if response.is_blocked:
                    self._metrics.increment_counter("blocked_requests")
                else:
                    self._metrics.increment_counter("allowed_requests")
            
            # Emit request completed event
            if self._event_bus:
                await self._event_bus.emit("request.completed", payload={
                    "request_id": request.id,
                    "path": request.path,
                    "method": request.method.value,
                    "status_code": response.status_code_int,
                    "blocked": response.is_blocked,
                    "duration": time.time() - start_time,
                })
            
            # Add response time
            response.set_response_time(start_time)
            
            return response
            
        except Exception as e:
            self._logger.error(f"Request processing failed: {e}")
            
            # Record error metrics
            if self._metrics:
                self._metrics.record_error(str(e), "error")
            
            # Emit error event
            if self._event_bus:
                await self._event_bus.emit("error.occurred", payload={
                    "request_id": request.id,
                    "path": request.path,
                    "method": request.method.value,
                    "error": str(e),
                })
            
            # Re-raise or convert to response
            raise
            
        finally:
            # Decrement active requests
            self._active_requests -= 1
            
            # Clear context
            set_current_context(None)
    
    async def _execute_pipeline(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Response:
        """
        Execute the complete request processing pipeline
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Response: HTTP response
        """
        # Pipeline stages
        pipeline_stages = [
            self._stage_middleware,
            self._stage_authentication,
            self._stage_authorization,
            self._stage_rate_limit,
            self._stage_validation,
            self._stage_threat_detection,
            self._stage_secret_detection,
            self._stage_injection_detection,
            self._stage_policy_evaluation,
            self._stage_ai_decision,
            self._stage_routing,
        ]
        
        # Execute each stage sequentially
        for stage in pipeline_stages:
            response = await stage(request, context)
            if response:
                # Stage returned a response (e.g., blocked request)
                return response
        
        # This should not be reached if routing is successful
        raise RouterError("No response generated from pipeline")
    
    # Pipeline Stage Methods
    
    async def _stage_middleware(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Execute middleware chain
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if middleware returns early
        """
        if not self._middleware:
            return None
        
        self._logger.debug("Executing middleware chain")
        
        try:
            # Execute middleware sequentially
            for middleware in self._middleware:
                response = await middleware(request, context)
                if response:
                    return response
            return None
            
        except Exception as e:
            self._logger.error(f"Middleware error: {e}")
            raise MiddlewareError(f"Middleware execution failed: {e}") from e
    
    async def _stage_authentication(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform authentication
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if authentication fails
        """
        if not self.enable_security or not self._authenticator:
            return None
        
        self._logger.debug("Performing authentication")
        
        try:
            # Delegate to authenticator
            result = await self._authenticator.authenticate(request, context)
            
            if result.get("success", False):
                context.authenticated = True
                context.user_id = result.get("user_id")
                context.auth_method = result.get("method")
                context.auth_provider = result.get("provider")
                context.auth_claims = result.get("claims", {})
                
                # Emit auth success event
                if self._event_bus:
                    await self._event_bus.emit("authentication.success", payload={
                        "user_id": context.user_id,
                        "method": context.auth_method,
                        "request_id": request.id,
                    })
                
                return None
            else:
                context.authenticated = False
                context.auth_method = None
                
                # Emit auth failure event
                if self._event_bus:
                    await self._event_bus.emit("authentication.failure", payload={
                        "reason": result.get("reason", "Authentication failed"),
                        "request_id": request.id,
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("auth_failures")
                
                # Return authentication failure response
                from runtime.core.response import Response
                return Response().unauthorized(
                    message=result.get("message", "Authentication failed")
                )
                
        except AuthenticationError as e:
            self._logger.warning(f"Authentication error: {e}")
            return Response().unauthorized(message=str(e))
            
        except Exception as e:
            self._logger.error(f"Authentication exception: {e}")
            raise AuthenticationError(f"Authentication error: {e}") from e
    
    async def _stage_authorization(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform authorization
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if authorization fails
        """
        if not self.enable_security or not self._authorizer:
            return None
        
        # Skip if not authenticated
        if not context.authenticated:
            return None
        
        self._logger.debug("Performing authorization")
        
        try:
            # Delegate to authorizer
            result = await self._authorizer.authorize(request, context)
            
            if result.get("success", False):
                context.authorized = True
                context.permissions = set(result.get("permissions", []))
                context.roles = set(result.get("roles", []))
                
                return None
            else:
                context.authorized = False
                
                # Emit authz failure event
                if self._event_bus:
                    await self._event_bus.emit("authorization.failure", payload={
                        "user_id": context.user_id,
                        "reason": result.get("reason", "Authorization failed"),
                        "request_id": request.id,
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("authz_failures")
                
                # Return authorization failure response
                from runtime.core.response import Response
                return Response().forbidden(
                    message=result.get("message", "Authorization failed")
                )
                
        except AuthorizationError as e:
            self._logger.warning(f"Authorization error: {e}")
            return Response().forbidden(message=str(e))
            
        except Exception as e:
            self._logger.error(f"Authorization exception: {e}")
            raise AuthorizationError(f"Authorization error: {e}") from e
    
    async def _stage_rate_limit(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform rate limiting
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if rate limit exceeded
        """
        # Rate limiting would be implemented by a dedicated module
        # This is a placeholder for the rate limiter integration
        return None
    
    async def _stage_validation(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform request validation
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if validation fails
        """
        # Validation would be implemented by a dedicated module
        # This is a placeholder for the validator integration
        return None
    
    async def _stage_threat_detection(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform threat detection
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if threat detected
        """
        if not self.enable_security or not self._threat_detector:
            return None
        
        self._logger.debug("Performing threat detection")
        
        try:
            # Delegate to threat detector
            result = await self._threat_detector.detect(request, context)
            
            if result.get("detected", False):
                # Update scores
                context.update_score(
                    security_score=result.get("security_score", context.security_scores.security_score),
                    threat_score=result.get("threat_score", context.security_scores.threat_score),
                )
                context.add_security_finding(
                    severity=result.get("severity", "high"),
                    category="threat",
                    description=result.get("description", "Threat detected"),
                    details=result.get("details", {}),
                    remediation=result.get("remediation"),
                    source=result.get("source", "threat_detector"),
                )
                
                # Emit threat detected event
                if self._event_bus:
                    await self._event_bus.emit("threat.detected", payload={
                        "request_id": request.id,
                        "threat_type": result.get("threat_type"),
                        "severity": result.get("severity"),
                        "confidence": result.get("confidence"),
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("threat_count")
                
                # Return blocked response
                from runtime.core.response import Response
                return Response().block(
                    reason=result.get("reason", "Threat detected"),
                    block_type="threat",
                    status_code=403,
                ).error(
                    message="Threat detected and blocked",
                    status_code=403,
                )
            
            return None
                
        except ThreatDetectedError as e:
            self._logger.warning(f"Threat detected: {e}")
            return Response().block(
                reason=str(e),
                block_type="threat",
                status_code=403,
            ).error(message=str(e), status_code=403)
            
        except Exception as e:
            self._logger.error(f"Threat detection exception: {e}")
            raise ThreatDetectedError(f"Threat detection error: {e}") from e
    
    async def _stage_secret_detection(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform secret detection
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if secret detected
        """
        if not self.enable_security or not self._secret_detector:
            return None
        
        self._logger.debug("Performing secret detection")
        
        try:
            # Delegate to secret detector
            result = await self._secret_detector.detect(request, context)
            
            if result.get("detected", False):
                context.add_security_finding(
                    severity=result.get("severity", "high"),
                    category="secret",
                    description=result.get("description", "Secret detected"),
                    details=result.get("details", {}),
                    remediation=result.get("remediation"),
                    source=result.get("source", "secret_detector"),
                )
                
                # Emit secret detected event
                if self._event_bus:
                    await self._event_bus.emit("secret.detected", payload={
                        "request_id": request.id,
                        "secret_type": result.get("secret_type"),
                        "severity": result.get("severity"),
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("secrets_found")
                
                # Return blocked response
                from runtime.core.response import Response
                return Response().block(
                    reason=result.get("reason", "Secret detected"),
                    block_type="secret",
                    status_code=403,
                ).error(
                    message="Secret detected and blocked",
                    status_code=403,
                )
            
            return None
                
        except SecretDetectedError as e:
            self._logger.warning(f"Secret detected: {e}")
            return Response().block(
                reason=str(e),
                block_type="secret",
                status_code=403,
            ).error(message=str(e), status_code=403)
            
        except Exception as e:
            self._logger.error(f"Secret detection exception: {e}")
            raise SecretDetectedError(f"Secret detection error: {e}") from e
    
    async def _stage_injection_detection(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform prompt injection detection
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if injection detected
        """
        if not self.enable_security or not self._injection_detector:
            return None
        
        self._logger.debug("Performing prompt injection detection")
        
        try:
            # Delegate to injection detector
            result = await self._injection_detector.detect(request, context)
            
            if result.get("detected", False):
                context.add_security_finding(
                    severity=result.get("severity", "high"),
                    category="injection",
                    description=result.get("description", "Prompt injection detected"),
                    details=result.get("details", {}),
                    remediation=result.get("remediation"),
                    source=result.get("source", "injection_detector"),
                )
                
                # Emit injection detected event
                if self._event_bus:
                    await self._event_bus.emit("prompt.injection.detected", payload={
                        "request_id": request.id,
                        "injection_type": result.get("injection_type"),
                        "severity": result.get("severity"),
                        "confidence": result.get("confidence"),
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("prompt_injections")
                
                # Return blocked response
                from runtime.core.response import Response
                return Response().block(
                    reason=result.get("reason", "Prompt injection detected"),
                    block_type="injection",
                    status_code=403,
                ).error(
                    message="Prompt injection detected and blocked",
                    status_code=403,
                )
            
            return None
                
        except PromptInjectionError as e:
            self._logger.warning(f"Prompt injection detected: {e}")
            return Response().block(
                reason=str(e),
                block_type="injection",
                status_code=403,
            ).error(message=str(e), status_code=403)
            
        except Exception as e:
            self._logger.error(f"Injection detection exception: {e}")
            raise PromptInjectionError(f"Injection detection error: {e}") from e
    
    async def _stage_policy_evaluation(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform policy evaluation
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if policy violated
        """
        if not self.enable_policy or not self._policy_engine:
            return None
        
        self._logger.debug("Evaluating policies")
        
        try:
            # Delegate to policy engine
            result = await self._policy_engine.evaluate(request, context)
            
            if result.get("violated", False):
                context.policy_decision = result.get("decision")
                
                # Add security finding
                context.add_security_finding(
                    severity=result.get("severity", "high"),
                    category="policy",
                    description=result.get("description", "Policy violation"),
                    details=result.get("details", {}),
                    remediation=result.get("remediation"),
                    source=result.get("source", "policy_engine"),
                )
                
                # Emit policy violation event
                if self._event_bus:
                    await self._event_bus.emit("policy.violation", payload={
                        "request_id": request.id,
                        "policy_id": result.get("policy_id"),
                        "rule_id": result.get("rule_id"),
                        "severity": result.get("severity"),
                    })
                
                # Record metrics
                if self._metrics:
                    self._metrics.increment_counter("policy_violations")
                
                # Return blocked response
                from runtime.core.response import Response
                return Response().block(
                    reason=result.get("reason", "Policy violation"),
                    block_type="policy",
                    status_code=result.get("status_code", 403),
                ).error(
                    message=result.get("message", "Policy violation"),
                    status_code=result.get("status_code", 403),
                )
            
            return None
                
        except PolicyViolationError as e:
            self._logger.warning(f"Policy violation: {e}")
            return Response().block(
                reason=str(e),
                block_type="policy",
                status_code=403,
            ).error(message=str(e), status_code=403)
            
        except Exception as e:
            self._logger.error(f"Policy evaluation exception: {e}")
            raise PolicyViolationError(f"Policy evaluation error: {e}") from e
    
    async def _stage_ai_decision(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Perform AI decision
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response if AI blocks request
        """
        if not self.enable_ai or not self._ai_engine:
            return None
        
        self._logger.debug("Making AI decision")
        
        try:
            # Delegate to AI engine
            result = await self._ai_engine.decide(request, context)
            
            if result:
                context.ai_decision = result
                
                if result.get("action") == "block":
                    # AI decided to block the request
                    return Response().block(
                        reason=result.get("reason", "AI decision block"),
                        block_type="ai",
                        status_code=403,
                    ).error(
                        message=result.get("message", "Request blocked by AI"),
                        status_code=403,
                    )
            
            return None
                
        except AIEngineError as e:
            self._logger.error(f"AI engine error: {e}")
            # Log but don't block - AI errors should be non-blocking
            return None
            
        except Exception as e:
            self._logger.error(f"AI decision exception: {e}")
            # Log but don't block
            return None
    
    async def _stage_routing(
        self,
        request: Request,
        context: RuntimeContext
    ) -> Optional[Response]:
        """
        Route the request to the appropriate handler
        
        Args:
            request: HTTP request
            context: Runtime context
            
        Returns:
            Optional[Response]: Response from the route handler
            
        Raises:
            RouteNotFoundError: If no route matches
        """
        if not self._router:
            raise RouterError("Router not initialized")
        
        self._logger.debug(f"Routing request: {request.method.value} {request.path}")
        
        try:
            # Dispatch via router
            response = await self._router.dispatch(request, context)
            
            # Add route-specific security headers if needed
            if response and not response.is_blocked:
                # Add security headers
                response.with_security_headers()
            
            return response
            
        except RouteNotFoundError:
            self._logger.warning(f"Route not found: {request.method.value} {request.path}")
            from runtime.core.response import Response
            return Response().not_found(
                message=f"Route {request.path} not found"
            )
            
        except Exception as e:
            self._logger.error(f"Routing error: {e}")
            raise RouterError(f"Routing error: {e}") from e
    
    # Health and Status Methods
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check of the runtime
        
        Returns:
            Dict[str, Any]: Health check results
        """
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {},
            "details": {},
        }
        
        # Check lifecycle
        if self._lifecycle:
            try:
                status = self._lifecycle.status()
                health_status["components"]["lifecycle"] = {
                    "status": status.value,
                    "healthy": status not in [
                        LifecycleStatus.ERROR,
                        LifecycleStatus.UNINITIALIZED,
                        LifecycleStatus.SHUTDOWN,
                    ],
                }
            except Exception as e:
                health_status["components"]["lifecycle"] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e),
                }
                health_status["status"] = "unhealthy"
        
        # Check metrics
        if self._metrics:
            try:
                metrics_snapshot = self._metrics.snapshot()
                health_status["components"]["metrics"] = {
                    "status": "healthy",
                    "healthy": True,
                }
                health_status["details"]["metrics"] = {
                    "total_requests": metrics_snapshot.get("metrics", {}).get("total_requests", {}).get("value", 0),
                    "errors": metrics_snapshot.get("metrics", {}).get("errors", {}).get("value", 0),
                }
            except Exception as e:
                health_status["components"]["metrics"] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e),
                }
                health_status["status"] = "unhealthy"
        
        # Check event bus
        if self._event_bus:
            try:
                is_running = self._event_bus._is_running if hasattr(self._event_bus, '_is_running') else False
                health_status["components"]["event_bus"] = {
                    "status": "running" if is_running else "stopped",
                    "healthy": is_running,
                }
                if not is_running:
                    health_status["status"] = "unhealthy"
            except Exception as e:
                health_status["components"]["event_bus"] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e),
                }
                health_status["status"] = "unhealthy"
        
        # Check router
        if self._router:
            try:
                stats = self._router.get_stats()
                health_status["components"]["router"] = {
                    "status": "healthy",
                    "healthy": True,
                    "details": {
                        "routes": stats.get("total_routes", 0),
                    },
                }
            except Exception as e:
                health_status["components"]["router"] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e),
                }
                health_status["status"] = "unhealthy"
        
        # Check active requests
        health_status["details"]["active_requests"] = self._active_requests
        health_status["details"]["uptime"] = self.uptime()
        health_status["details"]["status"] = "running" if self._running else "stopped"
        
        # Overall health
        health_status["healthy"] = health_status["status"] == "healthy"
        health_status["is_healthy"] = health_status["healthy"]
        
        return health_status
    
    async def _health_check_hook(self, context: RuntimeContext) -> None:
        """Health check hook for lifecycle manager"""
        health = await self.health_check()
        if not health.get("healthy", False):
            self._logger.warning("Health check failed")
            raise HealthCheckFailedError("Runtime health check failed")
    
    def status(self) -> str:
        """
        Get the current runtime status
        
        Returns:
            str: Runtime status string
        """
        if self._shutting_down:
            return "shutting_down"
        if self._running:
            return "running"
        if self._initialized:
            return "initialized"
        return "uninitialized"
    
    def uptime(self) -> float:
        """
        Get runtime uptime in seconds
        
        Returns:
            float: Uptime in seconds
        """
        if self._start_time:
            return time.time() - self._start_time
        return 0.0
    
    def version(self) -> str:
        """
        Get runtime version
        
        Returns:
            str: Version string
        """
        if self._config:
            return self._config.runtime_version
        return "1.0.0"
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get runtime statistics
        
        Returns:
            Dict[str, Any]: Statistics
        """
        stats = {
            "status": self.status(),
            "uptime": self.uptime(),
            "version": self.version(),
            "active_requests": self._active_requests,
            "total_requests": self._request_counter,
            "initialized": self._initialized,
            "running": self._running,
            "enabled_features": {
                "metrics": self.enable_metrics,
                "events": self.enable_events,
                "security": self.enable_security,
                "policy": self.enable_policy,
                "ai": self.enable_ai,
            },
        }
        
        # Add metrics if available
        if self._metrics:
            metrics_snapshot = self._metrics.snapshot()
            stats["metrics"] = {
                "total_requests": metrics_snapshot.get("metrics", {}).get("total_requests", {}).get("value", 0),
                "blocked_requests": metrics_snapshot.get("metrics", {}).get("blocked_requests", {}).get("value", 0),
                "errors": metrics_snapshot.get("metrics", {}).get("errors", {}).get("value", 0),
                "security_score": metrics_snapshot.get("metrics", {}).get("security_score", {}).get("value", 0),
            }
        
        # Add router stats if available
        if self._router:
            stats["router"] = self._router.get_stats()
        
        return stats
    
    # Component Registration Methods
    
    def register_component(self, name: str, component: Any) -> None:
        """
        Register a component with the runtime
        
        Args:
            name: Component name
            component: Component instance
        """
        self._lifecycle.add_component(name, component)
        self._logger.debug(f"Registered component: {name}")
    
    def register_middleware(self, middleware: Callable) -> None:
        """
        Register middleware
        
        Args:
            middleware: Middleware function
        """
        self._middleware.append(middleware)
        self._logger.debug(f"Registered middleware: {middleware.__name__}")
    
    def register_security_modules(
        self,
        authenticator: Any = None,
        authorizer: Any = None,
        threat_detector: Any = None,
        secret_detector: Any = None,
        injection_detector: Any = None,
    ) -> None:
        """
        Register security modules with the runtime
        
        Args:
            authenticator: Authentication module
            authorizer: Authorization module
            threat_detector: Threat detection module
            secret_detector: Secret detection module
            injection_detector: Prompt injection detection module
        """
        if authenticator:
            self._authenticator = authenticator
            self.register_component("authenticator", authenticator)
        if authorizer:
            self._authorizer = authorizer
            self.register_component("authorizer", authorizer)
        if threat_detector:
            self._threat_detector = threat_detector
            self.register_component("threat_detector", threat_detector)
        if secret_detector:
            self._secret_detector = secret_detector
            self.register_component("secret_detector", secret_detector)
        if injection_detector:
            self._injection_detector = injection_detector
            self.register_component("injection_detector", injection_detector)
        
        self._logger.info("Security modules registered")
    
    def register_policy_engine(self, policy_engine: Any) -> None:
        """
        Register policy engine with the runtime
        
        Args:
            policy_engine: Policy engine instance
        """
        self._policy_engine = policy_engine
        self.register_component("policy_engine", policy_engine)
        self._logger.info("Policy engine registered")
    
    def register_ai_engine(self, ai_engine: Any) -> None:
        """
        Register AI engine with the runtime
        
        Args:
            ai_engine: AI engine instance
        """
        self._ai_engine = ai_engine
        self.register_component("ai_engine", ai_engine)
        self._logger.info("AI engine registered")
    
    # Container Management
    
    def get_config(self) -> Optional[RuntimeConfig]:
        """Get runtime configuration"""
        return self._config
    
    def get_lifecycle(self) -> Optional[LifecycleManager]:
        """Get lifecycle manager"""
        return self._lifecycle
    
    def get_event_bus(self) -> Optional[EventBus]:
        """Get event bus"""
        return self._event_bus
    
    def get_metrics(self) -> Optional[MetricsCollector]:
        """Get metrics collector"""
        return self._metrics
    
    def get_router(self) -> Optional[RuntimeRouter]:
        """Get router"""
        return self._router
    
    # Async Context Manager Support
    
    async def __aenter__(self) -> "Runtime":
        """Async context manager entry"""
        await self.initialize()
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit"""
        await self.shutdown(graceful=True)
    
    def __repr__(self) -> str:
        return f"<Runtime name={self.name} status={self.status()} uptime={self.uptime():.2f}s>"


# Convenience Functions

async def create_runtime(**kwargs) -> Runtime:
    """
    Create and initialize a runtime instance
    
    Args:
        **kwargs: Runtime configuration arguments
        
    Returns:
        Runtime: Initialized runtime instance
    """
    runtime = Runtime(**kwargs)
    await runtime.initialize()
    return runtime


async def start_runtime(**kwargs) -> Runtime:
    """
    Create, initialize, and start a runtime instance
    
    Args:
        **kwargs: Runtime configuration arguments
        
    Returns:
        Runtime: Running runtime instance
    """
    runtime = await create_runtime(**kwargs)
    await runtime.start()
    return runtime


# Global runtime instance
_default_runtime: Optional[Runtime] = None


def get_runtime(**kwargs) -> Runtime:
    """
    Get or create the default runtime instance
    
    Args:
        **kwargs: Runtime configuration arguments
        
    Returns:
        Runtime: Runtime instance
    """
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = Runtime(**kwargs)
        # Don't auto-initialize - let the caller handle it
    return _default_runtime


def set_default_runtime(runtime: Runtime) -> None:
    """
    Set the default runtime instance
    
    Args:
        runtime: Runtime instance
    """
    global _default_runtime
    _default_runtime = runtime