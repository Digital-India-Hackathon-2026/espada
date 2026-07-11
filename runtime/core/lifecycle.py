# runtime/core/lifecycle.py
"""
Lifecycle Manager for Secure Runtime

This module manages the complete lifecycle of the Secure Runtime system,
coordinating initialization, startup, shutdown, and state transitions
with comprehensive hook support for extension points.
"""

import asyncio
import time
import signal
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Callable, Awaitable, Union, TypeVar
from enum import Enum
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
import logging
import inspect

from runtime.core.config import get_config
from runtime.core.errors import (
    InitializationError,
    InitializationTimeoutError,
    ShutdownError,
    GracefulShutdownError,
    HealthCheckFailedError,
    ComponentUnhealthyError,
)
from runtime.core.events import EventBus, get_event_bus, publish
from runtime.core.context import RuntimeContext, get_current_context, create_context

# Type variables
T = TypeVar('T')
AsyncHook = Callable[..., Awaitable[None]]
SyncHook = Callable[..., None]
Hook = Union[AsyncHook, SyncHook]


class LifecycleStatus(str, Enum):
    """Runtime lifecycle status"""
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    RESUMING = "resuming"
    RELOADING = "reloading"
    RESTARTING = "restarting"
    SHUTTING_DOWN = "shutting_down"
    SHUTDOWN = "shutdown"
    ERROR = "error"
    UNKNOWN = "unknown"


class LifecycleEvent(str, Enum):
    """Lifecycle events for hook registration"""
    BEFORE_INITIALIZE = "before_initialize"
    AFTER_INITIALIZE = "after_initialize"
    BEFORE_START = "before_start"
    AFTER_START = "after_start"
    BEFORE_REQUEST = "before_request"
    AFTER_REQUEST = "after_request"
    BEFORE_RELOAD = "before_reload"
    AFTER_RELOAD = "after_reload"
    BEFORE_SHUTDOWN = "before_shutdown"
    AFTER_SHUTDOWN = "after_shutdown"
    BEFORE_PAUSE = "before_pause"
    AFTER_PAUSE = "after_pause"
    BEFORE_RESUME = "before_resume"
    AFTER_RESUME = "after_resume"
    BEFORE_RESTART = "before_restart"
    AFTER_RESTART = "after_restart"
    ON_HEALTH_CHECK = "on_health_check"
    ON_ERROR = "on_error"


@dataclass
class ComponentHealth:
    """Health status of a runtime component"""
    name: str
    healthy: bool
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)
    last_check: Optional[float] = None
    error: Optional[str] = None
    response_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "healthy": self.healthy,
            "timestamp": self.timestamp,
            "last_check": self.last_check,
            "details": self.details,
            "error": self.error,
            "response_time": self.response_time,
        }


@dataclass
class HealthCheckResult:
    """Overall health check result"""
    healthy: bool
    timestamp: float = field(default_factory=time.time)
    components: Dict[str, ComponentHealth] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def add_component(self, name: str, healthy: bool, **kwargs) -> None:
        """Add a component health check"""
        self.components[name] = ComponentHealth(
            name=name,
            healthy=healthy,
            **kwargs
        )
        if not healthy:
            self.errors.append(f"Component {name} is unhealthy")
    
    def is_healthy(self) -> bool:
        """Check if all components are healthy"""
        return all(c.healthy for c in self.components.values()) and not self.errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "healthy": self.healthy,
            "timestamp": self.timestamp,
            "components": {
                name: comp.to_dict()
                for name, comp in self.components.items()
            },
            "details": self.details,
            "errors": self.errors,
        }


@dataclass
class LifecycleMetadata:
    """Metadata about the runtime lifecycle"""
    status: LifecycleStatus = LifecycleStatus.UNINITIALIZED
    start_time: Optional[float] = None
    stop_time: Optional[float] = None
    last_health_check: Optional[float] = None
    uptime_seconds: float = 0.0
    version: str = "1.0.0"
    environment: str = "production"
    instance_id: str = ""
    
    def uptime(self) -> float:
        """Get current uptime in seconds"""
        if self.start_time:
            if self.stop_time:
                return self.stop_time - self.start_time
            return time.time() - self.start_time
        return 0.0


class LifecycleHooks:
    """Container for lifecycle hooks"""
    
    def __init__(self):
        self._hooks: Dict[LifecycleEvent, List[Hook]] = {
            event: [] for event in LifecycleEvent
        }
        self._logger = logging.getLogger("runtime.lifecycle.hooks")
    
    def register(self, event: LifecycleEvent, hook: Hook) -> None:
        """
        Register a hook for a lifecycle event
        
        Args:
            event: Lifecycle event to hook into
            hook: Hook function to execute
        """
        if event not in self._hooks:
            self._hooks[event] = []
        
        # Validate hook signature
        sig = inspect.signature(hook)
        params = list(sig.parameters.keys())
        
        # Hooks can accept: (context, event_bus, runtime) or (context) or ()
        if len(params) > 3:
            raise ValueError(
                f"Hook {hook.__name__} has too many parameters ({len(params)}). "
                "Maximum 3 parameters allowed: (context, event_bus, runtime)"
            )
        
        self._hooks[event].append(hook)
        self._logger.debug(f"Registered hook for {event.value}: {hook.__name__}")
    
    def unregister(self, event: LifecycleEvent, hook: Hook) -> None:
        """
        Unregister a hook
        
        Args:
            event: Lifecycle event
            hook: Hook function to remove
        """
        if event in self._hooks and hook in self._hooks[event]:
            self._hooks[event].remove(hook)
            self._logger.debug(f"Unregistered hook for {event.value}: {hook.__name__}")
    
    def get_hooks(self, event: LifecycleEvent) -> List[Hook]:
        """Get all hooks for a specific event"""
        return self._hooks.get(event, [])
    
    def clear(self) -> None:
        """Clear all hooks"""
        for event in self._hooks:
            self._hooks[event].clear()
        self._logger.info("Cleared all lifecycle hooks")


class LifecycleManager:
    """
    Lifecycle Manager for Secure Runtime
    
    Controls the entire runtime lifecycle including initialization, startup,
    shutdown, and state transitions. Provides comprehensive hook system for
    extending lifecycle behavior.
    """
    
    def __init__(
        self,
        name: str = "secure-runtime",
        config_path: Optional[str] = None,
        enable_health_checks: bool = True,
        health_check_interval: int = 30,
        shutdown_timeout: int = 30,
        initialization_timeout: int = 60,
        **kwargs
    ):
        """
        Initialize the lifecycle manager
        
        Args:
            name: Runtime instance name
            config_path: Path to configuration file
            enable_health_checks: Enable automatic health checks
            health_check_interval: Interval between health checks (seconds)
            shutdown_timeout: Timeout for graceful shutdown (seconds)
            initialization_timeout: Timeout for initialization (seconds)
            **kwargs: Additional arguments
        """
        self.name = name
        self.config_path = config_path
        
        # Configuration
        self.config = get_config()
        if config_path:
            self.config.load(config_path)
        
        # Status and metadata
        self.status = LifecycleStatus.UNINITIALIZED
        self.metadata = LifecycleMetadata(
            status=LifecycleStatus.UNINITIALIZED,
            version=kwargs.get('version', '1.0.0'),
            environment=kwargs.get('environment', 'production'),
            instance_id=kwargs.get('instance_id', str(id(self))),
        )
        
        # Components
        self._components: Dict[str, Any] = {}
        self._component_health: Dict[str, ComponentHealth] = {}
        self._background_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        
        # Hooks
        self.hooks = LifecycleHooks()
        
        # Event bus
        self.event_bus: Optional[EventBus] = None
        
        # Settings
        self.enable_health_checks = enable_health_checks
        self.health_check_interval = health_check_interval
        self.shutdown_timeout = shutdown_timeout
        self.initialization_timeout = initialization_timeout
        
        # Logging
        self.logger = logging.getLogger(f"runtime.lifecycle.{name}")
        
        # Health check task
        self._health_check_task: Optional[asyncio.Task] = None
        
        # State lock
        self._lock = asyncio.Lock()
        
        # Signal handlers
        self._signal_handlers_setup = False
    
    async def initialize(self) -> "LifecycleManager":
        """
        Initialize the runtime
        
        Returns:
            LifecycleManager: Self for method chaining
            
        Raises:
            InitializationError: If initialization fails
            InitializationTimeoutError: If initialization times out
        """
        async with self._lock:
            if self.status in [LifecycleStatus.INITIALIZED, LifecycleStatus.RUNNING]:
                self.logger.warning(f"Runtime already initialized (status: {self.status})")
                return self
            
            self.status = LifecycleStatus.INITIALIZING
            self.logger.info("Initializing Secure Runtime...")
            
            try:
                # Execute before initialize hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_INITIALIZE)
                
                # Initialize components with timeout
                await asyncio.wait_for(
                    self._initialize_components(),
                    timeout=self.initialization_timeout
                )
                
                # Initialize event bus
                self.event_bus = get_event_bus(name=self.name)
                await self.event_bus.start()
                
                # Emit initialization event
                await publish(self._create_event("runtime.initializing"))
                
                # Update status
                self.status = LifecycleStatus.INITIALIZED
                self.metadata.status = LifecycleStatus.INITIALIZED
                self.logger.info("Secure Runtime initialized successfully")
                
                # Execute after initialize hooks
                await self._execute_hooks(LifecycleEvent.AFTER_INITIALIZE)
                
                # Emit initialized event
                await publish(self._create_event("runtime.initialized"))
                
                # Start health checks if enabled
                if self.enable_health_checks:
                    await self._start_health_checks()
                
                return self
                
            except asyncio.TimeoutError:
                self.status = LifecycleStatus.ERROR
                self.logger.error("Initialization timed out")
                raise InitializationTimeoutError(
                    component="lifecycle_manager",
                    timeout_seconds=self.initialization_timeout
                )
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Initialization failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise InitializationError(f"Initialization failed: {e}", cause=e)
    
    async def _initialize_components(self) -> None:
        """Initialize all runtime components"""
        # This is where component initialization would happen
        # For now, just simulate component initialization
        self._components = {
            "config": self.config,
            "event_bus": self.event_bus,
        }
        
        # Initialize any registered components
        for name, component in self._components.items():
            if hasattr(component, "initialize"):
                if asyncio.iscoroutinefunction(component.initialize):
                    await component.initialize()
                else:
                    component.initialize()
                self.logger.debug(f"Initialized component: {name}")
    
    async def start(self) -> "LifecycleManager":
        """
        Start the runtime
        
        Returns:
            LifecycleManager: Self for method chaining
            
        Raises:
            RuntimeError: If runtime is not initialized
        """
        async with self._lock:
            if self.status == LifecycleStatus.UNINITIALIZED:
                raise RuntimeError("Runtime must be initialized before starting")
            
            if self.status == LifecycleStatus.RUNNING:
                self.logger.warning("Runtime already running")
                return self
            
            self.status = LifecycleStatus.STARTING
            self.logger.info("Starting Secure Runtime...")
            
            try:
                # Execute before start hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_START)
                
                # Set start time
                self.metadata.start_time = time.time()
                
                # Setup signal handlers
                self._setup_signal_handlers()
                
                # Emit start event
                await publish(self._create_event("runtime.starting"))
                
                # Update status
                self.status = LifecycleStatus.RUNNING
                self.metadata.status = LifecycleStatus.RUNNING
                self.logger.info("Secure Runtime started successfully")
                
                # Execute after start hooks
                await self._execute_hooks(LifecycleEvent.AFTER_START)
                
                # Emit started event
                await publish(self._create_event("runtime.started"))
                
                return self
                
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Start failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise
    
    async def pause(self) -> "LifecycleManager":
        """
        Pause the runtime
        
        Returns:
            LifecycleManager: Self for method chaining
            
        Raises:
            RuntimeError: If runtime is not running
        """
        async with self._lock:
            if self.status != LifecycleStatus.RUNNING:
                raise RuntimeError(f"Cannot pause from status: {self.status}")
            
            self.status = LifecycleStatus.PAUSING
            self.logger.info("Pausing Secure Runtime...")
            
            try:
                # Execute before pause hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_PAUSE)
                
                # Pause components
                await self._pause_components()
                
                # Update status
                self.status = LifecycleStatus.PAUSED
                self.metadata.status = LifecycleStatus.PAUSED
                self.logger.info("Secure Runtime paused")
                
                # Emit paused event
                await publish(self._create_event("runtime.paused"))
                
                # Execute after pause hooks
                await self._execute_hooks(LifecycleEvent.AFTER_PAUSE)
                
                return self
                
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Pause failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise
    
    async def resume(self) -> "LifecycleManager":
        """
        Resume the runtime from paused state
        
        Returns:
            LifecycleManager: Self for method chaining
            
        Raises:
            RuntimeError: If runtime is not paused
        """
        async with self._lock:
            if self.status != LifecycleStatus.PAUSED:
                raise RuntimeError(f"Cannot resume from status: {self.status}")
            
            self.status = LifecycleStatus.RESUMING
            self.logger.info("Resuming Secure Runtime...")
            
            try:
                # Execute before resume hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_RESUME)
                
                # Resume components
                await self._resume_components()
                
                # Update status
                self.status = LifecycleStatus.RUNNING
                self.metadata.status = LifecycleStatus.RUNNING
                self.logger.info("Secure Runtime resumed")
                
                # Emit resumed event
                await publish(self._create_event("runtime.resumed"))
                
                # Execute after resume hooks
                await self._execute_hooks(LifecycleEvent.AFTER_RESUME)
                
                return self
                
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Resume failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise
    
    async def reload(self) -> "LifecycleManager":
        """
        Reload the runtime configuration and components
        
        Returns:
            LifecycleManager: Self for method chaining
        """
        async with self._lock:
            if self.status not in [LifecycleStatus.RUNNING, LifecycleStatus.PAUSED]:
                raise RuntimeError(f"Cannot reload from status: {self.status}")
            
            previous_status = self.status
            self.status = LifecycleStatus.RELOADING
            self.logger.info("Reloading Secure Runtime...")
            
            try:
                # Execute before reload hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_RELOAD)
                
                # Reload configuration
                self.config.reload()
                
                # Reload components
                await self._reload_components()
                
                # Update status
                self.status = previous_status
                self.metadata.status = previous_status
                self.logger.info("Secure Runtime reloaded successfully")
                
                # Emit reloaded event
                await publish(self._create_event("runtime.reloaded"))
                
                # Execute after reload hooks
                await self._execute_hooks(LifecycleEvent.AFTER_RELOAD)
                
                return self
                
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Reload failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise
    
    async def restart(self) -> "LifecycleManager":
        """
        Restart the runtime
        
        Returns:
            LifecycleManager: Self for method chaining
        """
        async with self._lock:
            if self.status not in [LifecycleStatus.RUNNING, LifecycleStatus.PAUSED]:
                raise RuntimeError(f"Cannot restart from status: {self.status}")
            
            self.status = LifecycleStatus.RESTARTING
            self.logger.info("Restarting Secure Runtime...")
            
            try:
                # Execute before restart hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_RESTART)
                
                # Perform restart
                await self._perform_restart()
                
                # Update status
                self.status = LifecycleStatus.RUNNING
                self.metadata.status = LifecycleStatus.RUNNING
                self.logger.info("Secure Runtime restarted successfully")
                
                # Emit restart event
                await publish(self._create_event("runtime.restarted"))
                
                # Execute after restart hooks
                await self._execute_hooks(LifecycleEvent.AFTER_RESTART)
                
                return self
                
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Restart failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise
    
    async def shutdown(self, graceful: bool = True) -> "LifecycleManager":
        """
        Shutdown the runtime
        
        Args:
            graceful: Whether to perform graceful shutdown
            
        Returns:
            LifecycleManager: Self for method chaining
            
        Raises:
            ShutdownError: If shutdown fails
            GracefulShutdownError: If graceful shutdown fails
        """
        async with self._lock:
            if self.status in [LifecycleStatus.SHUTDOWN, LifecycleStatus.UNINITIALIZED]:
                self.logger.warning(f"Runtime already shutdown or not initialized (status: {self.status})")
                return self
            
            self.status = LifecycleStatus.SHUTTING_DOWN
            self.logger.info(f"Shutting down Secure Runtime (graceful={graceful})...")
            
            try:
                # Execute before shutdown hooks
                await self._execute_hooks(LifecycleEvent.BEFORE_SHUTDOWN)
                
                if graceful:
                    await self._graceful_shutdown()
                else:
                    await self._force_shutdown()
                
                # Update status
                self.status = LifecycleStatus.SHUTDOWN
                self.metadata.status = LifecycleStatus.SHUTDOWN
                self.metadata.stop_time = time.time()
                self.metadata.uptime_seconds = self.metadata.uptime()
                self.logger.info("Secure Runtime shutdown successfully")
                
                # Emit shutdown event
                await publish(self._create_event("runtime.stopped"))
                
                # Execute after shutdown hooks
                await self._execute_hooks(LifecycleEvent.AFTER_SHUTDOWN)
                
                return self
                
            except asyncio.TimeoutError:
                self.status = LifecycleStatus.ERROR
                self.logger.error("Shutdown timed out")
                raise GracefulShutdownError(
                    component="lifecycle_manager",
                    shutdown_error="Shutdown timed out"
                )
            except Exception as e:
                self.status = LifecycleStatus.ERROR
                self.logger.error(f"Shutdown failed: {e}")
                await publish(self._create_event("error.occurred", payload={"error": str(e)}))
                raise ShutdownError(f"Shutdown failed: {e}", cause=e)
    
    async def _graceful_shutdown(self) -> None:
        """Perform graceful shutdown with timeout"""
        try:
            # Stop accepting new requests
            await self._stop_accepting_requests()
            
            # Wait for existing requests to complete
            await self._wait_for_requests_complete()
            
            # Stop health checks
            await self._stop_health_checks()
            
            # Cancel background tasks
            await self._cancel_background_tasks()
            
            # Shutdown event bus
            if self.event_bus:
                await self.event_bus.stop()
            
            # Shutdown components
            await self._shutdown_components()
            
        except asyncio.TimeoutError:
            self.logger.warning("Graceful shutdown timed out, forcing shutdown")
            await self._force_shutdown()
    
    async def _force_shutdown(self) -> None:
        """Force immediate shutdown"""
        self.logger.warning("Performing force shutdown")
        
        # Cancel all tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Cancel health check
        if self._health_check_task:
            self._health_check_task.cancel()
        
        # Force shutdown components
        for name, component in self._components.items():
            if hasattr(component, "force_shutdown"):
                try:
                    if asyncio.iscoroutinefunction(component.force_shutdown):
                        await component.force_shutdown()
                    else:
                        component.force_shutdown()
                except Exception as e:
                    self.logger.error(f"Error force shutting down {name}: {e}")
        
        # Shutdown event bus
        if self.event_bus:
            try:
                await self.event_bus.stop()
            except Exception as e:
                self.logger.error(f"Error stopping event bus: {e}")
    
    async def health(self) -> HealthCheckResult:
        """
        Perform health check on all components
        
        Returns:
            HealthCheckResult: Health check results
        """
        result = HealthCheckResult(
            healthy=True,
            timestamp=time.time()
        )
        
        # Check basic runtime status
        result.add_component(
            "runtime_status",
            self.status not in [LifecycleStatus.ERROR, LifecycleStatus.UNINITIALIZED],
            details={"status": self.status.value}
        )
        
        # Check configuration
        try:
            self.config.validate()
            result.add_component("configuration", True)
        except Exception as e:
            result.add_component("configuration", False, error=str(e))
            result.healthy = False
        
        # Check event bus
        if self.event_bus:
            try:
                # Check if event bus is running
                is_running = self.event_bus._is_running if hasattr(self.event_bus, '_is_running') else False
                result.add_component("event_bus", is_running)
                if not is_running:
                    result.healthy = False
            except Exception as e:
                result.add_component("event_bus", False, error=str(e))
                result.healthy = False
        else:
            result.add_component("event_bus", False, error="Event bus not initialized")
            result.healthy = False
        
        # Check components
        for name, component in self._components.items():
            if hasattr(component, "health_check"):
                try:
                    if asyncio.iscoroutinefunction(component.health_check):
                        health = await component.health_check()
                    else:
                        health = component.health_check()
                    
                    if isinstance(health, dict):
                        result.add_component(
                            name,
                            health.get("healthy", False),
                            details=health.get("details", {})
                        )
                    else:
                        result.add_component(name, bool(health))
                    
                    if not health:
                        result.healthy = False
                        
                except Exception as e:
                    result.add_component(name, False, error=str(e))
                    result.healthy = False
        
        # Execute health check hooks
        await self._execute_hooks(
            LifecycleEvent.ON_HEALTH_CHECK,
            context={"health_result": result}
        )
        
        self.metadata.last_health_check = time.time()
        
        if result.is_healthy():
            self.logger.debug("Health check passed")
        else:
            self.logger.warning(f"Health check failed: {result.errors}")
        
        return result
    
    def status(self) -> LifecycleStatus:
        """Get current lifecycle status"""
        return self.status
    
    def uptime(self) -> float:
        """Get runtime uptime in seconds"""
        return self.metadata.uptime()
    
    def ready(self) -> bool:
        """Check if runtime is ready to accept requests"""
        return self.status == LifecycleStatus.RUNNING
    
    def is_running(self) -> bool:
        """Check if runtime is currently running"""
        return self.status == LifecycleStatus.RUNNING
    
    async def _pause_components(self) -> None:
        """Pause all components"""
        for name, component in self._components.items():
            if hasattr(component, "pause"):
                try:
                    if asyncio.iscoroutinefunction(component.pause):
                        await component.pause()
                    else:
                        component.pause()
                    self.logger.debug(f"Paused component: {name}")
                except Exception as e:
                    self.logger.error(f"Error pausing {name}: {e}")
    
    async def _resume_components(self) -> None:
        """Resume all components"""
        for name, component in self._components.items():
            if hasattr(component, "resume"):
                try:
                    if asyncio.iscoroutinefunction(component.resume):
                        await component.resume()
                    else:
                        component.resume()
                    self.logger.debug(f"Resumed component: {name}")
                except Exception as e:
                    self.logger.error(f"Error resuming {name}: {e}")
    
    async def _reload_components(self) -> None:
        """Reload all components"""
        for name, component in self._components.items():
            if hasattr(component, "reload"):
                try:
                    if asyncio.iscoroutinefunction(component.reload):
                        await component.reload()
                    else:
                        component.reload()
                    self.logger.debug(f"Reloaded component: {name}")
                except Exception as e:
                    self.logger.error(f"Error reloading {name}: {e}")
    
    async def _shutdown_components(self) -> None:
        """Shutdown all components"""
        for name, component in self._components.items():
            if hasattr(component, "shutdown"):
                try:
                    if asyncio.iscoroutinefunction(component.shutdown):
                        await component.shutdown()
                    else:
                        component.shutdown()
                    self.logger.debug(f"Shutdown component: {name}")
                except Exception as e:
                    self.logger.error(f"Error shutting down {name}: {e}")
    
    async def _stop_accepting_requests(self) -> None:
        """Stop accepting new requests"""
        self.logger.debug("Stopping acceptance of new requests")
        # Implementation would depend on server component
    
    async def _wait_for_requests_complete(self) -> None:
        """Wait for existing requests to complete"""
        self.logger.debug("Waiting for existing requests to complete")
        # Implementation would track active requests
        await asyncio.sleep(0.5)  # Simulate waiting
    
    async def _cancel_background_tasks(self) -> None:
        """Cancel all background tasks"""
        if self._background_tasks:
            self.logger.debug(f"Cancelling {len(self._background_tasks)} background tasks")
            for task in self._background_tasks:
                if not task.done():
                    task.cancel()
            
            if self._background_tasks:
                await asyncio.gather(*self._background_tasks, return_exceptions=True)
            
            self._background_tasks.clear()
    
    async def _start_health_checks(self) -> None:
        """Start automatic health checks"""
        if self._health_check_task and not self._health_check_task.done():
            return
        
        self.logger.info(f"Starting health checks (interval: {self.health_check_interval}s)")
        
        async def health_check_loop():
            while self.status not in [LifecycleStatus.SHUTDOWN, LifecycleStatus.ERROR]:
                try:
                    await self.health()
                    await asyncio.sleep(self.health_check_interval)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Health check error: {e}")
                    await asyncio.sleep(self.health_check_interval)
        
        self._health_check_task = asyncio.create_task(health_check_loop())
    
    async def _stop_health_checks(self) -> None:
        """Stop automatic health checks"""
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
            self.logger.debug("Stopped health checks")
    
    async def _perform_restart(self) -> None:
        """Perform restart operation"""
        # Stop accepting requests
        await self._stop_accepting_requests()
        
        # Wait for requests to complete
        await self._wait_for_requests_complete()
        
        # Stop health checks
        await self._stop_health_checks()
        
        # Reload components
        await self._reload_components()
        
        # Start accepting requests
        await self._start_accepting_requests()
        
        # Restart health checks
        if self.enable_health_checks:
            await self._start_health_checks()
    
    async def _start_accepting_requests(self) -> None:
        """Start accepting requests"""
        self.logger.debug("Started accepting requests")
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        if self._signal_handlers_setup:
            return
        
        loop = asyncio.get_event_loop()
        
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.shutdown(graceful=True))
        
        try:
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            self._signal_handlers_setup = True
            self.logger.debug("Signal handlers setup complete")
        except ValueError:
            # Not in main thread, skip signal handling
            self.logger.debug("Signal handling not available in this context")
    
    def register_hook(self, event: LifecycleEvent, hook: Hook) -> None:
        """
        Register a lifecycle hook
        
        Args:
            event: Lifecycle event
            hook: Hook function
        """
        self.hooks.register(event, hook)
        self.logger.debug(f"Registered hook for {event.value}")
    
    def unregister_hook(self, event: LifecycleEvent, hook: Hook) -> None:
        """
        Unregister a lifecycle hook
        
        Args:
            event: Lifecycle event
            hook: Hook function
        """
        self.hooks.unregister(event, hook)
        self.logger.debug(f"Unregistered hook for {event.value}")
    
    async def _execute_hooks(self, event: LifecycleEvent, **kwargs) -> None:
        """
        Execute all hooks for a lifecycle event
        
        Args:
            event: Lifecycle event
            **kwargs: Additional context to pass to hooks
        """
        hooks = self.hooks.get_hooks(event)
        if not hooks:
            return
        
        self.logger.debug(f"Executing {len(hooks)} hooks for {event.value}")
        
        # Create context if not provided
        context = kwargs.get('context')
        if not context:
            context = create_context(request_id=f"lifecycle-{event.value}")
        
        for hook in hooks:
            try:
                sig = inspect.signature(hook)
                params = list(sig.parameters.keys())
                
                # Prepare arguments based on hook signature
                args = []
                if 'context' in params:
                    args.append(context)
                if 'event_bus' in params:
                    args.append(self.event_bus)
                if 'runtime' in params:
                    args.append(self)
                
                # Execute hook
                if asyncio.iscoroutinefunction(hook):
                    await hook(*args)
                else:
                    hook(*args)
                    
                self.logger.debug(f"Executed hook: {hook.__name__}")
                
            except Exception as e:
                self.logger.error(f"Error executing hook {hook.__name__}: {e}")
                # Continue with other hooks
                continue
    
    def _create_event(self, event_type: str, payload: Optional[Dict[str, Any]] = None) -> Event:
        """Create a lifecycle event"""
        from runtime.core.events import Event
        return Event(
            type=event_type,
            category="system",
            severity="info",
            payload=payload or {},
            context={
                "lifecycle_status": self.status.value,
                "instance_id": self.metadata.instance_id,
            }
        )
    
    def add_component(self, name: str, component: Any) -> None:
        """
        Add a component to the lifecycle manager
        
        Args:
            name: Component name
            component: Component instance
        """
        self._components[name] = component
        self.logger.debug(f"Added component: {name}")
    
    def remove_component(self, name: str) -> bool:
        """
        Remove a component from the lifecycle manager
        
        Args:
            name: Component name
            
        Returns:
            bool: True if removed, False if not found
        """
        if name in self._components:
            del self._components[name]
            self.logger.debug(f"Removed component: {name}")
            return True
        return False
    
    def get_component(self, name: str) -> Optional[Any]:
        """
        Get a component by name
        
        Args:
            name: Component name
            
        Returns:
            Optional[Any]: Component instance or None
        """
        return self._components.get(name)
    
    def get_all_components(self) -> Dict[str, Any]:
        """
        Get all components
        
        Returns:
            Dict[str, Any]: All components
        """
        return self._components.copy()
    
    def add_background_task(self, task: asyncio.Task) -> None:
        """
        Add a background task to track
        
        Args:
            task: Background task
        """
        self._background_tasks.append(task)
        self.logger.debug(f"Added background task: {task.get_name()}")
    
    @asynccontextmanager
    async def run_context(self):
        """
        Context manager for running the lifecycle
        
        Usage:
            async with lifecycle.run_context():
                # Runtime is running
                ...
        """
        await self.initialize()
        await self.start()
        try:
            yield self
        finally:
            await self.shutdown(graceful=True)
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get lifecycle metadata
        
        Returns:
            Dict[str, Any]: Metadata dictionary
        """
        return {
            "status": self.status.value,
            "start_time": self.metadata.start_time,
            "stop_time": self.metadata.stop_time,
            "uptime": self.uptime(),
            "version": self.metadata.version,
            "environment": self.metadata.environment,
            "instance_id": self.metadata.instance_id,
            "last_health_check": self.metadata.last_health_check,
            "components": list(self._components.keys()),
        }
    
    def __repr__(self) -> str:
        return f"<LifecycleManager name={self.name} status={self.status.value} uptime={self.uptime():.2f}s>"


# Global lifecycle manager instance
_default_lifecycle: Optional[LifecycleManager] = None


def get_lifecycle_manager(name: str = "secure-runtime", **kwargs) -> LifecycleManager:
    """
    Get or create a lifecycle manager instance
    
    Args:
        name: Runtime name
        **kwargs: Additional arguments
        
    Returns:
        LifecycleManager: Lifecycle manager instance
    """
    global _default_lifecycle
    
    if name == "secure-runtime":
        if _default_lifecycle is None:
            _default_lifecycle = LifecycleManager(name=name, **kwargs)
        return _default_lifecycle
    else:
        return LifecycleManager(name=name, **kwargs)


def set_default_lifecycle(lifecycle: LifecycleManager) -> None:
    """
    Set the default lifecycle manager
    
    Args:
        lifecycle: LifecycleManager instance
    """
    global _default_lifecycle
    _default_lifecycle = lifecycle


# Convenience functions
async def initialize_runtime(**kwargs) -> LifecycleManager:
    """Initialize the runtime using default lifecycle"""
    lifecycle = get_lifecycle_manager(**kwargs)
    await lifecycle.initialize()
    return lifecycle


async def start_runtime(**kwargs) -> LifecycleManager:
    """Start the runtime using default lifecycle"""
    lifecycle = get_lifecycle_manager(**kwargs)
    await lifecycle.start()
    return lifecycle


async def shutdown_runtime(graceful: bool = True, **kwargs) -> LifecycleManager:
    """Shutdown the runtime using default lifecycle"""
    lifecycle = get_lifecycle_manager(**kwargs)
    await lifecycle.shutdown(graceful=graceful)
    return lifecycle


def register_lifecycle_hook(event: LifecycleEvent, hook: Hook, name: str = "secure-runtime") -> None:
    """Register a lifecycle hook using default lifecycle"""
    lifecycle = get_lifecycle_manager(name=name)
    lifecycle.register_hook(event, hook)


# Hook decorators for convenience
def on_before_initialize(func: Hook) -> Hook:
    """Decorator for before initialize hook"""
    register_lifecycle_hook(LifecycleEvent.BEFORE_INITIALIZE, func)
    return func


def on_after_initialize(func: Hook) -> Hook:
    """Decorator for after initialize hook"""
    register_lifecycle_hook(LifecycleEvent.AFTER_INITIALIZE, func)
    return func


def on_before_start(func: Hook) -> Hook:
    """Decorator for before start hook"""
    register_lifecycle_hook(LifecycleEvent.BEFORE_START, func)
    return func


def on_after_start(func: Hook) -> Hook:
    """Decorator for after start hook"""
    register_lifecycle_hook(LifecycleEvent.AFTER_START, func)
    return func


def on_before_shutdown(func: Hook) -> Hook:
    """Decorator for before shutdown hook"""
    register_lifecycle_hook(LifecycleEvent.BEFORE_SHUTDOWN, func)
    return func


def on_after_shutdown(func: Hook) -> Hook:
    """Decorator for after shutdown hook"""
    register_lifecycle_hook(LifecycleEvent.AFTER_SHUTDOWN, func)
    return func