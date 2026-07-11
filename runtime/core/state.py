# runtime/core/state.py
"""
Runtime State Definitions

This module contains all state enums and helper functions for the Secure Runtime.
These states represent the various conditions and modes the runtime can be in
during its lifecycle and operation.
"""

from enum import Enum, auto, StrEnum
from typing import Set, Optional


class RuntimeState(StrEnum):
    """
    Runtime lifecycle states
    
    Represents the current lifecycle phase of the runtime instance.
    """
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    RELOADING = "reloading"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    
    # Active states that indicate the runtime can process requests
    ACTIVE_STATES: Set[str] = {
        "initializing",
        "starting",
        "running",
        "paused",
        "reloading",
    }
    
    # Terminal states that indicate the runtime has stopped
    TERMINAL_STATES: Set[str] = {
        "stopped",
        "error",
    }
    
    def is_active(self) -> bool:
        """
        Check if the runtime is in an active state
        
        Returns:
            bool: True if runtime is active
        """
        return self.value in self.ACTIVE_STATES
    
    def is_terminated(self) -> bool:
        """
        Check if the runtime is in a terminal state
        
        Returns:
            bool: True if runtime is terminated
        """
        return self.value in self.TERMINAL_STATES
    
    def can_transition_to(self, target: "RuntimeState") -> bool:
        """
        Check if transition from current state to target is valid
        
        Args:
            target: Target state
            
        Returns:
            bool: True if transition is valid
        """
        # Valid transitions map
        transitions = {
            RuntimeState.UNINITIALIZED: {RuntimeState.INITIALIZING, RuntimeState.ERROR},
            RuntimeState.INITIALIZING: {RuntimeState.STARTING, RuntimeState.ERROR, RuntimeState.STOPPED},
            RuntimeState.STARTING: {RuntimeState.RUNNING, RuntimeState.ERROR, RuntimeState.STOPPED},
            RuntimeState.RUNNING: {
                RuntimeState.PAUSED,
                RuntimeState.RELOADING,
                RuntimeState.STOPPING,
                RuntimeState.ERROR,
                RuntimeState.MAINTENANCE,
            },
            RuntimeState.PAUSED: {
                RuntimeState.RUNNING,
                RuntimeState.RELOADING,
                RuntimeState.STOPPING,
                RuntimeState.ERROR,
            },
            RuntimeState.RELOADING: {
                RuntimeState.RUNNING,
                RuntimeState.PAUSED,
                RuntimeState.STOPPING,
                RuntimeState.ERROR,
            },
            RuntimeState.STOPPING: {RuntimeState.STOPPED, RuntimeState.ERROR},
            RuntimeState.STOPPED: {RuntimeState.INITIALIZING, RuntimeState.MAINTENANCE},
            RuntimeState.ERROR: {RuntimeState.STOPPED, RuntimeState.MAINTENANCE, RuntimeState.INITIALIZING},
            RuntimeState.MAINTENANCE: {
                RuntimeState.RUNNING,
                RuntimeState.PAUSED,
                RuntimeState.STOPPING,
                RuntimeState.STOPPED,
                RuntimeState.ERROR,
            },
        }
        return target in transitions.get(self, set())


class HealthState(StrEnum):
    """
    Runtime health states
    
    Represents the health status of the runtime instance.
    """
    HEALTHY = "healthy"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    OFFLINE = "offline"
    
    # Health state priorities (higher = more severe)
    PRIORITY: dict = {
        "healthy": 0,
        "warning": 1,
        "degraded": 2,
        "critical": 3,
        "offline": 4,
    }
    
    def is_healthy(self) -> bool:
        """
        Check if the health state is healthy
        
        Returns:
            bool: True if healthy
        """
        return self == HealthState.HEALTHY
    
    def is_operational(self) -> bool:
        """
        Check if the runtime is operational
        
        Returns:
            bool: True if operational (healthy, warning, or degraded)
        """
        return self in {HealthState.HEALTHY, HealthState.WARNING, HealthState.DEGRADED}
    
    def severity(self) -> int:
        """
        Get the severity level of the health state
        
        Returns:
            int: Severity level (0-4, higher = more severe)
        """
        return self.PRIORITY.get(self.value, 0)
    
    def can_serve_traffic(self) -> bool:
        """
        Check if the runtime can serve traffic in this health state
        
        Returns:
            bool: True if traffic can be served
        """
        return self in {HealthState.HEALTHY, HealthState.WARNING}


class SecurityState(StrEnum):
    """
    Runtime security states
    
    Represents the current security posture of the runtime.
    """
    SAFE = "safe"
    MONITORING = "monitoring"
    THREAT_DETECTED = "threat_detected"
    BLOCKED = "blocked"
    RECOVERY = "recovery"
    
    # Security state severity
    PRIORITY: dict = {
        "safe": 0,
        "monitoring": 1,
        "threat_detected": 2,
        "blocked": 3,
        "recovery": 2,
    }
    
    def is_secure(self) -> bool:
        """
        Check if the runtime is in a secure state
        
        Returns:
            bool: True if secure
        """
        return self in {SecurityState.SAFE, SecurityState.MONITORING}
    
    def is_compromised(self) -> bool:
        """
        Check if the runtime is compromised
        
        Returns:
            bool: True if compromised
        """
        return self in {SecurityState.THREAT_DETECTED, SecurityState.BLOCKED}
    
    def severity(self) -> int:
        """
        Get the severity level of the security state
        
        Returns:
            int: Severity level (0-3, higher = more severe)
        """
        return self.PRIORITY.get(self.value, 0)


class ExecutionMode(StrEnum):
    """
    Runtime execution modes
    
    Defines how the runtime should operate.
    """
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    DEBUG = "debug"
    PASSIVE = "passive"
    BLOCKING = "blocking"
    
    def is_production(self) -> bool:
        """
        Check if in production mode
        
        Returns:
            bool: True if production mode
        """
        return self == ExecutionMode.PRODUCTION
    
    def is_development(self) -> bool:
        """
        Check if in development mode
        
        Returns:
            bool: True if development mode
        """
        return self in {ExecutionMode.DEVELOPMENT, ExecutionMode.DEBUG}
    
    def should_block(self) -> bool:
        """
        Check if runtime should block requests in this mode
        
        Returns:
            bool: True if requests should be blocked
        """
        return self in {ExecutionMode.BLOCKING, ExecutionMode.PRODUCTION}
    
    def should_log_detailed(self) -> bool:
        """
        Check if runtime should log detailed information
        
        Returns:
            bool: True if detailed logging should be enabled
        """
        return self in {ExecutionMode.DEVELOPMENT, ExecutionMode.DEBUG}


class ComponentState(StrEnum):
    """
    Component lifecycle states
    
    Represents the state of individual runtime components.
    """
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    DEGRADED = "degraded"
    
    def is_operational(self) -> bool:
        """
        Check if component is operational
        
        Returns:
            bool: True if operational
        """
        return self in {
            ComponentState.INITIALIZED,
            ComponentState.RUNNING,
            ComponentState.DEGRADED,
        }
    
    def is_transitioning(self) -> bool:
        """
        Check if component is transitioning
        
        Returns:
            bool: True if transitioning
        """
        return self in {
            ComponentState.INITIALIZING,
            ComponentState.STARTING,
            ComponentState.STOPPING,
        }


# Helper functions for state checking

def is_running(state: RuntimeState) -> bool:
    """
    Check if the runtime state indicates running
    
    Args:
        state: Runtime state to check
        
    Returns:
        bool: True if running
    """
    return state == RuntimeState.RUNNING


def is_active(state: RuntimeState) -> bool:
    """
    Check if the runtime state indicates active
    
    Args:
        state: Runtime state to check
        
    Returns:
        bool: True if active
    """
    return state.is_active()


def is_shutdown(state: RuntimeState) -> bool:
    """
    Check if the runtime state indicates shutdown
    
    Args:
        state: Runtime state to check
        
    Returns:
        bool: True if shutdown
    """
    return state in {RuntimeState.STOPPED, RuntimeState.ERROR}


def is_healthy(health: HealthState) -> bool:
    """
    Check if the health state indicates healthy
    
    Args:
        health: Health state to check
        
    Returns:
        bool: True if healthy
    """
    return health.is_healthy()


def is_operational(health: HealthState) -> bool:
    """
    Check if the health state indicates operational
    
    Args:
        health: Health state to check
        
    Returns:
        bool: True if operational
    """
    return health.is_operational()


def can_serve_traffic(health: HealthState, mode: Optional[ExecutionMode] = None) -> bool:
    """
    Check if the runtime can serve traffic based on health and mode
    
    Args:
        health: Health state
        mode: Optional execution mode
        
    Returns:
        bool: True if traffic can be served
    """
    if not health.can_serve_traffic():
        return False
    
    if mode and mode == ExecutionMode.PASSIVE:
        return False
    
    return True


def get_security_action(security: SecurityState) -> str:
    """
    Get recommended action based on security state
    
    Args:
        security: Security state
        
    Returns:
        str: Recommended action
    """
    actions = {
        SecurityState.SAFE: "continue_normal_operation",
        SecurityState.MONITORING: "monitor_requests",
        SecurityState.THREAT_DETECTED: "increase_monitoring",
        SecurityState.BLOCKED: "block_all_requests",
        SecurityState.RECOVERY: "investigate_and_recover",
    }
    return actions.get(security, "unknown")


def get_state_priority(state: RuntimeState) -> int:
    """
    Get priority level for a runtime state
    
    Args:
        state: Runtime state
        
    Returns:
        int: Priority level
    """
    priorities = {
        RuntimeState.UNINITIALIZED: 0,
        RuntimeState.INITIALIZING: 1,
        RuntimeState.STARTING: 2,
        RuntimeState.RUNNING: 3,
        RuntimeState.PAUSED: 2,
        RuntimeState.RELOADING: 2,
        RuntimeState.STOPPING: 1,
        RuntimeState.STOPPED: 0,
        RuntimeState.ERROR: -1,
        RuntimeState.MAINTENANCE: 1,
    }
    return priorities.get(state, 0)


def is_valid_transition(current: RuntimeState, target: RuntimeState) -> bool:
    """
    Check if a state transition is valid
    
    Args:
        current: Current state
        target: Target state
        
    Returns:
        bool: True if valid transition
    """
    return current.can_transition_to(target)


def get_health_from_state(state: RuntimeState) -> HealthState:
    """
    Get health state from runtime state
    
    Args:
        state: Runtime state
        
    Returns:
        HealthState: Corresponding health state
    """
    health_map = {
        RuntimeState.RUNNING: HealthState.HEALTHY,
        RuntimeState.PAUSED: HealthState.WARNING,
        RuntimeState.RELOADING: HealthState.WARNING,
        RuntimeState.MAINTENANCE: HealthState.DEGRADED,
        RuntimeState.ERROR: HealthState.CRITICAL,
        RuntimeState.STOPPED: HealthState.OFFLINE,
        RuntimeState.UNINITIALIZED: HealthState.OFFLINE,
        RuntimeState.INITIALIZING: HealthState.WARNING,
        RuntimeState.STARTING: HealthState.WARNING,
        RuntimeState.STOPPING: HealthState.WARNING,
    }
    return health_map.get(state, HealthState.OFFLINE)


def get_security_from_state(state: RuntimeState) -> SecurityState:
    """
    Get security state from runtime state
    
    Args:
        state: Runtime state
        
    Returns:
        SecurityState: Corresponding security state
    """
    security_map = {
        RuntimeState.RUNNING: SecurityState.SAFE,
        RuntimeState.PAUSED: SecurityState.MONITORING,
        RuntimeState.RELOADING: SecurityState.MONITORING,
        RuntimeState.ERROR: SecurityState.THREAT_DETECTED,
        RuntimeState.MAINTENANCE: SecurityState.MONITORING,
    }
    return security_map.get(state, SecurityState.MONITORING)


def is_component_healthy(component_state: ComponentState) -> bool:
    """
    Check if a component is healthy
    
    Args:
        component_state: Component state
        
    Returns:
        bool: True if healthy
    """
    return component_state in {ComponentState.INITIALIZED, ComponentState.RUNNING}


def is_component_recoverable(component_state: ComponentState) -> bool:
    """
    Check if a component can be recovered
    
    Args:
        component_state: Component state
        
    Returns:
        bool: True if recoverable
    """
    return component_state in {ComponentState.ERROR, ComponentState.DEGRADED}


# State change context class for tracking state transitions

class StateTransition:
    """
    Represents a state transition with metadata
    """
    
    def __init__(
        self,
        from_state: RuntimeState,
        to_state: RuntimeState,
        timestamp: Optional[float] = None,
        reason: Optional[str] = None,
        metadata: Optional[dict] = None,
    ):
        """
        Initialize a state transition
        
        Args:
            from_state: Source state
            to_state: Target state
            timestamp: Transition timestamp (defaults to current time)
            reason: Reason for transition
            metadata: Additional metadata
        """
        self.from_state = from_state
        self.to_state = to_state
        self.timestamp = timestamp or __import__('time').time()
        self.reason = reason
        self.metadata = metadata or {}
    
    def duration(self) -> float:
        """Get duration since transition (requires current time)"""
        return __import__('time').time() - self.timestamp
    
    def to_dict(self) -> dict:
        """Convert transition to dictionary"""
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "metadata": self.metadata,
        }
    
    def __repr__(self) -> str:
        return f"<StateTransition {self.from_state.value} -> {self.to_state.value} at {self.timestamp}>"


class StateHistory:
    """
    Tracks state transition history
    """
    
    def __init__(self, max_entries: int = 100):
        """
        Initialize state history
        
        Args:
            max_entries: Maximum number of transitions to track
        """
        self._transitions: list = []
        self._max_entries = max_entries
        self._current_state: Optional[RuntimeState] = None
    
    def add_transition(
        self,
        from_state: RuntimeState,
        to_state: RuntimeState,
        reason: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> StateTransition:
        """
        Add a state transition to history
        
        Args:
            from_state: Source state
            to_state: Target state
            reason: Reason for transition
            metadata: Additional metadata
            
        Returns:
            StateTransition: The added transition
        """
        transition = StateTransition(from_state, to_state, reason=reason, metadata=metadata)
        self._transitions.append(transition)
        self._current_state = to_state
        
        # Trim if exceeds max
        if len(self._transitions) > self._max_entries:
            self._transitions = self._transitions[-self._max_entries:]
        
        return transition
    
    def get_current(self) -> Optional[RuntimeState]:
        """Get current state"""
        return self._current_state
    
    def get_transitions(self, count: Optional[int] = None) -> list:
        """Get recent transitions"""
        if count is None:
            return self._transitions.copy()
        return self._transitions[-count:] if self._transitions else []
    
    def clear(self) -> None:
        """Clear transition history"""
        self._transitions.clear()
    
    def __len__(self) -> int:
        return len(self._transitions)


# Default state constants
DEFAULT_RUNTIME_STATE = RuntimeState.UNINITIALIZED
DEFAULT_HEALTH_STATE = HealthState.HEALTHY
DEFAULT_SECURITY_STATE = SecurityState.SAFE
DEFAULT_EXECUTION_MODE = ExecutionMode.PRODUCTION
DEFAULT_COMPONENT_STATE = ComponentState.UNINITIALIZED