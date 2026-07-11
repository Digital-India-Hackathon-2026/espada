# runtime/core/context.py
"""
Request-Scoped Runtime Context

This module provides a thread-safe context object that carries request-scoped
information through the entire runtime pipeline. It serves as the shared
object passed between middlewares, handlers, and components.
"""

import time
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel, Field, validator, ConfigDict

if TYPE_CHECKING:
    from runtime.core.logger import Logger
    from runtime.core.metrics import MetricsCollector


class ContextState(str, Enum):
    """Runtime context lifecycle states"""
    INITIALIZED = "initialized"
    PROCESSING = "processing"
    AUTHENTICATING = "authenticating"
    AUTHORIZING = "authorizing"
    THREAT_DETECTION = "threat_detection"
    AI_PROCESSING = "ai_processing"
    POLICY_EVALUATION = "policy_evaluation"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


class SecurityScores(BaseModel):
    """Security-related scores for the request"""
    security_score: float = 0.0
    threat_score: float = 0.0
    trust_score: float = 0.0
    risk_score: float = 0.0
    
    model_config = ConfigDict(extra="allow")
    
    @validator("security_score", "threat_score", "trust_score", "risk_score")
    def validate_score(cls, v: float) -> float:
        """Validate score is between 0 and 100"""
        if not 0 <= v <= 100:
            raise ValueError("Score must be between 0 and 100")
        return v


class SecurityFinding(BaseModel):
    """Security finding detected during processing"""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str  # critical, high, medium, low, info
    category: str  # injection, auth, data_exposure, etc.
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    source: Optional[str] = None
    
    model_config = ConfigDict(extra="allow")
    
    @validator("severity")
    def validate_severity(cls, v: str) -> str:
        """Validate severity level"""
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()


class RequestInfo(BaseModel):
    """Request information container"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str = ""
    path: str = ""
    query_params: Dict[str, Union[str, List[str]]] = Field(default_factory=dict)
    path_params: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    
    model_config = ConfigDict(extra="allow")


class ResponseInfo(BaseModel):
    """Response information container"""
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    response_time: Optional[float] = None
    
    model_config = ConfigDict(extra="allow")


class AIResponse(BaseModel):
    """AI decision response"""
    decision: str
    confidence: float = 0.0
    reasoning: Optional[str] = None
    alternative_decisions: List[str] = Field(default_factory=list)
    model_used: Optional[str] = None
    processing_time: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(extra="allow")
    
    @validator("confidence")
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence is between 0 and 1"""
        if not 0 <= v <= 1:
            raise ValueError("Confidence must be between 0 and 1")
        return v


class PolicyDecision(BaseModel):
    """Policy engine decision"""
    allowed: bool
    reason: Optional[str] = None
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    enforcement_action: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(extra="allow")


class RuntimeContext(BaseModel):
    """
    Request-scoped runtime context
    
    This is the primary context object passed through the entire runtime pipeline.
    It's designed to be thread-safe and supports contextvars for async operations.
    """
    
    # Core identifiers
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    
    # Request/Response
    request: RequestInfo = Field(default_factory=RequestInfo)
    response: ResponseInfo = Field(default_factory=ResponseInfo)
    
    # Security
    security_scores: SecurityScores = Field(default_factory=SecurityScores)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    
    # Authentication & Authorization
    authenticated: bool = False
    authorized: bool = False
    auth_method: Optional[str] = None
    auth_provider: Optional[str] = None
    auth_claims: Dict[str, Any] = Field(default_factory=dict)
    permissions: Set[str] = Field(default_factory=set)
    roles: Set[str] = Field(default_factory=set)
    
    # State
    state: ContextState = ContextState.INITIALIZED
    start_time: float = Field(default_factory=time.time)
    end_time: Optional[float] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    # Decisions
    ai_decision: Optional[AIResponse] = None
    policy_decision: Optional[PolicyDecision] = None
    
    # Custom attributes
    custom: Dict[str, Any] = Field(default_factory=dict)
    
    # Logging & Metrics references (set at runtime)
    logger: Optional[Any] = None
    metrics: Optional[Any] = None
    
    # Thread-safe context storage
    _context_data: Dict[str, Any] = Field(default_factory=dict, exclude=True)
    _context_metadata: Dict[str, Any] = Field(default_factory=dict, exclude=True)
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
        validate_assignment=True,
    )
    
    def __init__(self, **data):
        """Initialize context with validation"""
        super().__init__(**data)
        self._context_metadata["created_at"] = datetime.utcnow()
        self._context_metadata["version"] = "1.0"
    
    def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> "RuntimeContext":
        """
        Set a custom attribute in the context
        
        Args:
            key: Attribute key
            value: Attribute value
            metadata: Optional metadata about the value
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        self._context_data[key] = value
        if metadata:
            self._context_metadata[f"meta_{key}"] = metadata
        
        # Also try to set as attribute if possible
        if hasattr(self, key):
            setattr(self, key, value)
        
        self.events.append({
            "type": "context_set",
            "key": key,
            "timestamp": datetime.utcnow().isoformat(),
        })
        return self
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a custom attribute from the context
        
        Args:
            key: Attribute key
            default: Default value if key doesn't exist
            
        Returns:
            Any: Attribute value or default
        """
        # Check context data first
        if key in self._context_data:
            return self._context_data[key]
        
        # Check if it's a model field
        if hasattr(self, key):
            return getattr(self, key)
        
        return default
    
    def remove(self, key: str) -> "RuntimeContext":
        """
        Remove a custom attribute from the context
        
        Args:
            key: Attribute key to remove
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        if key in self._context_data:
            del self._context_data[key]
        
        if f"meta_{key}" in self._context_metadata:
            del self._context_metadata[f"meta_{key}"]
        
        self.events.append({
            "type": "context_remove",
            "key": key,
            "timestamp": datetime.utcnow().isoformat(),
        })
        return self
    
    def has(self, key: str) -> bool:
        """
        Check if a key exists in the context
        
        Args:
            key: Attribute key
            
        Returns:
            bool: True if key exists
        """
        return key in self._context_data or hasattr(self, key)
    
    def add_event(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> "RuntimeContext":
        """
        Add an event to the context
        
        Args:
            event_type: Type of event
            data: Event data
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if data:
            event.update(data)
        self.events.append(event)
        return self
    
    def add_warning(self, warning_message: str) -> "RuntimeContext":
        """
        Add a warning to the context
        
        Args:
            warning_message: Warning message
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        self.warnings.append(warning_message)
        self.add_event("warning", {"message": warning_message})
        return self
    
    def add_security_finding(
        self,
        severity: str,
        category: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        source: Optional[str] = None,
    ) -> "RuntimeContext":
        """
        Add a security finding to the context
        
        Args:
            severity: Finding severity (critical, high, medium, low, info)
            category: Finding category
            description: Description of the finding
            details: Additional details
            remediation: Remediation steps
            source: Source of the finding
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        finding = SecurityFinding(
            severity=severity,
            category=category,
            description=description,
            details=details or {},
            remediation=remediation,
            source=source,
        )
        self.security_findings.append(finding)
        
        # Update security scores based on findings
        severity_impact = {
            "critical": 20,
            "high": 15,
            "medium": 10,
            "low": 5,
            "info": 0,
        }
        impact = severity_impact.get(severity.lower(), 0)
        
        # Decrease security score, increase threat score
        self.security_scores.security_score = max(0, self.security_scores.security_score - impact)
        self.security_scores.threat_score = min(100, self.security_scores.threat_score + impact)
        
        self.add_event("security_finding", finding.dict())
        return self
    
    def update_score(
        self,
        security_score: Optional[float] = None,
        threat_score: Optional[float] = None,
        trust_score: Optional[float] = None,
        risk_score: Optional[float] = None,
    ) -> "RuntimeContext":
        """
        Update security scores
        
        Args:
            security_score: New security score (0-100)
            threat_score: New threat score (0-100)
            trust_score: New trust score (0-100)
            risk_score: New risk score (0-100)
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        if security_score is not None:
            self.security_scores.security_score = security_score
        if threat_score is not None:
            self.security_scores.threat_score = threat_score
        if trust_score is not None:
            self.security_scores.trust_score = trust_score
        if risk_score is not None:
            self.security_scores.risk_score = risk_score
        
        self.add_event("score_update", {
            "security": security_score,
            "threat": threat_score,
            "trust": trust_score,
            "risk": risk_score,
        })
        return self
    
    def execution_time(self) -> float:
        """
        Get the execution time of the context
        
        Returns:
            float: Execution time in seconds
        """
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def mark_completed(self) -> "RuntimeContext":
        """
        Mark the context as completed
        
        Returns:
            RuntimeContext: Self for method chaining
        """
        self.state = ContextState.COMPLETED
        self.end_time = time.time()
        self.add_event("context_completed", {
            "duration": self.execution_time(),
        })
        return self
    
    def mark_error(self, error_message: Optional[str] = None) -> "RuntimeContext":
        """
        Mark the context as error state
        
        Args:
            error_message: Error message
            
        Returns:
            RuntimeContext: Self for method chaining
        """
        self.state = ContextState.ERROR
        self.end_time = time.time()
        event_data = {"duration": self.execution_time()}
        if error_message:
            event_data["error"] = error_message
        self.add_event("context_error", event_data)
        return self
    
    def clear(self) -> "RuntimeContext":
        """
        Clear the context data (keeps request/response info)
        
        Returns:
            RuntimeContext: Self for method chaining
        """
        self._context_data.clear()
        self.security_findings.clear()
        self.events.clear()
        self.warnings.clear()
        self.security_scores = SecurityScores()
        self.custom.clear()
        self.state = ContextState.INITIALIZED
        self.start_time = time.time()
        self.end_time = None
        self.add_event("context_cleared")
        return self
    
    def clone(self, keep_scores: bool = True) -> "RuntimeContext":
        """
        Create a deep clone of the context
        
        Args:
            keep_scores: Whether to keep security scores
            
        Returns:
            RuntimeContext: New cloned context
        """
        # Create new context with basic info
        new_context = RuntimeContext(
            request_id=self.request_id,
            session_id=self.session_id,
            user_id=self.user_id,
            authenticated=self.authenticated,
            authorized=self.authorized,
            auth_method=self.auth_method,
            auth_provider=self.auth_provider,
            auth_claims=self.auth_claims.copy(),
            permissions=self.permissions.copy(),
            roles=self.roles.copy(),
            logger=self.logger,
            metrics=self.metrics,
        )
        
        # Copy request and response
        new_context.request = self.request.model_copy(deep=True)
        new_context.response = self.response.model_copy(deep=True)
        
        # Copy scores if requested
        if keep_scores:
            new_context.security_scores = self.security_scores.model_copy(deep=True)
            new_context.security_findings = [f.model_copy(deep=True) for f in self.security_findings]
        
        # Copy decisions
        if self.ai_decision:
            new_context.ai_decision = self.ai_decision.model_copy(deep=True)
        if self.policy_decision:
            new_context.policy_decision = self.policy_decision.model_copy(deep=True)
        
        # Copy custom data
        new_context._context_data = self._context_data.copy()
        new_context._context_metadata = self._context_metadata.copy()
        new_context.custom = self.custom.copy()
        
        # Copy state
        new_context.state = self.state
        new_context.start_time = time.time()
        
        new_context.add_event("context_cloned", {
            "original_request_id": self.request_id,
        })
        
        return new_context
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the context
        
        Returns:
            Dict[str, Any]: Context summary
        """
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "state": self.state.value,
            "authenticated": self.authenticated,
            "authorized": self.authorized,
            "execution_time": self.execution_time(),
            "security_score": self.security_scores.security_score,
            "threat_score": self.security_scores.threat_score,
            "risk_score": self.security_scores.risk_score,
            "events_count": len(self.events),
            "findings_count": len(self.security_findings),
            "warnings_count": len(self.warnings),
            "has_ai_decision": self.ai_decision is not None,
            "has_policy_decision": self.policy_decision is not None,
        }
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert context to dictionary
        
        Args:
            include_sensitive: Whether to include sensitive information
            
        Returns:
            Dict[str, Any]: Context dictionary
        """
        data = self.dict(exclude={"logger", "metrics", "_context_data", "_context_metadata"})
        
        # Include custom data
        if self._context_data:
            data["custom_data"] = self._context_data.copy()
        
        # Add summary
        data["summary"] = self.get_summary()
        
        # Include sensitive info only if requested
        if include_sensitive:
            data["headers"] = self.request.headers
            data["cookies"] = self.request.cookies
            data["auth_claims"] = self.auth_claims
        
        return data


# ContextVar for thread-safe context propagation
_context_var: ContextVar[Optional[RuntimeContext]] = ContextVar("runtime_context", default=None)


def get_current_context() -> Optional[RuntimeContext]:
    """
    Get the current context from thread-local storage
    
    Returns:
        Optional[RuntimeContext]: Current context or None
    """
    return _context_var.get()


def set_current_context(context: RuntimeContext) -> None:
    """
    Set the current context in thread-local storage
    
    Args:
        context: RuntimeContext to set
    """
    _context_var.set(context)


def create_context(
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    **kwargs
) -> RuntimeContext:
    """
    Create a new runtime context
    
    Args:
        request_id: Optional request ID
        session_id: Optional session ID
        user_id: Optional user ID
        **kwargs: Additional context parameters
        
    Returns:
        RuntimeContext: New context
    """
    context = RuntimeContext(
        request_id=request_id or str(uuid.uuid4()),
        session_id=session_id,
        user_id=user_id,
        **kwargs
    )
    context.add_event("context_created")
    return context


def with_context(context: RuntimeContext):
    """
    Decorator to run a function with a specific context
    
    Args:
        context: RuntimeContext to use
        
    Returns:
        Decorator function
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            token = _context_var.set(context)
            try:
                return func(*args, **kwargs)
            finally:
                _context_var.reset(token)
        return wrapper
    return decorator