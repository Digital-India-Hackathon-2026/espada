# runtime/security/ai_engine.py
"""
AI Decision Engine for Secure Runtime

This module aggregates outputs from various security detectors and the policy engine,
applies risk scoring and decision logic, and produces a final decision with explanations.

It does NOT perform detection; it only reasons based on provided inputs.
"""

import asyncio
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

# Core imports (existing)
from runtime.core.context import Context
from runtime.core.metrics import Metrics
from runtime.core.events import EventBus, Event
from runtime.core.errors import Error as CoreError

# Import from sibling security modules (assume they exist)
from .policy_engine import Action, PolicyDecision

logger = logging.getLogger(__name__)


# ------------------------ Exceptions ------------------------------

class AIEngineError(CoreError):
    """Base exception for AI Engine errors."""
    pass


# ------------------------ Input DTOs ------------------------------

@dataclass
class ThreatDetectionResult:
    """Output from Threat Detector."""
    threat_score: float = 0.0          # 0.0 to 1.0
    threat_type: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretDetectionResult:
    """Output from Secret Detector."""
    secrets_found: List[str] = field(default_factory=list)
    severity: Optional[str] = None     # e.g., "low", "medium", "high"


@dataclass
class PromptInjectionResult:
    """Output from Prompt Injection Detector."""
    injection_score: float = 0.0       # 0.0 to 1.0
    detected_patterns: List[str] = field(default_factory=list)


@dataclass
class AnalysisInput:
    """
    Aggregated input for the AI Engine.
    """
    threat: Optional[ThreatDetectionResult] = None
    secret: Optional[SecretDetectionResult] = None
    prompt_injection: Optional[PromptInjectionResult] = None
    policy_decision: Optional[PolicyDecision] = None
    context: Optional[Context] = None
    metrics: Optional[Metrics] = None
    events: Optional[EventBus] = None
    # Additional raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)


# ------------------------ Decision Models ------------------------------

class DecisionReasonCategory(str, Enum):
    """Categories for decision reasons."""
    THREAT = "threat"
    SECRET = "secret"
    PROMPT_INJECTION = "prompt_injection"
    POLICY = "policy"
    RISK = "risk"
    BEHAVIORAL = "behavioral"
    CONTEXTUAL = "contextual"
    OTHER = "other"


@dataclass
class DecisionReason:
    """A structured explanation for a decision."""
    category: DecisionReasonCategory
    code: str                          # e.g., "THR-001"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0            # 0.0 to 1.0


@dataclass
class DecisionResult:
    """Final decision produced by AI Engine."""
    action: Action
    confidence: float                  # 0.0 to 1.0
    risk_score: float                  # 0.0 to 1.0
    reasons: List[DecisionReason] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


# ------------------------ Risk Models ------------------------------

class RiskModel(ABC):
    """Abstract base for risk scoring models."""
    
    @abstractmethod
    def score(self, input_data: AnalysisInput) -> float:
        """Return a risk score between 0.0 and 1.0."""
        pass

    @abstractmethod
    def explain(self, input_data: AnalysisInput) -> List[DecisionReason]:
        """Return explanations for the score."""
        pass


class RuleBasedRiskModel(RiskModel):
    """
    Rule-based risk scoring model.
    Uses predefined weights and thresholds.
    """
    
    # Default weights
    THREAT_WEIGHT = 0.4
    SECRET_WEIGHT = 0.3
    INJECTION_WEIGHT = 0.2
    POLICY_WEIGHT = 0.1

    def __init__(self, config: Optional[Dict[str, float]] = None):
        if config:
            self.threat_weight = config.get('threat_weight', self.THREAT_WEIGHT)
            self.secret_weight = config.get('secret_weight', self.SECRET_WEIGHT)
            self.injection_weight = config.get('injection_weight', self.INJECTION_WEIGHT)
            self.policy_weight = config.get('policy_weight', self.POLICY_WEIGHT)
        else:
            self.threat_weight = self.THREAT_WEIGHT
            self.secret_weight = self.SECRET_WEIGHT
            self.injection_weight = self.INJECTION_WEIGHT
            self.policy_weight = self.POLICY_WEIGHT

    def score(self, input_data: AnalysisInput) -> float:
        score = 0.0
        if input_data.threat:
            score += self.threat_weight * input_data.threat.threat_score
        if input_data.secret and input_data.secret.secrets_found:
            # Heuristic: more secrets => higher score
            secret_risk = min(1.0, len(input_data.secret.secrets_found) / 5.0)
            score += self.secret_weight * secret_risk
        if input_data.prompt_injection:
            score += self.injection_weight * input_data.prompt_injection.injection_score
        if input_data.policy_decision:
            # If policy already blocked, elevate risk
            if input_data.policy_decision.action == Action.BLOCK:
                score += self.policy_weight * 1.0
            elif input_data.policy_decision.action == Action.WARN:
                score += self.policy_weight * 0.5
            # else allow -> no addition
        # Normalize to 0-1
        return min(1.0, score)

    def explain(self, input_data: AnalysisInput) -> List[DecisionReason]:
        reasons = []
        if input_data.threat and input_data.threat.threat_score > 0:
            reasons.append(DecisionReason(
                category=DecisionReasonCategory.THREAT,
                code="THR-001",
                message=f"Threat score {input_data.threat.threat_score:.2f} contributes to risk",
                details={"score": input_data.threat.threat_score},
                confidence=0.9
            ))
        if input_data.secret and input_data.secret.secrets_found:
            reasons.append(DecisionReason(
                category=DecisionReasonCategory.SECRET,
                code="SEC-001",
                message=f"Found {len(input_data.secret.secrets_found)} secrets",
                details={"secrets": input_data.secret.secrets_found},
                confidence=0.95
            ))
        if input_data.prompt_injection and input_data.prompt_injection.injection_score > 0:
            reasons.append(DecisionReason(
                category=DecisionReasonCategory.PROMPT_INJECTION,
                code="PI-001",
                message=f"Prompt injection score {input_data.prompt_injection.injection_score:.2f}",
                details={"score": input_data.prompt_injection.injection_score},
                confidence=0.85
            ))
        if input_data.policy_decision:
            policy_action = input_data.policy_decision.action
            reasons.append(DecisionReason(
                category=DecisionReasonCategory.POLICY,
                code="POL-001",
                message=f"Policy decision: {policy_action.name}",
                details={"policy": input_data.policy_decision.matched_policy or "none"},
                confidence=1.0
            ))
        return reasons


# ------------------------ AI Engine ------------------------------

class AIEngine:
    """
    Main decision engine.
    Thread-safe, supports async, dependency injection.
    """

    def __init__(
        self,
        risk_model: Optional[RiskModel] = None,
        metrics: Optional[Metrics] = None,
        event_bus: Optional[EventBus] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.risk_model = risk_model or RuleBasedRiskModel()
        self.metrics = metrics
        self.event_bus = event_bus
        self.config = config or {}
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

        # Decision thresholds
        self.block_threshold = self.config.get('block_threshold', 0.8)
        self.warn_threshold = self.config.get('warn_threshold', 0.5)
        self.challenge_threshold = self.config.get('challenge_threshold', 0.6)

    # -------------------- Public Synchronous API --------------------

    def analyze(self, input_data: AnalysisInput) -> DecisionResult:
        """
        Perform full analysis: score, decide, explain.
        """
        with self._lock:
            # Score
            risk_score = self.risk_model.score(input_data)
            # Get explanations
            reasons = self.risk_model.explain(input_data)
            # Decide action
            action = self._decide_action(risk_score, input_data)
            # Compute confidence based on consistency
            confidence = self._compute_confidence(risk_score, action, reasons)
            
            result = DecisionResult(
                action=action,
                confidence=confidence,
                risk_score=risk_score,
                reasons=reasons,
                metadata={
                    "input_summary": self._summarize_input(input_data),
                }
            )
            self._emit_metrics(result, input_data)
            self._emit_event(result, input_data)
            return result

    def decide(self, input_data: AnalysisInput) -> Action:
        """
        Only decide action (lightweight).
        """
        with self._lock:
            risk_score = self.risk_model.score(input_data)
            return self._decide_action(risk_score, input_data)

    def score(self, input_data: AnalysisInput) -> float:
        """
        Only compute risk score.
        """
        with self._lock:
            return self.risk_model.score(input_data)

    def recommend(self, input_data: AnalysisInput) -> str:
        """
        Provide a human-readable recommendation.
        """
        result = self.analyze(input_data)
        return f"Recommended action: {result.action.name} (confidence: {result.confidence:.2f})"

    def explain(self, input_data: AnalysisInput) -> List[DecisionReason]:
        """
        Only get explanations without full analysis.
        """
        with self._lock:
            return self.risk_model.explain(input_data)

    # -------------------- Asynchronous API --------------------

    async def analyze_async(self, input_data: AnalysisInput) -> DecisionResult:
        """Asynchronous version of analyze."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.analyze, input_data)

    async def decide_async(self, input_data: AnalysisInput) -> Action:
        """Asynchronous version of decide."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.decide, input_data)

    async def score_async(self, input_data: AnalysisInput) -> float:
        """Asynchronous version of score."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.score, input_data)

    # -------------------- Internal Helpers --------------------

    def _decide_action(self, risk_score: float, input_data: AnalysisInput) -> Action:
        """
        Map risk score and additional signals to an Action.
        """
        # If policy already blocked, we might still block, but we can override.
        # Policy decision may have higher precedence.
        if input_data.policy_decision:
            if input_data.policy_decision.action == Action.BLOCK:
                return Action.BLOCK
            # If policy says challenge, we may keep it or override based on risk
            if input_data.policy_decision.action == Action.CHALLENGE:
                # Only upgrade to block if risk is high
                if risk_score >= self.block_threshold:
                    return Action.BLOCK
                return Action.CHALLENGE

        # If prompt injection is high, block or challenge
        if input_data.prompt_injection and input_data.prompt_injection.injection_score > 0.9:
            return Action.BLOCK
        if input_data.prompt_injection and input_data.prompt_injection.injection_score > 0.6:
            return Action.CHALLENGE

        # Threat score based decisions
        if risk_score >= self.block_threshold:
            return Action.BLOCK
        elif risk_score >= self.challenge_threshold:
            return Action.CHALLENGE
        elif risk_score >= self.warn_threshold:
            return Action.WARN
        else:
            return Action.ALLOW

    def _compute_confidence(self, risk_score: float, action: Action, reasons: List[DecisionReason]) -> float:
        """
        Compute confidence based on how decisive the evidence is.
        """
        # Simple: more reasons, higher confidence, capped
        base = min(1.0, len(reasons) / 5.0)
        # If action is BLOCK and risk_score is high, confidence high
        if action == Action.BLOCK and risk_score > 0.7:
            base = max(base, 0.8)
        elif action == Action.ALLOW and risk_score < 0.3:
            base = max(base, 0.7)
        return min(1.0, base)

    def _summarize_input(self, input_data: AnalysisInput) -> Dict[str, Any]:
        """Produce a concise summary for metadata."""
        summary = {}
        if input_data.threat:
            summary['threat_score'] = input_data.threat.threat_score
        if input_data.secret:
            summary['secret_count'] = len(input_data.secret.secrets_found)
        if input_data.prompt_injection:
            summary['injection_score'] = input_data.prompt_injection.injection_score
        if input_data.policy_decision:
            summary['policy_action'] = input_data.policy_decision.action.name
        return summary

    def _emit_metrics(self, result: DecisionResult, input_data: AnalysisInput) -> None:
        """Emit metrics if available."""
        if self.metrics:
            self.metrics.increment_counter(
                "ai_engine.decisions",
                tags={"action": result.action.name}
            )
            self.metrics.gauge("ai_engine.risk_score", result.risk_score)
            self.metrics.gauge("ai_engine.confidence", result.confidence)

    def _emit_event(self, result: DecisionResult, input_data: AnalysisInput) -> None:
        """Emit event if available."""
        if self.event_bus:
            self.event_bus.emit(Event(
                type="ai_engine.decision",
                payload={
                    "action": result.action.name,
                    "risk_score": result.risk_score,
                    "confidence": result.confidence,
                    "reasons": [r.message for r in result.reasons],
                    "input_summary": self._summarize_input(input_data),
                }
            ))


# ------------------------ Global Default Instance --------------------

_default_engine: Optional[AIEngine] = None
_default_engine_lock = threading.Lock()


def get_default_engine() -> AIEngine:
    """Get or create the default AI Engine."""
    global _default_engine
    if _default_engine is None:
        with _default_engine_lock:
            if _default_engine is None:
                _default_engine = AIEngine()
    return _default_engine


# ------------------------ Convenience Functions ------------------------

def analyze(input_data: AnalysisInput) -> DecisionResult:
    """Analyze using default engine."""
    return get_default_engine().analyze(input_data)


async def analyze_async(input_data: AnalysisInput) -> DecisionResult:
    """Analyze asynchronously using default engine."""
    return await get_default_engine().analyze_async(input_data)


def decide(input_data: AnalysisInput) -> Action:
    """Decide using default engine."""
    return get_default_engine().decide(input_data)


def score(input_data: AnalysisInput) -> float:
    """Score using default engine."""
    return get_default_engine().score(input_data)
