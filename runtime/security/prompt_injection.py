# runtime/security/prompt_injection.py
"""
AI Prompt Injection Detection Engine

Detects various types of prompt injection attacks and manipulation attempts
in user input and system prompts. Provides risk scoring, classification,
and actionable recommendations.

Supports:
- Regex patterns
- Keyword matching
- Rule-based detection
- Context and conversation analysis
- Extension points for ML/AI models
"""

import asyncio
import logging
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

# Import existing core classes (do not redefine)
from runtime.core.context import Context
from runtime.core.metrics import Metrics
from runtime.core.events import EventBus, Event
from runtime.core.errors import Error as CoreError

logger = logging.getLogger(__name__)


# ------------------------ Exceptions ------------------------------

class PromptInjectionError(CoreError):
    """Base exception for prompt injection detection errors."""
    pass


# ------------------------ Enums ------------------------------

class InjectionCategory(Enum):
    """Categories of prompt injection attacks."""
    IGNORE_PREVIOUS_INSTRUCTIONS = "ignore_previous_instructions"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    ROLE_OVERRIDE = "role_override"
    JAILBREAK = "jailbreak"
    PROMPT_EXTRACTION = "prompt_extraction"
    TOOL_ABUSE = "tool_abuse"
    MEMORY_POISONING = "memory_poisoning"
    RECURSIVE_PROMPTING = "recursive_prompting"
    INSTRUCTION_OVERRIDE = "instruction_override"
    MODEL_MANIPULATION = "model_manipulation"
    INDIRECT_INJECTION = "indirect_injection"
    HIDDEN_INJECTION = "hidden_injection"
    ENCODED_INJECTION = "encoded_injection"
    CONTEXT_ESCAPE = "context_escape"
    FUNCTION_CALL_ABUSE = "function_call_abuse"
    OTHER = "other"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """
    Result of a prompt injection scan.
    """
    is_injection: bool
    category: Optional[InjectionCategory] = None
    severity: Severity = Severity.LOW
    risk_score: float = 0.0          # 0.0 to 1.0
    confidence: float = 1.0          # 0.0 to 1.0
    explanation: str = ""
    recommendation: str = ""
    matched_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ------------------------ Detection Rules ------------------------------

class InjectionRule:
    """
    Represents a single detection rule.
    Can be a regex pattern, keyword list, or custom callable.
    """
    def __init__(
        self,
        name: str,
        category: InjectionCategory,
        severity: Severity,
        pattern: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        condition: Optional[callable] = None,
        description: str = "",
    ):
        self.name = name
        self.category = category
        self.severity = severity
        self.pattern = pattern
        self.compiled_regex = re.compile(pattern, re.IGNORECASE) if pattern else None
        self.keywords = set(keywords) if keywords else set()
        self.condition = condition
        self.description = description

    def matches(self, text: str, context: Optional[Context] = None) -> bool:
        """Check if the rule matches the given text."""
        if self.compiled_regex:
            if self.compiled_regex.search(text):
                return True
        if self.keywords:
            lower_text = text.lower()
            for kw in self.keywords:
                if kw.lower() in lower_text:
                    return True
        if self.condition:
            try:
                return self.condition(text, context)
            except Exception as e:
                logger.error(f"Error in condition for rule {self.name}: {e}")
                return False
        return False


# ------------------------ Default Rule Set ------------------------------

DEFAULT_RULES = [
    InjectionRule(
        name="ignore_previous_instructions",
        category=InjectionCategory.IGNORE_PREVIOUS_INSTRUCTIONS,
        severity=Severity.HIGH,
        pattern=r"(ignore|disregard|forget|overwrite)\s+(previous|prior|all)\s+(instructions|directives|rules)",
        description="Attempt to ignore previous system instructions"
    ),
    InjectionRule(
        name="system_prompt_leakage",
        category=InjectionCategory.SYSTEM_PROMPT_LEAKAGE,
        severity=Severity.CRITICAL,
        pattern=r"(what is your (system )?prompt|show (me )?your instructions|what are your rules)",
        description="Attempt to extract system prompt"
    ),
    InjectionRule(
        name="role_override",
        category=InjectionCategory.ROLE_OVERRIDE,
        severity=Severity.HIGH,
        pattern=r"(you are now|your new role is|act as|pretend to be|from now on you are)",
        description="Attempt to override system role"
    ),
    InjectionRule(
        name="jailbreak",
        category=InjectionCategory.JAILBREAK,
        severity=Severity.CRITICAL,
        pattern=r"(jailbreak|break out of|escape the|bypass (the )?limits|unrestricted)",
        description="Jailbreak attempt"
    ),
    InjectionRule(
        name="prompt_extraction",
        category=InjectionCategory.PROMPT_EXTRACTION,
        severity=Severity.CRITICAL,
        pattern=r"(extract|expose|reveal|output)\s+(the\s+)?(prompt|instructions|system)",
        description="Prompt extraction attempt"
    ),
    InjectionRule(
        name="tool_abuse",
        category=InjectionCategory.TOOL_ABUSE,
        severity=Severity.HIGH,
        pattern=r"(use (the )?tool|call (the )?function|execute|run)\s+.*\s+(without|bypass|ignore)",
        description="Tool abuse attempt"
    ),
    InjectionRule(
        name="memory_poisoning",
        category=InjectionCategory.MEMORY_POISONING,
        severity=Severity.CRITICAL,
        pattern=r"(poison|corrupt|inject|overwrite)\s+(memory|context|history|state)",
        description="Memory poisoning attempt"
    ),
    InjectionRule(
        name="recursive_prompting",
        category=InjectionCategory.RECURSIVE_PROMPTING,
        severity=Severity.MEDIUM,
        pattern=r"(repeat|loop|recursive|infinite)\s+(prompt|query|request)",
        description="Recursive prompting attempt"
    ),
    InjectionRule(
        name="instruction_override",
        category=InjectionCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.HIGH,
        pattern=r"(new instruction|override|update|change)\s+(the\s+)?(policy|rule|constraint)",
        description="Attempt to override instructions"
    ),
    InjectionRule(
        name="model_manipulation",
        category=InjectionCategory.MODEL_MANIPULATION,
        severity=Severity.CRITICAL,
        pattern=r"(manipulate|control|hijack|take over)\s+(model|ai|system)",
        description="Model manipulation attempt"
    ),
    InjectionRule(
        name="indirect_injection",
        category=InjectionCategory.INDIRECT_INJECTION,
        severity=Severity.HIGH,
        pattern=r"(indirect|via|through)\s+(data|input|context)",
        description="Indirect injection attempt"
    ),
    InjectionRule(
        name="hidden_injection",
        category=InjectionCategory.HIDDEN_INJECTION,
        severity=Severity.HIGH,
        pattern=r"(hidden|obfuscated|encoded|escaped)\s+(command|injection|payload)",
        description="Hidden or obfuscated injection"
    ),
    InjectionRule(
        name="encoded_injection",
        category=InjectionCategory.ENCODED_INJECTION,
        severity=Severity.MEDIUM,
        pattern=r"(base64|hex|unicode|urlencode|escape)\s+(decode|encode)",
        description="Encoded payload injection"
    ),
    InjectionRule(
        name="context_escape",
        category=InjectionCategory.CONTEXT_ESCAPE,
        severity=Severity.HIGH,
        pattern=r"(escape|break out of|exit)\s+(context|conversation|scope)",
        description="Context escape attempt"
    ),
    InjectionRule(
        name="function_call_abuse",
        category=InjectionCategory.FUNCTION_CALL_ABUSE,
        severity=Severity.CRITICAL,
        pattern=r"(call|invoke|run)\s+(function|tool|action)\s+.*\s+(malicious|unauthorized|dangerous)",
        description="Function call abuse"
    ),
]

# Additional keyword-based rules (complements regex)
KEYWORD_RULES = {
    "ignore": [InjectionCategory.IGNORE_PREVIOUS_INSTRUCTIONS],
    "disregard": [InjectionCategory.IGNORE_PREVIOUS_INSTRUCTIONS],
    "forget": [InjectionCategory.IGNORE_PREVIOUS_INSTRUCTIONS],
    "system prompt": [InjectionCategory.SYSTEM_PROMPT_LEAKAGE],
    "instructions": [InjectionCategory.SYSTEM_PROMPT_LEAKAGE, InjectionCategory.INSTRUCTION_OVERRIDE],
    "role": [InjectionCategory.ROLE_OVERRIDE],
    "jailbreak": [InjectionCategory.JAILBREAK],
    "extract": [InjectionCategory.PROMPT_EXTRACTION],
    "expose": [InjectionCategory.PROMPT_EXTRACTION],
    "tool": [InjectionCategory.TOOL_ABUSE],
    "function": [InjectionCategory.FUNCTION_CALL_ABUSE],
    "memory": [InjectionCategory.MEMORY_POISONING],
    "poison": [InjectionCategory.MEMORY_POISONING],
    "recursive": [InjectionCategory.RECURSIVE_PROMPTING],
    "loop": [InjectionCategory.RECURSIVE_PROMPTING],
    "override": [InjectionCategory.INSTRUCTION_OVERRIDE, InjectionCategory.ROLE_OVERRIDE],
    "manipulate": [InjectionCategory.MODEL_MANIPULATION],
    "indirect": [InjectionCategory.INDIRECT_INJECTION],
    "hidden": [InjectionCategory.HIDDEN_INJECTION],
    "obfuscated": [InjectionCategory.HIDDEN_INJECTION],
    "encoded": [InjectionCategory.ENCODED_INJECTION],
    "escape": [InjectionCategory.CONTEXT_ESCAPE],
    "call": [InjectionCategory.FUNCTION_CALL_ABUSE],
}


# ------------------------ Detector Class ------------------------------

class PromptInjectionDetector:
    """
    Main detector for prompt injection attacks.
    Thread-safe, supports async, and can be extended with custom rules.
    """
    def __init__(
        self,
        rules: Optional[List[InjectionRule]] = None,
        enable_keywords: bool = True,
        metrics: Optional[Metrics] = None,
        event_bus: Optional[EventBus] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.rules = rules or DEFAULT_RULES.copy()
        self.enable_keywords = enable_keywords
        self.metrics = metrics
        self.event_bus = event_bus
        self.config = config or {}
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

        # Severity weights for risk score calculation
        self.severity_weights = {
            Severity.LOW: 0.2,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.8,
            Severity.CRITICAL: 1.0,
        }

    # -------------------- Core Detection ------------------------------

    def scan(self, text: str, context: Optional[Context] = None) -> DetectionResult:
        """
        Scan a single text for prompt injection.
        Returns a DetectionResult.
        """
        with self._lock:
            # Collect matches from regex rules
            matched_rules = []
            for rule in self.rules:
                if rule.matches(text, context):
                    matched_rules.append(rule)

            # Keyword-based matching (if enabled)
            keyword_categories = set()
            if self.enable_keywords:
                lower_text = text.lower()
                for kw, categories in KEYWORD_RULES.items():
                    if kw in lower_text:
                        keyword_categories.update(categories)

            # If we have matches from keywords but no regex rule, we need to create rules on the fly?
            # We'll treat keyword matches as additional evidence.
            # We'll also check if any keyword category matches a rule category not already matched.
            # For now, we'll just add them to the rule list for reporting.

            # Determine primary category and severity
            if not matched_rules and not keyword_categories:
                # No detection
                return DetectionResult(
                    is_injection=False,
                    risk_score=0.0,
                    confidence=1.0,
                    explanation="No injection patterns detected",
                    recommendation="Proceed with normal processing"
                )

            # Combine rule matches and keyword categories
            all_categories = set()
            severity_count = {Severity.LOW: 0, Severity.MEDIUM: 0, Severity.HIGH: 0, Severity.CRITICAL: 0}
            matched_names = []
            for rule in matched_rules:
                all_categories.add(rule.category)
                severity_count[rule.severity] += 1
                matched_names.append(rule.name)
            # Add keyword categories
            for cat in keyword_categories:
                all_categories.add(cat)
                # Assign default severity: we'll use category-specific mapping if available
                # For simplicity, we'll assign based on a default map
                cat_severity = self._category_severity(cat)
                severity_count[cat_severity] += 1

            # Determine highest severity
            highest_severity = Severity.LOW
            if severity_count[Severity.CRITICAL] > 0:
                highest_severity = Severity.CRITICAL
            elif severity_count[Severity.HIGH] > 0:
                highest_severity = Severity.HIGH
            elif severity_count[Severity.MEDIUM] > 0:
                highest_severity = Severity.MEDIUM

            # Risk score: weighted average of severity weights, capped at 1.0
            total_weight = 0
            total_count = 0
            for sev, count in severity_count.items():
                if count > 0:
                    total_weight += self.severity_weights[sev] * count
                    total_count += count
            risk_score = min(1.0, total_weight / total_count if total_count > 0 else 0.0)

            # Confidence: based on number of matches and consistency
            # More matches => higher confidence, but cap at 1.0
            confidence = min(1.0, 0.5 + 0.1 * (len(matched_rules) + len(keyword_categories)))
            confidence = min(1.0, confidence)

            # Build explanation
            categories_str = ", ".join([c.value for c in all_categories])
            explanation = f"Detected potential injection categories: {categories_str}"
            if matched_rules:
                explanation += f" (matched rules: {', '.join(matched_names)})"
            if keyword_categories:
                explanation += f" (keyword indicators: {', '.join([c.value for c in keyword_categories])})"

            # Recommendation based on severity
            if highest_severity in (Severity.CRITICAL, Severity.HIGH):
                recommendation = "Block or quarantine this input; investigate immediately."
            elif highest_severity == Severity.MEDIUM:
                recommendation = "Flag for review; consider challenging or warning."
            else:
                recommendation = "Monitor; low-risk indicator."

            result = DetectionResult(
                is_injection=True,
                category=next(iter(all_categories)) if all_categories else None,
                severity=highest_severity,
                risk_score=risk_score,
                confidence=confidence,
                explanation=explanation,
                recommendation=recommendation,
                matched_patterns=matched_names,
                metadata={
                    "matched_rules": matched_names,
                    "keyword_categories": [c.value for c in keyword_categories],
                }
            )

            self._emit_metrics(result, text)
            self._emit_event(result, text)
            return result

    def detect(self, text: str, context: Optional[Context] = None) -> bool:
        """
        Quick boolean detection.
        """
        result = self.scan(text, context)
        return result.is_injection

    def classify(self, text: str, context: Optional[Context] = None) -> InjectionCategory:
        """
        Return the primary category of injection, or None if none.
        """
        result = self.scan(text, context)
        return result.category

    def risk_score(self, text: str, context: Optional[Context] = None) -> float:
        """
        Return risk score (0.0 to 1.0).
        """
        result = self.scan(text, context)
        return result.risk_score

    # -------------------- Async Variants ------------------------------

    async def scan_async(self, text: str, context: Optional[Context] = None) -> DetectionResult:
        """Asynchronous version of scan."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.scan, text, context)

    async def detect_async(self, text: str, context: Optional[Context] = None) -> bool:
        """Asynchronous version of detect."""
        result = await self.scan_async(text, context)
        return result.is_injection

    async def classify_async(self, text: str, context: Optional[Context] = None) -> Optional[InjectionCategory]:
        """Asynchronous version of classify."""
        result = await self.scan_async(text, context)
        return result.category

    async def risk_score_async(self, text: str, context: Optional[Context] = None) -> float:
        """Asynchronous version of risk_score."""
        result = await self.scan_async(text, context)
        return result.risk_score

    # -------------------- Helpers ------------------------------

    def _category_severity(self, category: InjectionCategory) -> Severity:
        """Map category to a default severity."""
        mapping = {
            InjectionCategory.IGNORE_PREVIOUS_INSTRUCTIONS: Severity.HIGH,
            InjectionCategory.SYSTEM_PROMPT_LEAKAGE: Severity.CRITICAL,
            InjectionCategory.ROLE_OVERRIDE: Severity.HIGH,
            InjectionCategory.JAILBREAK: Severity.CRITICAL,
            InjectionCategory.PROMPT_EXTRACTION: Severity.CRITICAL,
            InjectionCategory.TOOL_ABUSE: Severity.HIGH,
            InjectionCategory.MEMORY_POISONING: Severity.CRITICAL,
            InjectionCategory.RECURSIVE_PROMPTING: Severity.MEDIUM,
            InjectionCategory.INSTRUCTION_OVERRIDE: Severity.HIGH,
            InjectionCategory.MODEL_MANIPULATION: Severity.CRITICAL,
            InjectionCategory.INDIRECT_INJECTION: Severity.HIGH,
            InjectionCategory.HIDDEN_INJECTION: Severity.HIGH,
            InjectionCategory.ENCODED_INJECTION: Severity.MEDIUM,
            InjectionCategory.CONTEXT_ESCAPE: Severity.HIGH,
            InjectionCategory.FUNCTION_CALL_ABUSE: Severity.CRITICAL,
            InjectionCategory.OTHER: Severity.MEDIUM,
        }
        return mapping.get(category, Severity.MEDIUM)

    def _emit_metrics(self, result: DetectionResult, text: str) -> None:
        if self.metrics:
            self.metrics.increment_counter(
                "prompt_injection.scans",
                tags={"injection": str(result.is_injection)}
            )
            if result.is_injection:
                self.metrics.increment_counter(
                    "prompt_injection.detections",
                    tags={"severity": result.severity.value, "category": result.category.value if result.category else "unknown"}
                )
                self.metrics.gauge("prompt_injection.risk_score", result.risk_score)
                self.metrics.gauge("prompt_injection.confidence", result.confidence)

    def _emit_event(self, result: DetectionResult, text: str) -> None:
        if self.event_bus and result.is_injection:
            self.event_bus.emit(Event(
                type="prompt_injection.detected",
                payload={
                    "category": result.category.value if result.category else None,
                    "severity": result.severity.value,
                    "risk_score": result.risk_score,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                    "text_preview": text[:100] if len(text) > 100 else text,
                }
            ))


# ------------------------ Global Default Instance --------------------

_default_detector: Optional[PromptInjectionDetector] = None
_default_detector_lock = threading.Lock()


def get_default_detector() -> PromptInjectionDetector:
    """Get or create the default prompt injection detector."""
    global _default_detector
    if _default_detector is None:
        with _default_detector_lock:
            if _default_detector is None:
                _default_detector = PromptInjectionDetector()
    return _default_detector


# ------------------------ Public Functions ------------------------------

def scan(text: str, context: Optional[Context] = None) -> DetectionResult:
    """Scan text for prompt injection using default detector."""
    return get_default_detector().scan(text, context)


async def scan_async(text: str, context: Optional[Context] = None) -> DetectionResult:
    """Async scan for prompt injection."""
    return await get_default_detector().scan_async(text, context)


def detect(text: str, context: Optional[Context] = None) -> bool:
    """Quick boolean detection."""
    return get_default_detector().detect(text, context)


def classify(text: str, context: Optional[Context] = None) -> Optional[InjectionCategory]:
    """Get primary category of injection."""
    return get_default_detector().classify(text, context)


def risk_score(text: str, context: Optional[Context] = None) -> float:
    """Get risk score."""
    return get_default_detector().risk_score(text, context)


# ------------------------ Extension Points ------------------------------

def add_rule(rule: InjectionRule) -> None:
    """Add a custom rule to the default detector."""
    get_default_detector().rules.append(rule)
