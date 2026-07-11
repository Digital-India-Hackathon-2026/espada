# runtime/security/secret_detector.py
"""
Production-grade Secret Detection Engine

Detects and manages secrets, credentials, and sensitive tokens in text.
Supports a wide range of secret types with entropy analysis and false positive filtering.

Features:
- Regex patterns for 20+ secret types
- Shannon entropy scoring
- False positive filtering (e.g., example keys, placeholder values)
- Masking and redaction
- Streaming scan for large files
- Thread-safe and async support
"""

import asyncio
import base64
import hashlib
import logging
import math
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Set, Union

# Import existing core classes
from runtime.core.context import Context
from runtime.core.metrics import Metrics
from runtime.core.events import EventBus, Event
from runtime.core.errors import Error as CoreError

logger = logging.getLogger(__name__)


# ------------------------ Exceptions ------------------------------

class SecretDetectionError(CoreError):
    """Base exception for secret detection errors."""
    pass


# ------------------------ Enums ------------------------------

class SecretType(Enum):
    """Types of secrets that can be detected."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    OPENAI_KEY = "openai_key"
    ANTHROPIC_KEY = "anthropic_key"
    GOOGLE_API_KEY = "google_api_key"
    STRIPE_KEY = "stripe_key"
    TWILIO_TOKEN = "twilio_token"
    JWT_TOKEN = "jwt_token"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    SSH_KEY = "ssh_key"
    RSA_KEY = "rsa_key"
    PASSWORD = "password"
    SECRET = "secret"
    ENV_VAR = "env_var"
    DATABASE_URL = "database_url"
    WEBHOOK_SECRET = "webhook_secret"
    COOKIE = "cookie"
    SESSION_TOKEN = "session_token"
    GENERIC = "generic"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ------------------------ Models ------------------------------

@dataclass
class Secret:
    """
    A detected secret.
    """
    type: SecretType
    value: str
    line: int = 0
    start: int = 0
    end: int = 0
    entropy: float = 0.0
    confidence: float = 1.0
    severity: Severity = Severity.MEDIUM
    recommendation: str = ""
    masked_value: str = ""

    def __post_init__(self):
        if not self.masked_value:
            self.masked_value = self.mask(self.value)

    @staticmethod
    def mask(value: str, keep: int = 4) -> str:
        """Mask a secret, keeping first and last few characters."""
        if len(value) <= keep * 2:
            return "*" * len(value)
        return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


@dataclass
class DetectionResult:
    """Result of a secret scan."""
    secrets: List[Secret] = field(default_factory=list)
    total_count: int = 0
    high_confidence_count: int = 0
    total_entropy: float = 0.0


# ------------------------ Pattern Definitions ------------------------------

class SecretPattern:
    """
    A regex-based pattern for detecting a specific secret type.
    Includes false-positive filtering and entropy requirements.
    """
    def __init__(
        self,
        secret_type: SecretType,
        pattern: str,
        severity: Severity = Severity.MEDIUM,
        entropy_threshold: Optional[float] = None,
        false_positive_patterns: Optional[List[str]] = None,
        pre_filter: Optional[callable] = None,
    ):
        self.secret_type = secret_type
        self.compiled = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.entropy_threshold = entropy_threshold
        self.false_positive_patterns = [re.compile(fp, re.IGNORECASE) for fp in (false_positive_patterns or [])]
        self.pre_filter = pre_filter

    def matches(self, text: str) -> List[re.Match]:
        """Find all matches in text, filtering false positives."""
        matches = []
        for m in self.compiled.finditer(text):
            candidate = m.group(0)
            # Pre-filter if provided
            if self.pre_filter and not self.pre_filter(candidate):
                continue
            # False positive check
            if self._is_false_positive(candidate):
                continue
            # Entropy check
            if self.entropy_threshold is not None:
                ent = shannon_entropy(candidate)
                if ent < self.entropy_threshold:
                    continue
            matches.append(m)
        return matches

    def _is_false_positive(self, candidate: str) -> bool:
        """Check if candidate matches any false positive pattern."""
        for fp in self.false_positive_patterns:
            if fp.search(candidate):
                return True
        return False


# ------------------------ Entropy Utility ------------------------------

def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string (base 2).
    """
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ------------------------ Default Patterns ------------------------------

# Commonly used false positive values
COMMON_FALSE_POSITIVES = [
    r"example", r"test", r"fake", r"placeholder", r"changeme",
    r"your-", r"your_", r"xxxx", r"***", r"TODO", r"FIXME",
]

# AWS
AWS_ACCESS_KEY_PATTERN = r"AKIA[0-9A-Z]{16}"
AWS_SECRET_KEY_PATTERN = r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
# Azure
AZURE_KEY_PATTERN = r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])"
# GCP
GCP_KEY_PATTERN = r"AIza[0-9A-Za-z\-_]{35}"
# GitHub Token
GITHUB_TOKEN_PATTERN = r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
# GitLab Token
GITLAB_TOKEN_PATTERN = r"glpat-[A-Za-z0-9\-_]{20}"
# OpenAI
OPENAI_KEY_PATTERN = r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"
# Anthropic
ANTHROPIC_KEY_PATTERN = r"sk-ant-api\d+-[A-Za-z0-9\-_]{48}-[A-Za-z0-9\-_]{16}"
# Google API
GOOGLE_API_KEY_PATTERN = r"AIza[0-9A-Za-z\-_]{35}"
# Stripe
STRIPE_KEY_PATTERN = r"(sk|pk)_(test|live)_[0-9A-Za-z]{24}"
# Twilio
TWILIO_TOKEN_PATTERN = r"SK[0-9a-fA-F]{32}"
# JWT (simplified)
JWT_PATTERN = r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
# Bearer Token (generic)
BEARER_TOKEN_PATTERN = r"Bearer\s+[a-zA-Z0-9\-_]+"
# Private Key (PEM)
PRIVATE_KEY_PATTERN = r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
# SSH Key
SSH_KEY_PATTERN = r"ssh-(rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]+[=]{0,3}"
# Database URL
DB_URL_PATTERN = r"(postgresql|mysql|mongodb|redis|sqlite)://[^:\s]+:[^@\s]+@[^/\s]+"
# Webhook secret (typical random hex)
WEBHOOK_SECRET_PATTERN = r"(webhook|hook)_secret[=:]\s*[a-f0-9]{32,64}"
# Session token (generic)
SESSION_TOKEN_PATTERN = r"session[=:]\s*[a-zA-Z0-9\-_]{20,}"
# Password (weak pattern)
PASSWORD_PATTERN = r"password[=:]\s*[^\s,;]+"

# Build default patterns
DEFAULT_PATTERNS = [
    SecretPattern(SecretType.AWS_ACCESS_KEY, AWS_ACCESS_KEY_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.AWS_SECRET_KEY, AWS_SECRET_KEY_PATTERN, Severity.CRITICAL,
                  entropy_threshold=4.5, false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.AZURE_KEY, AZURE_KEY_PATTERN, Severity.HIGH,
                  entropy_threshold=4.0, false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.GCP_KEY, GCP_KEY_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.GITHUB_TOKEN, GITHUB_TOKEN_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.GITLAB_TOKEN, GITLAB_TOKEN_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.OPENAI_KEY, OPENAI_KEY_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.ANTHROPIC_KEY, ANTHROPIC_KEY_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.GOOGLE_API_KEY, GOOGLE_API_KEY_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.STRIPE_KEY, STRIPE_KEY_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.TWILIO_TOKEN, TWILIO_TOKEN_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.JWT_TOKEN, JWT_PATTERN, Severity.MEDIUM,
                  entropy_threshold=4.0, false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.BEARER_TOKEN, BEARER_TOKEN_PATTERN, Severity.MEDIUM,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.PRIVATE_KEY, PRIVATE_KEY_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.SSH_KEY, SSH_KEY_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.DATABASE_URL, DB_URL_PATTERN, Severity.CRITICAL,
                  false_positive_patterns=COMMON_FALSE_POSITIVES + [r"localhost", r"127.0.0.1"]),
    SecretPattern(SecretType.WEBHOOK_SECRET, WEBHOOK_SECRET_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.SESSION_TOKEN, SESSION_TOKEN_PATTERN, Severity.MEDIUM,
                  entropy_threshold=3.5, false_positive_patterns=COMMON_FALSE_POSITIVES),
    SecretPattern(SecretType.PASSWORD, PASSWORD_PATTERN, Severity.HIGH,
                  false_positive_patterns=COMMON_FALSE_POSITIVES),
]


# ------------------------ Detector Class ------------------------------

class SecretDetector:
    """
    Main secret detection engine.
    Thread-safe, supports async and streaming.
    """
    def __init__(
        self,
        patterns: Optional[List[SecretPattern]] = None,
        metrics: Optional[Metrics] = None,
        event_bus: Optional[EventBus] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.patterns = patterns or DEFAULT_PATTERNS.copy()
        self.metrics = metrics
        self.event_bus = event_bus
        self.config = config or {}
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

        # Cache for entropy to avoid recomputation
        self._entropy_cache: Dict[str, float] = {}
        self._cache_max = self.config.get("entropy_cache_max", 10000)

    # -------------------- Core Scanning ------------------------------

    def scan(self, text: str, context: Optional[Context] = None) -> DetectionResult:
        """
        Scan a text for secrets. Returns a DetectionResult.
        """
        with self._lock:
            secrets = []
            # Process each pattern
            for pattern in self.patterns:
                matches = pattern.matches(text)
                for m in matches:
                    value = m.group(0)
                    entropy = self._get_entropy(value)
                    # Determine confidence based on entropy and pattern specificity
                    confidence = 0.8
                    if pattern.entropy_threshold is not None:
                        # Boost confidence if entropy is significantly above threshold
                        if entropy > pattern.entropy_threshold + 1.0:
                            confidence = 0.95
                        elif entropy > pattern.entropy_threshold:
                            confidence = 0.85
                    # line number: if text has newlines, compute line
                    line_no = text[:m.start()].count('\n') + 1
                    secret = Secret(
                        type=pattern.secret_type,
                        value=value,
                        line=line_no,
                        start=m.start(),
                        end=m.end(),
                        entropy=entropy,
                        confidence=confidence,
                        severity=pattern.severity,
                        recommendation=self._recommendation(pattern.severity),
                    )
                    secrets.append(secret)

            # Remove duplicates (same value, same type) - keep highest confidence
            unique = {}
            for s in secrets:
                key = (s.type, s.value)
                if key not in unique or s.confidence > unique[key].confidence:
                    unique[key] = s
            secrets = list(unique.values())

            # Sort by severity and confidence
            secrets.sort(key=lambda s: (s.severity.value, s.confidence), reverse=True)

            result = DetectionResult(
                secrets=secrets,
                total_count=len(secrets),
                high_confidence_count=sum(1 for s in secrets if s.confidence >= 0.8),
                total_entropy=sum(s.entropy for s in secrets)
            )

            self._emit_metrics(result, text)
            self._emit_event(result, text)
            return result

    def find(self, text: str, context: Optional[Context] = None) -> List[Secret]:
        """
        Return list of detected secrets (without result wrapper).
        """
        result = self.scan(text, context)
        return result.secrets

    def mask(self, text: str, context: Optional[Context] = None) -> str:
        """
        Return the text with all detected secrets masked.
        """
        secrets = self.find(text, context)
        # Sort by start index descending to avoid offset issues
        secrets.sort(key=lambda s: s.start, reverse=True)
        masked = text
        for s in secrets:
            masked = masked[:s.start] + s.masked_value + masked[s.end:]
        return masked

    def redact(self, text: str, context: Optional[Context] = None) -> str:
        """
        Return text with all detected secrets removed (replaced with [REDACTED]).
        """
        secrets = self.find(text, context)
        secrets.sort(key=lambda s: s.start, reverse=True)
        redacted = text
        for s in secrets:
            redacted = redacted[:s.start] + "[REDACTED]" + redacted[s.end:]
        return redacted

    def entropy_score(self, value: str) -> float:
        """
        Compute entropy of a string (cached).
        """
        return self._get_entropy(value)

    # -------------------- Streaming / File Scan ------------------------------

    def scan_stream(self, stream: Generator[str, None, None], context: Optional[Context] = None) -> Generator[Secret, None, None]:
        """
        Stream scan: process a generator of lines/chunks and yield secrets as they are found.
        """
        for chunk in stream:
            secrets = self.find(chunk, context)
            for s in secrets:
                yield s

    async def scan_stream_async(self, stream: Generator[str, None, None], context: Optional[Context] = None) -> AsyncGenerator[Secret, None]:
        """
        Async streaming scan.
        """
        for chunk in stream:
            secrets = await self.find_async(chunk, context)
            for s in secrets:
                yield s

    # -------------------- Async Methods ------------------------------

    async def scan_async(self, text: str, context: Optional[Context] = None) -> DetectionResult:
        """Asynchronous version of scan."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.scan, text, context)

    async def find_async(self, text: str, context: Optional[Context] = None) -> List[Secret]:
        """Asynchronous version of find."""
        result = await self.scan_async(text, context)
        return result.secrets

    async def mask_async(self, text: str, context: Optional[Context] = None) -> str:
        """Asynchronous version of mask."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.mask, text, context)

    async def redact_async(self, text: str, context: Optional[Context] = None) -> str:
        """Asynchronous version of redact."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.redact, text, context)

    # -------------------- Helpers ------------------------------

    def _get_entropy(self, value: str) -> float:
        """Get entropy with caching."""
        if value in self._entropy_cache:
            return self._entropy_cache[value]
        ent = shannon_entropy(value)
        if len(self._entropy_cache) < self._cache_max:
            self._entropy_cache[value] = ent
        return ent

    def _recommendation(self, severity: Severity) -> str:
        if severity == Severity.CRITICAL:
            return "Immediately revoke and rotate this secret; investigate potential exposure."
        elif severity == Severity.HIGH:
            return "Review and rotate this secret if valid; consider reducing permissions."
        elif severity == Severity.MEDIUM:
            return "Flag for review; ensure this secret is not exposed in production."
        else:
            return "Monitor for further occurrences."

    def _emit_metrics(self, result: DetectionResult, text: str) -> None:
        if self.metrics:
            self.metrics.increment_counter("secret_detector.scans")
            self.metrics.gauge("secret_detector.secrets_found", result.total_count)
            self.metrics.gauge("secret_detector.high_confidence", result.high_confidence_count)
            self.metrics.gauge("secret_detector.total_entropy", result.total_entropy)

    def _emit_event(self, result: DetectionResult, text: str) -> None:
        if self.event_bus and result.secrets:
            for s in result.secrets:
                self.event_bus.emit(Event(
                    type="secret_detector.detected",
                    payload={
                        "type": s.type.value,
                        "severity": s.severity.value,
                        "confidence": s.confidence,
                        "entropy": s.entropy,
                        "preview": s.value[:10] + "..." if len(s.value) > 10 else s.value,
                    }
                ))


# ------------------------ Global Default Instance --------------------

_default_detector: Optional[SecretDetector] = None
_default_detector_lock = threading.Lock()


def get_default_detector() -> SecretDetector:
    """Get or create the default secret detector."""
    global _default_detector
    if _default_detector is None:
        with _default_detector_lock:
            if _default_detector is None:
                _default_detector = SecretDetector()
    return _default_detector


# ------------------------ Public Functions ------------------------------

def scan(text: str, context: Optional[Context] = None) -> DetectionResult:
    """Scan text for secrets using default detector."""
    return get_default_detector().scan(text, context)


def find(text: str, context: Optional[Context] = None) -> List[Secret]:
    """Find secrets in text."""
    return get_default_detector().find(text, context)


def mask(text: str, context: Optional[Context] = None) -> str:
    """Mask secrets in text."""
    return get_default_detector().mask(text, context)


def redact(text: str, context: Optional[Context] = None) -> str:
    """Redact secrets in text."""
    return get_default_detector().redact(text, context)


def entropy_score(value: str) -> float:
    """Compute entropy of a string."""
    return get_default_detector().entropy_score(value)


async def scan_async(text: str, context: Optional[Context] = None) -> DetectionResult:
    """Async scan for secrets."""
    return await get_default_detector().scan_async(text, context)


async def find_async(text: str, context: Optional[Context] = None) -> List[Secret]:
    """Async find secrets."""
    return await get_default_detector().find_async(text, context)


async def mask_async(text: str, context: Optional[Context] = None) -> str:
    """Async mask secrets."""
    return await get_default_detector().mask_async(text, context)


async def redact_async(text: str, context: Optional[Context] = None) -> str:
    """Async redact secrets."""
    return await get_default_detector().redact_async(text, context)


# ------------------------ Customization ------------------------------

def add_pattern(pattern: SecretPattern) -> None:
    """Add a custom secret pattern to the default detector."""
    get_default_detector().patterns.append(pattern)
