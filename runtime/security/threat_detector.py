# runtime/security/threat_detector.py
"""
Threat Detection Engine for Secure Runtime

Detects common web and application security threats using regex-based signatures,
with support for custom rules, YARA (future), and async/thread-safe execution.

Threat types:
- SQL Injection
- Cross Site Scripting (XSS)
- Command Injection
- Remote Code Execution (RCE)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Path Traversal
- Template Injection
- Header Injection
- Host Header Attack
- Open Redirect
- CRLF Injection
- LDAP Injection
- NoSQL Injection
- Regex DoS
- Deserialization Attacks
- WebShell Detection
- Malicious Payload Detection
"""

import asyncio
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

# Existing core imports (do not redefine)
from runtime.core.context import Context
from runtime.core.metrics import Metrics
from runtime.core.events import EventBus, Event
from runtime.core.errors import Error as CoreError
from runtime.core.config import Config

logger = logging.getLogger(__name__)


# ------------------------ Exceptions ------------------------------

class ThreatDetectionError(CoreError):
    """Base exception for threat detection errors."""
    pass


# ------------------------ Enums ------------------------------

class ThreatType(Enum):
    """Types of detected threats."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"
    TEMPLATE_INJECTION = "template_injection"
    HEADER_INJECTION = "header_injection"
    HOST_HEADER_ATTACK = "host_header_attack"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    LDAP_INJECTION = "ldap_injection"
    NOSQL_INJECTION = "nosql_injection"
    REGEX_DOS = "regex_dos"
    DESERIALIZATION = "deserialization"
    WEBSHELL = "webshell"
    MALICIOUS_PAYLOAD = "malicious_payload"
    OTHER = "other"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ------------------------ Models ------------------------------

@dataclass
class ThreatSignature:
    """
    A detection rule/signature.
    """
    id: str
    threat_type: ThreatType
    severity: Severity
    pattern: str                       # regex pattern
    description: str = ""
    recommendation: str = ""
    compiled: Optional[re.Pattern] = field(default=None, init=False)
    # optional custom evaluator
    evaluator: Optional[Callable[[str, Context], bool]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.pattern:
            try:
                self.compiled = re.compile(self.pattern, re.IGNORECASE | re.UNICODE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern in signature {self.id}: {e}")

    def matches(self, text: str, context: Optional[Context] = None) -> bool:
        """Check if the signature matches the given text."""
        if self.evaluator:
            try:
                return self.evaluator(text, context)
            except Exception as e:
                logger.error(f"Error in custom evaluator for {self.id}: {e}")
                return False
        if self.compiled:
            return bool(self.compiled.search(text))
        return False


@dataclass
class ThreatResult:
    """
    Result of a threat detection scan.
    """
    threat_type: ThreatType
    severity: Severity
    confidence: float                   # 0.0 to 1.0
    risk_score: float                   # 0.0 to 1.0
    description: str
    recommendation: str
    matched_pattern: Optional[str] = None
    matched_signature_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ------------------------ Default Signatures ------------------------------

# SQL Injection
SQLI_PATTERNS = [
    r"(?i)(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|\binsert\b.*\binto\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b)",
    r"(?i)(\b(or|and)\s+\d+\s*=\s*\d+|\b(or|and)\s+'.*?'\s*=\s*'.*?')",
    r"(?i)(--\s*|#|\bexec\b|\bexecute\b|\bxp_cmdshell\b)",
]

# XSS
XSS_PATTERNS = [
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)on\w+\s*=\s*['\"]?[^'\">]*",
    r"(?i)javascript\s*:",
    r"(?i)<iframe[^>]*>.*?</iframe>",
    r"(?i)<img[^>]*src\s*=\s*['\"]?[^'\">]*['\"]?[^>]*>",
]

# Command Injection
CMD_INJECTION_PATTERNS = [
    r"(?i)(;|\||&|\$\(|`|&&|\|\|)\s*(cat|ls|dir|pwd|whoami|id|uname|ping|netstat|nmap|curl|wget|bash|sh|cmd)",
    r"(?i)(\|\s*(\w+\s*)*\||;\s*(\w+\s*)*;|`\s*\w+\s*`)",
]

# RCE
RCE_PATTERNS = [
    r"(?i)(eval|system|exec|popen|shell_exec|passthru|proc_open|pcntl_exec|assert)\s*\(",
    r"(?i)(include|require|include_once|require_once)\s*\(?\s*['\"][^'\"]+['\"]\s*\)?",
]

# LFI/RFI
LFI_RFI_PATTERNS = [
    r"(?i)(file://|php://|zip://|phar://|expect://|data://|gopher://|dict://)",
    r"(?i)(\.\./|\.\.\\)",
]

# SSRF
SSRF_PATTERNS = [
    r"(?i)(http://|https://|ftp://|gopher://|dict://|file://)[\w\.\-]+",
    r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
]

# XXE
XXE_PATTERNS = [
    r"(?i)<!DOCTYPE[^>]*<!ENTITY[^>]*SYSTEM[^>]*>",
    r"(?i)<!ENTITY[^>]*SYSTEM[^>]*>",
]

# Path Traversal
PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\./|\.\.\\)",
    r"(?i)/etc/passwd|/etc/shadow|c:\\windows\\system32|/proc/self/environ",
]

# Template Injection (SSTI)
TEMPLATE_INJECTION_PATTERNS = [
    r"(?i)\{\{.*\}\}|<%=\s*.*\s*%>|\${.*}|#\{.*\}",
]

# Header Injection
HEADER_INJECTION_PATTERNS = [
    r"(?i)\r?\n\s*[a-zA-Z-]+:",   # newline followed by header
]

# Host Header Attack
HOST_HEADER_ATTACK_PATTERNS = [
    r"(?i)^(www\.)?[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$",  # weak
    r"(?i)localhost|127\.0\.0\.1|0\.0\.0\.0",
]

# Open Redirect
OPEN_REDIRECT_PATTERNS = [
    r"(?i)(redirect|return|next|goto|url|target|dest|destination)\s*=\s*(https?://|//|\/\/)?[^/\s]+",
]

# CRLF Injection
CRLF_INJECTION_PATTERNS = [
    r"(?i)\r?\n\r?\n",
    r"(?i)%0d%0a",
]

# LDAP Injection
LDAP_INJECTION_PATTERNS = [
    r"(?i)(\*|\(|\)|\\|&|\||\||!|=|~|>|<|@|#|$|%)",
]

# NoSQL Injection
NOSQL_INJECTION_PATTERNS = [
    r"(?i)(\$ne|\$gt|\$lt|\$eq|\$in|\$nin|\$or|\$and|\$not|\$exists|\$type|\$regex|\$where|\$func)",
]

# Regex DoS
REGEX_DOS_PATTERNS = [
    r"(?i)(\w+\s*\+\s*)+",  # simplistic
]

# Deserialization
DESERIALIZATION_PATTERNS = [
    r"(?i)(O:\d+:" r"|C:\d+:" r"|rO0|a:\d+:\{)",  # PHP/Java
]

# WebShell
WEBSHELL_PATTERNS = [
    r"(?i)(eval|system|exec|passthru|shell_exec)\s*\([\s\S]*?\)",
    r"(?i)<\?(php|=)\s*(eval|system|exec)",
    r"(?i)base64_decode\s*\([\s\S]*?\)",
]

# Malicious Payload (generic)
MALICIOUS_PAYLOAD_PATTERNS = [
    r"(?i)(wget|curl|nc|netcat|python -c|perl -e|ruby -e|php -r)",
]


def _build_default_signatures() -> List[ThreatSignature]:
    signatures = []
    id_counter = 1

    def add_sigs(threat_type, severity, patterns, description, recommendation=""):
        nonlocal id_counter
        for pattern in patterns:
            sig_id = f"THR-{id_counter:04d}"
            sig = ThreatSignature(
                id=sig_id,
                threat_type=threat_type,
                severity=severity,
                pattern=pattern,
                description=description,
                recommendation=recommendation or f"Review for {threat_type.value.replace('_',' ')}",
            )
            signatures.append(sig)
            id_counter += 1

    # Add all signatures
    add_sigs(ThreatType.SQL_INJECTION, Severity.CRITICAL, SQLI_PATTERNS,
             "SQL injection pattern detected")
    add_sigs(ThreatType.XSS, Severity.HIGH, XSS_PATTERNS,
             "Cross-site scripting pattern detected")
    add_sigs(ThreatType.COMMAND_INJECTION, Severity.CRITICAL, CMD_INJECTION_PATTERNS,
             "Command injection pattern detected")
    add_sigs(ThreatType.RCE, Severity.CRITICAL, RCE_PATTERNS,
             "Remote code execution pattern detected")
    add_sigs(ThreatType.LFI, Severity.HIGH, LFI_RFI_PATTERNS,
             "Local/Remote file inclusion pattern detected")
    add_sigs(ThreatType.RFI, Severity.HIGH, LFI_RFI_PATTERNS,
             "Remote file inclusion pattern detected")
    add_sigs(ThreatType.SSRF, Severity.HIGH, SSRF_PATTERNS,
             "Server-side request forgery pattern detected")
    add_sigs(ThreatType.XXE, Severity.CRITICAL, XXE_PATTERNS,
             "XML external entity pattern detected")
    add_sigs(ThreatType.PATH_TRAVERSAL, Severity.HIGH, PATH_TRAVERSAL_PATTERNS,
             "Path traversal pattern detected")
    add_sigs(ThreatType.TEMPLATE_INJECTION, Severity.HIGH, TEMPLATE_INJECTION_PATTERNS,
             "Template injection pattern detected")
    add_sigs(ThreatType.HEADER_INJECTION, Severity.MEDIUM, HEADER_INJECTION_PATTERNS,
             "HTTP header injection pattern detected")
    add_sigs(ThreatType.HOST_HEADER_ATTACK, Severity.MEDIUM, HOST_HEADER_ATTACK_PATTERNS,
             "Host header attack pattern detected")
    add_sigs(ThreatType.OPEN_REDIRECT, Severity.MEDIUM, OPEN_REDIRECT_PATTERNS,
             "Open redirect pattern detected")
    add_sigs(ThreatType.CRLF_INJECTION, Severity.MEDIUM, CRLF_INJECTION_PATTERNS,
             "CRLF injection pattern detected")
    add_sigs(ThreatType.LDAP_INJECTION, Severity.HIGH, LDAP_INJECTION_PATTERNS,
             "LDAP injection pattern detected")
    add_sigs(ThreatType.NOSQL_INJECTION, Severity.HIGH, NOSQL_INJECTION_PATTERNS,
             "NoSQL injection pattern detected")
    add_sigs(ThreatType.REGEX_DOS, Severity.MEDIUM, REGEX_DOS_PATTERNS,
             "Regex Denial of Service pattern detected")
    add_sigs(ThreatType.DESERIALIZATION, Severity.CRITICAL, DESERIALIZATION_PATTERNS,
             "Deserialization attack pattern detected")
    add_sigs(ThreatType.WEBSHELL, Severity.CRITICAL, WEBSHELL_PATTERNS,
             "WebShell pattern detected")
    add_sigs(ThreatType.MALICIOUS_PAYLOAD, Severity.HIGH, MALICIOUS_PAYLOAD_PATTERNS,
             "Malicious payload pattern detected")

    return signatures


# ------------------------ Analyzer and Scanner ------------------------------

class ThreatAnalyzer:
    """
    Analyzes a single input against signatures and produces threat results.
    """
    def __init__(self, signatures: List[ThreatSignature]):
        self.signatures = signatures

    def analyze(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Analyze text and return list of threats."""
        results = []
        for sig in self.signatures:
            if sig.matches(text, context):
                # Calculate confidence: if compiled regex matched, high confidence.
                # Could be improved with more logic.
                confidence = 0.9
                if sig.evaluator:
                    confidence = 0.95
                risk_score = self._calculate_risk(sig.severity, confidence)
                result = ThreatResult(
                    threat_type=sig.threat_type,
                    severity=sig.severity,
                    confidence=confidence,
                    risk_score=risk_score,
                    description=sig.description,
                    recommendation=sig.recommendation or f"Mitigate {sig.threat_type.value}",
                    matched_pattern=sig.pattern,
                    matched_signature_id=sig.id,
                )
                results.append(result)
        return results

    def _calculate_risk(self, severity: Severity, confidence: float) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_weights = {
            Severity.LOW: 0.2,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.8,
            Severity.CRITICAL: 1.0,
        }
        base = severity_weights.get(severity, 0.5)
        # combine: risk = severity_weight * confidence
        return min(1.0, base * confidence * 1.1)  # slight boost


class ThreatScanner:
    """
    Scans data (string, file, stream) using multiple analyzers.
    """
    def __init__(self, signatures: List[ThreatSignature]):
        self.signatures = signatures

    def scan(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Scan text and return all detected threats."""
        analyzer = ThreatAnalyzer(self.signatures)
        return analyzer.analyze(text, context)

    def scan_stream(self, stream, context: Optional[Context] = None):
        """Scan a stream of text chunks (generator)."""
        for chunk in stream:
            results = self.scan(chunk, context)
            for r in results:
                yield r


# ------------------------ Main ThreatDetector ------------------------------

class ThreatDetector:
    """
    Main threat detection engine.
    Supports rule loading, reloading, async, thread-safe.
    """
    def __init__(
        self,
        signatures: Optional[List[ThreatSignature]] = None,
        metrics: Optional[Metrics] = None,
        event_bus: Optional[EventBus] = None,
        config: Optional[Config] = None,
    ):
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
        self.metrics = metrics
        self.event_bus = event_bus
        self.config = config

        self._signatures = signatures or _build_default_signatures()
        self._scanner = ThreatScanner(self._signatures)
        self._file_loads: Dict[str, Path] = {}  # track loaded files for reload

    # -------------------- Core Detection ------------------------------

    def detect(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Detect threats in text."""
        with self._lock:
            return self._scanner.scan(text, context)

    def analyze(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Alias for detect."""
        return self.detect(text, context)

    def scan(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Alias for detect."""
        return self.detect(text, context)

    def calculate_risk(self, results: List[ThreatResult]) -> float:
        """
        Calculate overall risk score from a list of threat results.
        Takes highest risk score, adjusted by count.
        """
        if not results:
            return 0.0
        # Max risk
        max_risk = max(r.risk_score for r in results)
        # Slight boost for multiple threats
        count_boost = min(1.0, 0.1 * len(results))
        return min(1.0, max_risk + count_boost * (1 - max_risk))

    # -------------------- Rule Management ------------------------------

    def load_rules(self, source: Union[str, Path, Dict[str, Any]]) -> int:
        """
        Load rules from a file (JSON/YAML) or dict.
        Returns number of signatures loaded.
        """
        with self._lock:
            if isinstance(source, (str, Path)):
                path = Path(source)
                if not path.exists():
                    raise FileNotFoundError(f"Rules file not found: {path}")
                with open(path, 'r') as f:
                    if path.suffix.lower() in ('.yaml', '.yml'):
                        import yaml
                        data = yaml.safe_load(f)
                    else:
                        data = json.load(f)
                # Remember for reload
                self._file_loads[path.name] = path
            elif isinstance(source, dict):
                data = source
            else:
                raise TypeError("source must be file path or dict")

            signatures = self._parse_rules(data)
            # Replace or extend? We'll replace to avoid duplication.
            self._signatures = signatures
            self._scanner = ThreatScanner(self._signatures)
            logger.info(f"Loaded {len(signatures)} threat signatures")
            return len(signatures)

    def reload_rules(self) -> int:
        """Reload all previously loaded rule files."""
        total = 0
        for name, path in list(self._file_loads.items()):
            try:
                total += self.load_rules(path)
            except Exception as e:
                logger.error(f"Failed to reload rules from {path}: {e}")
        return total

    def _parse_rules(self, data: Dict[str, Any]) -> List[ThreatSignature]:
        """
        Parse rule definitions from dict.
        Expected format:
        {
            "rules": [
                {
                    "id": "CUSTOM-001",
                    "threat_type": "sql_injection",
                    "severity": "critical",
                    "pattern": "(?i)select.*from",
                    "description": "...",
                    "recommendation": "..."
                }
            ]
        }
        """
        signatures = []
        rules_data = data.get('rules', [])
        for item in rules_data:
            threat_type_str = item.get('threat_type')
            try:
                threat_type = ThreatType(threat_type_str)
            except ValueError:
                raise ValueError(f"Invalid threat_type: {threat_type_str}")
            severity_str = item.get('severity')
            try:
                severity = Severity(severity_str.lower())
            except ValueError:
                raise ValueError(f"Invalid severity: {severity_str}")

            sig = ThreatSignature(
                id=item.get('id', f"CUSTOM-{len(signatures)+1:04d}"),
                threat_type=threat_type,
                severity=severity,
                pattern=item['pattern'],
                description=item.get('description', ''),
                recommendation=item.get('recommendation', ''),
                metadata=item.get('metadata', {}),
            )
            signatures.append(sig)
        return signatures

    # -------------------- Async Methods ------------------------------

    async def detect_async(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Async detect."""
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.detect, text, context)

    async def analyze_async(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Async analyze."""
        return await self.detect_async(text, context)

    async def scan_async(self, text: str, context: Optional[Context] = None) -> List[ThreatResult]:
        """Async scan."""
        return await self.detect_async(text, context)

    async def load_rules_async(self, source: Union[str, Path, Dict[str, Any]]) -> int:
        """Async load rules."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.load_rules, source)

    async def reload_rules_async(self) -> int:
        """Async reload rules."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.reload_rules)

    # -------------------- Event / Metrics ------------------------------

    def _emit_metrics(self, results: List[ThreatResult], text: str) -> None:
        if self.metrics:
            for r in results:
                self.metrics.increment_counter(
                    "threat_detector.detections",
                    tags={"threat_type": r.threat_type.value, "severity": r.severity.value}
                )
            if results:
                self.metrics.gauge("threat_detector.risk_score", self.calculate_risk(results))

    def _emit_event(self, results: List[ThreatResult], text: str) -> None:
        if self.event_bus:
            for r in results:
                self.event_bus.emit(Event(
                    type="threat_detector.threat_detected",
                    payload={
                        "threat_type": r.threat_type.value,
                        "severity": r.severity.value,
                        "confidence": r.confidence,
                        "risk_score": r.risk_score,
                        "description": r.description,
                    }
                ))


# ------------------------ Global Default Instance -------------------------

_default_detector: Optional[ThreatDetector] = None
_default_detector_lock = threading.Lock()


def get_default_detector() -> ThreatDetector:
    """Get or create the default threat detector."""
    global _default_detector
    if _default_detector is None:
        with _default_detector_lock:
            if _default_detector is None:
                _default_detector = ThreatDetector()
    return _default_detector


# ------------------------ Public API -------------------------------------

def detect(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Detect threats in text using default detector."""
    return get_default_detector().detect(text, context)


def analyze(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Alias for detect."""
    return detect(text, context)


def scan(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Alias for detect."""
    return detect(text, context)


def calculate_risk(results: List[ThreatResult]) -> float:
    """Calculate overall risk score."""
    return get_default_detector().calculate_risk(results)


def load_rules(source: Union[str, Path, Dict[str, Any]]) -> int:
    """Load rules into default detector."""
    return get_default_detector().load_rules(source)


def reload_rules() -> int:
    """Reload rules in default detector."""
    return get_default_detector().reload_rules()


async def detect_async(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Async detect."""
    return await get_default_detector().detect_async(text, context)


async def analyze_async(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Async analyze."""
    return await detect_async(text, context)


async def scan_async(text: str, context: Optional[Context] = None) -> List[ThreatResult]:
    """Async scan."""
    return await detect_async(text, context)


async def load_rules_async(source: Union[str, Path, Dict[str, Any]]) -> int:
    """Async load rules."""
    return await get_default_detector().load_rules_async(source)


async def reload_rules_async() -> int:
    """Async reload rules."""
    return await get_default_detector().reload_rules_async()
