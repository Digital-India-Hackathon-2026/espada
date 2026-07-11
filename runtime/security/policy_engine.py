# runtime/security/policy_engine.py
"""
Secure Runtime Policy Engine

Provides a comprehensive policy evaluation framework supporting multiple
policy sources, rule evaluation, and extensible actions.

All policies are evaluated against an incoming request context.
"""

import asyncio
import json
import logging
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union
import yaml

# Import existing core models (do not redefine)
from runtime.core.context import Context
from runtime.core.request import Request
from runtime.core.response import Response
from runtime.core.errors import PolicyError
from runtime.core.config import Config
from runtime.core.metrics import Metrics
from runtime.core.events import Event, EventBus

logger = logging.getLogger(__name__)


# ------------------------ Enums & Constants ------------------------------

class Action(Enum):
    """Policy decision actions."""
    ALLOW = auto()
    BLOCK = auto()
    WARN = auto()
    CHALLENGE = auto()
    MONITOR = auto()
    RATE_LIMIT = auto()
    QUARANTINE = auto()
    LOG_ONLY = auto()


# ------------------------ Policy Components ------------------------------

@dataclass
class PolicyRule:
    """
    A single rule within a policy.
    Condition: dict or callable that evaluates to bool.
    Action: the action to take if condition matches.
    Priority: higher priority rules evaluated first (default 0).
    """
    condition: Union[Dict[str, Any], Callable[[Request, Context], bool]]
    action: Action
    priority: int = 0
    name: Optional[str] = None
    description: str = ""

    def evaluate(self, request: Request, context: Context) -> bool:
        """Evaluate the rule condition."""
        if callable(self.condition):
            return self.condition(request, context)
        # Dict-based condition
        return ConditionEvaluator.evaluate(self.condition, request, context)


@dataclass
class Policy:
    """
    A policy containing multiple rules.
    Supports inheritance (extends) and priority ordering.
    """
    name: str
    version: str = "1.0"
    rules: List[PolicyRule] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    extends: Optional[str] = None          # name of parent policy
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Ensure rules are sorted by priority descending
        self.rules.sort(key=lambda r: r.priority, reverse=True)


@dataclass
class PolicyDecision:
    """
    Result of evaluating a policy set.
    """
    action: Action
    matched_policy: Optional[str] = None
    matched_rule: Optional[str] = None
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ------------------------ Condition Evaluator ----------------------------

class ConditionEvaluator:
    """
    Evaluates condition dictionaries against a request and context.
    Supports nested field access, operators, and logical combinators.
    """

    OPERATORS = {
        'eq': lambda a, b: a == b,
        'ne': lambda a, b: a != b,
        'gt': lambda a, b: a > b,
        'ge': lambda a, b: a >= b,
        'lt': lambda a, b: a < b,
        'le': lambda a, b: a <= b,
        'in': lambda a, b: a in b,
        'not_in': lambda a, b: a not in b,
        'contains': lambda a, b: b in a if hasattr(a, '__contains__') else False,
        'not_contains': lambda a, b: b not in a if hasattr(a, '__contains__') else True,
        'regex': lambda a, b: re.match(b, str(a)) is not None,
        'match': lambda a, b: str(a) == str(b),  # alias for eq
        'startswith': lambda a, b: str(a).startswith(str(b)),
        'endswith': lambda a, b: str(a).endswith(str(b)),
    }

    @classmethod
    def evaluate(cls, condition: Dict[str, Any], request: Request, context: Context) -> bool:
        """
        Evaluate a condition dict.

        Supported forms:
        - {"field": "request.ip", "operator": "eq", "value": "127.0.0.1"}
        - {"and": [cond1, cond2]} or {"or": [cond1, cond2]}
        - {"not": cond}
        - {"field": "request.headers.user-agent", "operator": "contains", "value": "Bot"}
        """
        if not isinstance(condition, dict):
            # If condition is not a dict, treat as boolean value or callable handled separately
            return bool(condition)

        # Logical combinators
        if 'and' in condition:
            return all(cls.evaluate(sub, request, context) for sub in condition['and'])
        if 'or' in condition:
            return any(cls.evaluate(sub, request, context) for sub in condition['or'])
        if 'not' in condition:
            return not cls.evaluate(condition['not'], request, context)

        # Simple condition: field, operator, value
        field = condition.get('field')
        op = condition.get('operator')
        value = condition.get('value')

        if not field or not op:
            raise ValueError(f"Invalid condition: missing field or operator: {condition}")

        # Resolve field value from request/context
        actual = cls._resolve_field(field, request, context)

        # Get operator function
        op_func = cls.OPERATORS.get(op.lower())
        if not op_func:
            raise ValueError(f"Unsupported operator: {op}")

        return op_func(actual, value)

    @classmethod
    def _resolve_field(cls, field: str, request: Request, context: Context) -> Any:
        """
        Resolve a dotted field path (e.g., 'request.headers.content-type').
        Falls back to context if not found in request.
        """
        parts = field.split('.')
        obj = None
        if parts[0] == 'request' and len(parts) > 1:
            obj = request
            parts = parts[1:]
        elif parts[0] == 'context':
            obj = context
            parts = parts[1:]
        else:
            # Assume it's a top-level attribute of request or fallback to context
            # Try request first
            if hasattr(request, parts[0]):
                obj = request
            else:
                obj = context

        for attr in parts:
            if obj is None:
                return None
            if isinstance(obj, dict):
                obj = obj.get(attr)
            else:
                obj = getattr(obj, attr, None)
        return obj


# ------------------------ Policy Registry -------------------------------

class PolicyRegistry:
    """
    Thread-safe registry for policies.
    """
    def __init__(self):
        self._policies: Dict[str, Policy] = {}
        self._lock = threading.RLock()

    def register(self, policy: Policy) -> None:
        """Register a policy (overwrites if name exists)."""
        with self._lock:
            self._policies[policy.name] = policy

    def remove(self, name: str) -> bool:
        """Remove a policy by name. Returns True if removed."""
        with self._lock:
            if name in self._policies:
                del self._policies[name]
                return True
            return False

    def get(self, name: str) -> Optional[Policy]:
        """Retrieve a policy by name."""
        with self._lock:
            return self._policies.get(name)

    def list(self) -> List[str]:
        """List all policy names."""
        with self._lock:
            return list(self._policies.keys())

    def all(self) -> List[Policy]:
        """Return all policies."""
        with self._lock:
            return list(self._policies.values())

    def resolve_inheritance(self, policy: Policy) -> List[Policy]:
        """
        Resolve inheritance chain for a policy (parent first, then child).
        Returns list of policies in order (most base to most derived).
        """
        chain = []
        current = policy
        visited = set()
        while current:
            if current.name in visited:
                raise PolicyError(f"Circular inheritance detected for policy {current.name}")
            visited.add(current.name)
            chain.append(current)
            if current.extends:
                parent = self.get(current.extends)
                if not parent:
                    raise PolicyError(f"Parent policy '{current.extends}' not found for '{current.name}'")
                current = parent
            else:
                break
        # Reverse so that base policies come first
        chain.reverse()
        return chain


# ------------------------ Policy Engine --------------------------------

class PolicyEngine:
    """
    Main policy evaluation engine.
    Supports synchronous and asynchronous evaluation, thread-safe.
    """
    def __init__(self, registry: Optional[PolicyRegistry] = None,
                 default_action: Action = Action.ALLOW,
                 config: Optional[Config] = None,
                 metrics: Optional[Metrics] = None,
                 event_bus: Optional[EventBus] = None):
        self.registry = registry or PolicyRegistry()
        self.default_action = default_action
        self.config = config
        self.metrics = metrics
        self.event_bus = event_bus
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

    # -------------------- Synchronous API ------------------------------

    def evaluate(self, request: Request, context: Optional[Context] = None) -> PolicyDecision:
        """
        Evaluate all active policies against the request.
        Policies are evaluated in order of priority (descending).
        For each policy, rules are evaluated in priority order.
        The first matching rule determines the action.
        If no rule matches, default_action is returned.
        """
        context = context or Context()
        policies = self._get_sorted_policies()
        for policy in policies:
            if not policy.enabled:
                continue
            # Resolve inheritance
            chain = self.registry.resolve_inheritance(policy)
            # Evaluate chain from base to derived (rules accumulate? Usually derived overrides)
            # Here we evaluate all rules in all policies in chain, but later policies
            # (derived) may override actions of earlier ones if they match.
            # We'll evaluate in order of chain (base to derived) but we want derived
            # to take precedence, so we should evaluate derived first? Actually, for
            # inheritance, we might want to evaluate all rules and let highest priority
            # rule win, but if derived policy has a rule that matches, it should override.
            # Simpler: evaluate all rules from all policies in chain, sorted by priority,
            # but we also need to consider that derived policy may want to block something
            # even if base allows. So we can evaluate all rules and pick the one with
            # highest priority (rule priority) and also consider that derived policies
            # have higher policy priority? We'll keep it simple: evaluate each policy
            # separately in order of policy priority, and within each policy rules sorted
            # by priority. For inheritance, we can merge rules from base and derived,
            # but derived rules should override base if they have higher priority.
            # For now, we treat each policy independently, but if a policy has extends,
            # we could merge its rules with parent's rules. Instead, we can evaluate
            # each policy in the chain as a separate policy, but the overall decision
            # should be the first matching rule across all policies in priority order.
            # To handle that, we collect all rules from all policies in the chain,
            # and then sort them by (policy priority, rule priority). We'll do that.
            all_rules = []
            for p in chain:
                for rule in p.rules:
                    all_rules.append((p, rule))
            # Sort by policy priority descending, then rule priority descending
            all_rules.sort(key=lambda x: (x[0].priority, x[1].priority), reverse=True)
            for p, rule in all_rules:
                try:
                    if rule.evaluate(request, context):
                        decision = PolicyDecision(
                            action=rule.action,
                            matched_policy=p.name,
                            matched_rule=rule.name or f"rule_{id(rule)}",
                            reason=f"Matched rule in policy {p.name}",
                        )
                        self._record_decision(decision, request, context)
                        return decision
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule} in policy {p.name}: {e}")
                    # Continue to next rule
        # No rule matched
        decision = PolicyDecision(
            action=self.default_action,
            reason="No matching policy rule",
        )
        self._record_decision(decision, request, context)
        return decision

    def _get_sorted_policies(self) -> List[Policy]:
        """Return policies sorted by priority descending."""
        with self._lock:
            policies = self.registry.all()
            policies.sort(key=lambda p: p.priority, reverse=True)
            return policies

    def _record_decision(self, decision: PolicyDecision, request: Request, context: Context) -> None:
        """Record metrics and events for a decision."""
        if self.metrics:
            self.metrics.increment_counter(
                "policy.decisions",
                tags={"action": decision.action.name, "policy": decision.matched_policy or "none"}
            )
        if self.event_bus:
            self.event_bus.emit(Event(
                type="policy.decision",
                payload={
                    "action": decision.action.name,
                    "policy": decision.matched_policy,
                    "rule": decision.matched_rule,
                    "reason": decision.reason,
                }
            ))

    # -------------------- Asynchronous API ------------------------------

    async def evaluate_async(self, request: Request, context: Optional[Context] = None) -> PolicyDecision:
        """Asynchronous version of evaluate."""
        # Use async lock if needed, but evaluation is typically CPU-bound; we can run in thread pool.
        # For simplicity, we run sync evaluate in executor.
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.evaluate, request, context)

    # -------------------- Policy Management ------------------------------

    def register(self, policy: Policy) -> None:
        """Register a policy."""
        with self._lock:
            self.registry.register(policy)

    def remove(self, name: str) -> bool:
        """Remove a policy by name."""
        with self._lock:
            return self.registry.remove(name)

    def list_policies(self) -> List[str]:
        """List all policy names."""
        with self._lock:
            return self.registry.list()

    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a policy by name."""
        with self._lock:
            return self.registry.get(name)

    def validate(self, policy: Union[Policy, Dict[str, Any]]) -> bool:
        """
        Validate a policy structure.
        Returns True if valid, raises PolicyError otherwise.
        """
        if isinstance(policy, dict):
            try:
                policy = self._dict_to_policy(policy)
            except Exception as e:
                raise PolicyError(f"Invalid policy dict: {e}")
        # Basic validation
        if not policy.name:
            raise PolicyError("Policy must have a name")
        if not isinstance(policy.rules, list):
            raise PolicyError("Policy rules must be a list")
        for idx, rule in enumerate(policy.rules):
            if not isinstance(rule, PolicyRule):
                raise PolicyError(f"Rule at index {idx} is not a PolicyRule")
            if not isinstance(rule.action, Action):
                raise PolicyError(f"Rule action must be an Action enum")
        return True

    def _dict_to_policy(self, data: Dict[str, Any]) -> Policy:
        """Convert a dict to Policy object."""
        rules = []
        for rdata in data.get('rules', []):
            # condition can be dict or callable (but callable cannot be serialized)
            condition = rdata.get('condition')
            if isinstance(condition, dict):
                # validate condition structure (optional)
                pass
            action = rdata.get('action')
            if isinstance(action, str):
                action = Action[action.upper()]
            elif not isinstance(action, Action):
                raise ValueError(f"Invalid action: {action}")
            rule = PolicyRule(
                condition=condition,
                action=action,
                priority=rdata.get('priority', 0),
                name=rdata.get('name'),
                description=rdata.get('description', ''),
            )
            rules.append(rule)
        return Policy(
            name=data['name'],
            version=data.get('version', '1.0'),
            rules=rules,
            priority=data.get('priority', 0),
            enabled=data.get('enabled', True),
            extends=data.get('extends'),
            metadata=data.get('metadata', {}),
        )

    # -------------------- Load / Reload ------------------------------

    def load_policy(self, source: Union[str, Path, Dict[str, Any]]) -> Policy:
        """
        Load a policy from a file (JSON/YAML) or a dict.
        Returns the loaded Policy object.
        """
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Policy file not found: {path}")
            with open(path, 'r') as f:
                if path.suffix.lower() in ('.yaml', '.yml'):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
        elif isinstance(source, dict):
            data = source
        else:
            raise TypeError("source must be a file path or dict")

        policy = self._dict_to_policy(data)
        self.validate(policy)
        self.register(policy)
        return policy

    def reload(self) -> None:
        """
        Reload all policies that were loaded from files.
        This requires that we store file paths for each loaded policy.
        For simplicity, we maintain a map of policy name -> file path.
        """
        # We need to track which policies came from files.
        # For this implementation, we'll add a _file_map attribute.
        if not hasattr(self, '_file_map'):
            self._file_map = {}
        # We'll reload each file
        to_reload = list(self._file_map.items())
        for name, path in to_reload:
            try:
                self.load_policy(path)  # will overwrite existing
                logger.info(f"Reloaded policy {name} from {path}")
            except Exception as e:
                logger.error(f"Failed to reload policy {name} from {path}: {e}")

    def load_policy_with_file(self, file_path: Union[str, Path]) -> Policy:
        """
        Load policy and remember the file path for later reload.
        """
        path = Path(file_path)
        policy = self.load_policy(path)
        if not hasattr(self, '_file_map'):
            self._file_map = {}
        self._file_map[policy.name] = path
        return policy


# ------------------------ Global Default Engine -------------------------

_default_engine: Optional[PolicyEngine] = None
_default_engine_lock = threading.Lock()


def get_default_engine() -> PolicyEngine:
    """Get or create the default policy engine."""
    global _default_engine
    if _default_engine is None:
        with _default_engine_lock:
            if _default_engine is None:
                _default_engine = PolicyEngine()
    return _default_engine


# ------------------------ Public API Functions --------------------------

def load_policy(source: Union[str, Path, Dict[str, Any]]) -> Policy:
    """Load a policy into the default engine."""
    engine = get_default_engine()
    return engine.load_policy(source)


def reload() -> None:
    """Reload all file-based policies in the default engine."""
    engine = get_default_engine()
    engine.reload()


def evaluate(request: Request, context: Optional[Context] = None) -> PolicyDecision:
    """Evaluate request against policies in the default engine."""
    engine = get_default_engine()
    return engine.evaluate(request, context)


async def evaluate_async(request: Request, context: Optional[Context] = None) -> PolicyDecision:
    """Asynchronously evaluate request."""
    engine = get_default_engine()
    return await engine.evaluate_async(request, context)


def register(policy: Policy) -> None:
    """Register a policy in the default engine."""
    engine = get_default_engine()
    engine.register(policy)


def remove(name: str) -> bool:
    """Remove a policy by name."""
    engine = get_default_engine()
    return engine.remove(name)


def list_policies() -> List[str]:
    """List all policy names in the default engine."""
    engine = get_default_engine()
    return engine.list_policies()


def validate(policy: Union[Policy, Dict[str, Any]]) -> bool:
    """Validate a policy structure."""
    engine = get_default_engine()
    return engine.validate(policy)


# ------------------------ Plugin Support ------------------------------

class PolicyPlugin(ABC):
    """Abstract base for policy plugins."""
    @abstractmethod
    def load(self) -> Policy:
        """Load a policy."""
        pass

    @abstractmethod
    def should_reload(self) -> bool:
        """Return True if policy should be reloaded."""
        pass


def load_plugin_policy(plugin: PolicyPlugin) -> Policy:
    """Load a policy from a plugin and register it."""
    policy = plugin.load()
    register(policy)
    return policy
