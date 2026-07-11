# runtime/core/metrics.py
"""
Production-Grade Metrics System for Secure Runtime

This module provides comprehensive metrics collection, aggregation, and export
capabilities with support for counters, gauges, histograms, and timers.
"""

import asyncio
import time
import threading
import psutil
import json
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from collections import deque, defaultdict
from functools import wraps
import logging
import math

from pydantic import BaseModel, Field


class MetricType(str, Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class MetricUnit(str, Enum):
    """Units for metrics"""
    COUNT = "count"
    BYTES = "bytes"
    SECONDS = "seconds"
    MILLISECONDS = "milliseconds"
    MICROSECONDS = "microseconds"
    PERCENT = "percent"
    REQUESTS = "requests"
    THREADS = "threads"
    NONE = "none"


@dataclass
class MetricValue:
    """Value of a metric at a point in time"""
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetricSnapshot:
    """Snapshot of a metric's current state"""
    name: str
    type: MetricType
    unit: MetricUnit
    value: float
    labels: Dict[str, str]
    timestamp: float
    min: Optional[float] = None
    max: Optional[float] = None
    count: Optional[int] = None
    sum: Optional[float] = None
    mean: Optional[float] = None
    p50: Optional[float] = None
    p90: Optional[float] = None
    p95: Optional[float] = None
    p99: Optional[float] = None


class Counter:
    """
    Counter metric - only increases
    Thread-safe for concurrent updates
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        unit: MetricUnit = MetricUnit.COUNT,
        labels: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self.description = description
        self.unit = unit
        self._labels = labels or {}
        self._value: float = 0.0
        self._lock = threading.RLock()
        self._history: deque = deque(maxlen=1000)
    
    def increment(self, value: float = 1.0) -> None:
        """Increment counter by value"""
        with self._lock:
            self._value += value
            self._history.append(MetricValue(self._value, time.time(), self._labels))
    
    def reset(self) -> None:
        """Reset counter to zero"""
        with self._lock:
            self._value = 0.0
            self._history.clear()
    
    def value(self) -> float:
        """Get current value"""
        with self._lock:
            return self._value
    
    def snapshot(self) -> MetricSnapshot:
        """Get snapshot of current state"""
        with self._lock:
            return MetricSnapshot(
                name=self.name,
                type=MetricType.COUNTER,
                unit=self.unit,
                value=self._value,
                labels=self._labels.copy(),
                timestamp=time.time(),
                count=int(self._value),
                min=self._value,
                max=self._value,
            )


class Gauge:
    """
    Gauge metric - can increase or decrease
    Thread-safe for concurrent updates
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        unit: MetricUnit = MetricUnit.NONE,
        labels: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self.description = description
        self.unit = unit
        self._labels = labels or {}
        self._value: float = 0.0
        self._lock = threading.RLock()
        self._history: deque = deque(maxlen=1000)
    
    def set(self, value: float) -> None:
        """Set gauge to a specific value"""
        with self._lock:
            self._value = value
            self._history.append(MetricValue(self._value, time.time(), self._labels))
    
    def increment(self, value: float = 1.0) -> None:
        """Increment gauge by value"""
        with self._lock:
            self._value += value
            self._history.append(MetricValue(self._value, time.time(), self._labels))
    
    def decrement(self, value: float = 1.0) -> None:
        """Decrement gauge by value"""
        with self._lock:
            self._value -= value
            self._history.append(MetricValue(self._value, time.time(), self._labels))
    
    def reset(self) -> None:
        """Reset gauge to zero"""
        with self._lock:
            self._value = 0.0
            self._history.clear()
    
    def value(self) -> float:
        """Get current value"""
        with self._lock:
            return self._value
    
    def snapshot(self) -> MetricSnapshot:
        """Get snapshot of current state"""
        with self._lock:
            return MetricSnapshot(
                name=self.name,
                type=MetricType.GAUGE,
                unit=self.unit,
                value=self._value,
                labels=self._labels.copy(),
                timestamp=time.time(),
                min=self._value,
                max=self._value,
            )


class Histogram:
    """
    Histogram metric - records value distributions
    Thread-safe for concurrent updates
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        unit: MetricUnit = MetricUnit.NONE,
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self.description = description
        self.unit = unit
        self._labels = labels or {}
        self._lock = threading.RLock()
        self._values: List[float] = []
        self._max_size = 10000
        self._buckets = buckets or [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0]
        self._bucket_counts: Dict[float, int] = {}
        self._count = 0
        self._sum = 0.0
        self._min = float('inf')
        self._max = float('-inf')
    
    def observe(self, value: float) -> None:
        """Observe a value"""
        with self._lock:
            self._values.append(value)
            if len(self._values) > self._max_size:
                # Remove oldest values if over max
                self._values = self._values[-self._max_size:]
            
            self._count += 1
            self._sum += value
            self._min = min(self._min, value)
            self._max = max(self._max, value)
            
            # Update bucket counts
            for bucket in self._buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] = self._bucket_counts.get(bucket, 0) + 1
    
    def reset(self) -> None:
        """Reset histogram"""
        with self._lock:
            self._values.clear()
            self._bucket_counts.clear()
            self._count = 0
            self._sum = 0.0
            self._min = float('inf')
            self._max = float('-inf')
    
    def snapshot(self) -> MetricSnapshot:
        """Get snapshot of current state"""
        with self._lock:
            sorted_values = sorted(self._values) if self._values else []
            total = len(sorted_values)
            
            def percentile(p: float) -> Optional[float]:
                if not sorted_values:
                    return None
                idx = int(p * total)
                if idx >= total:
                    idx = total - 1
                return sorted_values[idx]
            
            return MetricSnapshot(
                name=self.name,
                type=MetricType.HISTOGRAM,
                unit=self.unit,
                value=self._sum / self._count if self._count > 0 else 0,
                labels=self._labels.copy(),
                timestamp=time.time(),
                min=self._min if self._min != float('inf') else None,
                max=self._max if self._max != float('-inf') else None,
                count=self._count,
                sum=self._sum,
                mean=self._sum / self._count if self._count > 0 else None,
                p50=percentile(0.50),
                p90=percentile(0.90),
                p95=percentile(0.95),
                p99=percentile(0.99),
            )
    
    def get_bucket_counts(self) -> Dict[float, int]:
        """Get counts per bucket"""
        with self._lock:
            return self._bucket_counts.copy()


class Timer:
    """
    Timer metric - measures duration and records as histogram
    Can be used as context manager or decorator
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        unit: MetricUnit = MetricUnit.SECONDS,
        labels: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self.description = description
        self.unit = unit
        self._labels = labels or {}
        self._histogram = Histogram(
            name=name,
            description=description,
            unit=unit,
            labels=labels,
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
        )
        self._start_time: Optional[float] = None
        self._running = False
    
    def start(self) -> "Timer":
        """Start timing"""
        self._start_time = time.time()
        self._running = True
        return self
    
    def stop(self) -> float:
        """Stop timing and record duration"""
        if not self._running or self._start_time is None:
            return 0.0
        
        duration = time.time() - self._start_time
        self._histogram.observe(duration)
        self._running = False
        return duration
    
    def record(self, duration: float) -> None:
        """Record a duration directly"""
        self._histogram.observe(duration)
    
    def reset(self) -> None:
        """Reset timer"""
        self._histogram.reset()
        self._start_time = None
        self._running = False
    
    def snapshot(self) -> MetricSnapshot:
        """Get snapshot of current state"""
        return self._histogram.snapshot()
    
    def __enter__(self) -> "Timer":
        """Context manager entry"""
        return self.start()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit"""
        self.stop()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for timing functions"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        return wrapper
    
    @property
    def mean(self) -> Optional[float]:
        """Get mean duration"""
        return self._histogram.snapshot().mean


class MetricsRegistry:
    """Registry for all metrics"""
    
    def __init__(self):
        self._metrics: Dict[str, Union[Counter, Gauge, Histogram, Timer]] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger("runtime.metrics.registry")
    
    def register(
        self,
        name: str,
        metric_type: MetricType,
        **kwargs
    ) -> Union[Counter, Gauge, Histogram, Timer]:
        """Register a new metric"""
        with self._lock:
            if name in self._metrics:
                self._logger.warning(f"Metric {name} already registered, returning existing")
                return self._metrics[name]
            
            if metric_type == MetricType.COUNTER:
                metric = Counter(name, **kwargs)
            elif metric_type == MetricType.GAUGE:
                metric = Gauge(name, **kwargs)
            elif metric_type == MetricType.HISTOGRAM:
                metric = Histogram(name, **kwargs)
            elif metric_type == MetricType.TIMER:
                metric = Timer(name, **kwargs)
            else:
                raise ValueError(f"Unknown metric type: {metric_type}")
            
            self._metrics[name] = metric
            self._logger.debug(f"Registered metric: {name}")
            return metric
    
    def get(self, name: str) -> Optional[Union[Counter, Gauge, Histogram, Timer]]:
        """Get a metric by name"""
        with self._lock:
            return self._metrics.get(name)
    
    def get_all(self) -> Dict[str, Union[Counter, Gauge, Histogram, Timer]]:
        """Get all metrics"""
        with self._lock:
            return self._metrics.copy()
    
    def clear(self) -> None:
        """Clear all metrics"""
        with self._lock:
            self._metrics.clear()
            self._logger.info("Cleared all metrics")


class MetricsCollector:
    """
    Main metrics collector for Secure Runtime
    
    Collects system, runtime, and security metrics with support for
    counters, gauges, histograms, and timers. Provides export to
    JSON and Prometheus formats.
    """
    
    def __init__(
        self,
        name: str = "secure-runtime",
        enable_system_metrics: bool = True,
        history_size: int = 100,
        collect_interval: int = 10,
    ):
        self.name = name
        self.enable_system_metrics = enable_system_metrics
        self.history_size = history_size
        self.collect_interval = collect_interval
        
        self.registry = MetricsRegistry()
        self._system_metrics_cache: Dict[str, float] = {}
        self._history: deque = deque(maxlen=history_size)
        self._lock = threading.RLock()
        self._collector_task: Optional[asyncio.Task] = None
        self._is_collecting = False
        self._logger = logging.getLogger(f"runtime.metrics.collector.{name}")
        
        # Initialize default metrics
        self._setup_default_metrics()
    
    def _setup_default_metrics(self) -> None:
        """Setup default metrics for the runtime"""
        # Request metrics
        self.registry.register(
            "total_requests", MetricType.COUNTER,
            description="Total number of requests received",
            unit=MetricUnit.REQUESTS
        )
        self.registry.register(
            "allowed_requests", MetricType.COUNTER,
            description="Total number of requests allowed",
            unit=MetricUnit.REQUESTS
        )
        self.registry.register(
            "blocked_requests", MetricType.COUNTER,
            description="Total number of requests blocked",
            unit=MetricUnit.REQUESTS
        )
        self.registry.register(
            "requests_per_second", MetricType.GAUGE,
            description="Requests processed per second",
            unit=MetricUnit.REQUESTS
        )
        self.registry.register(
            "active_requests", MetricType.GAUGE,
            description="Currently active requests",
            unit=MetricUnit.REQUESTS
        )
        
        # Latency metrics
        self.registry.register(
            "request_latency", MetricType.TIMER,
            description="Request processing latency",
            unit=MetricUnit.MILLISECONDS
        )
        self.registry.register(
            "peak_latency", MetricType.GAUGE,
            description="Peak request latency",
            unit=MetricUnit.MILLISECONDS
        )
        
        # System metrics
        if self.enable_system_metrics:
            self.registry.register(
                "cpu_usage", MetricType.GAUGE,
                description="CPU usage percentage",
                unit=MetricUnit.PERCENT
            )
            self.registry.register(
                "memory_usage", MetricType.GAUGE,
                description="Memory usage in bytes",
                unit=MetricUnit.BYTES
            )
            self.registry.register(
                "disk_usage", MetricType.GAUGE,
                description="Disk usage in bytes",
                unit=MetricUnit.BYTES
            )
            self.registry.register(
                "thread_count", MetricType.GAUGE,
                description="Number of threads",
                unit=MetricUnit.THREADS
            )
        
        # Security metrics
        self.registry.register(
            "threat_count", MetricType.COUNTER,
            description="Total threats detected",
            unit=MetricUnit.COUNT
        )
        self.registry.register(
            "secrets_found", MetricType.COUNTER,
            description="Total secrets found",
            unit=MetricUnit.COUNT
        )
        self.registry.register(
            "prompt_injections", MetricType.COUNTER,
            description="Total prompt injections detected",
            unit=MetricUnit.COUNT
        )
        
        # Authentication metrics
        self.registry.register(
            "auth_failures", MetricType.COUNTER,
            description="Total authentication failures",
            unit=MetricUnit.COUNT
        )
        self.registry.register(
            "auth_success", MetricType.COUNTER,
            description="Total successful authentications",
            unit=MetricUnit.COUNT
        )
        
        # Authorization metrics
        self.registry.register(
            "authz_failures", MetricType.COUNTER,
            description="Total authorization failures",
            unit=MetricUnit.COUNT
        )
        
        # Policy metrics
        self.registry.register(
            "policy_violations", MetricType.COUNTER,
            description="Total policy violations",
            unit=MetricUnit.COUNT
        )
        
        # Error metrics
        self.registry.register(
            "warnings", MetricType.COUNTER,
            description="Total warnings",
            unit=MetricUnit.COUNT
        )
        self.registry.register(
            "errors", MetricType.COUNTER,
            description="Total errors",
            unit=MetricUnit.COUNT
        )
        
        # Score metrics
        self.registry.register(
            "security_score", MetricType.GAUGE,
            description="Current security score",
            unit=MetricUnit.COUNT
        )
        self.registry.register(
            "runtime_health_score", MetricType.GAUGE,
            description="Runtime health score",
            unit=MetricUnit.COUNT
        )
    
    async def start_collecting(self) -> None:
        """Start automatic metrics collection"""
        if self._is_collecting:
            return
        
        self._is_collecting = True
        
        async def collect_loop():
            while self._is_collecting:
                try:
                    await self._collect_system_metrics()
                    await asyncio.sleep(self.collect_interval)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self._logger.error(f"Error collecting metrics: {e}")
                    await asyncio.sleep(self.collect_interval)
        
        self._collector_task = asyncio.create_task(collect_loop())
        self._logger.info("Started metrics collection")
    
    async def stop_collecting(self) -> None:
        """Stop automatic metrics collection"""
        self._is_collecting = False
        
        if self._collector_task and not self._collector_task.done():
            self._collector_task.cancel()
            try:
                await self._collector_task
            except asyncio.CancelledError:
                pass
        
        self._collector_task = None
        self._logger.info("Stopped metrics collection")
    
    async def _collect_system_metrics(self) -> None:
        """Collect system metrics"""
        if not self.enable_system_metrics:
            return
        
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.registry.get("cpu_usage").set(cpu_percent)
            
            # Memory Usage
            memory = psutil.virtual_memory()
            self.registry.get("memory_usage").set(memory.used)
            
            # Disk Usage
            disk = psutil.disk_usage('/')
            self.registry.get("disk_usage").set(disk.used)
            
            # Thread Count
            thread_count = threading.active_count()
            self.registry.get("thread_count").set(thread_count)
            
            # Store in cache
            self._system_metrics_cache = {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.used,
                "memory_total": memory.total,
                "memory_percent": memory.percent,
                "disk_usage": disk.used,
                "disk_total": disk.total,
                "disk_percent": disk.percent,
                "thread_count": thread_count,
                "timestamp": time.time(),
            }
            
        except Exception as e:
            self._logger.error(f"Error collecting system metrics: {e}")
    
    def increment_counter(self, name: str, value: float = 1.0) -> None:
        """Increment a counter metric"""
        metric = self.registry.get(name)
        if metric and isinstance(metric, Counter):
            metric.increment(value)
    
    def decrement_gauge(self, name: str, value: float = 1.0) -> None:
        """Decrement a gauge metric"""
        metric = self.registry.get(name)
        if metric and isinstance(metric, Gauge):
            metric.decrement(value)
    
    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge metric"""
        metric = self.registry.get(name)
        if metric and isinstance(metric, Gauge):
            metric.set(value)
    
    def record_histogram(self, name: str, value: float) -> None:
        """Record a histogram value"""
        metric = self.registry.get(name)
        if metric and isinstance(metric, Histogram):
            metric.observe(value)
        elif metric and isinstance(metric, Timer):
            # Timer accepts record directly
            metric.record(value)
    
    def timer(self, name: str) -> Timer:
        """Get or create a timer for the given name"""
        metric = self.registry.get(name)
        if metric and isinstance(metric, Timer):
            return metric
        
        # Create timer if it doesn't exist
        if metric is None:
            return self.registry.register(name, MetricType.TIMER)
        
        raise TypeError(f"Metric {name} exists but is not a Timer")
    
    def record_request(self, allowed: bool, duration: float) -> None:
        """Record a request with its outcome and duration"""
        self.increment_counter("total_requests")
        
        if allowed:
            self.increment_counter("allowed_requests")
        else:
            self.increment_counter("blocked_requests")
        
        # Record latency
        timer = self.timer("request_latency")
        timer.record(duration / 1000.0)  # Convert to seconds for timer
        
        # Update peak latency
        current_peak = self.registry.get("peak_latency").value()
        if duration > current_peak:
            self.set_gauge("peak_latency", duration)
        
        # Update requests per second
        self._update_requests_per_second()
        
        # Add to history
        self._add_history_entry({
            "type": "request",
            "allowed": allowed,
            "duration": duration,
            "timestamp": time.time(),
        })
    
    def _update_requests_per_second(self) -> None:
        """Update the requests per second metric"""
        # Get recent request count from history
        now = time.time()
        window_start = now - 1.0
        
        recent_requests = sum(
            1 for entry in self._history
            if entry.get("type") == "request" and entry.get("timestamp", 0) >= window_start
        )
        
        self.set_gauge("requests_per_second", recent_requests)
    
    def record_security_event(
        self,
        event_type: str,
        severity: str = "medium"
    ) -> None:
        """Record a security event"""
        if event_type == "threat":
            self.increment_counter("threat_count")
        elif event_type == "secret":
            self.increment_counter("secrets_found")
        elif event_type == "prompt_injection":
            self.increment_counter("prompt_injections")
        elif event_type == "policy_violation":
            self.increment_counter("policy_violations")
        elif event_type == "auth_failure":
            self.increment_counter("auth_failures")
        elif event_type == "auth_success":
            self.increment_counter("auth_success")
        elif event_type == "authz_failure":
            self.increment_counter("authz_failures")
        
        # Update security score based on severity
        self._update_security_score(event_type, severity)
        
        self._add_history_entry({
            "type": "security",
            "event_type": event_type,
            "severity": severity,
            "timestamp": time.time(),
        })
    
    def _update_security_score(self, event_type: str, severity: str) -> None:
        """Update security score based on events"""
        score_metric = self.registry.get("security_score")
        if not score_metric:
            return
        
        current_score = score_metric.value()
        
        # Severity impact
        severity_impact = {
            "critical": -15,
            "high": -10,
            "medium": -5,
            "low": -2,
            "info": -1,
        }
        
        event_impact = {
            "threat": -10,
            "secret": -8,
            "prompt_injection": -12,
            "policy_violation": -7,
            "auth_failure": -5,
            "authz_failure": -4,
        }
        
        impact = event_impact.get(event_type, -3)
        severity_modifier = severity_impact.get(severity, -1)
        total_impact = impact * (severity_modifier / 5) if severity_modifier != 0 else impact
        
        new_score = max(0, min(100, current_score + total_impact))
        score_metric.set(new_score)
    
    def record_error(self, error_type: str, severity: str = "error") -> None:
        """Record an error"""
        if severity == "error":
            self.increment_counter("errors")
        elif severity == "warning":
            self.increment_counter("warnings")
        
        self._add_history_entry({
            "type": "error",
            "error_type": error_type,
            "severity": severity,
            "timestamp": time.time(),
        })
    
    def update_health_score(self, score: float) -> None:
        """Update the runtime health score"""
        self.set_gauge("runtime_health_score", min(100, max(0, score)))
    
    def _add_history_entry(self, entry: Dict[str, Any]) -> None:
        """Add an entry to history"""
        with self._lock:
            self._history.append(entry)
    
    def snapshot(self) -> Dict[str, Any]:
        """
        Get a snapshot of all metrics
        
        Returns:
            Dict[str, Any]: Snapshot of all metrics
        """
        snapshot = {
            "name": self.name,
            "timestamp": time.time(),
            "metrics": {},
            "system": self._system_metrics_cache.copy(),
            "history": list(self._history),
            "summary": {},
        }
        
        for name, metric in self.registry.get_all().items():
            snapshot["metrics"][name] = self._metric_to_dict(metric)
        
        # Build summary
        total = self.registry.get("total_requests")
        if total:
            snapshot["summary"]["total_requests"] = total.value()
        
        blocked = self.registry.get("blocked_requests")
        if blocked:
            snapshot["summary"]["blocked_requests"] = blocked.value()
        
        errors = self.registry.get("errors")
        if errors:
            snapshot["summary"]["errors"] = errors.value()
        
        security_score = self.registry.get("security_score")
        if security_score:
            snapshot["summary"]["security_score"] = security_score.value()
        
        health_score = self.registry.get("runtime_health_score")
        if health_score:
            snapshot["summary"]["health_score"] = health_score.value()
        
        return snapshot
    
    def _metric_to_dict(self, metric: Union[Counter, Gauge, Histogram, Timer]) -> Dict[str, Any]:
        """Convert a metric to dictionary"""
        snapshot = metric.snapshot()
        
        result = {
            "type": snapshot.type.value,
            "unit": snapshot.unit.value,
            "value": snapshot.value,
            "labels": snapshot.labels,
            "timestamp": snapshot.timestamp,
        }
        
        if snapshot.type == MetricType.HISTOGRAM or snapshot.type == MetricType.TIMER:
            result["count"] = snapshot.count
            result["sum"] = snapshot.sum
            result["mean"] = snapshot.mean
            result["min"] = snapshot.min
            result["max"] = snapshot.max
            result["p50"] = snapshot.p50
            result["p90"] = snapshot.p90
            result["p95"] = snapshot.p95
            result["p99"] = snapshot.p99
        
        return result
    
    def average(self, metric_name: str, window_seconds: int = 60) -> Optional[float]:
        """
        Calculate average of a metric over a time window
        
        Args:
            metric_name: Name of the metric
            window_seconds: Time window in seconds
            
        Returns:
            Optional[float]: Average value
        """
        metric = self.registry.get(metric_name)
        if not metric:
            return None
        
        # For counter, calculate rate over window
        if isinstance(metric, Counter):
            now = time.time()
            window_start = now - window_seconds
            
            # Get history for this metric
            values = [
                entry for entry in self._history
                if entry.get("type") == "request"
            ]
            
            if not values:
                return 0.0
            
            # Simple average
            total = sum(1 for _ in values)
            return total / window_seconds
        
        # For gauge, just return current value
        elif isinstance(metric, Gauge):
            return metric.value()
        
        # For histogram, return mean
        elif isinstance(metric, (Histogram, Timer)):
            return metric.snapshot().mean
        
        return None
    
    def reset(self) -> None:
        """Reset all metrics"""
        for metric in self.registry.get_all().values():
            if hasattr(metric, "reset"):
                metric.reset()
        
        with self._lock:
            self._history.clear()
            self._system_metrics_cache.clear()
        
        self._logger.info("Reset all metrics")
    
    def export_json(self) -> str:
        """
        Export metrics as JSON
        
        Returns:
            str: JSON representation of metrics
        """
        snapshot = self.snapshot()
        return json.dumps(snapshot, indent=2, default=str)
    
    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus format
        
        Returns:
            str: Prometheus-formatted metrics
        """
        lines = []
        timestamp = int(time.time() * 1000)
        
        for name, metric in self.registry.get_all().items():
            snapshot = metric.snapshot()
            
            # Convert metric name to Prometheus format
            prom_name = name.replace('-', '_')
            
            if snapshot.type == MetricType.COUNTER:
                lines.append(f"# HELP {prom_name} {metric.description or name}")
                lines.append(f"# TYPE {prom_name} counter")
                lines.append(f"{prom_name} {snapshot.value} {timestamp}")
            
            elif snapshot.type == MetricType.GAUGE:
                lines.append(f"# HELP {prom_name} {metric.description or name}")
                lines.append(f"# TYPE {prom_name} gauge")
                lines.append(f"{prom_name} {snapshot.value} {timestamp}")
            
            elif snapshot.type in (MetricType.HISTOGRAM, MetricType.TIMER):
                lines.append(f"# HELP {prom_name} {metric.description or name}")
                lines.append(f"# TYPE {prom_name} histogram")
                
                if snapshot.count is not None:
                    lines.append(f"{prom_name}_count {snapshot.count} {timestamp}")
                    lines.append(f"{prom_name}_sum {snapshot.sum or 0} {timestamp}")
                    
                    # Add quantiles
                    if snapshot.p50 is not None:
                        lines.append(f"{prom_name} {{quantile=\"0.5\"}} {snapshot.p50} {timestamp}")
                    if snapshot.p90 is not None:
                        lines.append(f"{prom_name} {{quantile=\"0.9\"}} {snapshot.p90} {timestamp}")
                    if snapshot.p95 is not None:
                        lines.append(f"{prom_name} {{quantile=\"0.95\"}} {snapshot.p95} {timestamp}")
                    if snapshot.p99 is not None:
                        lines.append(f"{prom_name} {{quantile=\"0.99\"}} {snapshot.p99} {timestamp}")
        
        return "\n".join(lines)
    
    def get_counters(self) -> Dict[str, float]:
        """Get all counter values"""
        result = {}
        for name, metric in self.registry.get_all().items():
            if isinstance(metric, Counter):
                result[name] = metric.value()
        return result
    
    def get_gauges(self) -> Dict[str, float]:
        """Get all gauge values"""
        result = {}
        for name, metric in self.registry.get_all().items():
            if isinstance(metric, Gauge):
                result[name] = metric.value()
        return result
    
    def get_histograms(self) -> Dict[str, Dict[str, Any]]:
        """Get all histogram snapshots"""
        result = {}
        for name, metric in self.registry.get_all().items():
            if isinstance(metric, (Histogram, Timer)):
                snapshot = metric.snapshot()
                result[name] = {
                    "count": snapshot.count,
                    "sum": snapshot.sum,
                    "mean": snapshot.mean,
                    "min": snapshot.min,
                    "max": snapshot.max,
                    "p50": snapshot.p50,
                    "p90": snapshot.p90,
                    "p95": snapshot.p95,
                    "p99": snapshot.p99,
                }
        return result
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all metrics
        
        Returns:
            Dict[str, Any]: Metrics summary
        """
        return {
            "name": self.name,
            "timestamp": time.time(),
            "counters": self.get_counters(),
            "gauges": self.get_gauges(),
            "histograms": self.get_histograms(),
            "system": self._system_metrics_cache.copy(),
            "history_count": len(self._history),
        }


# Global metrics collector instance
_default_collector: Optional[MetricsCollector] = None


def get_metrics_collector(name: str = "secure-runtime", **kwargs) -> MetricsCollector:
    """
    Get or create a metrics collector instance
    
    Args:
        name: Collector name
        **kwargs: Additional arguments
        
    Returns:
        MetricsCollector: Metrics collector instance
    """
    global _default_collector
    
    if name == "secure-runtime":
        if _default_collector is None:
            _default_collector = MetricsCollector(name=name, **kwargs)
        return _default_collector
    else:
        return MetricsCollector(name=name, **kwargs)


def set_default_collector(collector: MetricsCollector) -> None:
    """
    Set the default metrics collector
    
    Args:
        collector: MetricsCollector instance
    """
    global _default_collector
    _default_collector = collector


# Convenience functions
def increment_counter(name: str, value: float = 1.0) -> None:
    """Increment a counter using default collector"""
    collector = get_metrics_collector()
    collector.increment_counter(name, value)


def set_gauge(name: str, value: float) -> None:
    """Set a gauge using default collector"""
    collector = get_metrics_collector()
    collector.set_gauge(name, value)


def record_histogram(name: str, value: float) -> None:
    """Record a histogram value using default collector"""
    collector = get_metrics_collector()
    collector.record_histogram(name, value)


def timer(name: str) -> Timer:
    """Get a timer using default collector"""
    collector = get_metrics_collector()
    return collector.timer(name)


def timed(name: str):
    """Decorator for timing functions using default collector"""
    metric_timer = timer(name)
    return metric_timer


def record_request(allowed: bool, duration: float) -> None:
    """Record a request using default collector"""
    collector = get_metrics_collector()
    collector.record_request(allowed, duration)


def record_security_event(event_type: str, severity: str = "medium") -> None:
    """Record a security event using default collector"""
    collector = get_metrics_collector()
    collector.record_security_event(event_type, severity)


def record_error(error_type: str, severity: str = "error") -> None:
    """Record an error using default collector"""
    collector = get_metrics_collector()
    collector.record_error(error_type, severity)


def export_metrics_json() -> str:
    """Export metrics as JSON using default collector"""
    collector = get_metrics_collector()
    return collector.export_json()


def export_metrics_prometheus() -> str:
    """Export metrics in Prometheus format using default collector"""
    collector = get_metrics_collector()
    return collector.export_prometheus()


def get_metrics_snapshot() -> Dict[str, Any]:
    """Get metrics snapshot using default collector"""
    collector = get_metrics_collector()
    return collector.snapshot()