#!/usr/bin/env python3
"""
Security Runtime Dashboard

Provides a real-time monitoring and management interface for Security Runtime.

Usage:
    python dashboard.py [project_path]

Starts the dashboard at http://localhost:8080 and opens the browser.
"""

import asyncio
import json
import os
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from threading import Thread
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

# ============================================================================
# Attempt to import existing project components
# ============================================================================

try:
    import tech_scanner
except ImportError:
    tech_scanner = None

try:
    from project_intelligence import analyze_project, ProjectIntelligence
except ImportError:
    analyze_project = None
    ProjectIntelligence = None

# ============================================================================
# Data Models
# ============================================================================

class ThreatSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class RuntimeStatus(Enum):
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class Project:
    name: str
    framework: str
    language: str
    database: str
    runtime_version: str = "v1.0.0"
    started_at: datetime = field(default_factory=datetime.now)
    status: RuntimeStatus = RuntimeStatus.RUNNING
    security_score: int = 85

    def uptime(self) -> str:
        delta = datetime.now() - self.started_at
        hours, remainder = divmod(delta.total_seconds(), 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m"


@dataclass
class RequestMetrics:
    total: int = 0
    blocked: int = 0
    allowed: int = 0
    rate_per_second: float = 0.0
    avg_latency_ms: float = 0.0


@dataclass
class Threat:
    id: str
    timestamp: datetime
    method: str
    path: str
    severity: ThreatSeverity
    status: ThreatStatus
    reason: str
    decision: str  # "block" or "allow"
    source_ip: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "path": self.path,
            "severity": self.severity.value,
            "status": self.status.value,
            "reason": self.reason,
            "decision": self.decision,
            "source_ip": self.source_ip,
        }


@dataclass
class PerformanceMetrics:
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    avg_scan_time_ms: float = 0.0
    avg_runtime_cost_ms: float = 0.0
    requests_processed: int = 0
    requests_blocked: int = 0
    requests_allowed: int = 0


@dataclass
class Warning:
    id: str
    title: str
    description: str
    severity: ThreatSeverity
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class RuntimeConfig:
    status: RuntimeStatus = RuntimeStatus.RUNNING
    version: str = "v1.0.0"
    started_at: datetime = field(default_factory=datetime.now)


# ============================================================================
# Real Data Provider
# ============================================================================

class RuntimeDataProvider:
    """Provides real project data from technology detector and intelligence engine,
       and reads runtime metrics/events from files.
    """

    def __init__(self, project_path: str = "."):
        self.project_path = project_path
        self._projects: List[Project] = []
        self._warnings: List[Warning] = []
        self._intelligence: Optional[ProjectIntelligence] = None
        self._runtime_metrics_path = Path("runtime_metrics.json")
        self._runtime_events_path = Path("runtime_events.jsonl")
        self._runtime_config = RuntimeConfig(status=RuntimeStatus.STOPPED)
        self._load_project_intelligence()

    def _load_project_intelligence(self) -> None:
        """Load technology fingerprint and project intelligence."""
        if tech_scanner is None or analyze_project is None:
            # Fallback: create a dummy project from environment
            self._projects = [
                Project(
                    name="Unknown Project",
                    framework="unknown",
                    language="unknown",
                    database="unknown",
                    runtime_version="v0.0.0",
                    status=RuntimeStatus.STOPPED,
                    security_score=0,
                )
            ]
            return

        try:
            fingerprint = tech_scanner.scan_project(self.project_path)
            self._intelligence = analyze_project(fingerprint)
            self._build_projects_from_intelligence()
            self._build_warnings_from_intelligence()
            # Set runtime version from intelligence if available
            if self._intelligence and self._intelligence.primary_application:
                app = self._intelligence.primary_application
                # Infer version from framework version if present
                version = "v1.0.0"
                # Could look at dependencies
                self._runtime_config.version = version
        except Exception as e:
            print(f"Failed to load project intelligence: {e}")

    def _build_projects_from_intelligence(self) -> None:
        """Convert ProjectIntelligence applications to Project list."""
        if not self._intelligence:
            return
        apps = self._intelligence.applications
        if not apps:
            # Create a default project from fingerprint
            detected = self._intelligence.__dict__.get("detected", {})
            framework = detected.get("language", "unknown")
            lang = detected.get("language", "unknown")
            db = detected.get("databases", ["unknown"])[0] if detected.get("databases") else "unknown"
            self._projects = [
                Project(
                    name="Project",
                    framework=framework,
                    language=lang,
                    database=db,
                    runtime_version="v1.0.0",
                    status=RuntimeStatus.RUNNING if self._runtime_config.status == RuntimeStatus.RUNNING else RuntimeStatus.STOPPED,
                    security_score=self._compute_security_score_from_warnings(),
                )
            ]
            return

        for app in apps:
            # Map framework enum to string
            framework = app.framework.value if hasattr(app.framework, 'value') else str(app.framework)
            language = self._infer_language_from_framework(framework)
            database = "unknown"
            if app.security_boundaries:
                for boundary in app.security_boundaries:
                    if boundary.type.value == "database" and boundary.description:
                        # Try to extract database name
                        desc = boundary.description.lower()
                        if "postgres" in desc:
                            database = "PostgreSQL"
                        elif "mysql" in desc:
                            database = "MySQL"
                        elif "mongo" in desc:
                            database = "MongoDB"
                        elif "redis" in desc:
                            database = "Redis"
                        elif "sqlite" in desc:
                            database = "SQLite"
                        break
            # Attempt to get version from app confidence or other
            version = "v1.0.0"
            if app.confidence and app.confidence.evidence:
                for ev in app.confidence.evidence:
                    if "version" in ev.lower():
                        # crude extraction
                        import re
                        m = re.search(r'v?(\d+\.\d+\.\d+)', ev)
                        if m:
                            version = "v" + m.group(1)
                            break
            project = Project(
                name=app.name,
                framework=framework,
                language=language,
                database=database,
                runtime_version=version,
                status=self._runtime_config.status,
                security_score=self._compute_security_score_from_warnings(),
            )
            self._projects.append(project)

    def _infer_language_from_framework(self, framework: str) -> str:
        """Map framework to language."""
        framework_lower = framework.lower()
        if any(x in framework_lower for x in ["fastapi", "flask", "django", "quart"]):
            return "Python"
        if any(x in framework_lower for x in ["express", "nestjs", "next"]):
            return "JavaScript/TypeScript"
        if any(x in framework_lower for x in ["spring", "java"]):
            return "Java"
        if any(x in framework_lower for x in ["gin", "echo", "fiber"]):
            return "Go"
        if any(x in framework_lower for x in ["actix", "axum", "rocket"]):
            return "Rust"
        return "unknown"

    def _build_warnings_from_intelligence(self) -> None:
        """Extract warnings from project intelligence."""
        self._warnings = []
        if not self._intelligence:
            return

        # Use intelligence readiness report warnings
        if self._intelligence.readiness_report:
            report = self._intelligence.readiness_report
            # Convert warnings to our Warning model
            for w in report.warnings:
                severity = ThreatSeverity.MEDIUM
                if "critical" in w.lower() or "urgent" in w.lower():
                    severity = ThreatSeverity.CRITICAL
                elif "high" in w.lower():
                    severity = ThreatSeverity.HIGH
                elif "low" in w.lower():
                    severity = ThreatSeverity.LOW
                self._warnings.append(
                    Warning(
                        id=f"warn-{len(self._warnings)}",
                        title=w[:50],
                        description=w,
                        severity=severity,
                        timestamp=datetime.now(),
                    )
                )

            # Also check missing requirements
            for miss in report.missing_requirements:
                self._warnings.append(
                    Warning(
                        id=f"warn-{len(self._warnings)}",
                        title=f"Missing: {miss}",
                        description=f"Required for runtime integration: {miss}",
                        severity=ThreatSeverity.HIGH,
                        timestamp=datetime.now(),
                    )
                )

        # Add warnings from security boundaries if any
        if self._intelligence.security_boundaries:
            for boundary in self._intelligence.security_boundaries[:3]:
                if boundary.type.value == "authentication" and boundary.confidence and boundary.confidence.score < 0.5:
                    self._warnings.append(
                        Warning(
                            id=f"warn-{len(self._warnings)}",
                            title="Weak Authentication",
                            description=boundary.description[:100],
                            severity=ThreatSeverity.HIGH,
                            timestamp=datetime.now(),
                        )
                    )

    def _compute_security_score_from_warnings(self) -> int:
        """Compute score based on warnings and runtime health."""
        base = 100
        for w in self._warnings:
            if w.severity == ThreatSeverity.CRITICAL:
                base -= 15
            elif w.severity == ThreatSeverity.HIGH:
                base -= 10
            elif w.severity == ThreatSeverity.MEDIUM:
                base -= 5
            else:
                base -= 2
        # Deduct if runtime is not running
        if self._runtime_config.status != RuntimeStatus.RUNNING:
            base -= 20
        # Deduct based on runtime health from metrics if available
        metrics = self._read_runtime_metrics()
        if metrics:
            if metrics.get("health") == "unhealthy":
                base -= 15
            elif metrics.get("health") == "degraded":
                base -= 8
        return max(0, min(100, base))

    def _read_runtime_metrics(self) -> Dict[str, Any]:
        """Read runtime_metrics.json if exists."""
        if self._runtime_metrics_path.exists():
            try:
                with open(self._runtime_metrics_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _read_runtime_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Read last N events from runtime_events.jsonl."""
        events = []
        if self._runtime_events_path.exists():
            try:
                with open(self._runtime_events_path, "r") as f:
                    lines = f.readlines()
                    # Read last `limit` lines
                    for line in lines[-limit:]:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
        return events

    # ------------------------------------------------------------------------
    # Public methods for dashboard
    # ------------------------------------------------------------------------

    def get_projects(self) -> List[Dict[str, Any]]:
        """Return list of projects."""
        return [
            {
                "name": p.name,
                "framework": p.framework,
                "language": p.language,
                "database": p.database,
                "runtime_version": p.runtime_version,
                "started_at": p.started_at.isoformat(),
                "status": p.status.value,
                "security_score": p.security_score,
                "uptime": p.uptime(),
            }
            for p in self._projects
        ]

    def get_runtime_status(self) -> Dict[str, Any]:
        """Return current runtime status."""
        # Check if runtime_metrics.json indicates status
        metrics = self._read_runtime_metrics()
        if metrics:
            status_str = metrics.get("runtime_status", "stopped")
            try:
                status = RuntimeStatus(status_str)
                self._runtime_config.status = status
            except ValueError:
                pass
            # Update started_at if present
            if "started_at" in metrics:
                try:
                    self._runtime_config.started_at = datetime.fromisoformat(metrics["started_at"])
                except Exception:
                    pass
            if "version" in metrics:
                self._runtime_config.version = metrics["version"]

        return {
            "status": self._runtime_config.status.value,
            "version": self._runtime_config.version,
            "started_at": self._runtime_config.started_at.isoformat(),
            "uptime": self._runtime_config.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Return request metrics from runtime_metrics.json."""
        metrics = self._read_runtime_metrics()
        total = metrics.get("total_requests", 0)
        blocked = metrics.get("blocked_requests", 0)
        allowed = metrics.get("allowed_requests", 0)
        rate = metrics.get("requests_per_second", 0.0)
        latency = metrics.get("average_latency_ms", 0.0)
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "allowed_requests": allowed,
            "rate_per_second": round(rate, 1),
            "avg_latency_ms": round(latency, 1),
        }

    def get_threats(self) -> List[Dict[str, Any]]:
        """Convert runtime events to threat format."""
        events = self._read_runtime_events(limit=100)
        threats = []
        for ev in events:
            # Map event to threat
            severity_str = ev.get("severity", "info")
            try:
                severity = ThreatSeverity(severity_str)
            except ValueError:
                severity = ThreatSeverity.INFO
            status_str = ev.get("status", "blocked")
            try:
                status = ThreatStatus(status_str)
            except ValueError:
                status = ThreatStatus.BLOCKED
            decision = ev.get("decision", "block")
            threat = Threat(
                id=ev.get("id", f"evt-{len(threats)}"),
                timestamp=datetime.fromisoformat(ev["timestamp"]) if "timestamp" in ev else datetime.now(),
                method=ev.get("method", "UNKNOWN"),
                path=ev.get("path", "/"),
                severity=severity,
                status=status,
                reason=ev.get("reason", "No reason provided"),
                decision=decision,
                source_ip=ev.get("source_ip", "0.0.0.0"),
            )
            threats.append(threat)
        # Return as dict list
        return [t.to_dict() for t in threats]

    def get_warnings(self) -> List[Dict[str, Any]]:
        """Return warnings from project intelligence."""
        # Ensure warnings are up-to-date with latest intelligence
        self._build_warnings_from_intelligence()
        return [w.to_dict() for w in self._warnings]

    def get_performance(self) -> Dict[str, Any]:
        """Return performance from runtime_metrics.json."""
        metrics = self._read_runtime_metrics()
        return {
            "cpu_percent": metrics.get("cpu_percent", 0.0),
            "memory_mb": metrics.get("memory_mb", 0.0),
            "avg_scan_time_ms": metrics.get("avg_scan_time_ms", 0.0),
            "avg_runtime_cost_ms": metrics.get("avg_runtime_cost_ms", 0.0),
            "requests_processed": metrics.get("requests_processed", 0),
            "requests_blocked": metrics.get("requests_blocked", 0),
            "requests_allowed": metrics.get("requests_allowed", 0),
        }

    def get_security_score(self) -> int:
        """Compute security score from warnings and runtime health."""
        # Recalculate to reflect latest state
        return self._compute_security_score_from_warnings()

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Aggregate all data for WebSocket push."""
        # Update runtime status from metrics file
        self.get_runtime_status()  # triggers refresh
        return {
            "projects": self.get_projects(),
            "runtime": self.get_runtime_status(),
            "metrics": self.get_metrics(),
            "threats": self.get_threats(),
            "warnings": self.get_warnings(),
            "performance": self.get_performance(),
            "security_score": self.get_security_score(),
            "timestamp": datetime.now().isoformat(),
        }

    def set_runtime_status(self, status: str) -> None:
        """Update runtime status and persist to metrics file."""
        try:
            new_status = RuntimeStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")

        # Update internal state
        self._runtime_config.status = new_status
        # Write to runtime_metrics.json
        metrics = self._read_runtime_metrics()
        metrics["runtime_status"] = status
        if status == "running":
            metrics["started_at"] = datetime.now().isoformat()
        try:
            with open(self._runtime_metrics_path, "w") as f:
                json.dump(metrics, f, indent=2)
        except Exception as e:
            print(f"Failed to write runtime metrics: {e}")


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(title="Security Runtime Dashboard", version="1.0.0")

# Global data provider - will be initialized after parsing args
data_provider: Optional[RuntimeDataProvider] = None

# Active WebSocket connections
active_connections: Set[WebSocket] = set()


# ----------------------------------------------------------------------------
# HTML Dashboard (unchanged)
# ----------------------------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Runtime Dashboard</title>
    <style>
        /* === Reset & Base === */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background: #0b0e11;
            color: #e5e7eb;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
            display: flex;
            min-height: 100vh;
            margin: 0;
        }
        /* === Scrollbar === */
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: #1a1f24;
        }
        ::-webkit-scrollbar-thumb {
            background: #3b4a5a;
            border-radius: 4px;
        }

        /* === Sidebar === */
        .sidebar {
            width: 220px;
            background: #11161b;
            border-right: 1px solid #1f2a33;
            padding: 28px 16px;
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
            height: 100vh;
            position: sticky;
            top: 0;
        }
        .sidebar .logo {
            font-size: 18px;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: #3b82f6;
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .sidebar .logo span {
            background: #3b82f6;
            color: #fff;
            font-size: 14px;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .sidebar nav {
            flex: 1;
        }
        .sidebar nav a {
            display: block;
            padding: 10px 14px;
            color: #9aa4af;
            text-decoration: none;
            border-radius: 6px;
            margin-bottom: 4px;
            font-size: 14px;
            transition: all 0.15s;
        }
        .sidebar nav a:hover {
            background: #1f2a33;
            color: #e5e7eb;
        }
        .sidebar nav a.active {
            background: #1a2a3a;
            color: #60a5fa;
        }
        .sidebar .footer {
            margin-top: auto;
            font-size: 12px;
            color: #5a6a7a;
            border-top: 1px solid #1f2a33;
            padding-top: 16px;
            text-align: center;
        }

        /* === Main Content === */
        .main {
            flex: 1;
            padding: 24px 32px 40px;
            overflow-y: auto;
            max-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 12px;
        }
        .header h1 {
            font-size: 26px;
            font-weight: 600;
            color: #f0f2f5;
        }
        .header .time {
            color: #9aa4af;
            font-size: 14px;
        }

        /* === Cards Grid === */
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: #141c24;
            border: 1px solid #1f2a33;
            border-radius: 10px;
            padding: 16px 18px;
            transition: border-color 0.2s;
        }
        .card:hover {
            border-color: #2f4050;
        }
        .card .label {
            font-size: 13px;
            color: #9aa4af;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .card .value {
            font-size: 26px;
            font-weight: 600;
            color: #f0f2f5;
        }
        .card .sub {
            font-size: 13px;
            color: #7a8a9a;
            margin-top: 4px;
        }
        .card .badge {
            background: #1f2a33;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            color: #9aa4af;
        }
        .card.green .value { color: #34d399; }
        .card.red .value { color: #f87171; }
        .card.blue .value { color: #60a5fa; }
        .card.yellow .value { color: #fbbf24; }

        /* === Charts / Graphs === */
        .grid-2col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }
        .panel {
            background: #141c24;
            border: 1px solid #1f2a33;
            border-radius: 10px;
            padding: 16px 18px;
        }
        .panel .panel-title {
            font-size: 15px;
            font-weight: 500;
            color: #d1d5db;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel .panel-title .count {
            background: #1f2a33;
            padding: 0 8px;
            border-radius: 12px;
            font-size: 12px;
            color: #9aa4af;
        }
        .panel .empty {
            color: #5a6a7a;
            text-align: center;
            padding: 20px 0;
            font-size: 14px;
        }

        /* Threat timeline */
        .timeline {
            max-height: 300px;
            overflow-y: auto;
        }
        .timeline-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 8px 0;
            border-bottom: 1px solid #1a222a;
            font-size: 13px;
        }
        .timeline-item .time {
            color: #7a8a9a;
            width: 60px;
            flex-shrink: 0;
            font-size: 12px;
        }
        .timeline-item .severity {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-top: 3px;
        }
        .timeline-item .sev-critical { background: #ef4444; }
        .timeline-item .sev-high { background: #f97316; }
        .timeline-item .sev-medium { background: #eab308; }
        .timeline-item .sev-low { background: #22c55e; }
        .timeline-item .sev-info { background: #3b82f6; }
        .timeline-item .content {
            flex: 1;
            color: #d1d5db;
        }
        .timeline-item .content .path {
            color: #60a5fa;
            font-weight: 500;
        }
        .timeline-item .content .decision {
            display: inline-block;
            padding: 0 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 6px;
        }
        .decision-block {
            background: #7f1d1d;
            color: #fca5a5;
        }
        .decision-allow {
            background: #14532d;
            color: #86efac;
        }

        /* Heatmap (simplified) */
        .heatmap-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 6px;
            padding: 4px 0;
        }
        .heatmap-cell {
            background: #1f2a33;
            border-radius: 4px;
            padding: 6px 0;
            text-align: center;
            font-size: 11px;
            color: #9aa4af;
            transition: background 0.2s;
        }
        .heatmap-cell .count {
            font-weight: 600;
            color: #e5e7eb;
        }
        .heatmap-cell.high {
            background: #7f1d1d;
        }
        .heatmap-cell.medium {
            background: #78350f;
        }
        .heatmap-cell.low {
            background: #1e3a5f;
        }

        /* Blocked requests table */
        .table-wrap {
            max-height: 240px;
            overflow-y: auto;
        }
        .table-wrap table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .table-wrap th {
            text-align: left;
            padding: 8px 4px;
            color: #7a8a9a;
            font-weight: 500;
            border-bottom: 1px solid #1f2a33;
            position: sticky;
            top: 0;
            background: #141c24;
        }
        .table-wrap td {
            padding: 8px 4px;
            border-bottom: 1px solid #1a222a;
            color: #d1d5db;
        }
        .table-wrap .badge-sev {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
            display: inline-block;
        }
        .badge-critical { background: #7f1d1d; color: #fca5a5; }
        .badge-high { background: #7c2d12; color: #fdba74; }
        .badge-medium { background: #713f12; color: #fde047; }
        .badge-low { background: #14532d; color: #86efac; }
        .badge-info { background: #1e3a5f; color: #93c5fd; }

        /* Warnings */
        .warnings-list {
            max-height: 200px;
            overflow-y: auto;
        }
        .warning-item {
            display: flex;
            gap: 10px;
            align-items: flex-start;
            padding: 6px 0;
            border-bottom: 1px solid #1a222a;
            font-size: 13px;
        }
        .warning-item .icon {
            font-size: 16px;
            margin-top: 2px;
        }

        /* Runtime controls */
        .runtime-controls {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 12px;
        }
        .runtime-controls button {
            background: #1f2a33;
            border: 1px solid #2f4050;
            color: #e5e7eb;
            padding: 6px 18px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.15s;
        }
        .runtime-controls button:hover {
            background: #2f4050;
        }
        .runtime-controls button.primary {
            background: #3b82f6;
            border-color: #3b82f6;
            color: #fff;
        }
        .runtime-controls button.primary:hover {
            background: #2563eb;
        }
        .runtime-controls button.danger {
            background: #dc2626;
            border-color: #dc2626;
            color: #fff;
        }
        .runtime-controls button.danger:hover {
            background: #b91c1c;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
            background: #1f2a33;
            color: #9aa4af;
        }
        .status-running { background: #065f46; color: #6ee7b7; }
        .status-paused { background: #78350f; color: #fcd34d; }
        .status-stopped { background: #7f1d1d; color: #fca5a5; }
        .status-error { background: #7f1d1d; color: #fca5a5; }

        /* Responsive */
        @media (max-width: 900px) {
            .sidebar { width: 60px; padding: 16px 8px; }
            .sidebar .logo span { display: none; }
            .sidebar nav a { font-size: 0; padding: 10px 0; text-align: center; }
            .sidebar nav a::before { content: "•"; font-size: 20px; }
            .sidebar .footer { display: none; }
            .grid-2col { grid-template-columns: 1fr; }
            .main { padding: 16px; }
            .cards { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 600px) {
            .cards { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

<!-- Sidebar -->
<div class="sidebar">
    <div class="logo">
        🔒 <span>SR</span>
    </div>
    <nav>
        <a href="#" class="active">Dashboard</a>
        <a href="#">Projects</a>
        <a href="#">Threats</a>
        <a href="#">Analytics</a>
        <a href="#">Logs</a>
        <a href="#">Runtime</a>
        <a href="#">Policies</a>
        <a href="#">Performance</a>
        <a href="#">Settings</a>
    </nav>
    <div class="footer">v1.0.0</div>
</div>

<!-- Main -->
<div class="main">
    <div class="header">
        <h1>Dashboard</h1>
        <div class="time" id="live-time">Loading...</div>
    </div>

    <!-- Cards -->
    <div class="cards" id="cards-container">
        <div class="card blue">
            <div class="label">🛡️ Protected Projects</div>
            <div class="value" id="card-projects">-</div>
            <div class="sub">Active</div>
        </div>
        <div class="card green">
            <div class="label">⚡ Runtime Status</div>
            <div class="value" id="card-runtime-status">-</div>
            <div class="sub" id="card-runtime-uptime">-</div>
        </div>
        <div class="card">
            <div class="label">📥 Requests/sec</div>
            <div class="value" id="card-requests">-</div>
            <div class="sub" id="card-requests-detail">Allowed / Blocked</div>
        </div>
        <div class="card red">
            <div class="label">🚨 Active Threats</div>
            <div class="value" id="card-threats">-</div>
            <div class="sub" id="card-threats-detail">Last 24h</div>
        </div>
        <div class="card yellow">
            <div class="label">⚠️ Warnings</div>
            <div class="value" id="card-warnings">-</div>
            <div class="sub">Action required</div>
        </div>
        <div class="card blue">
            <div class="label">📊 Security Score</div>
            <div class="value" id="card-security-score">-</div>
            <div class="sub" id="card-score-detail">-</div>
        </div>
    </div>

    <!-- 2-col: Graph + Timeline -->
    <div class="grid-2col">
        <!-- Request Graph -->
        <div class="panel">
            <div class="panel-title">
                <span>📈 Live Request Rate</span>
                <span class="count">updates / 1s</span>
            </div>
            <canvas id="requestChart" height="120" style="width:100%; height:120px; background:#0b0e11; border-radius:6px;"></canvas>
        </div>

        <!-- Threat Timeline -->
        <div class="panel">
            <div class="panel-title">
                <span>⏳ Threat Timeline</span>
                <span class="count" id="threat-count">0</span>
            </div>
            <div class="timeline" id="timeline-container">
                <div class="empty">No threats yet</div>
            </div>
        </div>
    </div>

    <!-- 2-col: Heatmap + Blocked Requests -->
    <div class="grid-2col">
        <!-- Attack Heatmap -->
        <div class="panel">
            <div class="panel-title">
                <span>🔥 Attack Heatmap</span>
                <span class="count">endpoint severity</span>
            </div>
            <div id="heatmap-container">
                <div class="empty">Loading heatmap...</div>
            </div>
        </div>

        <!-- Blocked Requests -->
        <div class="panel">
            <div class="panel-title">
                <span>🚫 Blocked Requests</span>
                <span class="count" id="blocked-count">0</span>
            </div>
            <div class="table-wrap" id="blocked-table-wrap">
                <table>
                    <thead><tr><th>Method</th><th>Path</th><th>Reason</th><th>Severity</th><th>Decision</th><th>Time</th></tr></thead>
                    <tbody id="blocked-table-body">
                        <tr><td colspan="6" style="text-align:center;color:#5a6a7a;">No blocked requests</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Performance + Warnings -->
    <div class="grid-2col">
        <!-- Performance -->
        <div class="panel">
            <div class="panel-title">
                <span>⚙️ Performance</span>
                <span class="count">live</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                <div><span style="color:#7a8a9a;font-size:13px;">CPU</span><br><span id="perf-cpu" style="font-weight:600;">-</span></div>
                <div><span style="color:#7a8a9a;font-size:13px;">RAM</span><br><span id="perf-ram" style="font-weight:600;">-</span></div>
                <div><span style="color:#7a8a9a;font-size:13px;">Avg Scan</span><br><span id="perf-scan" style="font-weight:600;">-</span></div>
                <div><span style="color:#7a8a9a;font-size:13px;">Runtime Cost</span><br><span id="perf-cost" style="font-weight:600;">-</span></div>
                <div><span style="color:#7a8a9a;font-size:13px;">Requests</span><br><span id="perf-reqs" style="font-weight:600;">-</span></div>
                <div><span style="color:#7a8a9a;font-size:13px;">Blocked %</span><br><span id="perf-blocked" style="font-weight:600;">-</span></div>
            </div>
        </div>

        <!-- Warnings -->
        <div class="panel">
            <div class="panel-title">
                <span>⚠️ Warnings</span>
                <span class="count" id="warnings-count">0</span>
            </div>
            <div class="warnings-list" id="warnings-container">
                <div class="empty">No warnings</div>
            </div>
        </div>
    </div>

    <!-- Runtime Controls -->
    <div class="panel" style="margin-top:20px;">
        <div class="panel-title">
            <span>🔄 Runtime Controls</span>
            <span id="runtime-status-badge" class="status-badge">Unknown</span>
        </div>
        <div class="runtime-controls">
            <button class="primary" data-action="start">▶ Start</button>
            <button data-action="pause">⏸ Pause</button>
            <button class="danger" data-action="stop">⏹ Stop</button>
            <button data-action="restart">🔄 Restart</button>
            <button data-action="reload">📄 Reload Policies</button>
            <span style="color:#7a8a9a;font-size:13px;margin-left:auto;" id="runtime-version">v1.0.0</span>
        </div>
    </div>
</div>

<script>
// ============================================================
// WebSocket Connection
// ============================================================
let ws = null;
let chartData = [];
const MAX_CHART_POINTS = 60;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };

    ws.onclose = () => {
        console.log('WebSocket disconnected, reconnecting...');
        setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = (err) => {
        console.error('WebSocket error:', err);
    };
}

// ============================================================
// Dashboard Update
// ============================================================

function updateDashboard(data) {
    // Time
    document.getElementById('live-time').textContent = new Date(data.timestamp).toLocaleString();

    // Cards
    const projects = data.projects || [];
    document.getElementById('card-projects').textContent = projects.length;
    document.getElementById('card-runtime-status').textContent = data.runtime.status.toUpperCase();
    document.getElementById('card-runtime-status').className = 'status-badge status-' + data.runtime.status;
    document.getElementById('card-runtime-uptime').textContent = 'Uptime: ' + data.runtime.uptime;

    const metrics = data.metrics || {};
    document.getElementById('card-requests').textContent = metrics.rate_per_second || '0';
    document.getElementById('card-requests-detail').textContent =
        (metrics.allowed_requests || 0) + ' / ' + (metrics.blocked_requests || 0);

    const threats = data.threats || [];
    const activeThreats = threats.filter(t => t.status === 'active').length;
    document.getElementById('card-threats').textContent = activeThreats;
    document.getElementById('card-threats-detail').textContent = 'Total: ' + threats.length;

    const warnings = data.warnings || [];
    document.getElementById('card-warnings').textContent = warnings.length;

    const score = data.security_score || 0;
    document.getElementById('card-security-score').textContent = score;
    let scoreColor = '#34d399';
    if (score < 40) scoreColor = '#f87171';
    else if (score < 70) scoreColor = '#fbbf24';
    document.getElementById('card-security-score').style.color = scoreColor;
    document.getElementById('card-score-detail').textContent = score >= 70 ? 'Good' : score >= 40 ? 'Fair' : 'Poor';

    // Request Graph
    const rate = metrics.rate_per_second || 0;
    chartData.push(rate);
    if (chartData.length > MAX_CHART_POINTS) chartData.shift();
    drawChart(chartData);

    // Timeline
    renderTimeline(threats);

    // Heatmap
    renderHeatmap(threats);

    // Blocked requests
    renderBlocked(threats);

    // Performance
    const perf = data.performance || {};
    document.getElementById('perf-cpu').textContent = perf.cpu_percent + '%';
    document.getElementById('perf-ram').textContent = perf.memory_mb + ' MB';
    document.getElementById('perf-scan').textContent = perf.avg_scan_time_ms + ' ms';
    document.getElementById('perf-cost').textContent = perf.avg_runtime_cost_ms + ' ms';
    document.getElementById('perf-reqs').textContent = perf.requests_processed || 0;
    const blockPct = perf.requests_processed > 0 ? ((perf.requests_blocked / perf.requests_processed) * 100).toFixed(1) : 0;
    document.getElementById('perf-blocked').textContent = blockPct + '%';

    // Warnings
    renderWarnings(warnings);

    // Runtime status badge
    const statusEl = document.getElementById('runtime-status-badge');
    statusEl.textContent = data.runtime.status.toUpperCase();
    statusEl.className = 'status-badge status-' + data.runtime.status;
    document.getElementById('runtime-version').textContent = 'v' + data.runtime.version;

    // Counts
    document.getElementById('threat-count').textContent = threats.length;
    document.getElementById('blocked-count').textContent = threats.filter(t => t.decision === 'block').length;
    document.getElementById('warnings-count').textContent = warnings.length;
}

// ============================================================
// Render Functions
// ============================================================

function renderTimeline(threats) {
    const container = document.getElementById('timeline-container');
    if (!threats || threats.length === 0) {
        container.innerHTML = '<div class="empty">No threats yet</div>';
        return;
    }
    const recent = threats.slice(-15).reverse();
    let html = '';
    for (const t of recent) {
        const sevClass = 'sev-' + t.severity;
        const time = new Date(t.timestamp).toLocaleTimeString();
        const decisionClass = t.decision === 'block' ? 'decision-block' : 'decision-allow';
        html += `<div class="timeline-item">
            <div class="time">${time}</div>
            <div class="severity ${sevClass}"></div>
            <div class="content">
                <span class="path">${t.method} ${t.path}</span>
                <span class="decision ${decisionClass}">${t.decision.toUpperCase()}</span>
                <br><span style="color:#7a8a9a;font-size:12px;">${t.reason} (${t.source_ip})</span>
            </div>
        </div>`;
    }
    container.innerHTML = html;
}

function renderHeatmap(threats) {
    const container = document.getElementById('heatmap-container');
    if (!threats || threats.length === 0) {
        container.innerHTML = '<div class="empty">No attack data</div>';
        return;
    }
    // Group by path + severity
    const map = {};
    for (const t of threats) {
        const key = t.path;
        if (!map[key]) map[key] = { critical:0, high:0, medium:0, low:0 };
        map[key][t.severity] = (map[key][t.severity] || 0) + 1;
    }
    const entries = Object.entries(map).slice(0, 12);
    let html = '<div class="heatmap-grid">';
    for (const [path, counts] of entries) {
        const total = counts.critical + counts.high + counts.medium + counts.low;
        let level = 'low';
        if (counts.critical > 0) level = 'high';
        else if (counts.high > 2) level = 'high';
        else if (counts.medium > 3) level = 'medium';
        const label = path.length > 12 ? path.substring(0,10)+'…' : path;
        html += `<div class="heatmap-cell ${level}">
            <div class="count">${total}</div>
            <div>${label}</div>
        </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
}

function renderBlocked(threats) {
    const tbody = document.getElementById('blocked-table-body');
    const blocked = threats.filter(t => t.decision === 'block').slice(-10).reverse();
    if (blocked.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#5a6a7a;">No blocked requests</td></tr>';
        return;
    }
    let html = '';
    for (const t of blocked) {
        const time = new Date(t.timestamp).toLocaleTimeString();
        const sevBadge = 'badge-' + t.severity;
        html += `<tr>
            <td>${t.method}</td>
            <td style="color:#60a5fa;">${t.path}</td>
            <td>${t.reason}</td>
            <td><span class="badge-sev ${sevBadge}">${t.severity.toUpperCase()}</span></td>
            <td><span class="decision-block" style="padding:2px 6px;border-radius:4px;font-size:11px;">BLOCK</span></td>
            <td>${time}</td>
        </tr>`;
    }
    tbody.innerHTML = html;
}

function renderWarnings(warnings) {
    const container = document.getElementById('warnings-container');
    if (!warnings || warnings.length === 0) {
        container.innerHTML = '<div class="empty">No warnings</div>';
        return;
    }
    let html = '';
    for (const w of warnings) {
        const icon = w.severity === 'critical' ? '🔴' : w.severity === 'high' ? '🟠' : w.severity === 'medium' ? '🟡' : '🔵';
        html += `<div class="warning-item">
            <div class="icon">${icon}</div>
            <div><strong>${w.title}</strong><br><span style="color:#7a8a9a;font-size:12px;">${w.description}</span></div>
        </div>`;
    }
    container.innerHTML = html;
}

// ============================================================
// Chart
// ============================================================

function drawChart(data) {
    const canvas = document.getElementById('requestChart');
    const ctx = canvas.getContext('2d');
    const w = canvas.width || canvas.parentElement.clientWidth || 400;
    const h = canvas.height || 120;
    canvas.width = w;
    canvas.height = h;
    ctx.clearRect(0, 0, w, h);

    if (data.length < 2) {
        ctx.fillStyle = '#5a6a7a';
        ctx.font = '14px sans-serif';
        ctx.fillText('Waiting for data...', 10, 60);
        return;
    }

    const max = Math.max(10, ...data) * 1.2;
    const step = w / Math.max(1, data.length - 1);
    const baseline = h - 10;

    ctx.strokeStyle = '#60a5fa';
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = baseline - (data[i] / max) * (h - 20);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Fill
    ctx.lineTo((data.length - 1) * step, baseline);
    ctx.lineTo(0, baseline);
    ctx.closePath();
    ctx.fillStyle = 'rgba(96, 165, 250, 0.15)';
    ctx.fill();

    // Current value
    const last = data[data.length - 1] || 0;
    ctx.fillStyle = '#e5e7eb';
    ctx.font = '12px sans-serif';
    ctx.fillText(last.toFixed(1) + ' req/s', w - 80, 20);
}

// ============================================================
// Runtime Controls
// ============================================================

document.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
        const action = btn.dataset.action;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            alert('WebSocket not connected');
            return;
        }
        ws.send(JSON.stringify({ action: action }));
    });
});

// ============================================================
// Init
// ============================================================

connectWebSocket();

// Resize chart on window resize
window.addEventListener('resize', () => {
    if (chartData.length) drawChart(chartData);
});
</script>
</body>
</html>
"""


# ----------------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():
    return DASHBOARD_HTML


@app.get("/api/projects")
async def api_projects():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_projects()


@app.get("/api/runtime")
async def api_runtime():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_runtime_status()


@app.get("/api/metrics")
async def api_metrics():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_metrics()


@app.get("/api/threats")
async def api_threats():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_threats()


@app.get("/api/warnings")
async def api_warnings():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_warnings()


@app.get("/api/performance")
async def api_performance():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return data_provider.get_performance()


@app.get("/api/security-score")
async def api_security_score():
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    return {"score": data_provider.get_security_score()}


@app.get("/api/health")
async def api_health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.post("/api/runtime/{action}")
async def api_runtime_action(action: str):
    if data_provider is None:
        raise HTTPException(status_code=503, detail="Data provider not initialized")
    valid_actions = {"start", "pause", "stop", "restart", "reload"}
    if action not in valid_actions:
        raise HTTPException(status_code=400, detail="Invalid action")
    # Map actions to status changes
    status_map = {
        "start": "running",
        "pause": "paused",
        "stop": "stopped",
        "restart": "running",
        "reload": None,
    }
    if action == "restart":
        data_provider.set_runtime_status("running")
        # Also reset start time
        metrics = data_provider._read_runtime_metrics()
        metrics["started_at"] = datetime.now().isoformat()
        try:
            with open("runtime_metrics.json", "w") as f:
                json.dump(metrics, f, indent=2)
        except Exception:
            pass
    elif action == "reload":
        # Reload policies - just a placeholder
        pass
    else:
        new_status = status_map.get(action)
        if new_status:
            data_provider.set_runtime_status(new_status)
    return {"status": "ok", "action": action}


# ----------------------------------------------------------------------------
# WebSocket Endpoint
# ----------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        # Send initial data
        if data_provider is None:
            await websocket.send_json({"error": "Data provider not initialized"})
            return
        initial = data_provider.get_dashboard_data()
        await websocket.send_json(initial)

        # Push updates every second
        while True:
            # Check for client messages (runtime controls)
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                try:
                    data = json.loads(msg)
                    action = data.get("action")
                    if action in ("start", "pause", "stop", "restart", "reload"):
                        # Use the API handler logic
                        if action == "start":
                            data_provider.set_runtime_status("running")
                        elif action == "pause":
                            data_provider.set_runtime_status("paused")
                        elif action == "stop":
                            data_provider.set_runtime_status("stopped")
                        elif action == "restart":
                            data_provider.set_runtime_status("running")
                            metrics = data_provider._read_runtime_metrics()
                            metrics["started_at"] = datetime.now().isoformat()
                            try:
                                with open("runtime_metrics.json", "w") as f:
                                    json.dump(metrics, f, indent=2)
                            except Exception:
                                pass
                        elif action == "reload":
                            pass
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                pass

            # Send update
            if data_provider:
                update = data_provider.get_dashboard_data()
                await websocket.send_json(update)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        active_connections.discard(websocket)


# ============================================================================
# Main Entry Point
# ============================================================================

def open_browser():
    webbrowser.open("http://localhost:8080")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Security Runtime Dashboard")
    parser.add_argument("project_path", nargs="?", default=".", help="Project directory to analyze")
    args = parser.parse_args()

    global data_provider
    data_provider = RuntimeDataProvider(project_path=args.project_path)

    print("=" * 60)
    print("  Security Runtime Dashboard")
    print("=" * 60)
    print("\nTechnology Detection Complete")
    print("Project Intelligence Complete")
    print("Runtime Started")
    print("\nDashboard: http://localhost:8080")
    print("=" * 60)

    # Open browser after a short delay
    Thread(target=open_browser, daemon=True).start()

    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()