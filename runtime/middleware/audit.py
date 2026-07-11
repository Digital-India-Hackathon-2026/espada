# runtime/middleware/audit.py
"""
Audit Middleware for Secure Runtime

This module provides comprehensive audit logging for all runtime events,
including authentication, authorization, security threats, policy violations,
and system events. Audit entries are stored persistently with support for
querying, exporting, and compliance reporting.
"""

import json
import asyncio
import logging
import sqlite3
import csv
import io
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable, Iterator
from enum import StrEnum
from dataclasses import dataclass, field, asdict
from pathlib import Path
import aiosqlite

from runtime.core.context import RuntimeContext
from runtime.core.request import Request
from runtime.core.response import Response
from runtime.core.events import get_event_bus, Event
from runtime.core.errors import (
    RuntimeError as RuntimeErrorBase,
    AuthenticationError,
    AuthorizationError,
    ThreatDetectedError,
    SecretDetectedError,
    PromptInjectionError,
    PolicyViolationError,
)
from runtime.core.state import SecurityState


class AuditSeverity(StrEnum):
    """Audit event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    DEBUG = "debug"


class AuditCategory(StrEnum):
    """Audit event categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    THREAT = "threat"
    POLICY = "policy"
    SYSTEM = "system"
    CONFIGURATION = "configuration"
    PLUGIN = "plugin"
    RUNTIME = "runtime"
    REQUEST = "request"
    ERROR = "error"
    SECURITY = "security"


class AuditOutcome(StrEnum):
    """Audit event outcomes"""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class AuditEntry:
    """Individual audit log entry"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    category: AuditCategory = AuditCategory.SYSTEM
    severity: AuditSeverity = AuditSeverity.INFO
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    action: str = ""
    resource: str = ""
    reason: Optional[str] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    event_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit entry to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat() if self.timestamp else None
        data['category'] = self.category.value
        data['severity'] = self.severity.value
        data['outcome'] = self.outcome.value
        return data
    
    def to_json(self) -> str:
        """Convert audit entry to JSON"""
        return json.dumps(self.to_dict(), default=str)
    
    def to_csv_row(self) -> List[str]:
        """Convert audit entry to CSV row"""
        return [
            self.timestamp.isoformat() if self.timestamp else "",
            self.user_id or "",
            self.client_ip or "",
            self.request_id or "",
            self.session_id or "",
            self.category.value,
            self.severity.value,
            self.outcome.value,
            self.action,
            self.resource,
            self.reason or "",
            self.message,
            json.dumps(self.metadata, default=str),
            self.source or "",
            self.event_type or "",
        ]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Create audit entry from dictionary"""
        # Convert timestamp string to datetime if needed
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        
        # Convert enums from strings
        if 'category' in data and isinstance(data['category'], str):
            data['category'] = AuditCategory(data['category'])
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = AuditSeverity(data['severity'])
        if 'outcome' in data and isinstance(data['outcome'], str):
            data['outcome'] = AuditOutcome(data['outcome'])
        
        return cls(**data)


class AuditStorage:
    """Storage backend for audit entries"""
    
    def __init__(self, db_path: str = "./audit.db", max_entries: int = 1000000):
        """
        Initialize audit storage
        
        Args:
            db_path: Path to SQLite database file
            max_entries: Maximum number of entries before rotation
        """
        self.db_path = db_path
        self.max_entries = max_entries
        self._logger = logging.getLogger("runtime.audit.storage")
        self._initialized = False
        self._initialize_db()
    
    def _initialize_db(self) -> None:
        """Initialize the database schema"""
        try:
            # Ensure directory exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id TEXT,
                        client_ip TEXT,
                        request_id TEXT,
                        session_id TEXT,
                        correlation_id TEXT,
                        category TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        reason TEXT,
                        message TEXT,
                        metadata TEXT,
                        source TEXT,
                        event_type TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for common queries
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_entries(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_entries(category)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_entries(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_entries(request_id)")
                
                self._initialized = True
                
        except Exception as e:
            self._logger.error(f"Failed to initialize audit database: {e}")
            raise
    
    async def store(self, entry: AuditEntry) -> int:
        """
        Store an audit entry
        
        Args:
            entry: Audit entry to store
            
        Returns:
            int: Entry ID
        """
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                cursor = await conn.execute("""
                    INSERT INTO audit_entries (
                        timestamp, user_id, client_ip, request_id, session_id,
                        correlation_id, category, severity, outcome, action,
                        resource, reason, message, metadata, source, event_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.timestamp.isoformat(),
                    entry.user_id,
                    entry.client_ip,
                    entry.request_id,
                    entry.session_id,
                    entry.correlation_id,
                    entry.category.value,
                    entry.severity.value,
                    entry.outcome.value,
                    entry.action,
                    entry.resource,
                    entry.reason,
                    entry.message,
                    json.dumps(entry.metadata, default=str),
                    entry.source,
                    entry.event_type,
                ))
                await conn.commit()
                
                entry_id = cursor.lastrowid
                
                # Check if we need to rotate
                if self.max_entries and entry_id > self.max_entries:
                    await self._rotate_entries()
                
                return entry_id
                
        except Exception as e:
            self._logger.error(f"Failed to store audit entry: {e}")
            raise
    
    async def _rotate_entries(self) -> None:
        """Remove oldest entries to maintain size limit"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                # Delete oldest entries, keeping max_entries
                await conn.execute("""
                    DELETE FROM audit_entries 
                    WHERE id IN (
                        SELECT id FROM audit_entries 
                        ORDER BY id ASC 
                        LIMIT ? 
                    )
                """, (self.max_entries // 10,))  # Remove 10% of entries
                await conn.commit()
                self._logger.info(f"Rotated audit entries (limit: {self.max_entries})")
                
        except Exception as e:
            self._logger.error(f"Failed to rotate audit entries: {e}")
    
    async def search(
        self,
        user_id: Optional[str] = None,
        category: Optional[AuditCategory] = None,
        severity: Optional[AuditSeverity] = None,
        outcome: Optional[AuditOutcome] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """
        Search audit entries with filters
        
        Args:
            user_id: Filter by user ID
            category: Filter by category
            severity: Filter by severity
            outcome: Filter by outcome
            action: Filter by action
            resource: Filter by resource
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum results
            offset: Results offset
            
        Returns:
            List[AuditEntry]: Matching audit entries
        """
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM audit_entries WHERE 1=1"
                params = []
                
                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)
                if category:
                    query += " AND category = ?"
                    params.append(category.value)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity.value)
                if outcome:
                    query += " AND outcome = ?"
                    params.append(outcome.value)
                if action:
                    query += " AND action LIKE ?"
                    params.append(f"%{action}%")
                if resource:
                    query += " AND resource LIKE ?"
                    params.append(f"%{resource}%")
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor = await conn.execute(query, params)
                rows = await cursor.fetchall()
                
                entries = []
                for row in rows:
                    entry_data = dict(row)
                    # Parse metadata
                    if entry_data.get('metadata'):
                        entry_data['metadata'] = json.loads(entry_data['metadata'])
                    entry_data['category'] = AuditCategory(entry_data['category'])
                    entry_data['severity'] = AuditSeverity(entry_data['severity'])
                    entry_data['outcome'] = AuditOutcome(entry_data['outcome'])
                    entry_data['timestamp'] = datetime.fromisoformat(entry_data['timestamp'])
                    entries.append(AuditEntry(**entry_data))
                
                return entries
                
        except Exception as e:
            self._logger.error(f"Failed to search audit entries: {e}")
            return []
    
    async def count(
        self,
        user_id: Optional[str] = None,
        category: Optional[AuditCategory] = None,
        severity: Optional[AuditSeverity] = None,
        outcome: Optional[AuditOutcome] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Count audit entries matching filters
        
        Args:
            user_id: Filter by user ID
            category: Filter by category
            severity: Filter by severity
            outcome: Filter by outcome
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            int: Count of matching entries
        """
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                query = "SELECT COUNT(*) FROM audit_entries WHERE 1=1"
                params = []
                
                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)
                if category:
                    query += " AND category = ?"
                    params.append(category.value)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity.value)
                if outcome:
                    query += " AND outcome = ?"
                    params.append(outcome.value)
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())
                
                cursor = await conn.execute(query, params)
                result = await cursor.fetchone()
                return result[0] if result else 0
                
        except Exception as e:
            self._logger.error(f"Failed to count audit entries: {e}")
            return 0
    
    async def export_csv(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 10000,
    ) -> str:
        """
        Export audit entries as CSV
        
        Args:
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum entries to export
            
        Returns:
            str: CSV data
        """
        try:
            entries = await self.search(
                start_time=start_time,
                end_time=end_time,
                limit=limit,
            )
            
            if not entries:
                return ""
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "id", "timestamp", "user_id", "client_ip", "request_id",
                "session_id", "correlation_id", "category", "severity",
                "outcome", "action", "resource", "reason", "message",
                "metadata", "source", "event_type"
            ])
            
            # Write data
            for entry in entries:
                writer.writerow([
                    entry.id,
                    entry.timestamp.isoformat(),
                    entry.user_id or "",
                    entry.client_ip or "",
                    entry.request_id or "",
                    entry.session_id or "",
                    entry.correlation_id or "",
                    entry.category.value,
                    entry.severity.value,
                    entry.outcome.value,
                    entry.action,
                    entry.resource,
                    entry.reason or "",
                    entry.message,
                    json.dumps(entry.metadata, default=str),
                    entry.source or "",
                    entry.event_type or "",
                ])
            
            return output.getvalue()
            
        except Exception as e:
            self._logger.error(f"Failed to export audit entries: {e}")
            return ""
    
    async def export_json(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 10000,
    ) -> str:
        """
        Export audit entries as JSON
        
        Args:
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum entries to export
            
        Returns:
            str: JSON data
        """
        try:
            entries = await self.search(
                start_time=start_time,
                end_time=end_time,
                limit=limit,
            )
            
            data = [entry.to_dict() for entry in entries]
            return json.dumps(data, indent=2, default=str)
            
        except Exception as e:
            self._logger.error(f"Failed to export audit entries: {e}")
            return "[]"
    
    async def cleanup(self, older_than_days: int = 90) -> int:
        """
        Clean up old audit entries
        
        Args:
            older_than_days: Delete entries older than this many days
            
        Returns:
            int: Number of entries deleted
        """
        try:
            cutoff = datetime.utcnow() - timedelta(days=older_than_days)
            
            async with aiosqlite.connect(self.db_path) as conn:
                cursor = await conn.execute(
                    "DELETE FROM audit_entries WHERE timestamp < ?",
                    (cutoff.isoformat(),)
                )
                await conn.commit()
                
                deleted = cursor.rowcount
                self._logger.info(f"Cleaned up {deleted} audit entries older than {older_than_days} days")
                return deleted
                
        except Exception as e:
            self._logger.error(f"Failed to cleanup audit entries: {e}")
            return 0
    
    async def close(self) -> None:
        """Close database connection"""
        # No-op for aiosqlite (connections are created per operation)
        pass


class AuditLogger:
    """Main audit logging interface"""
    
    def __init__(
        self,
        storage: Optional[AuditStorage] = None,
        db_path: str = "./audit.db",
        enable_async_logging: bool = True,
    ):
        """
        Initialize audit logger
        
        Args:
            storage: Audit storage instance (optional)
            db_path: Path to database (if storage not provided)
            enable_async_logging: Enable asynchronous logging
        """
        self.storage = storage or AuditStorage(db_path)
        self.enable_async_logging = enable_async_logging
        self._logger = logging.getLogger("runtime.audit.logger")
        self._event_bus = None
    
    async def log(
        self,
        action: str,
        resource: str,
        category: AuditCategory = AuditCategory.SYSTEM,
        severity: AuditSeverity = AuditSeverity.INFO,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Optional[int]:
        """
        Log an audit entry
        
        Args:
            action: The action being audited
            resource: The resource being accessed
            category: Audit category
            severity: Severity level
            outcome: Outcome of the action
            user_id: User identifier
            client_ip: Client IP address
            request_id: Request identifier
            session_id: Session identifier
            correlation_id: Correlation identifier
            message: Human-readable message
            reason: Reason for the outcome
            metadata: Additional metadata
            source: Source component
            event_type: Event type identifier
            
        Returns:
            Optional[int]: Entry ID if stored
        """
        entry = AuditEntry(
            action=action,
            resource=resource,
            category=category,
            severity=severity,
            outcome=outcome,
            user_id=user_id,
            client_ip=client_ip,
            request_id=request_id,
            session_id=session_id,
            correlation_id=correlation_id,
            message=message or "",
            reason=reason,
            metadata=metadata or {},
            source=source,
            event_type=event_type,
        )
        
        if self.enable_async_logging:
            # Fire and forget - log asynchronously
            asyncio.create_task(self._store_entry(entry))
            return None
        else:
            # Store synchronously
            try:
                entry_id = await self.storage.store(entry)
                
                # Publish event if event bus is available
                if self._event_bus:
                    asyncio.create_task(self._publish_event(entry))
                
                self._logger.debug(f"Audit entry stored: {entry_id}")
                return entry_id
                
            except Exception as e:
                self._logger.error(f"Failed to store audit entry: {e}")
                return None
    
    async def _store_entry(self, entry: AuditEntry) -> None:
        """Store entry asynchronously"""
        try:
            entry_id = await self.storage.store(entry)
            
            # Publish event if event bus is available
            if self._event_bus:
                await self._publish_event(entry)
            
            self._logger.debug(f"Audit entry stored: {entry_id}")
            
        except Exception as e:
            self._logger.error(f"Failed to store audit entry: {e}")
    
    async def _publish_event(self, entry: AuditEntry) -> None:
        """Publish audit event"""
        if not self._event_bus:
            return
        
        try:
            await self._event_bus.emit(
                "audit.entry",
                payload={
                    "id": entry.id,
                    "action": entry.action,
                    "resource": entry.resource,
                    "category": entry.category.value,
                    "severity": entry.severity.value,
                    "outcome": entry.outcome.value,
                    "user_id": entry.user_id,
                    "request_id": entry.request_id,
                    "session_id": entry.session_id,
                }
            )
        except Exception as e:
            self._logger.error(f"Failed to publish audit event: {e}")
    
    def log_from_context(
        self,
        context: RuntimeContext,
        action: str,
        resource: str,
        category: AuditCategory = AuditCategory.SYSTEM,
        severity: AuditSeverity = AuditSeverity.INFO,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        """
        Log an audit entry using data from a runtime context
        
        Args:
            context: Runtime context
            action: The action being audited
            resource: The resource being accessed
            category: Audit category
            severity: Severity level
            outcome: Outcome of the action
            message: Human-readable message
            reason: Reason for the outcome
            metadata: Additional metadata
            
        Returns:
            Optional[int]: Entry ID if stored
        """
        return asyncio.create_task(self.log(
            action=action,
            resource=resource,
            category=category,
            severity=severity,
            outcome=outcome,
            user_id=context.user_id,
            client_ip=context.request.client_ip if context.request else None,
            request_id=context.request_id,
            session_id=context.session_id,
            correlation_id=context.request.headers.get("x-correlation-id") if context.request else None,
            message=message,
            reason=reason,
            metadata=metadata,
        ))
    
    async def from_exception(
        self,
        exception: Exception,
        context: RuntimeContext,
        action: str,
        resource: str,
    ) -> Optional[int]:
        """
        Log an audit entry from an exception
        
        Args:
            exception: The exception
            context: Runtime context
            action: The action being audited
            resource: The resource being accessed
            
        Returns:
            Optional[int]: Entry ID if stored
        """
        # Determine category and severity from exception type
        if isinstance(exception, AuthenticationError):
            category = AuditCategory.AUTHENTICATION
            severity = AuditSeverity.HIGH
            outcome = AuditOutcome.FAILURE
        elif isinstance(exception, AuthorizationError):
            category = AuditCategory.AUTHORIZATION
            severity = AuditSeverity.HIGH
            outcome = AuditOutcome.FAILURE
        elif isinstance(exception, (ThreatDetectedError, SecretDetectedError, PromptInjectionError)):
            category = AuditCategory.THREAT
            severity = AuditSeverity.CRITICAL
            outcome = AuditOutcome.BLOCKED
        elif isinstance(exception, PolicyViolationError):
            category = AuditCategory.POLICY
            severity = AuditSeverity.HIGH
            outcome = AuditOutcome.BLOCKED
        else:
            category = AuditCategory.ERROR
            severity = AuditSeverity.ERROR
            outcome = AuditOutcome.ERROR
        
        return await self.log(
            action=action,
            resource=resource,
            category=category,
            severity=severity,
            outcome=outcome,
            user_id=context.user_id,
            client_ip=context.request.client_ip if context.request else None,
            request_id=context.request_id,
            session_id=context.session_id,
            message=str(exception),
            reason=type(exception).__name__,
            metadata={
                "exception_type": type(exception).__name__,
                "exception_details": getattr(exception, 'details', {}),
                "trace_id": getattr(exception, 'trace_id', None),
            },
        )
    
    async def search(
        self,
        **filters
    ) -> List[AuditEntry]:
        """
        Search audit entries
        
        Args:
            **filters: Search filters (user_id, category, severity, etc.)
            
        Returns:
            List[AuditEntry]: Matching entries
        """
        return await self.storage.search(**filters)
    
    async def count(
        self,
        **filters
    ) -> int:
        """
        Count audit entries
        
        Args:
            **filters: Count filters
            
        Returns:
            int: Number of entries
        """
        return await self.storage.count(**filters)
    
    async def export_csv(
        self,
        **filters
    ) -> str:
        """
        Export audit entries as CSV
        
        Args:
            **filters: Export filters
            
        Returns:
            str: CSV data
        """
        return await self.storage.export_csv(**filters)
    
    async def export_json(
        self,
        **filters
    ) -> str:
        """
        Export audit entries as JSON
        
        Args:
            **filters: Export filters
            
        Returns:
            str: JSON data
        """
        return await self.storage.export_json(**filters)
    
    async def cleanup(self, older_than_days: int = 90) -> int:
        """
        Clean up old audit entries
        
        Args:
            older_than_days: Delete entries older than this many days
            
        Returns:
            int: Number of entries deleted
        """
        return await self.storage.cleanup(older_than_days)
    
    def set_event_bus(self, event_bus) -> None:
        """Set the event bus for publishing audit events"""
        self._event_bus = event_bus


class AuditMiddleware:
    """
    Audit middleware for the Secure Runtime
    
    This middleware intercepts requests and logs audit entries for all
    significant events that occur during request processing.
    """
    
    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        db_path: str = "./audit.db",
        log_all_requests: bool = False,
        log_security_events: bool = True,
        log_auth_events: bool = True,
        log_policy_events: bool = True,
        log_error_events: bool = True,
        log_system_events: bool = True,
        enable_async_logging: bool = True,
    ):
        """
        Initialize audit middleware
        
        Args:
            audit_logger: Audit logger instance (optional)
            db_path: Path to audit database
            log_all_requests: Log all requests
            log_security_events: Log security events
            log_auth_events: Log authentication/authorization events
            log_policy_events: Log policy events
            log_error_events: Log error events
            log_system_events: Log system events
            enable_async_logging: Enable asynchronous logging
        """
        self.logger = audit_logger or AuditLogger(
            db_path=db_path,
            enable_async_logging=enable_async_logging,
        )
        self.log_all_requests = log_all_requests
        self.log_security_events = log_security_events
        self.log_auth_events = log_auth_events
        self.log_policy_events = log_policy_events
        self.log_error_events = log_error_events
        self.log_system_events = log_system_events
        
        self._logger = logging.getLogger("runtime.middleware.audit")
    
    async def __call__(
        self,
        request: Request,
        context: RuntimeContext,
        next_middleware: Callable[[Request, RuntimeContext], Awaitable[Response]],
    ) -> Response:
        """
        Process the request through audit middleware
        
        Args:
            request: HTTP request
            context: Runtime context
            next_middleware: Next middleware in chain
            
        Returns:
            Response: HTTP response
        """
        # Log request start
        if self.log_all_requests:
            await self.logger.log(
                action="request.received",
                resource=request.path,
                category=AuditCategory.REQUEST,
                severity=AuditSeverity.INFO,
                outcome=AuditOutcome.SUCCESS,
                user_id=context.user_id,
                client_ip=request.client_ip,
                request_id=request.id,
                session_id=context.session_id,
                correlation_id=request.headers.get("x-correlation-id"),
                message=f"Request received: {request.method.value} {request.path}",
                metadata={
                    "method": request.method.value,
                    "path": request.path,
                    "query_params": request.query_params,
                    "content_type": request.content_type,
                    "content_length": request.content_length,
                    "user_agent": request.headers.get("user-agent"),
                },
                source="audit_middleware",
                event_type="request.received",
            )
        
        try:
            # Process the request
            response = await next_middleware(request, context)
            
            # Log based on response
            await self._log_response(request, context, response)
            
            return response
            
        except Exception as e:
            # Log exception
            await self._log_exception(request, context, e)
            raise
    
    async def _log_response(
        self,
        request: Request,
        context: RuntimeContext,
        response: Response,
    ) -> None:
        """Log response details"""
        # Determine category and severity
        if response.is_blocked:
            if response.block_type == "threat":
                category = AuditCategory.THREAT
                severity = AuditSeverity.CRITICAL if self.log_security_events else None
            elif response.block_type == "policy":
                category = AuditCategory.POLICY
                severity = AuditSeverity.HIGH if self.log_policy_events else None
            elif response.block_type in ["injection", "secret"]:
                category = AuditCategory.SECURITY
                severity = AuditSeverity.HIGH if self.log_security_events else None
            else:
                category = AuditCategory.SECURITY
                severity = AuditSeverity.MEDIUM if self.log_security_events else None
            
            if severity:
                await self.logger.log(
                    action="request.blocked",
                    resource=request.path,
                    category=category,
                    severity=severity,
                    outcome=AuditOutcome.BLOCKED,
                    user_id=context.user_id,
                    client_ip=request.client_ip,
                    request_id=request.id,
                    session_id=context.session_id,
                    correlation_id=request.headers.get("x-correlation-id"),
                    message=f"Request blocked: {response.block_reason or 'Unknown reason'}",
                    reason=response.block_reason,
                    metadata={
                        "method": request.method.value,
                        "path": request.path,
                        "block_type": response.block_type,
                        "status_code": response.status_code_int,
                        "security_score": context.security_scores.security_score,
                        "threat_score": context.security_scores.threat_score,
                    },
                    source="audit_middleware",
                    event_type="request.blocked",
                )
        
        elif self.log_all_requests:
            await self.logger.log(
                action="request.completed",
                resource=request.path,
                category=AuditCategory.REQUEST,
                severity=AuditSeverity.INFO,
                outcome=AuditOutcome.SUCCESS,
                user_id=context.user_id,
                client_ip=request.client_ip,
                request_id=request.id,
                session_id=context.session_id,
                correlation_id=request.headers.get("x-correlation-id"),
                message=f"Request completed: {request.method.value} {request.path}",
                metadata={
                    "method": request.method.value,
                    "path": request.path,
                    "status_code": response.status_code_int,
                    "duration": context.execution_time(),
                    "security_score": context.security_scores.security_score,
                },
                source="audit_middleware",
                event_type="request.completed",
            )
    
    async def _log_exception(
        self,
        request: Request,
        context: RuntimeContext,
        exception: Exception,
    ) -> None:
        """Log exception details"""
        if not self.log_error_events:
            return
        
        # Determine category and severity
        if isinstance(exception, AuthenticationError):
            category = AuditCategory.AUTHENTICATION
            severity = AuditSeverity.HIGH if self.log_auth_events else None
        elif isinstance(exception, AuthorizationError):
            category = AuditCategory.AUTHORIZATION
            severity = AuditSeverity.HIGH if self.log_auth_events else None
        elif isinstance(exception, (ThreatDetectedError, SecretDetectedError, PromptInjectionError)):
            category = AuditCategory.THREAT
            severity = AuditSeverity.CRITICAL if self.log_security_events else None
        elif isinstance(exception, PolicyViolationError):
            category = AuditCategory.POLICY
            severity = AuditSeverity.HIGH if self.log_policy_events else None
        else:
            category = AuditCategory.ERROR
            severity = AuditSeverity.MEDIUM
        
        if severity:
            await self.logger.log(
                action="error.occurred",
                resource=request.path,
                category=category,
                severity=severity,
                outcome=AuditOutcome.ERROR,
                user_id=context.user_id,
                client_ip=request.client_ip,
                request_id=request.id,
                session_id=context.session_id,
                correlation_id=request.headers.get("x-correlation-id"),
                message=f"Error processing request: {str(exception)}",
                reason=type(exception).__name__,
                metadata={
                    "method": request.method.value,
                    "path": request.path,
                    "exception_type": type(exception).__name__,
                    "exception_details": getattr(exception, 'details', {}),
                    "trace_id": getattr(exception, 'trace_id', None),
                },
                source="audit_middleware",
                event_type="error.occurred",
            )
    
    # Helper methods for explicit audit logging from other components
    
    async def log_auth_event(
        self,
        context: RuntimeContext,
        action: str,
        resource: str,
        success: bool,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log an authentication or authorization event
        
        Args:
            context: Runtime context
            action: Action being performed
            resource: Resource being accessed
            success: Whether the operation succeeded
            reason: Reason for failure
            metadata: Additional metadata
        """
        if not self.log_auth_events:
            return
        
        category = AuditCategory.AUTHORIZATION if "authorization" in action else AuditCategory.AUTHENTICATION
        outcome = AuditOutcome.SUCCESS if success else AuditOutcome.FAILURE
        severity = AuditSeverity.INFO if success else AuditSeverity.HIGH
        
        await self.logger.log(
            action=action,
            resource=resource,
            category=category,
            severity=severity,
            outcome=outcome,
            user_id=context.user_id,
            client_ip=context.request.client_ip if context.request else None,
            request_id=context.request_id,
            session_id=context.session_id,
            reason=reason,
            metadata=metadata,
            source="audit_middleware",
        )
    
    async def log_security_event(
        self,
        context: RuntimeContext,
        action: str,
        resource: str,
        severity: AuditSeverity = AuditSeverity.HIGH,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a security event
        
        Args:
            context: Runtime context
            action: Action being performed
            resource: Resource being accessed
            severity: Severity level
            reason: Reason for the event
            metadata: Additional metadata
        """
        if not self.log_security_events:
            return
        
        await self.logger.log(
            action=action,
            resource=resource,
            category=AuditCategory.SECURITY,
            severity=severity,
            outcome=AuditOutcome.WARNING,
            user_id=context.user_id,
            client_ip=context.request.client_ip if context.request else None,
            request_id=context.request_id,
            session_id=context.session_id,
            reason=reason,
            metadata=metadata,
            source="audit_middleware",
        )
    
    async def log_policy_event(
        self,
        context: RuntimeContext,
        action: str,
        resource: str,
        violated: bool,
        policy_id: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a policy event
        
        Args:
            context: Runtime context
            action: Action being performed
            resource: Resource being accessed
            violated: Whether the policy was violated
            policy_id: Policy identifier
            reason: Reason for violation
            metadata: Additional metadata
        """
        if not self.log_policy_events:
            return
        
        outcome = AuditOutcome.BLOCKED if violated else AuditOutcome.SUCCESS
        severity = AuditSeverity.HIGH if violated else AuditSeverity.INFO
        
        await self.logger.log(
            action=action,
            resource=resource,
            category=AuditCategory.POLICY,
            severity=severity,
            outcome=outcome,
            user_id=context.user_id,
            client_ip=context.request.client_ip if context.request else None,
            request_id=context.request_id,
            session_id=context.session_id,
            reason=reason or (f"Policy violated: {policy_id}" if policy_id else None),
            metadata={**metadata, "policy_id": policy_id} if policy_id else metadata,
            source="audit_middleware",
        )
    
    async def log_system_event(
        self,
        action: str,
        resource: str,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a system event
        
        Args:
            action: Action being performed
            resource: Resource being accessed
            outcome: Outcome of the action
            message: Human-readable message
            metadata: Additional metadata
        """
        if not self.log_system_events:
            return
        
        await self.logger.log(
            action=action,
            resource=resource,
            category=AuditCategory.SYSTEM,
            severity=AuditSeverity.INFO,
            outcome=outcome,
            message=message,
            metadata=metadata,
            source="audit_middleware",
        )
    
    async def log_config_change(
        self,
        user_id: Optional[str],
        resource: str,
        old_value: Any,
        new_value: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a configuration change
        
        Args:
            user_id: User making the change
            resource: Configuration resource being changed
            old_value: Old configuration value
            new_value: New configuration value
            metadata: Additional metadata
        """
        if not self.log_system_events:
            return
        
        await self.logger.log(
            action="config.changed",
            resource=resource,
            category=AuditCategory.CONFIGURATION,
            severity=AuditSeverity.INFO,
            outcome=AuditOutcome.SUCCESS,
            user_id=user_id,
            message=f"Configuration changed: {resource}",
            metadata={
                "old_value": old_value,
                "new_value": new_value,
                **(metadata or {}),
            },
            source="audit_middleware",
        )
    
    # Storage operations
    
    async def search(self, **filters) -> List[AuditEntry]:
        """Search audit entries"""
        return await self.logger.search(**filters)
    
    async def count(self, **filters) -> int:
        """Count audit entries"""
        return await self.logger.count(**filters)
    
    async def export_csv(self, **filters) -> str:
        """Export audit entries as CSV"""
        return await self.logger.export_csv(**filters)
    
    async def export_json(self, **filters) -> str:
        """Export audit entries as JSON"""
        return await self.logger.export_json(**filters)
    
    async def cleanup(self, older_than_days: int = 90) -> int:
        """Clean up old audit entries"""
        return await self.logger.cleanup(older_than_days)
    
    async def close(self) -> None:
        """Close the audit logger"""
        await self.logger.storage.close()


# Convenience function to create audit middleware
def create_audit_middleware(**kwargs) -> AuditMiddleware:
    """
    Create an audit middleware instance
    
    Args:
        **kwargs: AuditMiddleware configuration
        
    Returns:
        AuditMiddleware: Configured audit middleware
    """
    return AuditMiddleware(**kwargs)