This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/audit.py

Create a production-grade Audit Middleware.

Responsibilities

Record

Authentication Events

Authorization Events

Threat Events

Blocked Requests

Policy Violations

Configuration Changes

Plugin Events

Runtime Events

Errors

Warnings

Every audit record should contain

Timestamp

User

IP Address

Request ID

Session ID

Action

Resource

Severity

Outcome

Reason

Metadata

Provide

AuditMiddleware

AuditEntry

AuditLogger

Methods

record()

search()

export()

filter()

cleanup()

Support

SQLite

PostgreSQL (future)

JSON Export

CSV Export

Compliance Logging

Tamper Detection (future)

Never implement

Authentication

Threat Detection

Runtime

Business Logic

Only auditing.

Python 3.12

Async

FastAPI compatible

Production ready

Return ONLY audit.py