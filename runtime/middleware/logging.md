This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/logging.py

Create a production-grade Logging Middleware.

Responsibilities

Log

Incoming Requests

Outgoing Responses

Errors

Warnings

Performance

Execution Time

Security Events

Authentication Events

Authorization Events

Threat Events

Support

Console Logging

JSON Logging

Structured Logging

File Logging

Log Rotation

Correlation IDs

Trace IDs

Request IDs

Provide

LoggingMiddleware

LogFormatter

LogWriter

Methods

log_request()

log_response()

log_error()

log_security_event()

log_metrics()

Do NOT implement

Threat Detection

Authentication

Runtime

Database

Business Logic

Use

logging

structlog (optional)

Python typing

Async

Production ready

Return ONLY logging.py