This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/authorization.py

Create a production-grade Authorization Middleware.

Responsibilities

Verify access permissions.

Support

RBAC

ABAC

Policy-based Authorization

Permission Groups

Scopes

Roles

Ownership Validation

Admin Access

Guest Access

Resource-level Authorization

Methods

authorize()

check_permission()

check_role()

evaluate_policy()

validate_scope()

Return

Authorization Result

Denied Reason

Matched Policy

Permission Tree

Never implement

Authentication

Threat Detection

Runtime

Database

Business Logic

Only authorization.

Python 3.12

Async

FastAPI compatible

Production ready

Return ONLY authorization.py