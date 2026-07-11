This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/auth.py

Create a production-grade Authentication Middleware.

Responsibilities

Authenticate incoming requests.

Support

JWT Authentication

Bearer Tokens

API Keys

OAuth2

Basic Authentication

Session Authentication

Cookie Authentication

Custom Authentication Providers

Token Refresh

Token Expiration

Multi-Factor Authentication (future support)

Provide

AuthenticationMiddleware

AuthenticationResult

AuthenticationProvider

AuthenticationContext

Methods

authenticate()

verify_token()

validate_api_key()

validate_session()

extract_credentials()

refresh_token()

revoke_token()

Return

Authenticated User

Roles

Permissions

Claims

Scopes

Token Metadata

Never implement

Authorization

Threat Detection

Runtime

Database Queries

Business Logic

Only authenticate.

Python 3.12

FastAPI compatible

Dependency Injection

Async

Production ready

Return ONLY auth.py