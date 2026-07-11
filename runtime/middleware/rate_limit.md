This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/rate_limit.py

Create a production-grade Rate Limiting Middleware.

Support

Token Bucket

Sliding Window

Fixed Window

Leaky Bucket

Distributed Rate Limiting (future)

Limit by

IP

API Key

User

Session

Route

Method

Headers

Country

Provide

RateLimitMiddleware

RateLimiter

RateLimitResult

Methods

allow()

check()

consume()

reset()

remaining()

retry_after()

Return

Remaining Requests

Retry Time

Window

Current Usage

Do NOT implement

Authentication

Threat Detection

Database

Runtime

Business Logic

Use asyncio

Python typing

FastAPI compatible

Production ready

Return ONLY rate_limit.py