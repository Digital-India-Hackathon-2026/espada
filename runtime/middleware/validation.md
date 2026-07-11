This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY

runtime/middleware/validation.py

Create a production-grade Request Validation Middleware.

Responsibilities

Validate

Headers

JSON Body

Form Data

Multipart Data

Content Type

Request Size

Encoding

Required Fields

Query Parameters

Cookies

Path Parameters

JSON Schema

Pydantic Models

Provide

ValidationMiddleware

ValidationResult

ValidationRule

Methods

validate()

validate_headers()

validate_json()

validate_query()

validate_form()

Return

Validation Errors

Warnings

Suggestions

Never implement

Threat Detection

Authentication

Database

Runtime

Business Logic

Python 3.12

Async

FastAPI compatible

Production ready

Return ONLY validation.py