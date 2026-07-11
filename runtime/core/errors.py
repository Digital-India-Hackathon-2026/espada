Assume all other project files already exist.

Never redefine classes that belong in another module.

Always import existing models instead of recreating them.

Generate ONLY

runtime/core/errors.py

This file contains every custom exception used by Secure Runtime.

Create a base exception

RuntimeError

Then create child exceptions

ConfigurationError

InitializationError

AuthenticationError

AuthorizationError

ValidationError

RateLimitError

ThreatDetectedError

SecretDetectedError

PromptInjectionError

PolicyViolationError

AIEngineError

RouterError

MiddlewareError

PluginError

DatabaseError

CacheError

SerializationError

TimeoutError

ShutdownError

HealthCheckError

NetworkError

Each exception should contain

Error Code

Message

Timestamp

Details

Severity

HTTP Status

Trace ID

Provide helper methods

to_dict()

to_json()

log()

__str__()

Fully documented.

Production ready.

Do NOT implement

Runtime

Business Logic

Database

Authentication

Detection

Return ONLY errors.py