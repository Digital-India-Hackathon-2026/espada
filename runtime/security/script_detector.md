Assume all other project files already exist.

Never redefine classes that belong in another module.

Always import existing models instead of recreating them.

Generate ONLY

runtime/security/secret_detector.py

Create a production-grade Secret Detection Engine.

Responsibilities

Detect

AWS Keys

Azure Keys

GCP Keys

GitHub Tokens

GitLab Tokens

OpenAI Keys

Anthropic Keys

Google API Keys

Stripe Keys

Twilio Tokens

JWT Tokens

Bearer Tokens

Private Keys

SSH Keys

RSA Keys

Passwords

Secrets

Environment Variables

Database URLs

Webhook Secrets

Cookies

Session Tokens

Return

Secret Type

Severity

Confidence

Entropy

Location

Recommendation

Provide

scan()

find()

mask()

redact()

entropy_score()

Support

Regex

Entropy Analysis

False Positive Filtering

Streaming Scan

Large Files

Thread Safe

Async

Do NOT implement

Runtime

Threat Detection

Authentication

Database

Return ONLY secret_detector.py

This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY the requested file.

Do not create duplicate models.