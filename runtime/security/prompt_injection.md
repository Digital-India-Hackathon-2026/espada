Assume all other project files already exist.

Never redefine classes that belong in another module.

Always import existing models instead of recreating them.

Generate ONLY

runtime/security/prompt_injection.py

Create an AI Prompt Injection Detection Engine.

Responsibilities

Detect

Ignore Previous Instructions

System Prompt Leakage

Role Override

Jailbreak Attempts

Prompt Extraction

Tool Abuse

Memory Poisoning

Recursive Prompting

Instruction Override

Model Manipulation

Indirect Prompt Injection

Hidden Prompt Injection

Encoded Prompt Injection

Context Escape

Function Call Abuse

Return

Risk Score

Confidence

Category

Severity

Explanation

Recommendation

Provide

scan()

detect()

classify()

risk_score()

Support

Regex

Rule Engine

Keyword Matching

AI Model Integration (future)

Context Analysis

Conversation Analysis

Async

Production ready

Do NOT implement

Runtime

Authentication

Routing

Database

Business Logic

Return ONLY prompt_injection.py

This project already contains runtime/core/.

Never recreate Runtime, Request, Response, Context, Errors, Config, Metrics, Events, State, or Router.

Always import existing classes.

Generate ONLY the requested file.

Do not create duplicate models.