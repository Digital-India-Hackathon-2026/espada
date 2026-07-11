This project already contains runtime/core/, runtime/security/, runtime/middleware/.

Never recreate Runtime, Request, Response, Context, Config, Metrics, Events, Errors, or Router.

Always import existing classes.

Generate ONLY

engine/analyzer.py

This module is the central analysis engine.

Responsibilities

Analyze an entire software project.

Coordinate

Parser

Detector

Fingerprint Engine

Scorer

Recommendation Engine

Generate complete project analysis.

Input

Local Project

Git Repository

Extracted Source Code

Output

Detected Languages

Frameworks

Libraries

Package Managers

Databases

Deployment Platforms

Cloud Providers

Architecture Pattern

AI Frameworks

Security Score

Complexity Score

Risk Score

Dependencies

Project Metadata

Provide

ProjectAnalyzer

AnalysisResult

AnalysisSession

Methods

analyze()

analyze_project()

analyze_directory()

analyze_repository()

generate_summary()

Do NOT detect technologies directly.

Only orchestrate other engine modules.

Python 3.12

Async

SOLID

Production ready

Return ONLY analyzer.py