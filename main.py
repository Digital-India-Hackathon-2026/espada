#!/usr/bin/env python3
"""
Project Intelligence Engine - Understand how a project actually works.

This engine consumes the Technology Detector fingerprint and builds
a semantic understanding of the project's structure, execution flow,
security boundaries, and runtime integration points.

IMPORTANT: This does NOT scan the filesystem. It ONLY consumes the
existing fingerprint from tech_scanner.py.

Usage:
    from project_intelligence import analyze_project, ProjectIntelligence

    fingerprint = detect_project(".")  # from tech_scanner
    intelligence = analyze_project(fingerprint)

Architecture:
    Technology Detector -> Fingerprint -> Intelligence Engine -> Runtime Integrator
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict


# ============================================================================
# Enums and Types
# ============================================================================

class FrameworkType(Enum):
    """Supported web frameworks."""
    FASTAPI = "fastapi"
    FLASK = "flask"
    QUART = "quart"
    DJANGO = "django"
    EXPRESS = "express"
    NESTJS = "nestjs"
    SPRING_BOOT = "spring-boot"
    ACTIX = "actix-web"
    AXUM = "axum"
    ROCKET = "rocket"
    GIN = "gin"
    ECHO = "echo"
    FIBER = "fiber"
    RUBY_ON_RAILS = "ruby-on-rails"
    LARAVEL = "laravel"
    SYMFONY = "symfony"
    UNKNOWN = "unknown"


class HttpMethod(Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


class SecurityBoundaryType(Enum):
    """Types of security boundaries."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    FILE_UPLOAD = "file_upload"
    SESSION = "session"
    TOKEN = "token"
    SECRET = "secret"
    COOKIE = "cookie"
    EXTERNAL_API = "external_api"
    PAYMENT = "payment"
    FILESYSTEM = "filesystem"
    INPUT_VALIDATION = "input_validation"
    RATE_LIMITING = "rate_limiting"


class HookPointType(Enum):
    """Types of runtime hook points."""
    MIDDLEWARE = "middleware"
    BEFORE_REQUEST = "before_request"
    AFTER_REQUEST = "after_request"
    ON_STARTUP = "on_startup"
    ON_SHUTDOWN = "on_shutdown"
    EXCEPTION_HANDLER = "exception_handler"
    REQUEST_HANDLER = "request_handler"
    RESPONSE_HANDLER = "response_handler"
    WEBSOCKET = "websocket"


class ReadinessStatus(Enum):
    """Runtime readiness status."""
    SUPPORTED = "supported"
    PARTIAL = "partial"
    EXPERIMENTAL = "experimental"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ModuleType(Enum):
    """Types of modules based on naming patterns."""
    CONTROLLER = "controller"
    ROUTE = "route"
    SERVICE = "service"
    REPOSITORY = "repository"
    DATABASE = "database"
    MODEL = "model"
    SCHEMA = "schema"
    CONFIGURATION = "configuration"
    CORE = "core"
    UTILS = "utils"
    WORKER = "worker"
    BACKGROUND = "background"
    TEST = "test"
    SCRIPT = "script"
    STATIC = "static"
    TEMPLATE = "template"
    MIDDLEWARE = "middleware"
    AUTH = "auth"
    API = "api"
    UNKNOWN = "unknown"


# ============================================================================
# Data Classes - Core Intelligence Objects
# ============================================================================

@dataclass
class Confidence:
    """Confidence score with supporting evidence."""
    score: float  # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)
    fingerprint_refs: List[str] = field(default_factory=list)  # Keys from fingerprint
    reason: str = ""

    def __post_init__(self):
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")


@dataclass
class Route:
    """Discovered route with execution context."""
    method: HttpMethod
    path: str
    handler: str
    file_ref: str  # Reference to fingerprint file
    authentication_required: Optional[bool] = None
    middleware_chain: List[str] = field(default_factory=list)
    confidence: Optional[Confidence] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.value,
            "path": self.path,
            "handler": self.handler,
            "file": self.file_ref,
            "auth_required": self.authentication_required,
            "middleware": self.middleware_chain,
            "confidence": self.confidence.score if self.confidence else 0.0,
        }


@dataclass
class Middleware:
    """Discovered middleware with order and context."""
    name: str
    file_ref: str
    hook_type: HookPointType
    order: Optional[int] = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[Confidence] = None


@dataclass
class Module:
    """Semantic module representing a project component."""
    name: str
    type: ModuleType
    path: str  # Relative path from fingerprint
    imports: List[str] = field(default_factory=list)
    imported_by: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    is_security_sensitive: bool = False
    confidence: Optional[Confidence] = None


@dataclass
class SecurityBoundary:
    """Security boundary in the execution flow."""
    type: SecurityBoundaryType
    description: str
    file_refs: List[str] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[Confidence] = None


@dataclass
class HookPoint:
    """Runtime hook point for Security Runtime integration."""
    framework: FrameworkType
    hook_type: HookPointType
    file_ref: str
    object_name: str
    configuration: Dict[str, Any] = field(default_factory=dict)
    is_safe_integration: bool = False
    integration_priority: int = 0  # Lower = higher priority
    confidence: Optional[Confidence] = None


@dataclass
class Application:
    """Complete application model."""
    name: str
    framework: FrameworkType
    entry_file: str
    app_object: str
    startup_command: str
    
    # Runtime components
    routes: List[Route] = field(default_factory=list)
    middleware: List[Middleware] = field(default_factory=list)
    hook_points: List[HookPoint] = field(default_factory=list)
    security_boundaries: List[SecurityBoundary] = field(default_factory=list)
    
    # Dependencies
    modules: List[Module] = field(default_factory=list)
    dependency_names: List[str] = field(default_factory=list)
    
    # Metadata
    port: Optional[int] = None
    host: Optional[str] = None
    is_web_application: bool = True
    
    # Confidence
    confidence: Optional[Confidence] = None


@dataclass
class ExecutionFlow:
    """Execution flow graph showing request/response flow."""
    nodes: List[str] = field(default_factory=list)
    edges: List[Tuple[str, str]] = field(default_factory=list)  # (from, to)
    entry_point: Optional[str] = None
    exit_point: Optional[str] = None
    
    def add_node(self, node: str) -> None:
        if node not in self.nodes:
            self.nodes.append(node)
    
    def add_edge(self, from_node: str, to_node: str) -> None:
        if (from_node, to_node) not in self.edges:
            self.edges.append((from_node, to_node))


@dataclass
class ReadinessReport:
    """Runtime readiness assessment."""
    status: ReadinessStatus
    can_attach: bool
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    missing_requirements: List[str] = field(default_factory=list)
    
    # Metrics
    expected_latency: Optional[str] = None  # e.g., "Very Low", "Low", "Medium"
    compatibility_score: float = 0.0  # 0.0 - 1.0
    potential_conflicts: List[str] = field(default_factory=list)
    
    # Integration details
    recommended_hook_points: List[str] = field(default_factory=list)
    recommended_order: List[str] = field(default_factory=list)


@dataclass
class ProjectIntelligence:
    """Complete project intelligence object."""
    # Core
    project_path: str
    fingerprint_version: str = "1.0"
    
    # Applications
    applications: List[Application] = field(default_factory=list)
    primary_application: Optional[Application] = None
    
    # Flow understanding
    execution_flow: Optional[ExecutionFlow] = None
    security_flow: Optional[ExecutionFlow] = None
    
    # Knowledge graph
    module_graph: Dict[str, List[str]] = field(default_factory=dict)  # module -> dependencies
    reverse_module_graph: Dict[str, List[str]] = field(default_factory=dict)  # module -> dependents
    
    # Security
    security_boundaries: List[SecurityBoundary] = field(default_factory=list)
    
    # Runtime
    hook_points: List[HookPoint] = field(default_factory=list)
    
    # Readiness
    readiness_report: Optional[ReadinessReport] = None
    
    # Confidence
    overall_confidence: float = 0.0
    evidence_summary: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        result = {
            "project_path": self.project_path,
            "applications": [
                {
                    "name": app.name,
                    "framework": app.framework.value,
                    "entry_file": app.entry_file,
                    "startup_command": app.startup_command,
                    "routes": [r.to_dict() for r in app.routes[:20]],
                    "middleware": [
                        {"name": m.name, "hook_type": m.hook_type.value}
                        for m in app.middleware[:10]
                    ],
                    "hook_points": [
                        {"type": h.hook_type.value, "object": h.object_name}
                        for h in app.hook_points[:10]
                    ],
                    "security_boundaries": [
                        {"type": b.type.value, "description": b.description[:50]}
                        for b in app.security_boundaries[:10]
                    ],
                }
                for app in self.applications
            ],
            "hook_points": [
                {
                    "hook_type": h.hook_type.value,
                    "framework": h.framework.value,
                    "file": h.file_ref,
                    "object": h.object_name,
                    "safe_integration": h.is_safe_integration,
                }
                for h in self.hook_points[:20]
            ],
            "security_boundaries": [
                {
                    "type": b.type.value,
                    "description": b.description[:80],
                    "files": b.file_refs[:5],
                    "confidence": b.confidence.score if b.confidence else 0.0,
                }
                for b in self.security_boundaries
            ],
            "readiness": {
                "status": self.readiness_report.status.value if self.readiness_report else "unknown",
                "can_attach": self.readiness_report.can_attach if self.readiness_report else False,
                "score": self.readiness_report.compatibility_score if self.readiness_report else 0.0,
            } if self.readiness_report else None,
            "overall_confidence": self.overall_confidence,
            "evidence": self.evidence_summary[:10],
        }
        return result


# ============================================================================
# Main Intelligence Engine
# ============================================================================

class ProjectIntelligenceEngine:
    """
    Builds project intelligence from a technology fingerprint.
    
    This engine does NOT scan the filesystem. It consumes the fingerprint
    generated by tech_scanner.py and builds a semantic understanding.
    """
    
    def __init__(self, fingerprint: Dict[str, Any]):
        self.fingerprint = fingerprint
        self._detected = fingerprint.get("detected", {})
        self._apps_found = fingerprint.get("apps_found", [])
        self.project_path = fingerprint.get("project_path", ".")
        
        # Internal state
        self._applications: List[Application] = []
        self._modules: List[Module] = []
        self._security_boundaries: List[SecurityBoundary] = []
        self._hook_points: List[HookPoint] = []
        self._routes: List[Route] = []
        self._middleware: List[Middleware] = []
        self._module_graph: Dict[str, List[str]] = {}
        self._reverse_module_graph: Dict[str, List[str]] = defaultdict(list)
        self._execution_flow: Optional[ExecutionFlow] = None
        self._security_flow: Optional[ExecutionFlow] = None
        self._readiness_report: Optional[ReadinessReport] = None
    
    # ========================================================================
    # Main Entry Point
    # ========================================================================
    
    def analyze(self) -> ProjectIntelligence:
        """Run full intelligence analysis from fingerprint."""
        # Build applications
        self._discover_applications()
        
        # Build modules from fingerprint structure
        self._discover_modules()
        
        # Build security boundaries from fingerprint
        self._discover_security_boundaries()
        
        # Discover hook points
        self._discover_hook_points()
        
        # Build execution flow
        self._build_execution_flow()
        
        # Build security flow
        self._build_security_flow()
        
        # Build module graph
        self._build_module_graph()
        
        # Assess readiness
        self._assess_readiness()
        
        # Calculate confidence
        overall_confidence, evidence = self._calculate_overall_confidence()
        
        # Determine primary application
        primary_app = self._applications[0] if self._applications else None
        
        return ProjectIntelligence(
            project_path=self.project_path,
            applications=self._applications,
            primary_application=primary_app,
            execution_flow=self._execution_flow,
            security_flow=self._security_flow,
            module_graph=self._module_graph,
            reverse_module_graph=dict(self._reverse_module_graph),
            security_boundaries=self._security_boundaries,
            hook_points=self._hook_points,
            readiness_report=self._readiness_report,
            overall_confidence=overall_confidence,
            evidence_summary=evidence,
        )
    
    # ========================================================================
    # Application Discovery (from fingerprint)
    # ========================================================================
    
    def _discover_applications(self) -> None:
        """Discover applications from fingerprint data."""
        frameworks = self._detected.get("frameworks", [])
        framework_set = {f.lower().split()[0] if f else "" for f in frameworks}
        
        # Python frameworks
        if "fastapi" in framework_set:
            app = self._build_fastapi_app()
            if app:
                self._applications.append(app)
        
        if "flask" in framework_set:
            app = self._build_flask_app()
            if app:
                self._applications.append(app)
        
        if "django" in framework_set:
            app = self._build_django_app()
            if app:
                self._applications.append(app)
        
        # Node.js frameworks
        if "express" in framework_set:
            app = self._build_express_app()
            if app:
                self._applications.append(app)
        
        # Use apps_found from fingerprint as fallback
        if not self._applications and self._apps_found:
            for app_info in self._apps_found:
                fw_name = app_info.get("framework", "").lower()
                framework = self._guess_framework(fw_name)
                app = Application(
                    name=app_info.get("framework", "Unknown"),
                    framework=framework,
                    entry_file=app_info.get("file", ""),
                    app_object=app_info.get("object", "app"),
                    startup_command=f"python {app_info.get('file', '')}",
                    confidence=Confidence(
                        score=0.5,
                        evidence=[f"From fingerprint apps_found"],
                        fingerprint_refs=["apps_found"],
                        reason="Application discovered from detector output",
                    ),
                )
                self._applications.append(app)
    
    def _guess_framework(self, name: str) -> FrameworkType:
        """Guess framework from name string."""
        name_lower = name.lower()
        mapping = {
            "fastapi": FrameworkType.FASTAPI,
            "flask": FrameworkType.FLASK,
            "django": FrameworkType.DJANGO,
            "quart": FrameworkType.QUART,
            "express": FrameworkType.EXPRESS,
            "nestjs": FrameworkType.NESTJS,
            "spring": FrameworkType.SPRING_BOOT,
            "spring boot": FrameworkType.SPRING_BOOT,
            "gin": FrameworkType.GIN,
            "echo": FrameworkType.ECHO,
            "fiber": FrameworkType.FIBER,
        }
        for key, value in mapping.items():
            if key in name_lower:
                return value
        return FrameworkType.UNKNOWN
    
    def _build_fastapi_app(self) -> Optional[Application]:
        """Build FastAPI application from fingerprint."""
        frameworks = self._detected.get("frameworks", [])
        fastapi_entries = [fw for fw in frameworks if "fastapi" in fw.lower()]
        
        # Use apps_found for FastAPI
        app_files = [a.get("file", "") for a in self._apps_found if "fastapi" in a.get("framework", "").lower()]
        
        if not app_files and self._apps_found:
            # Use first app as fallback
            app_files = [self._apps_found[0].get("file", "")]
        
        entry_file = app_files[0] if app_files else "main.py"
        app_object = "app"
        
        # Try to find app object from apps_found
        for app_info in self._apps_found:
            if "fastapi" in app_info.get("framework", "").lower():
                app_object = app_info.get("object", "app")
                entry_file = app_info.get("file", entry_file)
                break
        
        # Build routes from route patterns
        routes = self._infer_fastapi_routes()
        
        # Build middleware
        middleware = self._infer_fastapi_middleware()
        
        # Build hook points
        hook_points = self._infer_fastapi_hooks()
        
        # Build security boundaries
        security_boundaries = self._infer_security_boundaries_from_fingerprint()
        
        app = Application(
            name="FastAPI Application",
            framework=FrameworkType.FASTAPI,
            entry_file=entry_file,
            app_object=app_object,
            startup_command=f"uvicorn {entry_file.replace('.py', '')}:{app_object} --reload",
            routes=routes,
            middleware=middleware,
            hook_points=hook_points,
            security_boundaries=security_boundaries,
            modules=self._modules,
            dependency_names=self._detected.get("dependencies", []),
            port=8000,
            is_web_application=True,
            confidence=Confidence(
                score=0.9,
                evidence=["FastAPI framework detected in fingerprint", 
                          f"Found {len(routes)} route patterns"],
                fingerprint_refs=["frameworks", "apps_found"],
                reason="FastAPI detected with high confidence from fingerprint",
            ),
        )
        return app
    
    def _build_flask_app(self) -> Optional[Application]:
        """Build Flask application from fingerprint."""
        app_files = [a.get("file", "") for a in self._apps_found if "flask" in a.get("framework", "").lower()]
        entry_file = app_files[0] if app_files else "app.py"
        app_object = "app"
        
        # Try to find app object
        for app_info in self._apps_found:
            if "flask" in app_info.get("framework", "").lower():
                app_object = app_info.get("object", "app")
                entry_file = app_info.get("file", entry_file)
                break
        
        routes = self._infer_flask_routes()
        middleware = self._infer_flask_middleware()
        hook_points = self._infer_flask_hooks()
        
        app = Application(
            name="Flask Application",
            framework=FrameworkType.FLASK,
            entry_file=entry_file,
            app_object=app_object,
            startup_command=f"flask run --host=0.0.0.0 --port=5000",
            routes=routes,
            middleware=middleware,
            hook_points=hook_points,
            security_boundaries=self._security_boundaries,
            modules=self._modules,
            dependency_names=self._detected.get("dependencies", []),
            port=5000,
            is_web_application=True,
            confidence=Confidence(
                score=0.85,
                evidence=["Flask framework detected in fingerprint"],
                fingerprint_refs=["frameworks", "apps_found"],
                reason="Flask detected with high confidence",
            ),
        )
        return app
    
    def _build_django_app(self) -> Optional[Application]:
        """Build Django application from fingerprint."""
        app = Application(
            name="Django Application",
            framework=FrameworkType.DJANGO,
            entry_file="manage.py",
            app_object="wsgi",
            startup_command="python manage.py runserver",
            routes=[],  # Django routes not easily inferred from fingerprint
            middleware=[],
            hook_points=[],
            security_boundaries=self._security_boundaries,
            modules=self._modules,
            dependency_names=self._detected.get("dependencies", []),
            port=8000,
            is_web_application=True,
            confidence=Confidence(
                score=0.8,
                evidence=["Django framework detected in fingerprint"],
                fingerprint_refs=["frameworks"],
                reason="Django detected from fingerprint",
            ),
        )
        return app
    
    def _build_express_app(self) -> Optional[Application]:
        """Build Express application from fingerprint."""
        app = Application(
            name="Express Application",
            framework=FrameworkType.EXPRESS,
            entry_file="index.js",
            app_object="app",
            startup_command="npm start",
            routes=[],
            middleware=[],
            hook_points=[],
            security_boundaries=self._security_boundaries,
            modules=self._modules,
            dependency_names=self._detected.get("dependencies", []),
            port=3000,
            is_web_application=True,
            confidence=Confidence(
                score=0.7,
                evidence=["Express framework detected in fingerprint"],
                fingerprint_refs=["frameworks"],
                reason="Express detected from fingerprint",
            ),
        )
        return app
    
    # ========================================================================
    # Route Inference (from fingerprint patterns)
    # ========================================================================
    
    def _infer_fastapi_routes(self) -> List[Route]:
        """Infer FastAPI routes from fingerprint patterns."""
        routes = []
        
        # Look for route patterns in the fingerprint's apps_found
        for app_info in self._apps_found:
            if "fastapi" in app_info.get("framework", "").lower():
                # If we have file info, we can infer routes
                file_ref = app_info.get("file", "")
                
                # Common route patterns (heuristic from framework detection)
                common_routes = [
                    ("GET", "/", "root"),
                    ("GET", "/health", "health_check"),
                    ("GET", "/api", "api_root"),
                ]
                
                for method, path, handler in common_routes:
                    routes.append(Route(
                        method=HttpMethod(method),
                        path=path,
                        handler=handler,
                        file_ref=file_ref,
                        confidence=Confidence(
                            score=0.3,
                            evidence=["Inferred from common FastAPI patterns"],
                            fingerprint_refs=["apps_found"],
                            reason="Route patterns inferred from fingerprint",
                        ),
                    ))
                break
        
        return routes
    
    def _infer_flask_routes(self) -> List[Route]:
        """Infer Flask routes from fingerprint patterns."""
        routes = []
        for app_info in self._apps_found:
            if "flask" in app_info.get("framework", "").lower():
                file_ref = app_info.get("file", "")
                common_routes = [
                    ("GET", "/", "index"),
                    ("GET", "/health", "health"),
                ]
                for method, path, handler in common_routes:
                    routes.append(Route(
                        method=HttpMethod(method),
                        path=path,
                        handler=handler,
                        file_ref=file_ref,
                        confidence=Confidence(
                            score=0.3,
                            evidence=["Inferred from common Flask patterns"],
                            fingerprint_refs=["apps_found"],
                            reason="Route patterns inferred from fingerprint",
                        ),
                    ))
                break
        return routes
    
    # ========================================================================
    # Middleware Inference
    # ========================================================================
    
    def _infer_fastapi_middleware(self) -> List[Middleware]:
        """Infer FastAPI middleware from fingerprint."""
        middleware = []
        
        # Common middleware from framework detection
        if "cors" in str(self._detected.get("features", [])).lower():
            middleware.append(Middleware(
                name="CORSMiddleware",
                file_ref="",
                hook_type=HookPointType.MIDDLEWARE,
                configuration={"allow_origins": ["*"]},
                confidence=Confidence(
                    score=0.6,
                    evidence=["CORS feature detected"],
                    fingerprint_refs=["features"],
                    reason="CORS middleware inferred from fingerprint",
                ),
            ))
        
        # Auth middleware if authentication detected
        if self._detected.get("authentication", {}):
            middleware.append(Middleware(
                name="AuthenticationMiddleware",
                file_ref="",
                hook_type=HookPointType.MIDDLEWARE,
                order=0,
                confidence=Confidence(
                    score=0.5,
                    evidence=["Authentication detected in fingerprint"],
                    fingerprint_refs=["authentication"],
                    reason="Auth middleware inferred",
                ),
            ))
        
        return middleware
    
    def _infer_flask_middleware(self) -> List[Middleware]:
        """Infer Flask middleware from fingerprint."""
        middleware = []
        if self._detected.get("authentication", {}):
            middleware.append(Middleware(
                name="before_request_auth",
                file_ref="",
                hook_type=HookPointType.BEFORE_REQUEST,
                order=0,
                confidence=Confidence(
                    score=0.5,
                    evidence=["Authentication detected"],
                    fingerprint_refs=["authentication"],
                    reason="Auth before_request inferred",
                ),
            ))
        return middleware
    
    # ========================================================================
    # Hook Point Inference
    # ========================================================================
    
    def _infer_fastapi_hooks(self) -> List[HookPoint]:
        """Infer FastAPI hook points from fingerprint."""
        hooks = []
        frameworks = self._detected.get("frameworks", [])
        
        if any("fastapi" in f.lower() for f in frameworks):
            # Middleware hook
            hooks.append(HookPoint(
                framework=FrameworkType.FASTAPI,
                hook_type=HookPointType.MIDDLEWARE,
                file_ref="",
                object_name="app.add_middleware",
                is_safe_integration=True,
                integration_priority=10,
                confidence=Confidence(
                    score=0.9,
                    evidence=["FastAPI supports middleware"],
                    fingerprint_refs=["frameworks"],
                    reason="FastAPI middleware hook available",
                ),
            ))
            
            # Startup hook
            hooks.append(HookPoint(
                framework=FrameworkType.FASTAPI,
                hook_type=HookPointType.ON_STARTUP,
                file_ref="",
                object_name="app.on_event('startup')",
                is_safe_integration=True,
                integration_priority=5,
                confidence=Confidence(
                    score=0.85,
                    evidence=["FastAPI supports startup events"],
                    fingerprint_refs=["frameworks"],
                    reason="FastAPI startup hook available",
                ),
            ))
        
        return hooks
    
    def _infer_flask_hooks(self) -> List[HookPoint]:
        """Infer Flask hook points from fingerprint."""
        hooks = []
        frameworks = self._detected.get("frameworks", [])
        
        if any("flask" in f.lower() for f in frameworks):
            hooks.append(HookPoint(
                framework=FrameworkType.FLASK,
                hook_type=HookPointType.BEFORE_REQUEST,
                file_ref="",
                object_name="app.before_request",
                is_safe_integration=True,
                integration_priority=10,
                confidence=Confidence(
                    score=0.9,
                    evidence=["Flask supports before_request"],
                    fingerprint_refs=["frameworks"],
                    reason="Flask before_request hook available",
                ),
            ))
        return hooks
    
    # ========================================================================
    # Security Boundaries Discovery (from fingerprint)
    # ========================================================================
    
    def _discover_security_boundaries(self) -> None:
        """Discover security boundaries from fingerprint."""
        boundaries = []
        
        # From authentication data
        auth_data = self._detected.get("authentication", {})
        if auth_data:
            boundaries.append(SecurityBoundary(
                type=SecurityBoundaryType.AUTHENTICATION,
                description=f"Authentication: {auth_data}",
                file_refs=[],
                confidence=Confidence(
                    score=0.8,
                    evidence=["Authentication data in fingerprint"],
                    fingerprint_refs=["authentication"],
                    reason="Authentication boundary detected",
                ),
            ))
        
        # From database detection
        databases = self._detected.get("databases", [])
        if databases:
            boundaries.append(SecurityBoundary(
                type=SecurityBoundaryType.DATABASE,
                description=f"Database access: {', '.join(databases)}",
                file_refs=[],
                confidence=Confidence(
                    score=0.7,
                    evidence=["Databases detected in fingerprint"],
                    fingerprint_refs=["databases"],
                    reason="Database boundary detected",
                ),
            ))
        
        # From deployment data (secrets)
        deployment = self._detected.get("deployment", [])
        if deployment:
            boundaries.append(SecurityBoundary(
                type=SecurityBoundaryType.SECRET,
                description=f"Secrets/configuration in deployment",
                file_refs=[],
                confidence=Confidence(
                    score=0.6,
                    evidence=["Deployment configuration found"],
                    fingerprint_refs=["deployment"],
                    reason="Secrets boundary detected",
                ),
            ))
        
        self._security_boundaries = boundaries
    
    # ========================================================================
    # Module Discovery (from fingerprint structure)
    # ========================================================================
    
    def _discover_modules(self) -> None:
        """Discover modules from fingerprint."""
        modules = []
        
        # Module type patterns
        type_patterns = {
            ModuleType.CONTROLLER: ["controller", "controllers"],
            ModuleType.ROUTE: ["route", "routes", "router", "routers"],
            ModuleType.SERVICE: ["service", "services"],
            ModuleType.REPOSITORY: ["repository", "repositories", "repo"],
            ModuleType.DATABASE: ["database", "db", "dal"],
            ModuleType.MODEL: ["model", "models", "entity", "entities"],
            ModuleType.CONFIGURATION: ["config", "conf", "settings"],
            ModuleType.CORE: ["core", "common"],
            ModuleType.UTILS: ["util", "utils", "helpers"],
            ModuleType.WORKER: ["worker", "workers", "tasks"],
            ModuleType.TEST: ["test", "tests"],
            ModuleType.SCRIPT: ["scripts", "bin", "cli"],
            ModuleType.STATIC: ["static", "public", "assets"],
            ModuleType.TEMPLATE: ["templates", "views"],
            ModuleType.MIDDLEWARE: ["middleware"],
            ModuleType.AUTH: ["auth", "authentication"],
            ModuleType.API: ["api", "apis", "endpoints"],
        }
        
        # Use apps_found to infer modules
        for app_info in self._apps_found:
            file_path = app_info.get("file", "")
            if file_path:
                parts = file_path.split("/")
                for part in parts:
                    if part.endswith(".py"):
                        continue
                    part_lower = part.lower()
                    module_type = ModuleType.UNKNOWN
                    for mtype, patterns in type_patterns.items():
                        if any(p in part_lower for p in patterns):
                            module_type = mtype
                            break
                    
                    # Avoid duplicates
                    if not any(m.name == part for m in modules):
                        modules.append(Module(
                            name=part,
                            type=module_type,
                            path=file_path,
                            confidence=Confidence(
                                score=0.5,
                                evidence=[f"Inferred from app file path"],
                                fingerprint_refs=["apps_found"],
                                reason=f"Module classified as {module_type.value}",
                            ),
                        ))
        
        self._modules = modules
    
    # ========================================================================
    # Module Graph
    # ========================================================================
    
    def _build_module_graph(self) -> None:
        """Build module dependency graph from fingerprint."""
        self._module_graph = {}
        self._reverse_module_graph = defaultdict(list)
        
        # Build from imports in modules
        for module in self._modules:
            self._module_graph[module.name] = module.imports
            for imp in module.imports:
                self._reverse_module_graph[imp].append(module.name)
        
        # If no modules, build from app dependencies
        if not self._module_graph and self._applications:
            app = self._applications[0]
            # Create a simple graph from application to dependencies
            self._module_graph[app.name] = app.dependency_names
            for dep in app.dependency_names:
                self._reverse_module_graph[dep].append(app.name)
    
    # ========================================================================
    # Execution Flow
    # ========================================================================
    
    def _build_execution_flow(self) -> None:
        """Build execution flow graph."""
        flow = ExecutionFlow()
        
        # Build from application data
        if self._applications:
            app = self._applications[0]
            
            # Standard request flow for web frameworks
            if app.framework in [FrameworkType.FASTAPI, FrameworkType.FLASK]:
                flow.entry_point = "HTTP Request"
                flow.exit_point = "HTTP Response"
                
                # Add standard flow nodes
                flow.add_node("HTTP Request")
                flow.add_node("Middleware Chain")
                flow.add_node("Authentication")
                flow.add_node("Router")
                flow.add_node("Handler")
                flow.add_node("Service Layer")
                flow.add_node("Database")
                flow.add_node("Response")
                flow.add_node("HTTP Response")
                
                # Add edges
                flow.add_edge("HTTP Request", "Middleware Chain")
                flow.add_edge("Middleware Chain", "Authentication")
                flow.add_edge("Authentication", "Router")
                flow.add_edge("Router", "Handler")
                flow.add_edge("Handler", "Service Layer")
                flow.add_edge("Service Layer", "Database")
                flow.add_edge("Database", "Response")
                flow.add_edge("Response", "HTTP Response")
                
                # Add middleware from detection
                for mw in app.middleware:
                    if mw.name:
                        flow.add_node(mw.name)
                        # Insert before Authentication
                        flow.add_edge("Middleware Chain", mw.name)
                        flow.add_edge(mw.name, "Authentication")
        
        self._execution_flow = flow
    
    # ========================================================================
    # Security Flow
    # ========================================================================
    
    def _build_security_flow(self) -> None:
        """Build security flow graph."""
        flow = ExecutionFlow()
        
        # Security flow follows the execution flow with security checkpoints
        flow.entry_point = "Request Received"
        flow.exit_point = "Response Sent"
        
        # Build security flow
        flow.add_node("Request Received")
        flow.add_node("Authentication Check")
        flow.add_node("Authorization Check")
        flow.add_node("Input Validation")
        flow.add_node("Rate Limiting")
        flow.add_node("Business Logic")
        flow.add_node("Database Access")
        flow.add_node("Response Preparation")
        flow.add_node("Response Sent")
        
        # Edges
        flow.add_edge("Request Received", "Authentication Check")
        flow.add_edge("Authentication Check", "Authorization Check")
        flow.add_edge("Authorization Check", "Input Validation")
        flow.add_edge("Input Validation", "Rate Limiting")
        flow.add_edge("Rate Limiting", "Business Logic")
        flow.add_edge("Business Logic", "Database Access")
        flow.add_edge("Database Access", "Response Preparation")
        flow.add_edge("Response Preparation", "Response Sent")
        
        # Add discovered security boundaries
        for boundary in self._security_boundaries:
            if boundary.type == SecurityBoundaryType.AUTHENTICATION:
                flow.add_node("Authentication Check")
                # Make sure it's connected properly
                flow.add_edge("Request Received", "Authentication Check")
                flow.add_edge("Authentication Check", "Authorization Check")
            elif boundary.type == SecurityBoundaryType.DATABASE:
                flow.add_node("Database Access")
                flow.add_edge("Business Logic", "Database Access")
                flow.add_edge("Database Access", "Response Preparation")
        
        self._security_flow = flow
    
    # ========================================================================
    # Hook Points Discovery (from security boundaries)
    # ========================================================================
    
    def _discover_hook_points(self) -> None:
        """Discover hook points from security boundaries and framework."""
        frameworks = self._detected.get("frameworks", [])
        
        for fw_name in frameworks:
            fw_lower = fw_name.lower()
            
            if "fastapi" in fw_lower:
                self._hook_points.append(HookPoint(
                    framework=FrameworkType.FASTAPI,
                    hook_type=HookPointType.MIDDLEWARE,
                    file_ref="",
                    object_name="app.add_middleware",
                    is_safe_integration=True,
                    integration_priority=10,
                    confidence=Confidence(
                        score=0.9,
                        evidence=["FastAPI middleware is safe to attach"],
                        fingerprint_refs=["frameworks"],
                        reason="Middleware hook point available",
                    ),
                ))
                
                self._hook_points.append(HookPoint(
                    framework=FrameworkType.FASTAPI,
                    hook_type=HookPointType.ON_STARTUP,
                    file_ref="",
                    object_name="app.on_event('startup')",
                    is_safe_integration=True,
                    integration_priority=5,
                    confidence=Confidence(
                        score=0.85,
                        evidence=["FastAPI startup hook available"],
                        fingerprint_refs=["frameworks"],
                        reason="Startup hook point available",
                    ),
                ))
            
            elif "flask" in fw_lower:
                self._hook_points.append(HookPoint(
                    framework=FrameworkType.FLASK,
                    hook_type=HookPointType.BEFORE_REQUEST,
                    file_ref="",
                    object_name="app.before_request",
                    is_safe_integration=True,
                    integration_priority=10,
                    confidence=Confidence(
                        score=0.9,
                        evidence=["Flask before_request is safe to attach"],
                        fingerprint_refs=["frameworks"],
                        reason="Before_request hook point available",
                    ),
                ))
        
        # If no hook points found but we have applications, infer from framework type
        if not self._hook_points and self._applications:
            app = self._applications[0]
            if app.framework == FrameworkType.FASTAPI:
                # Add default FastAPI hooks
                self._hook_points.append(HookPoint(
                    framework=FrameworkType.FASTAPI,
                    hook_type=HookPointType.MIDDLEWARE,
                    file_ref="",
                    object_name="app.add_middleware",
                    is_safe_integration=True,
                    integration_priority=10,
                    confidence=Confidence(
                        score=0.7,
                        evidence=["Inferred from FastAPI application"],
                        fingerprint_refs=["applications"],
                        reason="Middleware hook inferred from application type",
                    ),
                ))
    
    # ========================================================================
    # Readiness Assessment
    # ========================================================================
    
    def _assess_readiness(self) -> None:
        """Assess runtime readiness."""
        can_attach = False
        reasons = []
        warnings = []
        missing = []
        recommended_hooks = []
        conflicts = []
        score = 0.0
        
        # Check for applications
        if not self._applications:
            warnings.append("No applications found")
            missing.append("Application discovery")
        else:
            score += 0.2
            reasons.append(f"Found {len(self._applications)} application(s)")
        
        # Check for hook points
        if self._hook_points:
            score += 0.3
            reasons.append(f"Found {len(self._hook_points)} hook points")
            can_attach = True
            for hook in self._hook_points[:5]:
                recommended_hooks.append(hook.object_name)
        else:
            warnings.append("No hook points found")
            missing.append("Hook points")
        
        # Check for security boundaries
        if self._security_boundaries:
            score += 0.2
            reasons.append(f"Found {len(self._security_boundaries)} security boundaries")
        else:
            warnings.append("No security boundaries detected")
            missing.append("Security boundaries")
        
        # Check for execution flow
        if self._execution_flow and self._execution_flow.nodes:
            score += 0.15
            reasons.append("Execution flow mapped")
        
        # Check for modules
        if self._modules:
            score += 0.1
            reasons.append(f"Found {len(self._modules)} modules")
        
        # Check for startup info
        if self._applications and self._applications[0].startup_command:
            score += 0.05
            reasons.append("Startup command available")
        
        # Determine status
        if score >= 0.8:
            status = ReadinessStatus.SUPPORTED
        elif score >= 0.5:
            status = ReadinessStatus.PARTIAL
        elif score >= 0.3:
            status = ReadinessStatus.EXPERIMENTAL
        else:
            status = ReadinessStatus.UNSUPPORTED
            can_attach = False
        
        # Check for potential conflicts
        framework_names = [f.lower() for f in self._detected.get("frameworks", [])]
        if "fastapi" in " ".join(framework_names) or "flask" in " ".join(framework_names):
            # Web frameworks are well supported
            pass
        else:
            conflicts.append("Unsupported or unrecognized framework")
        
        self._readiness_report = ReadinessReport(
            status=status,
            can_attach=can_attach,
            reasons=reasons,
            warnings=warnings,
            missing_requirements=missing,
            expected_latency=self._assess_latency(),
            compatibility_score=score,
            potential_conflicts=conflicts,
            recommended_hook_points=recommended_hooks,
            recommended_order=recommended_hooks,
        )
    
    def _assess_latency(self) -> str:
        """Assess expected latency impact."""
        if self._applications:
            app = self._applications[0]
            if app.framework in [FrameworkType.FASTAPI, FrameworkType.FLASK]:
                return "Very Low (Middleware overhead minimal)"
            elif app.framework in [FrameworkType.DJANGO]:
                return "Low (Request/response cycle supports middleware)"
        return "Unknown"
    
    # ========================================================================
    # Confidence Calculation
    # ========================================================================
    
    def _calculate_overall_confidence(self) -> Tuple[float, List[str]]:
        """Calculate overall confidence score with evidence."""
        scores = []
        evidence = []
        
        # Applications
        if self._applications:
            scores.append(0.8)
            evidence.append(f"Found {len(self._applications)} applications")
        
        # Hook points
        if self._hook_points:
            scores.append(0.8)
            evidence.append(f"Found {len(self._hook_points)} hook points")
        
        # Security boundaries
        if self._security_boundaries:
            scores.append(0.6)
            evidence.append(f"Found {len(self._security_boundaries)} security boundaries")
        
        # Modules
        if self._modules:
            scores.append(0.6)
            evidence.append(f"Found {len(self._modules)} modules")
        
        # Execution flow
        if self._execution_flow and self._execution_flow.nodes:
            scores.append(0.7)
            evidence.append("Execution flow mapped")
        
        # Readiness report
        if self._readiness_report:
            scores.append(self._readiness_report.compatibility_score)
            evidence.append(f"Readiness: {self._readiness_report.status.value}")
        
        if not scores:
            return 0.2, ["Limited information available from fingerprint"]
        
        avg_score = sum(scores) / len(scores)
        # Boost for multiple evidence sources
        boost = min(len(scores) * 0.03, 0.15)
        final_score = min(avg_score + boost, 1.0)
        
        # Add key evidence
        if self._readiness_report:
            evidence.extend(self._readiness_report.reasons[:3])
        
        return final_score, evidence[:8]
    
    # ========================================================================
    # Helper for inference from fingerprint
    # ========================================================================
    
    def _infer_security_boundaries_from_fingerprint(self) -> List[SecurityBoundary]:
        """Infer security boundaries from fingerprint data."""
        return self._security_boundaries


# ============================================================================
# Public API
# ============================================================================

def analyze_project(fingerprint: Dict[str, Any]) -> ProjectIntelligence:
    """
    Analyze project intelligence from a technology fingerprint.
    
    Args:
        fingerprint: Output from tech_scanner.scan_project()
        
    Returns:
        ProjectIntelligence: Complete intelligence about the project
    """
    engine = ProjectIntelligenceEngine(fingerprint)
    return engine.analyze()


# ============================================================================
# CLI Entry Point
# ============================================================================

def _print_report(intelligence: ProjectIntelligence) -> None:
    """Print a beautiful intelligence report."""
    header = "=" * 65
    bar = "-" * 65
    
    print("\n" + header)
    print("                    PROJECT INTELLIGENCE")
    print(header)
    
    # Project Info
    print(f"\nProject Path: {intelligence.project_path}")
    print(f"Confidence: {intelligence.overall_confidence:.1%}")
    
    # Applications
    print(f"\n{bar}")
    print("APPLICATIONS")
    print(bar)
    if intelligence.applications:
        for i, app in enumerate(intelligence.applications, 1):
            print(f"\n  [{i}] {app.name}")
            print(f"    Framework    : {app.framework.value}")
            print(f"    Entry File   : {app.entry_file}")
            print(f"    App Object   : {app.app_object}")
            print(f"    Startup      : {app.startup_command}")
            if app.port:
                print(f"    Port         : {app.port}")
            print(f"    Routes       : {len(app.routes)}")
            print(f"    Middleware   : {len(app.middleware)}")
            print(f"    Hook Points  : {len(app.hook_points)}")
            if app.confidence:
                print(f"    Confidence   : {app.confidence.score:.1%}")
    else:
        print("  ❌ No applications detected")
    
    # Execution Flow
    print(f"\n{bar}")
    print("EXECUTION FLOW")
    print(bar)
    if intelligence.execution_flow and intelligence.execution_flow.nodes:
        flow = intelligence.execution_flow
        print(f"  Entry: {flow.entry_point or 'Unknown'}")
        print(f"  Exit: {flow.exit_point or 'Unknown'}")
        print(f"  Nodes: {len(flow.nodes)}")
        if flow.nodes:
            print("\n  Flow:")
            for i, node in enumerate(flow.nodes[:10]):
                print(f"    {i+1}. {node}")
            if len(flow.nodes) > 10:
                print(f"    ... and {len(flow.nodes) - 10} more")
    else:
        print("  ⚠ Execution flow not mapped")
    
    # Security Flow
    print(f"\n{bar}")
    print("SECURITY FLOW")
    print(bar)
    if intelligence.security_flow and intelligence.security_flow.nodes:
        flow = intelligence.security_flow
        for node in flow.nodes[:8]:
            print(f"  → {node}")
        if len(flow.nodes) > 8:
            print(f"  ... and {len(flow.nodes) - 8} more")
    else:
        print("  ⚠ Security flow not mapped")
    
    # Security Boundaries
    print(f"\n{bar}")
    print(f"SECURITY BOUNDARIES ({len(intelligence.security_boundaries)})")
    print(bar)
    if intelligence.security_boundaries:
        for b in intelligence.security_boundaries[:10]:
            print(f"  ✓ {b.type.value.upper()}: {b.description[:60]}")
            if b.confidence:
                print(f"    Confidence: {b.confidence.score:.1%}")
        if len(intelligence.security_boundaries) > 10:
            print(f"  ... and {len(intelligence.security_boundaries) - 10} more")
    else:
        print("  ❌ No security boundaries detected")
    
    # Hook Points
    print(f"\n{bar}")
    print(f"RUNTIME HOOK POINTS ({len(intelligence.hook_points)})")
    print(bar)
    if intelligence.hook_points:
        for hook in intelligence.hook_points[:10]:
            safe = "✅" if hook.is_safe_integration else "⚠️"
            print(f"  {safe} {hook.hook_type.value}: {hook.object_name}")
            print(f"       Framework: {hook.framework.value}, Priority: {hook.integration_priority}")
        if len(intelligence.hook_points) > 10:
            print(f"  ... and {len(intelligence.hook_points) - 10} more")
    else:
        print("  ❌ No hook points found")
    
    # Readiness
    print(f"\n{bar}")
    print("RUNTIME READINESS")
    print(bar)
    if intelligence.readiness_report:
        report = intelligence.readiness_report
        can_attach = "✅ YES" if report.can_attach else "❌ NO"
        print(f"\n  Can Security Runtime Attach? {can_attach}")
        print(f"  Status: {report.status.value.upper()}")
        print(f"  Compatibility Score: {report.compatibility_score:.1%}")
        
        if report.reasons:
            print(f"\n  ✓ Reasons:")
            for r in report.reasons[:5]:
                print(f"    - {r}")
        
        if report.warnings:
            print(f"\n  ⚠ Warnings:")
            for w in report.warnings[:5]:
                print(f"    - {w}")
        
        if report.missing_requirements:
            print(f"\n  ❌ Missing:")
            for m in report.missing_requirements[:5]:
                print(f"    - {m}")
        
        if report.recommended_hook_points:
            print(f"\n  🔗 Recommended Hook Points:")
            for hook in report.recommended_hook_points[:5]:
                print(f"    - {hook}")
        
        if report.expected_latency:
            print(f"\n  ⚡ Expected Latency: {report.expected_latency}")
    else:
        print("  ❌ Readiness report not available")
    
    # Intelligence Score
    print(f"\n{bar}")
    print(f"Intelligence Score: {intelligence.overall_confidence:.1%}")
    
    # Evidence
    if intelligence.evidence_summary:
        print("\nEvidence Summary:")
        for evidence in intelligence.evidence_summary[:5]:
            print(f"  • {evidence}")
    
    print(bar + "\n")


def main() -> None:
    """CLI entry point."""
    import argparse
    import json
    import sys
    
    parser = argparse.ArgumentParser(
        prog="project-intelligence",
        description="Analyze project from technology fingerprint",
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Project path or fingerprint JSON file",
    )
    parser.add_argument(
        "--json", "-j", action="store_true",
        help="Output as JSON",
    )
    
    args = parser.parse_args()
    
    # Try to load fingerprint from file or generate
    fingerprint = None
    
    if args.path.endswith(".json"):
        try:
            with open(args.path, "r") as f:
                fingerprint = json.load(f)
        except Exception as e:
            print(f"Error loading fingerprint: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            import tech_scanner
            fingerprint = tech_scanner.scan_project(args.path)
        except ImportError:
            print("Error: tech_scanner.py not found", file=sys.stderr)
            print("Please run from project root or provide a fingerprint JSON file", file=sys.stderr)
            sys.exit(1)
    
    # Analyze
    intelligence = analyze_project(fingerprint)
    
    # Output
    if args.json:
        print(json.dumps(intelligence.to_dict(), indent=2))
    else:
        _print_report(intelligence)


if __name__ == "__main__":
    main()
