"""
Technology Detection Engine for software project analysis.

This module detects technologies used in a project by analyzing project files,
dependencies, configurations, and patterns. It uses the parser engine to
extract file information without performing direct file parsing.
"""

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

# Import parser module (will be implemented separately)
from engine.parser import Parser, ParseResult

logger = logging.getLogger(__name__)


class TechnologyCategory(Enum):
    """Categories of technologies that can be detected."""
    LANGUAGE = "language"
    FRAMEWORK = "framework"
    DATABASE = "database"
    CLOUD = "cloud"
    PACKAGE_MANAGER = "package_manager"
    CI_CD = "ci_cd"
    CONTAINER = "container"
    AI_ML = "ai_ml"
    SECURITY = "security"
    WEB_SERVER = "web_server"
    OS = "operating_system"
    FRONTEND = "frontend"
    BACKEND = "backend"
    TESTING = "testing"
    MONITORING = "monitoring"
    MESSAGING = "messaging"
    CACHE = "cache"


@dataclass
class DetectionRule:
    """Rule for detecting a specific technology."""
    name: str
    category: TechnologyCategory
    patterns: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    dependency_patterns: List[str] = field(default_factory=list)
    config_patterns: List[str] = field(default_factory=list)
    lock_patterns: List[str] = field(default_factory=list)
    confidence_boost: float = 0.0
    required_files: List[str] = field(default_factory=list)
    optional_files: List[str] = field(default_factory=list)
    weight: float = 1.0


@dataclass
class DetectedTechnology:
    """Represents a detected technology."""
    name: str
    category: TechnologyCategory
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Result of technology detection."""
    technologies: List[DetectedTechnology] = field(default_factory=list)
    languages: Dict[str, float] = field(default_factory=dict)
    frameworks: Dict[str, str] = field(default_factory=dict)
    databases: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    package_managers: List[str] = field(default_factory=list)
    ci_cd_tools: List[str] = field(default_factory=list)
    container_platforms: List[str] = field(default_factory=list)
    ai_frameworks: List[str] = field(default_factory=list)
    security_libraries: List[str] = field(default_factory=list)
    web_servers: List[str] = field(default_factory=list)
    operating_systems: List[str] = field(default_factory=list)
    frontend_frameworks: List[str] = field(default_factory=list)
    backend_frameworks: List[str] = field(default_factory=list)
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    raw_matches: Dict[str, List[str]] = field(default_factory=dict)
    
    def get_technology(self, name: str) -> Optional[DetectedTechnology]:
        """Get a technology by name."""
        for tech in self.technologies:
            if tech.name == name:
                return tech
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "languages": self.languages,
            "frameworks": self.frameworks,
            "databases": self.databases,
            "cloud_providers": self.cloud_providers,
            "package_managers": self.package_managers,
            "ci_cd_tools": self.ci_cd_tools,
            "container_platforms": self.container_platforms,
            "ai_frameworks": self.ai_frameworks,
            "security_libraries": self.security_libraries,
            "web_servers": self.web_servers,
            "operating_systems": self.operating_systems,
            "frontend_frameworks": self.frontend_frameworks,
            "backend_frameworks": self.backend_frameworks,
            "dependencies": self.dependencies,
            "dev_dependencies": self.dev_dependencies,
            "technologies": [
                {
                    "name": t.name,
                    "category": t.category.value,
                    "version": t.version,
                    "confidence": t.confidence,
                    "evidence": t.evidence,
                }
                for t in self.technologies
            ],
        }


class TechnologyDetector:
    """
    Technology detection engine that identifies technologies used in a project.
    
    This class analyzes project structure, files, and dependencies to detect
    various technologies without performing direct file parsing.
    """
    
    def __init__(self, parser: Parser, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the technology detector.
        
        Args:
            parser: Parser instance for accessing project file information
            config: Optional configuration parameters
        """
        self.parser = parser
        self.config = config or {}
        
        # Initialize runtime components
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        # Initialize detection rules
        self._rules: List[DetectionRule] = []
        self._initialize_rules()
        
        logger.info(f"TechnologyDetector initialized with {len(self._rules)} rules")
    
    async def detect(self, parse_result: ParseResult) -> DetectionResult:
        """
        Detect all technologies in the parsed project.
        
        Args:
            parse_result: ParseResult from the parser
            
        Returns:
            DetectionResult containing all detected technologies
        """
        logger.info("Starting technology detection")
        
        result = DetectionResult()
        
        # Detect languages
        languages = await self.detect_language(parse_result)
        result.languages.update(languages)
        
        # Detect frameworks
        frameworks = await self.detect_framework(parse_result)
        result.frameworks.update(frameworks)
        
        # Detect databases
        databases = await self.detect_database(parse_result)
        result.databases.extend(databases)
        
        # Detect cloud providers
        cloud_providers = await self.detect_cloud(parse_result)
        result.cloud_providers.extend(cloud_providers)
        
        # Detect CI/CD tools
        ci_tools = await self.detect_ci(parse_result)
        result.ci_cd_tools.extend(ci_tools)
        
        # Detect package managers
        package_managers = await self.detect_package_manager(parse_result)
        result.package_managers.extend(package_managers)
        
        # Detect container platforms
        containers = await self.detect_container(parse_result)
        result.container_platforms.extend(containers)
        
        # Detect AI frameworks
        ai_frameworks = await self.detect_ai(parse_result)
        result.ai_frameworks.extend(ai_frameworks)
        
        # Detect security libraries
        security_libs = await self.detect_security(parse_result)
        result.security_libraries.extend(security_libs)
        
        # Detect web servers
        web_servers = await self.detect_web_server(parse_result)
        result.web_servers.extend(web_servers)
        
        # Detect operating systems
        os_list = await self.detect_os(parse_result)
        result.operating_systems.extend(os_list)
        
        # Detect frontend frameworks
        frontend = await self.detect_frontend(parse_result)
        result.frontend_frameworks.extend(frontend)
        
        # Detect backend frameworks
        backend = await self.detect_backend(parse_result)
        result.backend_frameworks.extend(backend)
        
        # Extract dependencies
        deps, dev_deps = await self._extract_dependencies(parse_result)
        result.dependencies.update(deps)
        result.dev_dependencies.update(dev_deps)
        
        # Build complete technology list with confidence scores
        result.technologies = await self._build_technologies(result, parse_result)
        
        # Calculate confidence for all technologies
        for tech in result.technologies:
            tech.confidence = await self.calculate_confidence(tech, parse_result)
        
        logger.info(f"Detection complete: {len(result.technologies)} technologies found")
        return result
    
    async def detect_language(self, parse_result: ParseResult) -> Dict[str, float]:
        """
        Detect programming languages used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            Dictionary mapping language names to confidence scores
        """
        languages = {}
        file_extensions = parse_result.file_extensions
        
        # Language detection rules by file extension
        lang_rules = {
            'python': {'.py', '.pyw', '.pyc', '.pyx', '.pxd', '.pyd'},
            'java': {'.java', '.class', '.jar'},
            'rust': {'.rs', '.rlib'},
            'go': {'.go'},
            'javascript': {'.js', '.mjs', '.cjs', '.jsx'},
            'typescript': {'.ts', '.tsx'},
            'php': {'.php', '.php3', '.php4', '.php5', '.php7', '.phtml'},
            'ruby': {'.rb', '.rbw', '.rake', '.gemspec'},
            'csharp': {'.cs', '.csx', '.cshtml'},
            'cpp': {'.cpp', '.cxx', '.cc', '.c++', '.hpp', '.hxx', '.hh'},
            'c': {'.c', '.h'},
            'kotlin': {'.kt', '.kts'},
            'swift': {'.swift'},
            'scala': {'.scala', '.sc'},
            'dart': {'.dart'},
            'r': {'.r', '.rmd'},
            'perl': {'.pl', '.pm', '.t'},
            'lua': {'.lua'},
            'shell': {'.sh', '.bash', '.zsh', '.fish'},
            'sql': {'.sql'},
            'html': {'.html', '.htm'},
            'css': {'.css', '.scss', '.sass', '.less'},
            'json': {'.json', '.json5'},
            'yaml': {'.yaml', '.yml'},
            'xml': {'.xml'},
            'markdown': {'.md', '.markdown'},
        }
        
        total_files = len(parse_result.files)
        if total_files == 0:
            return {}
        
        # Count files by language
        lang_counts = {}
        for file_info in parse_result.files:
            ext = file_info.get('extension', '')
            for lang, extensions in lang_rules.items():
                if ext in extensions:
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    break
        
        # Calculate confidence based on file count ratio
        for lang, count in lang_counts.items():
            confidence = (count / total_files) * 100
            # Boost confidence for known project indicators
            if self._has_language_indicator(parse_result, lang):
                confidence = min(100, confidence + 20)
            languages[lang] = round(confidence, 2)
        
        return languages
    
    async def detect_framework(self, parse_result: ParseResult) -> Dict[str, str]:
        """
        Detect frameworks used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            Dictionary mapping framework names to detected versions
        """
        frameworks = {}
        
        # Framework detection patterns
        framework_patterns = {
            'fastapi': {
                'files': ['fastapi', 'main.py'],
                'dependencies': ['fastapi'],
                'config': ['uvicorn', 'gunicorn'],
            },
            'flask': {
                'files': ['flask', 'app.py', 'wsgi.py'],
                'dependencies': ['flask'],
                'config': ['app.config'],
            },
            'django': {
                'files': ['manage.py', 'settings.py', 'urls.py'],
                'dependencies': ['django'],
                'config': ['django.conf'],
            },
            'react': {
                'files': ['react', 'App.js', 'App.jsx', 'App.tsx'],
                'dependencies': ['react', 'react-dom'],
                'config': ['package.json'],
            },
            'vue': {
                'files': ['vue', 'App.vue', 'main.js'],
                'dependencies': ['vue'],
                'config': ['vue.config.js'],
            },
            'angular': {
                'files': ['angular', 'app.module.ts', 'angular.json'],
                'dependencies': ['@angular/core'],
                'config': ['angular.json'],
            },
            'nextjs': {
                'files': ['next', 'pages', 'next.config.js'],
                'dependencies': ['next'],
                'config': ['next.config.js'],
            },
            'spring': {
                'files': ['spring', 'Application.java', 'application.yml'],
                'dependencies': ['spring-boot', 'spring-core'],
                'config': ['application.properties'],
            },
            'laravel': {
                'files': ['laravel', 'artisan', 'web.php'],
                'dependencies': ['laravel/framework'],
                'config': ['config/app.php'],
            },
            'aspnet': {
                'files': ['aspnet', 'Startup.cs', 'Program.cs'],
                'dependencies': ['Microsoft.AspNetCore'],
                'config': ['appsettings.json'],
            },
            'express': {
                'files': ['express', 'app.js', 'server.js'],
                'dependencies': ['express'],
                'config': ['package.json'],
            },
            'rails': {
                'files': ['rails', 'Gemfile', 'config/routes.rb'],
                'dependencies': ['rails'],
                'config': ['config/application.rb'],
            },
            'gin': {
                'files': ['gin', 'main.go'],
                'dependencies': ['github.com/gin-gonic/gin'],
                'config': ['go.mod'],
            },
            'echo': {
                'files': ['echo', 'main.go'],
                'dependencies': ['github.com/labstack/echo'],
                'config': ['go.mod'],
            },
            'actix': {
                'files': ['actix', 'main.rs'],
                'dependencies': ['actix-web'],
                'config': ['Cargo.toml'],
            },
        }
        
        # Check for framework indicators
        for framework, patterns in framework_patterns.items():
            if self._detect_framework_from_patterns(parse_result, patterns):
                version = await self._detect_framework_version(parse_result, framework)
                frameworks[framework] = version or 'latest'
        
        return frameworks
    
    async def detect_database(self, parse_result: ParseResult) -> List[str]:
        """
        Detect databases used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected database names
        """
        databases = set()
        
        # Database detection patterns
        db_patterns = {
            'postgresql': {
                'dependencies': ['psycopg2', 'pg', 'postgres', 'pg8000', 'asyncpg'],
                'config': ['postgres', 'postgresql'],
                'files': ['postgresql.conf'],
            },
            'mysql': {
                'dependencies': ['mysql', 'mysql-connector', 'pymysql', 'PyMySQL'],
                'config': ['mysql', 'mysqld'],
                'files': ['my.cnf'],
            },
            'mongodb': {
                'dependencies': ['mongodb', 'pymongo', 'mongoose', 'mongodb'],
                'config': ['mongodb'],
                'files': ['mongod.conf'],
            },
            'redis': {
                'dependencies': ['redis', 'redis-py', 'ioredis', 'redis'],
                'config': ['redis'],
                'files': ['redis.conf'],
            },
            'sqlite': {
                'dependencies': ['sqlite3', 'sqlite'],
                'config': ['sqlite'],
                'files': ['.sqlite', '.db'],
            },
            'elasticsearch': {
                'dependencies': ['elasticsearch', 'elasticsearch-py', 'elasticsearch'],
                'config': ['elasticsearch'],
                'files': ['elasticsearch.yml'],
            },
            'cassandra': {
                'dependencies': ['cassandra', 'cassandra-driver'],
                'config': ['cassandra'],
                'files': ['cassandra.yaml'],
            },
            'dynamodb': {
                'dependencies': ['dynamodb', 'boto3'],
                'config': ['dynamodb'],
                'files': ['dynamodb'],
            },
            'firebase': {
                'dependencies': ['firebase', 'firebase-admin'],
                'config': ['firebase'],
                'files': ['firebase.json'],
            },
        }
        
        for db, patterns in db_patterns.items():
            if self._check_database_patterns(parse_result, patterns):
                databases.add(db)
        
        return list(databases)
    
    async def detect_cloud(self, parse_result: ParseResult) -> List[str]:
        """
        Detect cloud providers used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected cloud providers
        """
        cloud_providers = set()
        
        # Cloud provider detection
        cloud_patterns = {
            'aws': {
                'dependencies': ['boto3', 'aws-sdk', 'aws'],
                'config': ['aws', '.aws', 'AWS_ACCESS_KEY'],
                'files': ['credentials', 'config'],
            },
            'gcp': {
                'dependencies': ['google-cloud', 'googleapis', 'gcloud'],
                'config': ['gcp', 'google_cloud', 'GCP'],
                'files': ['credentials.json', 'service-account'],
            },
            'azure': {
                'dependencies': ['azure', 'azure-sdk', 'azure'],
                'config': ['azure', 'AZURE'],
                'files': ['azure', 'appsettings.json'],
            },
            'alibaba': {
                'dependencies': ['alibaba', 'aliyun'],
                'config': ['alibaba', 'aliyun'],
                'files': ['alibaba'],
            },
            'digitalocean': {
                'dependencies': ['digitalocean', 'do'],
                'config': ['digitalocean', 'DIGITALOCEAN'],
                'files': ['digitalocean'],
            },
            'heroku': {
                'dependencies': ['heroku', 'heroku'],
                'config': ['heroku', 'HEROKU'],
                'files': ['Procfile', 'app.json'],
            },
            'vercel': {
                'dependencies': ['vercel', 'vercel'],
                'config': ['vercel', 'VERCEL'],
                'files': ['vercel.json', 'now.json'],
            },
            'netlify': {
                'dependencies': ['netlify', 'netlify'],
                'config': ['netlify', 'NETLIFY'],
                'files': ['netlify.toml'],
            },
        }
        
        for cloud, patterns in cloud_patterns.items():
            if self._check_cloud_patterns(parse_result, patterns):
                cloud_providers.add(cloud)
        
        return list(cloud_providers)
    
    async def detect_ci(self, parse_result: ParseResult) -> List[str]:
        """
        Detect CI/CD tools used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected CI/CD tools
        """
        ci_tools = set()
        
        # CI/CD detection
        ci_patterns = {
            'github_actions': {
                'files': ['.github/workflows'],
                'config': ['github', 'GITHUB'],
            },
            'gitlab_ci': {
                'files': ['.gitlab-ci.yml'],
                'config': ['gitlab-ci', 'GITLAB'],
            },
            'jenkins': {
                'files': ['Jenkinsfile', 'jenkins'],
                'config': ['jenkins', 'JENKINS'],
            },
            'circleci': {
                'files': ['.circleci'],
                'config': ['circleci', 'CIRCLE'],
            },
            'travis': {
                'files': ['.travis.yml'],
                'config': ['travis', 'TRAVIS'],
            },
            'azure_devops': {
                'files': ['azure-pipelines.yml', '.azure'],
                'config': ['azure-pipelines', 'AZURE'],
            },
            'teamcity': {
                'files': ['.teamcity'],
                'config': ['teamcity', 'TEAMCITY'],
            },
            'drone': {
                'files': ['.drone.yml'],
                'config': ['drone', 'DRONE'],
            },
            'concourse': {
                'files': ['concourse.yml'],
                'config': ['concourse', 'CONCOURSE'],
            },
            'bitbucket_pipelines': {
                'files': ['bitbucket-pipelines.yml'],
                'config': ['bitbucket-pipelines', 'BITBUCKET'],
            },
        }
        
        for ci, patterns in ci_patterns.items():
            if self._check_ci_patterns(parse_result, patterns):
                ci_tools.add(ci)
        
        return list(ci_tools)
    
    async def detect_package_manager(self, parse_result: ParseResult) -> List[str]:
        """
        Detect package managers used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected package managers
        """
        package_managers = set()
        
        # Package manager detection
        pm_patterns = {
            'npm': {
                'files': ['package.json', 'package-lock.json'],
                'config': ['npm', 'node_modules'],
            },
            'yarn': {
                'files': ['yarn.lock'],
                'config': ['yarn', '.yarn'],
            },
            'pnpm': {
                'files': ['pnpm-lock.yaml', 'pnpm-workspace.yaml'],
                'config': ['pnpm'],
            },
            'pip': {
                'files': ['requirements.txt', 'setup.py', 'pyproject.toml'],
                'config': ['pip'],
            },
            'poetry': {
                'files': ['pyproject.toml', 'poetry.lock'],
                'config': ['poetry'],
            },
            'conda': {
                'files': ['environment.yml', 'conda.yml'],
                'config': ['conda'],
            },
            'cargo': {
                'files': ['Cargo.toml', 'Cargo.lock'],
                'config': ['cargo'],
            },
            'go_mod': {
                'files': ['go.mod', 'go.sum'],
                'config': ['go.mod'],
            },
            'maven': {
                'files': ['pom.xml'],
                'config': ['maven'],
            },
            'gradle': {
                'files': ['build.gradle', 'settings.gradle'],
                'config': ['gradle'],
            },
            'composer': {
                'files': ['composer.json', 'composer.lock'],
                'config': ['composer'],
            },
            'bundler': {
                'files': ['Gemfile', 'Gemfile.lock'],
                'config': ['bundler'],
            },
            'nuget': {
                'files': ['*.csproj', 'packages.config'],
                'config': ['nuget'],
            },
        }
        
        for pm, patterns in pm_patterns.items():
            if self._check_package_manager_patterns(parse_result, patterns):
                package_managers.add(pm)
        
        return list(package_managers)
    
    async def detect_container(self, parse_result: ParseResult) -> List[str]:
        """
        Detect container platforms used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected container platforms
        """
        containers = set()
        
        # Container platform detection
        container_patterns = {
            'docker': {
                'files': ['Dockerfile', '.dockerignore'],
                'config': ['docker', 'docker-compose'],
            },
            'kubernetes': {
                'files': ['k8s', 'kubernetes'],
                'config': ['kubectl', 'k8s'],
                'extensions': ['.yaml', '.yml'],
            },
            'docker_compose': {
                'files': ['docker-compose.yml', 'docker-compose.yaml'],
                'config': ['compose'],
            },
            'podman': {
                'files': ['Containerfile', '.podman'],
                'config': ['podman'],
            },
            'rancher': {
                'files': ['rancher'],
                'config': ['rancher'],
            },
        }
        
        for container, patterns in container_patterns.items():
            if self._check_container_patterns(parse_result, patterns):
                containers.add(container)
        
        return list(containers)
    
    async def detect_ai(self, parse_result: ParseResult) -> List[str]:
        """
        Detect AI and machine learning frameworks.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected AI frameworks
        """
        ai_frameworks = set()
        
        # AI framework detection
        ai_patterns = {
            'tensorflow': {
                'dependencies': ['tensorflow', 'tf'],
                'files': ['tensorflow'],
            },
            'pytorch': {
                'dependencies': ['torch', 'pytorch'],
                'files': ['pytorch'],
            },
            'keras': {
                'dependencies': ['keras'],
                'files': ['keras'],
            },
            'scikit_learn': {
                'dependencies': ['sklearn', 'scikit-learn'],
                'files': ['sklearn'],
            },
            'jax': {
                'dependencies': ['jax'],
                'files': ['jax'],
            },
            'huggingface': {
                'dependencies': ['transformers', 'huggingface'],
                'files': ['huggingface'],
            },
            'openai': {
                'dependencies': ['openai'],
                'files': ['openai'],
            },
            'langchain': {
                'dependencies': ['langchain'],
                'files': ['langchain'],
            },
            'paddlepaddle': {
                'dependencies': ['paddlepaddle'],
                'files': ['paddle'],
            },
            'mlflow': {
                'dependencies': ['mlflow'],
                'files': ['mlflow'],
            },
        }
        
        for ai, patterns in ai_patterns.items():
            if self._check_ai_patterns(parse_result, patterns):
                ai_frameworks.add(ai)
        
        return list(ai_frameworks)
    
    async def detect_security(self, parse_result: ParseResult) -> List[str]:
        """
        Detect security libraries and tools.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected security libraries
        """
        security_libs = set()
        
        # Security library detection
        security_patterns = {
            'jwt': {
                'dependencies': ['jwt', 'pyjwt', 'jsonwebtoken'],
                'files': ['jwt'],
            },
            'oauth': {
                'dependencies': ['oauth', 'oauthlib', 'oauth2'],
                'files': ['oauth'],
            },
            'cryptography': {
                'dependencies': ['cryptography', 'pycrypto', 'crypto'],
                'files': ['crypto'],
            },
            'bcrypt': {
                'dependencies': ['bcrypt'],
                'files': ['bcrypt'],
            },
            'argon2': {
                'dependencies': ['argon2'],
                'files': ['argon2'],
            },
            'passport': {
                'dependencies': ['passport'],
                'files': ['passport'],
            },
            'spring_security': {
                'dependencies': ['spring-security'],
                'files': ['security'],
            },
            'django_auth': {
                'dependencies': ['django.contrib.auth'],
                'files': ['auth'],
            },
            'flask_login': {
                'dependencies': ['flask-login'],
                'files': ['login'],
            },
        }
        
        for security, patterns in security_patterns.items():
            if self._check_security_patterns(parse_result, patterns):
                security_libs.add(security)
        
        return list(security_libs)
    
    async def detect_web_server(self, parse_result: ParseResult) -> List[str]:
        """
        Detect web servers used in the project.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected web servers
        """
        web_servers = set()
        
        # Web server detection
        server_patterns = {
            'nginx': {
                'files': ['nginx.conf', 'nginx'],
                'config': ['nginx'],
            },
            'apache': {
                'files': ['httpd.conf', '.htaccess'],
                'config': ['apache'],
            },
            'uvicorn': {
                'dependencies': ['uvicorn'],
                'config': ['uvicorn'],
            },
            'gunicorn': {
                'dependencies': ['gunicorn'],
                'config': ['gunicorn'],
            },
            'node': {
                'dependencies': ['node', 'node-server'],
                'config': ['node'],
            },
            'tomcat': {
                'files': ['tomcat'],
                'config': ['tomcat'],
            },
            'jetty': {
                'files': ['jetty'],
                'config': ['jetty'],
            },
            'caddy': {
                'files': ['Caddyfile'],
                'config': ['caddy'],
            },
        }
        
        for server, patterns in server_patterns.items():
            if self._check_web_server_patterns(parse_result, patterns):
                web_servers.add(server)
        
        return list(web_servers)
    
    async def detect_os(self, parse_result: ParseResult) -> List[str]:
        """
        Detect operating systems targeted or used.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected operating systems
        """
        os_list = set()
        
        # OS detection
        os_patterns = {
            'linux': {
                'files': ['Dockerfile', 'Makefile'],
                'config': ['linux', 'ubuntu', 'centos', 'debian'],
            },
            'windows': {
                'files': ['*.ps1', '*.bat', '*.cmd'],
                'config': ['windows', 'win32'],
            },
            'macos': {
                'files': ['*.sh', '*.plist'],
                'config': ['macos', 'darwin'],
            },
            'android': {
                'files': ['AndroidManifest.xml', 'build.gradle'],
                'config': ['android'],
            },
            'ios': {
                'files': ['Info.plist', '*.xcodeproj'],
                'config': ['ios', 'iphone'],
            },
        }
        
        for os_name, patterns in os_patterns.items():
            if self._check_os_patterns(parse_result, patterns):
                os_list.add(os_name)
        
        return list(os_list)
    
    async def detect_frontend(self, parse_result: ParseResult) -> List[str]:
        """
        Detect frontend frameworks.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected frontend frameworks
        """
        frontend = set()
        
        # Frontend framework detection
        frontend_patterns = {
            'react': {
                'dependencies': ['react', 'react-dom'],
                'files': ['jsx', 'tsx'],
            },
            'vue': {
                'dependencies': ['vue'],
                'files': ['.vue'],
            },
            'angular': {
                'dependencies': ['@angular/core'],
                'files': ['.ts'],
            },
            'svelte': {
                'dependencies': ['svelte'],
                'files': ['.svelte'],
            },
            'nextjs': {
                'dependencies': ['next'],
                'files': ['pages', 'next.config.js'],
            },
            'nuxt': {
                'dependencies': ['nuxt'],
                'files': ['nuxt.config.js'],
            },
            'gatsby': {
                'dependencies': ['gatsby'],
                'files': ['gatsby-config.js'],
            },
            'ember': {
                'dependencies': ['ember'],
                'files': ['ember-cli'],
            },
            'backbone': {
                'dependencies': ['backbone'],
                'files': ['backbone'],
            },
        }
        
        for framework, patterns in frontend_patterns.items():
            if self._check_frontend_patterns(parse_result, patterns):
                frontend.add(framework)
        
        return list(frontend)
    
    async def detect_backend(self, parse_result: ParseResult) -> List[str]:
        """
        Detect backend frameworks.
        
        Args:
            parse_result: Parsed project information
            
        Returns:
            List of detected backend frameworks
        """
        backend = set()
        
        # Backend framework detection
        backend_patterns = {
            'django': {
                'dependencies': ['django'],
                'files': ['models.py', 'views.py'],
            },
            'flask': {
                'dependencies': ['flask'],
                'files': ['app.py', 'routes.py'],
            },
            'fastapi': {
                'dependencies': ['fastapi'],
                'files': ['main.py'],
            },
            'spring_boot': {
                'dependencies': ['spring-boot'],
                'files': ['Application.java'],
            },
            'laravel': {
                'dependencies': ['laravel'],
                'files': ['web.php'],
            },
            'aspnet_core': {
                'dependencies': ['Microsoft.AspNetCore'],
                'files': ['Startup.cs'],
            },
            'rails': {
                'dependencies': ['rails'],
                'files': ['Gemfile', 'config/routes.rb'],
            },
            'express': {
                'dependencies': ['express'],
                'files': ['app.js', 'server.js'],
            },
            'gin': {
                'dependencies': ['gin'],
                'files': ['main.go'],
            },
            'echo': {
                'dependencies': ['echo'],
                'files': ['main.go'],
            },
        }
        
        for framework, patterns in backend_patterns.items():
            if self._check_backend_patterns(parse_result, patterns):
                backend.add(framework)
        
        return list(backend)
    
    async def calculate_confidence(
        self,
        technology: DetectedTechnology,
        parse_result: ParseResult,
    ) -> float:
        """
        Calculate confidence score for a detected technology.
        
        Args:
            technology: The detected technology
            parse_result: Parsed project information
            
        Returns:
            Confidence score between 0 and 100
        """
        confidence = 0.0
        
        # Find matching rule
        rule = self._find_rule(technology.name, technology.category)
        if not rule:
            return 50.0  # Default confidence
        
        # Check for evidence
        evidence_score = 0
        total_checks = 0
        
        # Check file patterns
        if rule.file_patterns:
            for pattern in rule.file_patterns:
                if self._check_file_pattern(parse_result, pattern):
                    evidence_score += 10
                total_checks += 1
        
        # Check dependency patterns
        if rule.dependency_patterns:
            for pattern in rule.dependency_patterns:
                if self._check_dependency(parse_result, pattern):
                    evidence_score += 15
                total_checks += 1
        
        # Check config patterns
        if rule.config_patterns:
            for pattern in rule.config_patterns:
                if self._check_config_pattern(parse_result, pattern):
                    evidence_score += 10
                total_checks += 1
        
        # Check required files
        if rule.required_files:
            for file in rule.required_files:
                if self._check_file_exists(parse_result, file):
                    evidence_score += 20
                total_checks += 1
        
        # Calculate base confidence
        if total_checks > 0:
            confidence = (evidence_score)