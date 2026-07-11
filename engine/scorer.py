"""
Scoring Engine for software project analysis.

This module calculates various scores for software projects including security,
complexity, maintainability, and readiness scores. It generates explanations
for each score without performing any parsing or detection.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

logger = logging.getLogger(__name__)


@dataclass
class Score:
    """Represents a calculated score with metadata."""
    name: str
    value: float
    min_value: float = 0.0
    max_value: float = 100.0
    category: str = "general"
    confidence: float = 1.0
    explanation: str = ""
    factors: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def is_good(self) -> bool:
        """Check if the score is good (above 70%)."""
        normalized = self._normalize()
        return normalized >= 0.7
    
    def is_excellent(self) -> bool:
        """Check if the score is excellent (above 90%)."""
        normalized = self._normalize()
        return normalized >= 0.9
    
    def is_poor(self) -> bool:
        """Check if the score is poor (below 40%)."""
        normalized = self._normalize()
        return normalized < 0.4
    
    def _normalize(self) -> float:
        """Normalize score to 0-1 range."""
        if self.max_value == self.min_value:
            return 1.0
        return (self.value - self.min_value) / (self.max_value - self.min_value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert score to dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "category": self.category,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "factors": self.factors,
            "timestamp": self.timestamp.isoformat(),
            "level": self._get_level(),
        }
    
    def _get_level(self) -> str:
        """Get human-readable level."""
        normalized = self._normalize()
        if normalized >= 0.9:
            return "Excellent"
        elif normalized >= 0.7:
            return "Good"
        elif normalized >= 0.5:
            return "Fair"
        elif normalized >= 0.3:
            return "Poor"
        else:
            return "Critical"


@dataclass
class RiskScore(Score):
    """Risk-specific score with risk level."""
    risk_level: str = "unknown"
    risk_factors: List[str] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.value >= 70:
            self.risk_level = "High"
        elif self.value >= 40:
            self.risk_level = "Medium"
        else:
            self.risk_level = "Low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert risk score to dictionary."""
        data = super().to_dict()
        data.update({
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "mitigation_suggestions": self.mitigation_suggestions,
        })
        return data


@dataclass
class ScoreResult:
    """Container for all calculated scores."""
    project_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Scores
    confidence_score: Optional[Score] = None
    popularity_score: Optional[Score] = None
    security_score: Optional[Score] = None
    complexity_score: Optional[Score] = None
    maintainability_score: Optional[Score] = None
    deployment_readiness: Optional[Score] = None
    ai_readiness: Optional[Score] = None
    cloud_readiness: Optional[Score] = None
    documentation_score: Optional[Score] = None
    dependency_health: Optional[Score] = None
    overall_score: Optional[Score] = None
    risk_score: Optional[RiskScore] = None
    
    # Additional scores
    additional_scores: Dict[str, Score] = field(default_factory=dict)
    
    def get_score(self, name: str) -> Optional[Score]:
        """Get a score by name."""
        score_map = {
            "confidence": self.confidence_score,
            "popularity": self.popularity_score,
            "security": self.security_score,
            "complexity": self.complexity_score,
            "maintainability": self.maintainability_score,
            "deployment_readiness": self.deployment_readiness,
            "ai_readiness": self.ai_readiness,
            "cloud_readiness": self.cloud_readiness,
            "documentation": self.documentation_score,
            "dependency_health": self.dependency_health,
            "overall": self.overall_score,
            "risk": self.risk_score,
        }
        return score_map.get(name)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert all scores to dictionary."""
        return {
            "project_id": self.project_id,
            "timestamp": self.timestamp.isoformat(),
            "scores": {
                name: score.to_dict()
                for name, score in [
                    ("confidence", self.confidence_score),
                    ("popularity", self.popularity_score),
                    ("security", self.security_score),
                    ("complexity", self.complexity_score),
                    ("maintainability", self.maintainability_score),
                    ("deployment_readiness", self.deployment_readiness),
                    ("ai_readiness", self.ai_readiness),
                    ("cloud_readiness", self.cloud_readiness),
                    ("documentation", self.documentation_score),
                    ("dependency_health", self.dependency_health),
                    ("overall", self.overall_score),
                    ("risk", self.risk_score),
                ]
                if score is not None
            },
            "additional_scores": {
                name: score.to_dict()
                for name, score in self.additional_scores.items()
            },
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of key scores."""
        return {
            "overall": self.overall_score.value if self.overall_score else 0.0,
            "security": self.security_score.value if self.security_score else 0.0,
            "maintainability": self.maintainability_score.value if self.maintainability_score else 0.0,
            "complexity": self.complexity_score.value if self.complexity_score else 0.0,
            "risk": self.risk_score.value if self.risk_score else 0.0,
            "deployment_readiness": self.deployment_readiness.value if self.deployment_readiness else 0.0,
            "confidence": self.confidence_score.value if self.confidence_score else 0.0,
        }


class ScoringEngine:
    """
    Scoring engine for calculating various project metrics.
    
    This engine calculates scores based on project metadata without performing
    any parsing or detection itself. It provides explanations for each score.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the scoring engine.
        
        Args:
            config: Optional configuration parameters
        """
        self.config = config or {}
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        # Weight configurations
        self.weights = self.config.get("weights", {
            "security": 0.25,
            "maintainability": 0.20,
            "complexity": 0.15,
            "dependencies": 0.15,
            "documentation": 0.10,
            "popularity": 0.10,
            "confidence": 0.05,
        })
        
        logger.info("ScoringEngine initialized")
    
    async def calculate(
        self,
        analysis_data: Dict[str, Any],
        project_id: Optional[str] = None,
    ) -> ScoreResult:
        """
        Calculate all scores from analysis data.
        
        Args:
            analysis_data: Analysis data from analyzer
            project_id: Optional project identifier
            
        Returns:
            ScoreResult containing all calculated scores
        """
        logger.info("Calculating scores")
        
        result = ScoreResult(project_id=project_id)
        
        # Calculate individual scores
        result.confidence_score = await self.calculate_confidence(analysis_data)
        result.popularity_score = await self.calculate_popularity(analysis_data)
        result.security_score = await self.calculate_security(analysis_data)
        result.complexity_score = await self.calculate_complexity(analysis_data)
        result.maintainability_score = await self.calculate_maintainability(analysis_data)
        result.deployment_readiness = await self.calculate_deployment_readiness(analysis_data)
        result.ai_readiness = await self.calculate_ai_readiness(analysis_data)
        result.cloud_readiness = await self.calculate_cloud_readiness(analysis_data)
        result.documentation_score = await self.calculate_documentation(analysis_data)
        result.dependency_health = await self.calculate_dependency_health(analysis_data)
        result.risk_score = await self.calculate_risk(analysis_data)
        result.overall_score = await self.calculate_overall(analysis_data)
        
        logger.info("Scores calculated successfully")
        return result
    
    async def score_project(
        self,
        analysis_data: Dict[str, Any],
    ) -> Score:
        """
        Calculate overall project score.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Overall project score
        """
        return await self.calculate_overall(analysis_data)
    
    async def score_dependencies(
        self,
        analysis_data: Dict[str, Any],
    ) -> Score:
        """
        Calculate dependency health score.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Dependency health score
        """
        return await self.calculate_dependency_health(analysis_data)
    
    async def score_security(
        self,
        analysis_data: Dict[str, Any],
    ) -> Score:
        """
        Calculate security score.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Security score
        """
        return await self.calculate_security(analysis_data)
    
    async def score_complexity(
        self,
        analysis_data: Dict[str, Any],
    ) -> Score:
        """
        Calculate complexity score.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Complexity score
        """
        return await self.calculate_complexity(analysis_data)
    
    async def calculate_confidence(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate confidence score based on analysis completeness.
        
        Args:
            data: Analysis data
            
        Returns:
            Confidence score
        """
        factors = {}
        score = 50.0
        explanations = []
        
        # Check for various data completeness factors
        has_languages = bool(data.get("languages"))
        has_frameworks = bool(data.get("frameworks"))
        has_dependencies = bool(data.get("dependencies"))
        has_metadata = bool(data.get("metadata"))
        has_scores = bool(data.get("scores"))
        
        factors["has_languages"] = has_languages
        factors["has_frameworks"] = has_frameworks
        factors["has_dependencies"] = has_dependencies
        factors["has_metadata"] = has_metadata
        factors["has_scores"] = has_scores
        
        # Calculate score based on data completeness
        completeness_score = 0
        if has_languages:
            completeness_score += 25
            explanations.append("Languages detected")
        if has_frameworks:
            completeness_score += 20
            explanations.append("Frameworks detected")
        if has_dependencies:
            completeness_score += 20
            explanations.append("Dependencies analyzed")
        if has_metadata:
            completeness_score += 15
            explanations.append("Project metadata available")
        if has_scores:
            completeness_score += 20
            explanations.append("Scores calculated")
        
        score = completeness_score
        confidence = 0.9  # Base confidence
        
        # Adjust confidence based on data quality
        if data.get("detection_errors"):
            confidence *= 0.8
            factors["has_errors"] = True
            explanations.append("Detection errors present")
        
        if data.get("total_files", 0) < 3:
            confidence *= 0.7
            factors["few_files"] = True
            explanations.append("Very few files analyzed")
        
        # Create score
        return Score(
            name="Confidence Score",
            value=round(score, 2),
            category="quality",
            confidence=confidence,
            explanation="; ".join(explanations) if explanations else "Analysis data is limited",
            factors=factors,
        )
    
    async def calculate_popularity(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate popularity score based on dependencies and frameworks.
        
        Args:
            data: Analysis data
            
        Returns:
            Popularity score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Get dependencies and frameworks
        deps = data.get("dependencies", {})
        frameworks = data.get("frameworks", {})
        languages = data.get("languages", {})
        
        # Count technology usage
        num_deps = len(deps)
        num_frameworks = len(frameworks)
        num_langs = len(languages)
        
        factors["dependency_count"] = num_deps
        factors["framework_count"] = num_frameworks
        factors["language_count"] = num_langs
        
        # Score based on ecosystem size and diversity
        if num_deps > 0:
            # More dependencies generally means more popular
            dep_score = min(30, num_deps * 2)
            score += dep_score
            explanations.append(f"{num_deps} dependencies")
        
        if num_frameworks > 0:
            # Popular frameworks indicate popularity
            framework_score = min(30, num_frameworks * 10)
            score += framework_score
            explanations.append(f"{num_frameworks} frameworks")
        
        if num_langs > 0:
            # More languages can indicate a mature project
            lang_score = min(20, num_langs * 5)
            score += lang_score
            explanations.append(f"{num_langs} languages")
        
        # Check for popular technologies
        popular_techs = self._get_popular_technologies()
        tech_popularity = 0
        for tech in popular_techs:
            if tech in str(deps) or tech in str(frameworks):
                tech_popularity += 5
        
        score += min(20, tech_popularity)
        factors["popular_technologies_count"] = tech_popularity // 5
        
        if tech_popularity > 0:
            explanations.append("Uses popular technologies")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Popularity Score",
            value=round(score, 2),
            category="popularity",
            confidence=0.85,
            explanation="; ".join(explanations) if explanations else "Limited popularity indicators",
            factors=factors,
        )
    
    async def calculate_security(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate security score based on security practices and libraries.
        
        Args:
            data: Analysis data
            
        Returns:
            Security score
        """
        factors = {}
        explanations = []
        score = 50.0  # Start from neutral
        
        # Check for security-related technologies
        security_libs = data.get("security_libraries", [])
        security_libs_detected = data.get("security_libraries_detected", [])
        all_security_libs = set(security_libs + security_libs_detected)
        
        num_security_libs = len(all_security_libs)
        factors["security_libraries_count"] = num_security_libs
        
        if num_security_libs > 0:
            score += min(20, num_security_libs * 5)
            explanations.append(f"{num_security_libs} security libraries")
        else:
            score -= 10
            explanations.append("No security libraries detected")
        
        # Check for authentication/authorization
        auth_terms = ["auth", "jwt", "oauth", "session", "login", "permission"]
        has_auth = any(
            term in str(data.get("dependencies", {})) or 
            term in str(data.get("framework_details", {}))
            for term in auth_terms
        )
        factors["has_authentication"] = has_auth
        
        if has_auth:
            score += 15
            explanations.append("Authentication/authorization detected")
        else:
            score -= 5
            explanations.append("No authentication detected")
        
        # Check for encryption
        crypto_terms = ["crypto", "encrypt", "bcrypt", "argon2", "hash"]
        has_crypto = any(
            term in str(data.get("dependencies", {}))
            for term in crypto_terms
        )
        factors["has_encryption"] = has_crypto
        
        if has_crypto:
            score += 15
            explanations.append("Encryption libraries detected")
        
        # Check for input validation
        validation_terms = ["validation", "sanitize", "escape", "param"]
        has_validation = any(
            term in str(data.get("dependencies", {}))
            for term in validation_terms
        )
        factors["has_input_validation"] = has_validation
        
        if has_validation:
            score += 10
            explanations.append("Input validation detected")
        
        # Check for SQL injection prevention
        sql_terms = ["sql", "param", "prepare", "statement"]
        has_sql_prev = any(
            term in str(data.get("dependencies", {}))
            for term in sql_terms
        )
        factors["has_sql_prevention"] = has_sql_prev
        
        if has_sql_prev:
            score += 10
            explanations.append("SQL injection prevention detected")
        
        # Check for security headers
        header_terms = ["cors", "helmet", "headers", "xss"]
        has_headers = any(
            term in str(data.get("dependencies", {}))
            for term in header_terms
        )
        factors["has_security_headers"] = has_headers
        
        if has_headers:
            score += 5
            explanations.append("Security headers detected")
        
        # Cap and validate
        score = max(0, min(100, score))
        
        return Score(
            name="Security Score",
            value=round(score, 2),
            category="security",
            confidence=0.75,
            explanation="; ".join(explanations) if explanations else "Security assessment incomplete",
            factors=factors,
        )
    
    async def calculate_complexity(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate complexity score.
        
        Args:
            data: Analysis data
            
        Returns:
            Complexity score (higher = more complex)
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Count files and lines
        total_files = data.get("total_files", 0)
        total_lines = data.get("total_lines", 0)
        
        factors["total_files"] = total_files
        factors["total_lines"] = total_lines
        
        # File complexity
        if total_files > 0:
            file_score = min(30, total_files / 10)  # 300+ files = max
            score += file_score
            if total_files > 100:
                explanations.append(f"{total_files} files")
            elif total_files > 50:
                explanations.append(f"{total_files} files")
        
        # Line complexity
        if total_lines > 0:
            line_score = min(30, total_lines / 1000)  # 30k+ lines = max
            score += line_score
            if total_lines > 10000:
                explanations.append(f"{total_lines} lines")
        
        # Framework complexity
        num_frameworks = len(data.get("frameworks", {}))
        factors["framework_count"] = num_frameworks
        if num_frameworks > 0:
            framework_score = min(20, num_frameworks * 5)
            score += framework_score
            if num_frameworks > 3:
                explanations.append(f"{num_frameworks} frameworks")
        
        # Language complexity
        num_languages = len(data.get("languages", {}))
        factors["language_count"] = num_languages
        if num_languages > 1:
            lang_score = min(20, num_languages * 5)
            score += lang_score
            if num_languages > 3:
                explanations.append(f"{num_languages} languages")
        
        # Architecture patterns
        arch_patterns = data.get("architecture_patterns", [])
        factors["architecture_patterns"] = len(arch_patterns)
        if len(arch_patterns) > 2:
            score += 10
            explanations.append("Multiple architecture patterns")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Complexity Score",
            value=round(score, 2),
            category="complexity",
            confidence=0.9,
            explanation="; ".join(explanations) if explanations else "Low complexity",
            factors=factors,
        )
    
    async def calculate_maintainability(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate maintainability score.
        
        Args:
            data: Analysis data
            
        Returns:
            Maintainability score
        """
        factors = {}
        explanations = []
        score = 100.0  # Start from perfect
        
        # Check for testing framework
        testing_terms = ["test", "jest", "pytest", "mocha", "junit", "rspec", "test"]
        has_tests = any(
            term in str(data.get("dependencies", {})).lower()
            for term in testing_terms
        )
        factors["has_testing_framework"] = has_tests
        
        if not has_tests:
            score -= 25
            explanations.append("No testing framework detected")
        else:
            explanations.append("Testing framework detected")
        
        # Check for linting/formatting
        lint_terms = ["lint", "prettier", "black", "flake8", "eslint", "pylint"]
        has_lint = any(
            term in str(data.get("dependencies", {})).lower()
            for term in lint_terms
        )
        factors["has_linting"] = has_lint
        
        if not has_lint:
            score -= 15
            explanations.append("No linting detected")
        else:
            explanations.append("Linting detected")
        
        # Check for type checking
        type_terms = ["types", "mypy", "pyright", "typescript", "flow"]
        has_types = any(
            term in str(data.get("dependencies", {})).lower()
            for term in type_terms
        )
        factors["has_type_checking"] = has_types
        
        if not has_types:
            score -= 10
            explanations.append("No type checking detected")
        else:
            explanations.append("Type checking detected")
        
        # Check for documentation
        doc_terms = ["docs", "documentation", "sphinx", "docstring", "jsdoc"]
        has_docs = any(
            term in str(data.get("dependencies", {})).lower()
            or term in str(data.get("metadata", {})).lower()
            for term in doc_terms
        )
        factors["has_documentation"] = has_docs
        
        if not has_docs:
            score -= 15
            explanations.append("Limited documentation detected")
        else:
            explanations.append("Documentation detected")
        
        # Check for CI/CD
        ci_terms = ["ci", "github", "gitlab", "jenkins", "circle", "travis"]
        has_ci = any(
            term in str(data.get("ci_cd", {})).lower()
            for term in ci_terms
        )
        factors["has_ci_cd"] = has_ci
        
        if not has_ci:
            score -= 10
            explanations.append("No CI/CD detected")
        else:
            explanations.append("CI/CD detected")
        
        # Complexity penalty
        complexity = data.get("complexity_score", 50)
        if complexity > 70:
            score -= (complexity - 70) * 0.5
            explanations.append("High complexity affecting maintainability")
        
        # Number of dependencies penalty
        dep_count = len(data.get("dependencies", {}))
        if dep_count > 50:
            score -= min(10, (dep_count - 50) * 0.2)
            if dep_count > 100:
                explanations.append("Many dependencies")
        
        # Cap and validate
        score = max(0, min(100, score))
        
        return Score(
            name="Maintainability Score",
            value=round(score, 2),
            category="maintainability",
            confidence=0.8,
            explanation="; ".join(explanations) if explanations else "Good maintainability practices",
            factors=factors,
        )
    
    async def calculate_deployment_readiness(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate deployment readiness score.
        
        Args:
            data: Analysis data
            
        Returns:
            Deployment readiness score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Check for deployment configuration
        has_docker = False
        has_kubernetes = False
        has_procfile = False
        has_deployment_script = False
        
        # Check files
        files = data.get("files", [])
        for file in files:
            filename = file.get("name", "").lower()
            if "dockerfile" in filename:
                has_docker = True
            elif "docker-compose" in filename:
                has_docker = True
            elif "k8s" in filename or "kubernetes" in filename:
                has_kubernetes = True
            elif "procfile" in filename:
                has_procfile = True
            elif "deploy" in filename or "deployment" in filename:
                has_deployment_script = True
        
        factors["has_docker"] = has_docker
        factors["has_kubernetes"] = has_kubernetes
        factors["has_procfile"] = has_procfile
        factors["has_deployment_script"] = has_deployment_script
        
        if has_docker:
            score += 30
            explanations.append("Docker configuration detected")
        if has_kubernetes:
            score += 20
            explanations.append("Kubernetes configuration detected")
        if has_procfile:
            score += 15
            explanations.append("Procfile detected")
        if has_deployment_script:
            score += 10
            explanations.append("Deployment scripts detected")
        
        # Check for environment configuration
        env_terms = [".env", "environment", "config"]
        has_env = any(
            term in str(data.get("files", {}))
            for term in env_terms
        )
        factors["has_environment_config"] = has_env
        
        if has_env:
            score += 10
            explanations.append("Environment configuration detected")
        
        # Check for CI/CD
        ci_terms = ["ci", "github", "gitlab", "jenkins", "circle", "travis", "actions"]
        has_ci = any(
            term in str(data.get("ci_cd", {})).lower()
            for term in ci_terms
        )
        factors["has_ci_cd"] = has_ci
        
        if has_ci:
            score += 15
            explanations.append("CI/CD detected")
        
        # Check for monitoring
        monitor_terms = ["monitor", "health", "metrics", "logging", "trace", "opentelemetry"]
        has_monitor = any(
            term in str(data.get("dependencies", {})).lower()
            for term in monitor_terms
        )
        factors["has_monitoring"] = has_monitor
        
        if has_monitor:
            score += 10
            explanations.append("Monitoring detected")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Deployment Readiness",
            value=round(score, 2),
            category="deployment",
            confidence=0.75,
            explanation="; ".join(explanations) if explanations else "Limited deployment configuration",
            factors=factors,
        )
    
    async def calculate_ai_readiness(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate AI readiness score.
        
        Args:
            data: Analysis data
            
        Returns:
            AI readiness score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Check for AI/ML frameworks
        ai_frameworks = data.get("ai_frameworks", [])
        factors["ai_frameworks"] = ai_frameworks
        
        if ai_frameworks:
            score += 40
            explanations.append(f"{len(ai_frameworks)} AI frameworks detected")
        
        # Check for ML libraries
        ml_terms = ["tensorflow", "pytorch", "keras", "scikit", "transformers", "langchain", "openai"]
        has_ml = any(
            term in str(data.get("dependencies", {})).lower()
            for term in ml_terms
        )
        factors["has_ml_libraries"] = has_ml
        
        if has_ml:
            score += 30
            explanations.append("ML libraries detected")
        
        # Check for data processing
        data_terms = ["pandas", "numpy", "scipy", "dask", "arrow", "data"]
        has_data = any(
            term in str(data.get("dependencies", {})).lower()
            for term in data_terms
        )
        factors["has_data_processing"] = has_data
        
        if has_data:
            score += 15
            explanations.append("Data processing libraries detected")
        
        # Check for API readiness
        api_terms = ["fastapi", "flask", "django", "express", "graphql", "grpc"]
        has_api = any(
            term in str(data.get("frameworks", {})).lower()
            for term in api_terms
        )
        factors["has_api"] = has_api
        
        if has_api:
            score += 15
            explanations.append("API frameworks detected")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="AI Readiness",
            value=round(score, 2),
            category="ai",
            confidence=0.8,
            explanation="; ".join(explanations) if explanations else "No AI/ML technologies detected",
            factors=factors,
        )
    
    async def calculate_cloud_readiness(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate cloud readiness score.
        
        Args:
            data: Analysis data
            
        Returns:
            Cloud readiness score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Check cloud providers
        cloud_providers = data.get("cloud_providers", [])
        factors["cloud_providers"] = cloud_providers
        
        if cloud_providers:
            score += 30
            explanations.append(f"{len(cloud_providers)} cloud providers detected")
        
        # Check for cloud SDKs
        cloud_sdks = ["boto3", "aws", "gcloud", "azure", "google-cloud"]
        has_cloud_sdk = any(
            term in str(data.get("dependencies", {})).lower()
            for term in cloud_sdks
        )
        factors["has_cloud_sdk"] = has_cloud_sdk
        
        if has_cloud_sdk:
            score += 20
            explanations.append("Cloud SDKs detected")
        
        # Check for containerization
        container_platforms = data.get("container_platforms", [])
        factors["container_platforms"] = container_platforms
        
        if container_platforms:
            score += 15
            explanations.append("Containerization detected")
        
        # Check for infrastructure as code
        iac_terms = ["terraform", "pulumi", "cloudformation", "cdk", "k8s"]
        has_iac = any(
            term in str(data.get("files", {})).lower()
            for term in iac_terms
        )
        factors["has_infrastructure_as_code"] = has_iac
        
        if has_iac:
            score += 15
            explanations.append("Infrastructure as code detected")
        
        # Check for cloud configuration
        cloud_config_terms = ["cloud", "region", "zone", "cluster", "instance"]
        has_cloud_config = any(
            term in str(data.get("config_files", {})).lower()
            for term in cloud_config_terms
        )
        factors["has_cloud_config"] = has_cloud_config
        
        if has_cloud_config:
            score += 10
            explanations.append("Cloud configuration detected")
        
        # Check for secrets management
        secrets_terms = ["secret", "vault", "key", "credentials", "env"]
        has_secrets = any(
            term in str(data.get("config_files", {})).lower()
            for term in secrets_terms
        )
        factors["has_secrets_management"] = has_secrets
        
        if has_secrets:
            score += 10
            explanations.append("Secrets management detected")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Cloud Readiness",
            value=round(score, 2),
            category="cloud",
            confidence=0.7,
            explanation="; ".join(explanations) if explanations else "Limited cloud readiness",
            factors=factors,
        )
    
    async def calculate_documentation(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate documentation score.
        
        Args:
            data: Analysis data
            
        Returns:
            Documentation score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Check for README
        files = data.get("files", [])
        has_readme = any(
            file.get("name", "").lower() in ["readme.md", "readme.txt", "readme.rst"]
            for file in files
        )
        factors["has_readme"] = has_readme
        
        if has_readme:
            score += 30
            explanations.append("README detected")
        
        # Check for documentation directory
        has_docs_dir = any(
            "docs" in file.get("path", "").lower().split("/")
            for file in files
        )
        factors["has_docs_directory"] = has_docs_dir
        
        if has_docs_dir:
            score += 20
            explanations.append("Documentation directory detected")
        
        # Check for docstrings/comments
        # This would require parsing files - simplified approach
        has_docstrings = data.get("has_docstrings", False)
        factors["has_docstrings"] = has_docstrings
        
        if has_docstrings:
            score += 20
            explanations.append("Docstrings detected")
        
        # Check for API documentation
        api_doc_terms = ["swagger", "openapi", "api-doc", "api-docs", "apidoc", "postman"]
        has_api_docs = any(
            term in str(data.get("files", {})).lower()
            for term in api_doc_terms
        )
        factors["has_api_documentation"] = has_api_docs
        
        if has_api_docs:
            score += 15
            explanations.append("API documentation detected")
        
        # Check for guides/tutorials
        guide_terms = ["guide", "tutorial", "getting-started", "example", "sample"]
        has_guides = any(
            term in str(data.get("files", {})).lower()
            for term in guide_terms
        )
        factors["has_guides"] = has_guides
        
        if has_guides:
            score += 15
            explanations.append("Examples/guides detected")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Documentation Score",
            value=round(score, 2),
            category="documentation",
            confidence=0.7,
            explanation="; ".join(explanations) if explanations else "Limited documentation",
            factors=factors,
        )
    
    async def calculate_dependency_health(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate dependency health score.
        
        Args:
            data: Analysis data
            
        Returns:
            Dependency health score
        """
        factors = {}
        explanations = []
        score = 100.0  # Start from perfect
        
        deps = data.get("dependencies", {})
        num_deps = len(deps)
        factors["dependency_count"] = num_deps
        
        if num_deps == 0:
            score = 50
            explanations.append("No dependencies detected")
        else:
            # Check for outdated-looking version patterns
            old_versions = 0
            dev_deps = data.get("dev_dependencies", {})
            
            # Simple version pattern check
            for dep, version in deps.items():
                if version and version.startswith("0."):
                    old_versions += 1
                    explanations.append(f"Possible outdated: {dep} {version}")
            
            # Check for lock files
            has_lock_file = any(
                "lock" in file.get("name", "").lower()
                for file in data.get("files", [])
            )
            factors["has_lock_file"] = has_lock_file
            
            if not has_lock_file:
                score -= 20
                explanations.append("No lock file detected")
            
            # Check for dependency count
            if num_deps > 50:
                score -= min(15, (num_deps - 50) * 0.3)
                if num_deps > 100:
                    explanations.append("Many dependencies")
            
            # Check for dev dependency ratio
            if dev_deps and len(dev_deps) > num_deps * 0.5:
                score -= 10
                explanations.append("Many development dependencies")
            
            # Penalize for outdated packages
            if old_versions > 0:
                score -= min(20, old_versions * 2)
                explanations.append(f"{old_versions} possible outdated packages")
        
        # Check for security issues in dependencies
        # This would require vulnerability DB - simplified
        factors["has_security_checks"] = False
        
        # Cap and validate
        score = max(0, min(100, score))
        
        return Score(
            name="Dependency Health",
            value=round(score, 2),
            category="dependencies",
            confidence=0.6,
            explanation="; ".join(explanations) if explanations else "Healthy dependencies",
            factors=factors,
        )
    
    async def calculate_risk(
        self,
        data: Dict[str, Any],
    ) -> RiskScore:
        """
        Calculate risk score.
        
        Args:
            data: Analysis data
            
        Returns:
            Risk score
        """
        factors = {}
        risk_factors = []
        mitigation = []
        score = 0.0
        
        # Security risk
        security_score = data.get("security_score", 50)
        if security_score < 50:
            risk_weight = (50 - security_score) / 50 * 20
            score += risk_weight
            risk_factors.append("Low security score")
            mitigation.append("Implement security best practices")
        
        # Complexity risk
        complexity = data.get("complexity_score", 50)
        if complexity > 70:
            risk_weight = (complexity - 70) / 30 * 15
            score += risk_weight
            risk_factors.append("High complexity")
            mitigation.append("Refactor to reduce complexity")
        
        # Dependency risk
        dep_count = len(data.get("dependencies", {}))
        if dep_count > 50:
            risk_weight = min(15, (dep_count - 50) / 50 * 15)
            score += risk_weight
            risk_factors.append("Many dependencies")
            mitigation.append("Reduce dependency count")
        
        # Maintainability risk
        maintainability = data.get("maintainability_score", 50)
        if maintainability < 50:
            risk_weight = (50 - maintainability) / 50 * 15
            score += risk_weight
            risk_factors.append("Poor maintainability")
            mitigation.append("Improve code quality")
        
        # Documentation risk
        doc_score = data.get("documentation_score", 50)
        if doc_score < 40:
            risk_weight = (40 - doc_score) / 40 * 10
            score += risk_weight
            risk_factors.append("Limited documentation")
            mitigation.append("Improve documentation")
        
        # Deployment risk
        deployment = data.get("deployment_readiness", 50)
        if deployment < 40:
            risk_weight = (40 - deployment) / 40 * 10
            score += risk_weight
            risk_factors.append("Low deployment readiness")
            mitigation.append("Improve deployment configuration")
        
        # Cloud readiness risk
        cloud = data.get("cloud_readiness", 50)
        if cloud < 30:
            risk_weight = (30 - cloud) / 30 * 10
            score += risk_weight
            risk_factors.append("Low cloud readiness")
            mitigation.append("Improve cloud readiness")
        
        # Dependency health risk
        dep_health = data.get("dependency_health", 50)
        if dep_health < 50:
            risk_weight = (50 - dep_health) / 50 * 10
            score += risk_weight
            risk_factors.append("Poor dependency health")
            mitigation.append("Update dependencies")
        
        # Cap at 100
        score = min(100, score)
        
        factors["risk_factors"] = risk_factors
        factors["mitigation_suggestions"] = mitigation
        
        return RiskScore(
            name="Risk Score",
            value=round(score, 2),
            category="risk",
            confidence=0.8,
            explanation="; ".join(risk_factors) if risk_factors else "Low risk profile",
            factors=factors,
            risk_factors=risk_factors,
            mitigation_suggestions=mitigation,
        )
    
    async def calculate_overall(
        self,
        data: Dict[str, Any],
    ) -> Score:
        """
        Calculate overall project score.
        
        Args:
            data: Analysis data
            
        Returns:
            Overall score
        """
        factors = {}
        explanations = []
        score = 0.0
        
        # Get individual scores
        security = data.get("security_score", 50)
        maintainability = data.get("maintainability_score", 50)
        complexity = data.get("complexity_score", 50)
        dependency_health = data.get("dependency_health", 50)
        documentation = data.get("documentation_score", 50)
        popularity = data.get("popularity_score", 50)
        confidence = data.get("confidence_score", 50)
        
        factors.update({
            "security_score": security,
            "maintainability_score": maintainability,
            "complexity_score": complexity,
            "dependency_health": dependency_health,
            "documentation_score": documentation,
            "popularity_score": popularity,
            "confidence_score": confidence,
        })
        
        # Weighted average
        weights = self.weights
        score = (
            weights["security"] * security +
            weights["maintainability"] * maintainability +
            weights["complexity"] * (100 - complexity) +  # Invert complexity
            weights["dependencies"] * dependency_health +
            weights["documentation"] * documentation +
            weights["popularity"] * popularity +
            weights["confidence"] * confidence
        )
        
        # Adjust for risk
        risk = data.get("risk_score", 50)
        risk_penalty = risk * 0.1
        score = max(0, score - risk_penalty)
        
        # Build explanations
        if security > 70:
            explanations.append("Good security practices")
        if maintainability > 70:
            explanations.append("Good maintainability")
        if complexity < 30:
            explanations.append("Low complexity")
        
        # Cap at 100
        score = min(100, score)
        
        return Score(
            name="Overall Score",
            value=round(score, 2),
            category="overall",
            confidence=0.85,
            explanation="; ".join(explanations) if explanations else "Average project health",
            factors=factors,
        )
    
    def _get_popular_technologies(self) -> List[str]:
        """Get list of popular technologies for scoring."""
        return [
            "react", "vue", "angular", "django", "flask", "fastapi",
            "spring", "laravel", "rails", "express", "gin", "echo",
            "python", "javascript", "typescript", "java", "go", "rust",
            "postgresql", "mysql", "mongodb", "redis", "elasticsearch",
            "docker", "kubernetes", "terraform", "aws", "gcp", "azure",
            "tensorflow", "pytorch", "scikit-learn", "pandas", "numpy",
            "jwt", "oauth", "bcrypt", "argon2", "crypto",
        ]