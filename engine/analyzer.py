"""
Central analysis engine for software project analysis.

This module orchestrates all analysis components to generate a comprehensive
project analysis. It coordinates parsers, detectors, fingerprint engines,
scorers, and recommendation engines without performing any direct analysis.
"""

import asyncio
import logging
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from uuid import uuid4

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

# Import existing engine modules (these will be implemented separately)
# For now, we define type stubs to satisfy imports
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class Parser(Protocol):
    """Protocol for source code parsers."""
    async def parse_directory(self, path: Path) -> Dict[str, Any]: ...
    async def parse_file(self, file_path: Path) -> Dict[str, Any]: ...


@runtime_checkable
class Detector(Protocol):
    """Protocol for technology detectors."""
    async def detect_technologies(self, context: Dict[str, Any]) -> Dict[str, Any]: ...


@runtime_checkable
class FingerprintEngine(Protocol):
    """Protocol for fingerprint generation."""
    async def generate_fingerprint(self, analysis_data: Dict[str, Any]) -> str: ...


@runtime_checkable
class Scorer(Protocol):
    """Protocol for scoring engines."""
    async def calculate_scores(self, analysis_data: Dict[str, Any]) -> Dict[str, float]: ...


@runtime_checkable
class RecommendationEngine(Protocol):
    """Protocol for recommendation generation."""
    async def generate_recommendations(self, analysis_data: Dict[str, Any]) -> List[str]: ...


@dataclass
class AnalysisResult:
    """Complete analysis result container."""
    project_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Project metadata
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    description: Optional[str] = None
    
    # Technology detection
    languages: Dict[str, float] = field(default_factory=dict)
    frameworks: Dict[str, str] = field(default_factory=dict)
    libraries: Dict[str, str] = field(default_factory=dict)
    package_managers: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    deployment_platforms: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    architecture_patterns: List[str] = field(default_factory=list)
    ai_frameworks: List[str] = field(default_factory=list)
    
    # Dependencies
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    
    # Scores
    security_score: float = 0.0
    complexity_score: float = 0.0
    risk_score: float = 0.0
    maintainability_score: float = 0.0
    
    # Additional analysis data
    raw_analysis: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    fingerprint: Optional[str] = None
    
    # File information
    total_files: int = 0
    total_lines: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "project_id": self.project_id,
            "timestamp": self.timestamp.isoformat(),
            "project_name": self.project_name,
            "project_version": self.project_version,
            "description": self.description,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "libraries": self.libraries,
            "package_managers": self.package_managers,
            "databases": self.databases,
            "deployment_platforms": self.deployment_platforms,
            "cloud_providers": self.cloud_providers,
            "architecture_patterns": self.architecture_patterns,
            "ai_frameworks": self.ai_frameworks,
            "dependencies": self.dependencies,
            "dev_dependencies": self.dev_dependencies,
            "security_score": self.security_score,
            "complexity_score": self.complexity_score,
            "risk_score": self.risk_score,
            "maintainability_score": self.maintainability_score,
            "recommendations": self.recommendations,
            "fingerprint": self.fingerprint,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
        }


@dataclass
class AnalysisSession:
    """Session context for an analysis run."""
    session_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "initialized"
    progress: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    result: Optional[AnalysisResult] = None
    
    def update_status(self, status: str, progress: Optional[float] = None) -> None:
        """Update session status and progress."""
        self.status = status
        if progress is not None:
            self.progress = progress
    
    def add_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Add an error to the session."""
        self.errors.append({
            "error": str(error),
            "type": type(error).__name__,
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    def add_warning(self, warning: str) -> None:
        """Add a warning to the session."""
        self.warnings.append(warning)


class ProjectAnalyzer:
    """
    Central analysis engine that orchestrates all analysis components.
    
    This class coordinates the parsing, detection, fingerprinting, scoring,
    and recommendation processes without performing any direct technology
    detection itself.
    """
    
    def __init__(
        self,
        parser: Parser,
        detector: Detector,
        fingerprint_engine: FingerprintEngine,
        scorer: Scorer,
        recommendation_engine: RecommendationEngine,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the project analyzer with required engine components.
        
        Args:
            parser: Parser instance for code parsing
            detector: Detector instance for technology detection
            fingerprint_engine: Fingerprint engine for generating project fingerprints
            scorer: Scorer instance for calculating metrics
            recommendation_engine: Recommendation engine for suggestions
            config: Optional configuration parameters
        """
        self.parser = parser
        self.detector = detector
        self.fingerprint_engine = fingerprint_engine
        self.scorer = scorer
        self.recommendation_engine = recommendation_engine
        self.config = config or {}
        
        # Initialize runtime components
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        logger.info("ProjectAnalyzer initialized with all engine components")
    
    async def analyze(
        self,
        source_path: Union[str, Path],
        session: Optional[AnalysisSession] = None,
    ) -> AnalysisResult:
        """
        Analyze a project from a local path.
        
        Args:
            source_path: Path to the project directory
            session: Optional analysis session for progress tracking
            
        Returns:
            Complete AnalysisResult
        """
        path = Path(source_path).resolve()
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")
        
        session = session or AnalysisSession()
        session.update_status("analyzing_project", 0.0)
        
        try:
            # Step 1: Parse the project
            session.update_status("parsing_project", 20.0)
            parse_context = await self._parse_project(path, session)
            
            # Step 2: Detect technologies
            session.update_status("detecting_technologies", 40.0)
            tech_context = await self._detect_technologies(parse_context, session)
            
            # Step 3: Generate fingerprint
            session.update_status("generating_fingerprint", 60.0)
            fingerprint = await self._generate_fingerprint(tech_context, session)
            
            # Step 4: Calculate scores
            session.update_status("calculating_scores", 75.0)
            scores = await self._calculate_scores(tech_context, session)
            
            # Step 5: Generate recommendations
            session.update_status("generating_recommendations", 90.0)
            recommendations = await self._generate_recommendations(tech_context, session)
            
            # Step 6: Build result
            result = self._build_result(
                tech_context,
                scores,
                recommendations,
                fingerprint,
                path,
            )
            
            session.result = result
            session.update_status("completed", 100.0)
            
            logger.info(f"Analysis completed for project: {result.project_id}")
            return result
            
        except Exception as e:
            session.add_error(e)
            session.update_status("failed")
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            raise
    
    async def analyze_project(
        self,
        project_path: Union[str, Path],
        include_dev_deps: bool = True,
        session: Optional[AnalysisSession] = None,
    ) -> AnalysisResult:
        """
        Analyze a project with enhanced options.
        
        Args:
            project_path: Path to the project
            include_dev_deps: Whether to include development dependencies
            session: Optional analysis session
            
        Returns:
            Complete AnalysisResult
        """
        result = await self.analyze(project_path, session)
        
        # Additional processing for project-specific metadata
        path = Path(project_path).resolve()
        
        # Extract project metadata from package files
        project_meta = await self._extract_project_metadata(path)
        if project_meta:
            result.project_name = project_meta.get("name")
            result.project_version = project_meta.get("version")
            result.description = project_meta.get("description")
        
        if not include_dev_deps:
            result.dev_dependencies = {}
        
        return result
    
    async def analyze_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        session: Optional[AnalysisSession] = None,
    ) -> AnalysisResult:
        """
        Analyze a directory structure.
        
        Args:
            directory: Directory path to analyze
            recursive: Whether to analyze subdirectories recursively
            session: Optional analysis session
            
        Returns:
            Complete AnalysisResult
        """
        path = Path(directory).resolve()
        if not path.exists():
            raise ValueError(f"Directory does not exist: {path}")
        
        session = session or AnalysisSession()
        session.metadata["analysis_type"] = "directory"
        session.metadata["recursive"] = recursive
        
        # For directory analysis, we may want to add directory-specific metadata
        result = await self.analyze(path, session)
        
        # Add directory-specific metadata
        result.raw_analysis["analyzed_directory"] = str(path)
        result.raw_analysis["recursive_scan"] = recursive
        
        return result
    
    async def analyze_repository(
        self,
        repo_url: str,
        branch: str = "main",
        session: Optional[AnalysisSession] = None,
    ) -> AnalysisResult:
        """
        Analyze a Git repository.
        
        Args:
            repo_url: Git repository URL
            branch: Branch to analyze
            session: Optional analysis session
            
        Returns:
            Complete AnalysisResult
        """
        session = session or AnalysisSession()
        session.metadata["repository_url"] = repo_url
        session.metadata["branch"] = branch
        
        # Clone repository to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                await self._clone_repository(repo_url, temp_path, branch)
                logger.info(f"Cloned repository to: {temp_path}")
                
                result = await self.analyze(temp_path, session)
                
                # Add repository metadata
                result.raw_analysis["repository_url"] = repo_url
                result.raw_analysis["branch"] = branch
                result.project_name = result.project_name or self._extract_repo_name(repo_url)
                
                return result
                
            except Exception as e:
                session.add_error(e, {"repo_url": repo_url, "branch": branch})
                logger.error(f"Repository analysis failed: {str(e)}")
                raise
    
    async def generate_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate a human-readable summary of the analysis result.
        
        Args:
            result: AnalysisResult to summarize
            
        Returns:
            Dictionary containing summary information
        """
        summary = {
            "project": {
                "id": result.project_id,
                "name": result.project_name or "Unknown",
                "version": result.project_version or "N/A",
                "timestamp": result.timestamp.isoformat(),
            },
            "technologies": {
                "languages": list(result.languages.keys()),
                "frameworks": list(result.frameworks.keys()),
                "databases": result.databases,
                "package_managers": result.package_managers,
            },
            "scores": {
                "security": result.security_score,
                "complexity": result.complexity_score,
                "risk": result.risk_score,
                "maintainability": result.maintainability_score,
            },
            "metrics": {
                "total_files": result.total_files,
                "total_lines": result.total_lines,
                "total_dependencies": len(result.dependencies),
            },
            "recommendations": result.recommendations[:5],  # Top 5 recommendations
            "fingerprint": result.fingerprint,
        }
        
        return summary
    
    async def _parse_project(
        self,
        path: Path,
        session: AnalysisSession,
    ) -> Dict[str, Any]:
        """Parse the project using the parser engine."""
        try:
            parse_result = await self.parser.parse_directory(path)
            
            # Update session with parse statistics
            session.metadata["parse_result"] = parse_result
            session.metadata["parsed_files"] = len(parse_result.get("files", []))
            
            return parse_result
        except Exception as e:
            session.add_error(e, {"phase": "parsing"})
            raise RuntimeError(f"Parsing failed: {str(e)}") from e
    
    async def _detect_technologies(
        self,
        context: Dict[str, Any],
        session: AnalysisSession,
    ) -> Dict[str, Any]:
        """Detect technologies using the detector engine."""
        try:
            detection_result = await self.detector.detect_technologies(context)
            
            # Update session with detection results
            session.metadata["detection_result"] = detection_result
            
            return {**context, "detected_technologies": detection_result}
        except Exception as e:
            session.add_error(e, {"phase": "detection"})
            raise RuntimeError(f"Technology detection failed: {str(e)}") from e
    
    async def _generate_fingerprint(
        self,
        context: Dict[str, Any],
        session: AnalysisSession,
    ) -> str:
        """Generate a fingerprint using the fingerprint engine."""
        try:
            fingerprint = await self.fingerprint_engine.generate_fingerprint(context)
            session.metadata["fingerprint_generated"] = True
            return fingerprint
        except Exception as e:
            session.add_error(e, {"phase": "fingerprint"})
            logger.warning(f"Fingerprint generation failed: {str(e)}")
            return ""
    
    async def _calculate_scores(
        self,
        context: Dict[str, Any],
        session: AnalysisSession,
    ) -> Dict[str, float]:
        """Calculate scores using the scorer engine."""
        try:
            scores = await self.scorer.calculate_scores(context)
            session.metadata["scores_calculated"] = True
            return scores
        except Exception as e:
            session.add_error(e, {"phase": "scoring"})
            logger.warning(f"Score calculation failed: {str(e)}")
            return {
                "security_score": 0.0,
                "complexity_score": 0.0,
                "risk_score": 0.0,
                "maintainability_score": 0.0,
            }
    
    async def _generate_recommendations(
        self,
        context: Dict[str, Any],
        session: AnalysisSession,
    ) -> List[str]:
        """Generate recommendations using the recommendation engine."""
        try:
            recommendations = await self.recommendation_engine.generate_recommendations(
                context
            )
            session.metadata["recommendations_generated"] = True
            return recommendations
        except Exception as e:
            session.add_error(e, {"phase": "recommendations"})
            logger.warning(f"Recommendation generation failed: {str(e)}")
            return []
    
    def _build_result(
        self,
        context: Dict[str, Any],
        scores: Dict[str, float],
        recommendations: List[str],
        fingerprint: str,
        path: Path,
    ) -> AnalysisResult:
        """Build the final analysis result from all components."""
        # Extract technology data from context
        tech_data = context.get("detected_technologies", {})
        
        result = AnalysisResult(
            project_id=str(uuid4()),
            languages=tech_data.get("languages", {}),
            frameworks=tech_data.get("frameworks", {}),
            libraries=tech_data.get("libraries", {}),
            package_managers=tech_data.get("package_managers", []),
            databases=tech_data.get("databases", []),
            deployment_platforms=tech_data.get("deployment_platforms", []),
            cloud_providers=tech_data.get("cloud_providers", []),
            architecture_patterns=tech_data.get("architecture_patterns", []),
            ai_frameworks=tech_data.get("ai_frameworks", []),
            dependencies=tech_data.get("dependencies", {}),
            dev_dependencies=tech_data.get("dev_dependencies", {}),
            security_score=scores.get("security_score", 0.0),
            complexity_score=scores.get("complexity_score", 0.0),
            risk_score=scores.get("risk_score", 0.0),
            maintainability_score=scores.get("maintainability_score", 0.0),
            raw_analysis=context,
            recommendations=recommendations,
            fingerprint=fingerprint,
            total_files=context.get("total_files", 0),
            total_lines=context.get("total_lines", 0),
        )
        
        return result
    
    async def _extract_project_metadata(self, path: Path) -> Dict[str, Any]:
        """Extract project metadata from package files."""
        metadata = {}
        
        # Check for various package files
        package_files = [
            ("package.json", "json"),
            ("pyproject.toml", "toml"),
            ("setup.py", "python"),
            ("Cargo.toml", "toml"),
            ("go.mod", "go_mod"),
            ("pom.xml", "xml"),
            ("build.gradle", "gradle"),
        ]
        
        for filename, _ in package_files:
            file_path = path / filename
            if file_path.exists():
                try:
                    # Parse based on file type (simplified)
                    if filename == "package.json":
                        import json
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            metadata["name"] = data.get("name")
                            metadata["version"] = data.get("version")
                            metadata["description"] = data.get("description")
                            break
                except Exception as e:
                    logger.debug(f"Failed to parse {filename}: {str(e)}")
        
        return metadata
    
    async def _clone_repository(
        self,
        repo_url: str,
        target_path: Path,
        branch: str,
    ) -> None:
        """Clone a Git repository to the target path."""
        import subprocess
        
        try:
            # Create target directory
            target_path.mkdir(parents=True, exist_ok=True)
            
            # Clone the repository
            cmd = [
                "git", "clone",
                "--branch", branch,
                "--depth", "1",
                repo_url,
                str(target_path),
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"Git clone failed: {stderr.decode()}")
                
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not available in PATH")
        except Exception as e:
            raise RuntimeError(f"Failed to clone repository: {str(e)}")
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL."""
        import re
        # Remove git protocol and get the last part
        name = repo_url.split("/")[-1]
        name = re.sub(r"\.git$", "", name)
        return name or "unknown_repository"


# Convenience function for quick analysis
async def analyze_project(
    path: Union[str, Path],
    parser: Parser,
    detector: Detector,
    fingerprint_engine: FingerprintEngine,
    scorer: Scorer,
    recommendation_engine: RecommendationEngine,
    config: Optional[Dict[str, Any]] = None,
) -> AnalysisResult:
    """
    Convenience function to analyze a project with default settings.
    
    Args:
        path: Path to the project
        parser: Parser instance
        detector: Detector instance
        fingerprint_engine: Fingerprint engine instance
        scorer: Scorer instance
        recommendation_engine: Recommendation engine instance
        config: Optional configuration
        
    Returns:
        Complete AnalysisResult
    """
    analyzer = ProjectAnalyzer(
        parser=parser,
        detector=detector,
        fingerprint_engine=fingerprint_engine,
        scorer=scorer,
        recommendation_engine=recommendation_engine,
        config=config,
    )
    return await analyzer.analyze(path)