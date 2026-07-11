"""
Project Fingerprint Engine for generating unique project identifiers.

This module generates comprehensive fingerprints of software projects including
technology stacks, dependencies, and architectural patterns. It creates
consistent, comparable fingerprints for project identification and similarity
analysis.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

# Import existing engine modules
from engine.detector import DetectionResult, DetectedTechnology, TechnologyCategory

logger = logging.getLogger(__name__)


class FingerprintVersion(Enum):
    """Version of fingerprint format."""
    V1 = "1.0"
    V2 = "1.1"


@dataclass
class TechnologyNode:
    """Node in the technology graph."""
    id: str
    name: str
    category: TechnologyCategory
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class TechnologyEdge:
    """Edge in the technology graph."""
    source: str
    target: str
    relationship: str
    weight: float = 1.0


@dataclass
class TechnologyGraph:
    """Graph representation of technologies and their relationships."""
    nodes: List[TechnologyNode] = field(default_factory=list)
    edges: List[TechnologyEdge] = field(default_factory=list)
    
    def add_node(self, node: TechnologyNode) -> None:
        """Add a node to the graph."""
        if not self.get_node(node.id):
            self.nodes.append(node)
    
    def add_edge(self, edge: TechnologyEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)
    
    def get_node(self, node_id: str) -> Optional[TechnologyNode]:
        """Get a node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None
    
    def get_edges_from(self, node_id: str) -> List[TechnologyEdge]:
        """Get all edges originating from a node."""
        return [edge for edge in self.edges if edge.source == node_id]
    
    def get_edges_to(self, node_id: str) -> List[TechnologyEdge]:
        """Get all edges targeting a node."""
        return [edge for edge in self.edges if edge.target == node_id]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "category": n.category.value,
                    "version": n.version,
                    "metadata": n.metadata,
                    "confidence": n.confidence,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relationship": e.relationship,
                    "weight": e.weight,
                }
                for e in self.edges
            ],
        }


@dataclass
class DependencyGraph:
    """Graph representation of project dependencies."""
    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: List[Tuple[str, str, Optional[str]]] = field(default_factory=list)
    
    def add_dependency(self, source: str, target: str, version: Optional[str] = None) -> None:
        """Add a dependency relationship."""
        self.edges.append((source, target, version))
        
        # Add nodes if they don't exist
        if source not in self.nodes:
            self.nodes[source] = {"type": "package"}
        if target not in self.nodes:
            self.nodes[target] = {"type": "package"}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary."""
        return {
            "nodes": {
                node_id: {
                    "type": info["type"],
                    "version": info.get("version"),
                    "name": node_id,
                }
                for node_id, info in self.nodes.items()
            },
            "edges": [
                {
                    "source": source,
                    "target": target,
                    "version": version,
                }
                for source, target, version in self.edges
            ],
        }


@dataclass
class ProjectFingerprint:
    """
    Complete project fingerprint containing all identifying information.
    """
    fingerprint_id: str = field(default_factory=lambda: str(uuid4()))
    fingerprint_hash: str = ""
    version: str = FingerprintVersion.V1.value
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Project metadata
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    
    # Technology stack
    languages: Dict[str, float] = field(default_factory=dict)
    frameworks: Dict[str, str] = field(default_factory=dict)
    databases: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    package_managers: List[str] = field(default_factory=list)
    container_platforms: List[str] = field(default_factory=list)
    ci_cd_tools: List[str] = field(default_factory=list)
    ai_frameworks: List[str] = field(default_factory=list)
    security_libraries: List[str] = field(default_factory=list)
    web_servers: List[str] = field(default_factory=list)
    operating_systems: List[str] = field(default_factory=list)
    frontend_frameworks: List[str] = field(default_factory=list)
    backend_frameworks: List[str] = field(default_factory=list)
    
    # Architecture and deployment
    architecture_patterns: List[str] = field(default_factory=list)
    deployment_platforms: List[str] = field(default_factory=list)
    
    # Dependencies
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    
    # Graphs
    technology_graph: Optional[TechnologyGraph] = None
    dependency_graph: Optional[DependencyGraph] = None
    
    # Signature
    project_signature: str = ""
    
    # Raw data for reference
    raw_technology_data: Dict[str, Any] = field(default_factory=dict)
    
    def generate_hash(self) -> str:
        """
        Generate a unique hash for this fingerprint.
        
        Returns:
            SHA-256 hash string
        """
        # Create a stable representation of the fingerprint
        fingerprint_data = {
            "project_name": self.project_name,
            "project_version": self.project_version,
            "languages": sorted(self.languages.items()),
            "frameworks": sorted(self.frameworks.items()),
            "databases": sorted(self.databases),
            "cloud_providers": sorted(self.cloud_providers),
            "package_managers": sorted(self.package_managers),
            "container_platforms": sorted(self.container_platforms),
            "ai_frameworks": sorted(self.ai_frameworks),
            "dependencies": sorted(self.dependencies.items()),
            "architecture_patterns": sorted(self.architecture_patterns),
        }
        
        # Convert to JSON with sorted keys for consistency
        json_str = json.dumps(fingerprint_data, sort_keys=True)
        
        # Generate hash
        hash_obj = hashlib.sha256(json_str.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert fingerprint to dictionary."""
        return {
            "fingerprint_id": self.fingerprint_id,
            "fingerprint_hash": self.fingerprint_hash,
            "version": self.version,
            "generated_at": self.generated_at.isoformat(),
            "project_name": self.project_name,
            "project_version": self.project_version,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "databases": self.databases,
            "cloud_providers": self.cloud_providers,
            "package_managers": self.package_managers,
            "container_platforms": self.container_platforms,
            "ci_cd_tools": self.ci_cd_tools,
            "ai_frameworks": self.ai_frameworks,
            "security_libraries": self.security_libraries,
            "web_servers": self.web_servers,
            "operating_systems": self.operating_systems,
            "frontend_frameworks": self.frontend_frameworks,
            "backend_frameworks": self.backend_frameworks,
            "architecture_patterns": self.architecture_patterns,
            "deployment_platforms": self.deployment_platforms,
            "dependencies": self.dependencies,
            "dev_dependencies": self.dev_dependencies,
            "technology_graph": self.technology_graph.to_dict() if self.technology_graph else None,
            "dependency_graph": self.dependency_graph.to_dict() if self.dependency_graph else None,
            "project_signature": self.project_signature,
        }
    
    def to_json(self) -> str:
        """Export fingerprint as JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectFingerprint':
        """Create fingerprint from dictionary."""
        fingerprint = cls(
            fingerprint_id=data.get("fingerprint_id", str(uuid4())),
            fingerprint_hash=data.get("fingerprint_hash", ""),
            version=data.get("version", FingerprintVersion.V1.value),
            generated_at=datetime.fromisoformat(data.get("generated_at", datetime.utcnow().isoformat())),
            project_name=data.get("project_name"),
            project_version=data.get("project_version"),
            languages=data.get("languages", {}),
            frameworks=data.get("frameworks", {}),
            databases=data.get("databases", []),
            cloud_providers=data.get("cloud_providers", []),
            package_managers=data.get("package_managers", []),
            container_platforms=data.get("container_platforms", []),
            ci_cd_tools=data.get("ci_cd_tools", []),
            ai_frameworks=data.get("ai_frameworks", []),
            security_libraries=data.get("security_libraries", []),
            web_servers=data.get("web_servers", []),
            operating_systems=data.get("operating_systems", []),
            frontend_frameworks=data.get("frontend_frameworks", []),
            backend_frameworks=data.get("backend_frameworks", []),
            architecture_patterns=data.get("architecture_patterns", []),
            deployment_platforms=data.get("deployment_platforms", []),
            dependencies=data.get("dependencies", {}),
            dev_dependencies=data.get("dev_dependencies", {}),
            project_signature=data.get("project_signature", ""),
        )
        
        # Rebuild graphs if present
        if "technology_graph" in data and data["technology_graph"]:
            graph_data = data["technology_graph"]
            technology_graph = TechnologyGraph()
            
            for node_data in graph_data.get("nodes", []):
                node = TechnologyNode(
                    id=node_data["id"],
                    name=node_data["name"],
                    category=TechnologyCategory(node_data["category"]),
                    version=node_data.get("version"),
                    metadata=node_data.get("metadata", {}),
                    confidence=node_data.get("confidence", 0.0),
                )
                technology_graph.add_node(node)
            
            for edge_data in graph_data.get("edges", []):
                edge = TechnologyEdge(
                    source=edge_data["source"],
                    target=edge_data["target"],
                    relationship=edge_data["relationship"],
                    weight=edge_data.get("weight", 1.0),
                )
                technology_graph.add_edge(edge)
            
            fingerprint.technology_graph = technology_graph
        
        if "dependency_graph" in data and data["dependency_graph"]:
            graph_data = data["dependency_graph"]
            dependency_graph = DependencyGraph()
            
            for node_id, node_info in graph_data.get("nodes", {}).items():
                dependency_graph.nodes[node_id] = node_info
            
            for edge_data in graph_data.get("edges", []):
                dependency_graph.add_dependency(
                    edge_data["source"],
                    edge_data["target"],
                    edge_data.get("version"),
                )
            
            fingerprint.dependency_graph = dependency_graph
        
        return fingerprint


class FingerprintEngine:
    """
    Engine for generating and managing project fingerprints.
    
    This engine creates comprehensive, unique fingerprints of software projects
    that can be used for identification, comparison, and similarity analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the fingerprint engine.
        
        Args:
            config: Optional configuration parameters
        """
        self.config = config or {}
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        logger.info("FingerprintEngine initialized")
    
    async def generate(
        self,
        detection_result: DetectionResult,
        project_name: Optional[str] = None,
        project_version: Optional[str] = None,
    ) -> ProjectFingerprint:
        """
        Generate a fingerprint from detection results.
        
        Args:
            detection_result: DetectionResult from the detector
            project_name: Optional project name
            project_version: Optional project version
            
        Returns:
            ProjectFingerprint containing all identifying information
        """
        logger.info("Generating project fingerprint")
        
        # Create fingerprint
        fingerprint = ProjectFingerprint(
            project_name=project_name,
            project_version=project_version,
        )
        
        # Populate fingerprint with detection results
        fingerprint.languages = detection_result.languages
        fingerprint.frameworks = detection_result.frameworks
        fingerprint.databases = detection_result.databases
        fingerprint.cloud_providers = detection_result.cloud_providers
        fingerprint.package_managers = detection_result.package_managers
        fingerprint.container_platforms = detection_result.container_platforms
        fingerprint.ci_cd_tools = detection_result.ci_cd_tools
        fingerprint.ai_frameworks = detection_result.ai_frameworks
        fingerprint.security_libraries = detection_result.security_libraries
        fingerprint.web_servers = detection_result.web_servers
        fingerprint.operating_systems = detection_result.operating_systems
        fingerprint.frontend_frameworks = detection_result.frontend_frameworks
        fingerprint.backend_frameworks = detection_result.backend_frameworks
        
        # Copy dependencies
        fingerprint.dependencies = detection_result.dependencies
        fingerprint.dev_dependencies = detection_result.dev_dependencies
        
        # Store raw data
        fingerprint.raw_technology_data = detection_result.to_dict()
        
        # Build technology graph
        fingerprint.technology_graph = await self._build_technology_graph(detection_result)
        
        # Build dependency graph
        fingerprint.dependency_graph = await self._build_dependency_graph(detection_result)
        
        # Generate project signature
        fingerprint.project_signature = await self._generate_signature(fingerprint)
        
        # Generate fingerprint hash
        fingerprint.fingerprint_hash = fingerprint.generate_hash()
        
        logger.info(f"Fingerprint generated: {fingerprint.fingerprint_id}")
        return fingerprint
    
    async def compare(
        self,
        fingerprint1: ProjectFingerprint,
        fingerprint2: ProjectFingerprint,
    ) -> Dict[str, Any]:
        """
        Compare two fingerprints and return similarity metrics.
        
        Args:
            fingerprint1: First fingerprint
            fingerprint2: Second fingerprint
            
        Returns:
            Dictionary containing comparison results
        """
        logger.info("Comparing fingerprints")
        
        # Calculate similarity scores
        language_similarity = self._calculate_set_similarity(
            set(fingerprint1.languages.keys()),
            set(fingerprint2.languages.keys()),
        )
        
        framework_similarity = self._calculate_set_similarity(
            set(fingerprint1.frameworks.keys()),
            set(fingerprint2.frameworks.keys()),
        )
        
        database_similarity = self._calculate_set_similarity(
            set(fingerprint1.databases),
            set(fingerprint2.databases),
        )
        
        cloud_similarity = self._calculate_set_similarity(
            set(fingerprint1.cloud_providers),
            set(fingerprint2.cloud_providers),
        )
        
        dependency_similarity = self._calculate_dict_similarity(
            fingerprint1.dependencies,
            fingerprint2.dependencies,
        )
        
        # Calculate overall similarity
        weights = {
            "languages": 0.25,
            "frameworks": 0.20,
            "databases": 0.15,
            "cloud": 0.10,
            "dependencies": 0.30,
        }
        
        overall_similarity = (
            weights["languages"] * language_similarity +
            weights["frameworks"] * framework_similarity +
            weights["databases"] * database_similarity +
            weights["cloud"] * cloud_similarity +
            weights["dependencies"] * dependency_similarity
        )
        
        return {
            "overall_similarity": overall_similarity,
            "metrics": {
                "languages": language_similarity,
                "frameworks": framework_similarity,
                "databases": database_similarity,
                "cloud_providers": cloud_similarity,
                "dependencies": dependency_similarity,
            },
            "fingerprint1_id": fingerprint1.fingerprint_id,
            "fingerprint2_id": fingerprint2.fingerprint_id,
            "hash_match": fingerprint1.fingerprint_hash == fingerprint2.fingerprint_hash,
        }
    
    async def similarity(
        self,
        fingerprint1: ProjectFingerprint,
        fingerprint2: ProjectFingerprint,
    ) -> float:
        """
        Calculate similarity score between two fingerprints.
        
        Args:
            fingerprint1: First fingerprint
            fingerprint2: Second fingerprint
            
        Returns:
            Similarity score between 0 and 1
        """
        result = await self.compare(fingerprint1, fingerprint2)
        return result["overall_similarity"]
    
    async def hash(self, fingerprint: ProjectFingerprint) -> str:
        """
        Get or generate the fingerprint hash.
        
        Args:
            fingerprint: The fingerprint to hash
            
        Returns:
            SHA-256 hash string
        """
        if not fingerprint.fingerprint_hash:
            fingerprint.fingerprint_hash = fingerprint.generate_hash()
        return fingerprint.fingerprint_hash
    
    async def export(
        self,
        fingerprint: ProjectFingerprint,
        format: str = "json",
    ) -> Union[str, Dict[str, Any]]:
        """
        Export fingerprint in specified format.
        
        Args:
            fingerprint: Fingerprint to export
            format: Export format ("json" or "dict")
            
        Returns:
            Exported fingerprint in specified format
        """
        if format == "json":
            return fingerprint.to_json()
        elif format == "dict":
            return fingerprint.to_dict()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def _build_technology_graph(
        self,
        detection_result: DetectionResult,
    ) -> TechnologyGraph:
        """
        Build a technology graph from detection results.
        
        Args:
            detection_result: DetectionResult from detector
            
        Returns:
            TechnologyGraph representing technology relationships
        """
        graph = TechnologyGraph()
        
        # Add technology nodes
        for tech in detection_result.technologies:
            node = TechnologyNode(
                id=tech.name.lower().replace(" ", "_"),
                name=tech.name,
                category=tech.category,
                version=tech.version,
                confidence=tech.confidence,
                metadata={"evidence": tech.evidence, "details": tech.details},
            )
            graph.add_node(node)
        
        # Add relationships between technologies
        self._add_technology_relationships(graph)
        
        return graph
    
    def _add_technology_relationships(self, graph: TechnologyGraph) -> None:
        """Add relationship edges between technology nodes."""
        # Framework to language relationships
        framework_language_map = {
            "django": "python",
            "flask": "python",
            "fastapi": "python",
            "spring": "java",
            "spring_boot": "java",
            "laravel": "php",
            "rails": "ruby",
            "express": "javascript",
            "gin": "go",
            "echo": "go",
            "actix": "rust",
            "aspnet_core": "csharp",
            "react": "javascript",
            "vue": "javascript",
            "angular": "typescript",
            "nextjs": "javascript",
            "nuxt": "javascript",
        }
        
        for node in graph.nodes:
            # Add framework to language relationships
            for framework, language in framework_language_map.items():
                if node.name.lower() == framework:
                    language_node = graph.get_node(language)
                    if language_node:
                        graph.add_edge(TechnologyEdge(
                            source=node.id,
                            target=language_node.id,
                            relationship="depends_on",
                            weight=0.8,
                        ))
            
            # Add database to ORM relationships
            db_orm_map = {
                "postgresql": ["sqlalchemy", "django_orm", "gorm", "typeorm"],
                "mysql": ["sqlalchemy", "django_orm", "gorm", "typeorm"],
                "mongodb": ["mongoose", "pymongo", "mongoengine"],
                "redis": ["redis_py", "ioredis"],
            }
            
            for db, orms in db_orm_map.items():
                if node.name.lower() == db:
                    for orm in orms:
                        orm_node = graph.get_node(orm)
                        if orm_node:
                            graph.add_edge(TechnologyEdge(
                                source=node.id,
                                target=orm_node.id,
                                relationship="compatible_with",
                                weight=0.6,
                            ))
        
        # Add cloud to deployment relationships
        cloud_deployment_map = {
            "aws": ["ec2", "lambda", "s3", "rds", "dynamodb"],
            "gcp": ["compute_engine", "cloud_functions", "cloud_run"],
            "azure": ["azure_vm", "azure_functions", "azure_app_service"],
        }
        
        for node in graph.nodes:
            for cloud, services in cloud_deployment_map.items():
                if node.name.lower() == cloud:
                    for service in services:
                        service_node = graph.get_node(service)
                        if service_node:
                            graph.add_edge(TechnologyEdge(
                                source=node.id,
                                target=service_node.id,
                                relationship="integrates_with",
                                weight=0.7,
                            ))
    
    async def _build_dependency_graph(
        self,
        detection_result: DetectionResult,
    ) -> DependencyGraph:
        """
        Build a dependency graph from detection results.
        
        Args:
            detection_result: DetectionResult from detector
            
        Returns:
            DependencyGraph representing dependency relationships
        """
        graph = DependencyGraph()
        
        # Add dependencies to graph
        for package, version in detection_result.dependencies.items():
            graph.add_dependency("project", package, version)
        
        # Add dev dependencies
        for package, version in detection_result.dev_dependencies.items():
            graph.add_dependency("project_dev", package, version)
        
        # Try to add relationships between packages (simplified)
        for package, version in detection_result.dependencies.items():
            # Add relationships based on package naming conventions
            if package.startswith("@") and "/" in package:
                # Scoped package
                scope, name = package[1:].split("/", 1)
                graph.add_dependency(scope, name, version)
        
        return graph
    
    async def _generate_signature(self, fingerprint: ProjectFingerprint) -> str:
        """
        Generate a project signature string.
        
        Args:
            fingerprint: The fingerprint to generate signature for
            
        Returns:
            Project signature string
        """
        signature_parts = []
        
        # Add languages
        if fingerprint.languages:
            langs = sorted(fingerprint.languages.keys())
            signature_parts.append(f"lang:{'+'.join(langs)}")
        
        # Add frameworks
        if fingerprint.frameworks:
            frames = sorted(fingerprint.frameworks.keys())
            signature_parts.append(f"fw:{'+'.join(frames)}")
        
        # Add databases
        if fingerprint.databases:
            dbs = sorted(fingerprint.databases)
            signature_parts.append(f"db:{'+'.join(dbs)}")
        
        # Add cloud providers
        if fingerprint.cloud_providers:
            clouds = sorted(fingerprint.cloud_providers)
            signature_parts.append(f"cloud:{'+'.join(clouds)}")
        
        # Add architecture patterns
        if fingerprint.architecture_patterns:
            arch = sorted(fingerprint.architecture_patterns)
            signature_parts.append(f"arch:{'+'.join(arch)}")
        
        # Add package managers
        if fingerprint.package_managers:
            pms = sorted(fingerprint.package_managers)
            signature_parts.append(f"pm:{'+'.join(pms)}")
        
        # Create signature
        signature = "|".join(signature_parts)
        
        # Hash signature for shorter representation
        if signature:
            hash_obj = hashlib.sha256(signature.encode('utf-8'))
            return f"{hash_obj.hexdigest()[:12]}"
        
        return "unknown"
    
    def _calculate_set_similarity(self, set1: Set, set2: Set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union
    
    def _calculate_dict_similarity(
        self,
        dict1: Dict[str, Any],
        dict2: Dict[str, Any],
    ) -> float:
        """Calculate similarity between two dictionaries."""
        keys1 = set(dict1.keys())
        keys2 = set(dict2.keys())
        
        if not keys1 and not keys2:
            return 1.0
        if not keys1 or not keys2:
            return 0.0
        
        # Calculate key similarity
        key_similarity = self._calculate_set_similarity(keys1, keys2)
        
        # Calculate value similarity for common keys
        common_keys = keys1 & keys2
        if common_keys:
            value_match = sum(
                1 for k in common_keys
                if dict1.get(k) == dict2.get(k)
            )
            value_similarity = value_match / len(common_keys)
        else:
            value_similarity = 0.0
        
        # Combine key and value similarity
        return (key_similarity + value_similarity) / 2
    
    async def find_similar(
        self,
        fingerprint: ProjectFingerprint,
        fingerprint_collection: List[ProjectFingerprint],
        threshold: float = 0.7,
    ) -> List[Tuple[ProjectFingerprint, float]]:
        """
        Find similar fingerprints in a collection.
        
        Args:
            fingerprint: Target fingerprint
            fingerprint_collection: List of fingerprints to search
            threshold: Similarity threshold (0-1)
            
        Returns:
            List of (fingerprint, similarity_score) tuples sorted by similarity
        """
        similar = []
        
        for candidate in fingerprint_collection:
            if candidate.fingerprint_id == fingerprint.fingerprint_id:
                continue
            
            similarity_score = await self.similarity(fingerprint, candidate)
            if similarity_score >= threshold:
                similar.append((candidate, similarity_score))
        
        # Sort by similarity descending
        similar.sort(key=lambda x: x[1], reverse=True)
        
        return similar