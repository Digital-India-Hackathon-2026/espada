"""
Report Generator for software project analysis.

This module generates comprehensive reports in various formats including JSON,
HTML, Markdown, and CSV. It creates visual-ready data and summaries without
performing any analysis itself.
"""

import csv
import io
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

# Import existing modules
from engine.analyzer import AnalysisResult, AnalysisSession
from engine.detector import DetectionResult
from engine.fingerprint import ProjectFingerprint

logger = logging.getLogger(__name__)


@dataclass
class ReportData:
    """Container for all report data."""
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Analysis results
    analysis_result: Optional[AnalysisResult] = None
    detection_result: Optional[DetectionResult] = None
    fingerprint: Optional[ProjectFingerprint] = None
    
    # Computed report data
    summary: Dict[str, Any] = field(default_factory=dict)
    technology_stack: Dict[str, Any] = field(default_factory=dict)
    security_metrics: Dict[str, Any] = field(default_factory=dict)
    dependencies_report: Dict[str, Any] = field(default_factory=dict)
    architecture_report: Dict[str, Any] = field(default_factory=dict)
    recommendations_list: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    visual_data: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    """Complete report container."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Project Analysis Report"
    created_at: datetime = field(default_factory=datetime.utcnow)
    format: str = "json"
    data: ReportData = field(default_factory=ReportData)
    html_content: Optional[str] = None
    markdown_content: Optional[str] = None
    csv_data: Optional[Dict[str, List[Dict[str, Any]]]] = None


class ReportGenerator:
    """
    Report generation engine for creating comprehensive project reports.
    
    This class generates reports in multiple formats using analysis results,
    without performing any analysis itself. It creates visual-ready data and
    provides various export options.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the report generator.
        
        Args:
            config: Optional configuration parameters
        """
        self.config = config or {}
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        # Report settings
        self.include_raw_data = self.config.get("include_raw_data", False)
        self.max_recommendations = self.config.get("max_recommendations", 20)
        self.theme = self.config.get("theme", "light")
        
        logger.info("ReportGenerator initialized")
    
    async def generate(
        self,
        analysis_result: AnalysisResult,
        detection_result: Optional[DetectionResult] = None,
        fingerprint: Optional[ProjectFingerprint] = None,
        format: str = "json",
    ) -> Report:
        """
        Generate a report from analysis results.
        
        Args:
            analysis_result: AnalysisResult from analyzer
            detection_result: Optional DetectionResult from detector
            fingerprint: Optional ProjectFingerprint
            format: Output format (json, html, markdown, csv)
            
        Returns:
            Report containing generated content
        """
        logger.info(f"Generating {format} report")
        
        # Build report data
        report_data = await self._build_report_data(
            analysis_result,
            detection_result,
            fingerprint,
        )
        
        # Create report
        report = Report(
            title=f"Project Analysis Report - {report_data.project_name or 'Unknown'}",
            data=report_data,
            format=format,
        )
        
        # Generate content based on format
        if format == "json":
            report.html_content = None
            report.markdown_content = None
            report.csv_data = None
        elif format == "html":
            report.html_content = await self._generate_html_report(report_data)
            report.markdown_content = None
            report.csv_data = None
        elif format == "markdown":
            report.markdown_content = await self._generate_markdown_report(report_data)
            report.html_content = None
            report.csv_data = None
        elif format == "csv":
            report.csv_data = await self._generate_csv_data(report_data)
            report.html_content = None
            report.markdown_content = None
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Report generated: {report.id}")
        return report
    
    async def export_json(self, report: Report) -> str:
        """
        Export report as JSON string.
        
        Args:
            report: Report to export
            
        Returns:
            JSON string representation
        """
        export_data = {
            "report_id": report.id,
            "title": report.title,
            "created_at": report.created_at.isoformat(),
            "format": report.format,
            "data": self._serialize_report_data(report.data),
        }
        return json.dumps(export_data, indent=2, default=str)
    
    async def export_html(self, report: Report) -> str:
        """
        Export report as HTML string.
        
        Args:
            report: Report to export
            
        Returns:
            HTML string
        """
        if report.html_content:
            return report.html_content
        
        # Generate HTML if not already present
        report.html_content = await self._generate_html_report(report.data)
        return report.html_content
    
    async def export_markdown(self, report: Report) -> str:
        """
        Export report as Markdown string.
        
        Args:
            report: Report to export
            
        Returns:
            Markdown string
        """
        if report.markdown_content:
            return report.markdown_content
        
        # Generate Markdown if not already present
        report.markdown_content = await self._generate_markdown_report(report.data)
        return report.markdown_content
    
    async def summary(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate an executive summary.
        
        Args:
            analysis_result: AnalysisResult to summarize
            
        Returns:
            Summary dictionary
        """
        summary = {
            "project": {
                "id": analysis_result.project_id,
                "name": analysis_result.project_name or "Unknown",
                "version": analysis_result.project_version or "N/A",
                "timestamp": analysis_result.timestamp.isoformat(),
            },
            "technology": {
                "total_languages": len(analysis_result.languages),
                "total_frameworks": len(analysis_result.frameworks),
                "total_dependencies": len(analysis_result.dependencies),
                "databases": analysis_result.databases,
                "cloud_providers": analysis_result.cloud_providers,
            },
            "scores": {
                "security": analysis_result.security_score,
                "complexity": analysis_result.complexity_score,
                "risk": analysis_result.risk_score,
                "maintainability": analysis_result.maintainability_score,
            },
            "metrics": {
                "total_files": analysis_result.total_files,
                "total_lines": analysis_result.total_lines,
            },
            "recommendations_count": len(analysis_result.recommendations),
            "top_3_recommendations": analysis_result.recommendations[:3],
        }
        
        # Add risk level
        if analysis_result.risk_score >= 70:
            summary["risk_level"] = "High"
        elif analysis_result.risk_score >= 40:
            summary["risk_level"] = "Medium"
        else:
            summary["risk_level"] = "Low"
        
        # Add security level
        if analysis_result.security_score >= 80:
            summary["security_level"] = "Strong"
        elif analysis_result.security_score >= 50:
            summary["security_level"] = "Moderate"
        else:
            summary["security_level"] = "Needs Improvement"
        
        return summary
    
    async def _build_report_data(
        self,
        analysis_result: AnalysisResult,
        detection_result: Optional[DetectionResult],
        fingerprint: Optional[ProjectFingerprint],
    ) -> ReportData:
        """
        Build complete report data from all results.
        
        Args:
            analysis_result: AnalysisResult from analyzer
            detection_result: Optional DetectionResult
            fingerprint: Optional ProjectFingerprint
            
        Returns:
            ReportData containing all report data
        """
        report_data = ReportData(
            project_name=analysis_result.project_name,
            project_version=analysis_result.project_version,
            analysis_result=analysis_result,
            detection_result=detection_result,
            fingerprint=fingerprint,
        )
        
        # Generate summary
        report_data.summary = await self.summary(analysis_result)
        
        # Build technology stack
        report_data.technology_stack = self._build_technology_stack(analysis_result)
        
        # Build security metrics
        report_data.security_metrics = self._build_security_metrics(analysis_result)
        
        # Build dependencies report
        report_data.dependencies_report = self._build_dependencies_report(analysis_result)
        
        # Build architecture report
        report_data.architecture_report = self._build_architecture_report(analysis_result)
        
        # Extract recommendations
        report_data.recommendations_list = analysis_result.recommendations[:self.max_recommendations]
        
        # Build statistics
        report_data.statistics = self._build_statistics(analysis_result)
        
        # Build visual-ready data
        report_data.visual_data = self._build_visual_data(analysis_result)
        
        # Include raw data if configured
        if self.include_raw_data:
            report_data.raw_data = analysis_result.to_dict()
            if detection_result:
                report_data.raw_data["detection"] = detection_result.to_dict()
            if fingerprint:
                report_data.raw_data["fingerprint"] = fingerprint.to_dict()
        
        return report_data
    
    def _build_technology_stack(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build technology stack data."""
        return {
            "languages": [
                {"name": lang, "percentage": pct}
                for lang, pct in analysis_result.languages.items()
            ],
            "frameworks": [
                {"name": name, "version": version}
                for name, version in analysis_result.frameworks.items()
            ],
            "databases": analysis_result.databases,
            "cloud_providers": analysis_result.cloud_providers,
            "package_managers": analysis_result.package_managers,
            "ai_frameworks": analysis_result.ai_frameworks,
            "architecture_patterns": analysis_result.architecture_patterns,
        }
    
    def _build_security_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build security metrics data."""
        metrics = {
            "overall_score": analysis_result.security_score,
            "risk_score": analysis_result.risk_score,
            "complexity_score": analysis_result.complexity_score,
            "maintainability_score": analysis_result.maintainability_score,
            "risk_level": self._get_risk_level(analysis_result.risk_score),
            "security_level": self._get_security_level(analysis_result.security_score),
            "maintainability_level": self._get_maintainability_level(
                analysis_result.maintainability_score
            ),
        }
        
        # Add detailed metrics if available
        if hasattr(analysis_result, "security_details"):
            metrics["details"] = analysis_result.security_details
        
        return metrics
    
    def _build_dependencies_report(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build dependencies report data."""
        deps = {
            "total": len(analysis_result.dependencies),
            "dependencies": [
                {"name": name, "version": version}
                for name, version in analysis_result.dependencies.items()
            ],
        }
        
        if analysis_result.dev_dependencies:
            deps["dev_total"] = len(analysis_result.dev_dependencies)
            deps["dev_dependencies"] = [
                {"name": name, "version": version}
                for name, version in analysis_result.dev_dependencies.items()
            ]
        
        # Categorize dependencies
        if deps["total"] > 0:
            deps["categories"] = self._categorize_dependencies(
                analysis_result.dependencies
            )
        
        return deps
    
    def _build_architecture_report(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build architecture report data."""
        return {
            "patterns": analysis_result.architecture_patterns,
            "deployment_platforms": analysis_result.deployment_platforms,
            "architecture_complexity": self._calculate_architecture_complexity(
                analysis_result
            ),
            "features": self._extract_architecture_features(analysis_result),
        }
    
    def _build_statistics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build statistics data."""
        stats = {
            "files": analysis_result.total_files,
            "lines": analysis_result.total_lines,
            "languages_count": len(analysis_result.languages),
            "frameworks_count": len(analysis_result.frameworks),
            "dependencies_count": len(analysis_result.dependencies),
            "dev_dependencies_count": len(analysis_result.dev_dependencies),
            "databases_count": len(analysis_result.databases),
            "cloud_providers_count": len(analysis_result.cloud_providers),
            "recommendations_count": len(analysis_result.recommendations),
        }
        
        # Calculate additional metrics
        if analysis_result.total_files > 0:
            stats["avg_lines_per_file"] = round(
                analysis_result.total_lines / analysis_result.total_files, 2
            )
        
        return stats
    
    def _build_visual_data(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """
        Build visual-ready data for charts and graphs.
        
        Returns:
            Data ready for visualization libraries
        """
        visual_data = {
            "chart_data": {},
            "distributions": {},
            "comparisons": {},
        }
        
        # Language distribution for pie/donut charts
        if analysis_result.languages:
            visual_data["chart_data"]["languages"] = {
                "labels": list(analysis_result.languages.keys()),
                "values": list(analysis_result.languages.values()),
            }
        
        # Framework data for bar charts
        if analysis_result.frameworks:
            visual_data["chart_data"]["frameworks"] = {
                "labels": list(analysis_result.frameworks.keys()),
                "values": [1] * len(analysis_result.frameworks),
            }
        
        # Score data for radar/spider charts
        visual_data["chart_data"]["scores"] = {
            "labels": ["Security", "Complexity", "Risk", "Maintainability"],
            "values": [
                analysis_result.security_score,
                analysis_result.complexity_score,
                analysis_result.risk_score,
                analysis_result.maintainability_score,
            ],
        }
        
        # Dependency distribution
        if analysis_result.dependencies:
            dep_categories = self._categorize_dependencies(
                analysis_result.dependencies
            )
            visual_data["distributions"]["dependencies"] = {
                "labels": list(dep_categories.keys()),
                "values": [len(v) for v in dep_categories.values()],
            }
        
        # Architecture complexity radar data
        visual_data["chart_data"]["architecture"] = {
            "labels": ["Scalability", "Maintainability", "Security", "Performance", "Modularity"],
            "values": [
                self._calculate_architectural_metric(analysis_result, "scalability"),
                analysis_result.maintainability_score,
                analysis_result.security_score,
                self._calculate_architectural_metric(analysis_result, "performance"),
                self._calculate_architectural_metric(analysis_result, "modularity"),
            ],
        }
        
        return visual_data
    
    def _categorize_dependencies(self, dependencies: Dict[str, str]) -> Dict[str, List[str]]:
        """Categorize dependencies by type."""
        categories = {
            "web": [],
            "database": [],
            "testing": [],
            "security": [],
            "utilities": [],
            "other": [],
        }
        
        # Simple categorization based on package names
        for dep in dependencies.keys():
            dep_lower = dep.lower()
            if any(web in dep_lower for web in ["express", "django", "flask", "spring", "laravel"]):
                categories["web"].append(dep)
            elif any(db in dep_lower for db in ["sql", "db", "mongo", "postgres", "mysql", "redis"]):
                categories["database"].append(dep)
            elif any(test in dep_lower for test in ["test", "jest", "pytest", "mocha", "junit"]):
                categories["testing"].append(dep)
            elif any(sec in dep_lower for sec in ["auth", "security", "jwt", "crypto", "encrypt"]):
                categories["security"].append(dep)
            elif any(util in dep_lower for util in ["utils", "helpers", "tools", "common"]):
                categories["utilities"].append(dep)
            else:
                categories["other"].append(dep)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _calculate_architecture_complexity(self, analysis_result: AnalysisResult) -> str:
        """Calculate architecture complexity level."""
        score = analysis_result.complexity_score
        
        if score >= 80:
            return "Very High"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Very Low"
    
    def _extract_architecture_features(self, analysis_result: AnalysisResult) -> List[str]:
        """Extract architecture features from analysis."""
        features = []
        
        # Check for common architectural patterns
        if "microservices" in str(analysis_result.architecture_patterns).lower():
            features.append("Microservices")
        if "monolithic" in str(analysis_result.architecture_patterns).lower():
            features.append("Monolithic")
        if "event-driven" in str(analysis_result.architecture_patterns).lower():
            features.append("Event-driven")
        if "serverless" in str(analysis_result.architecture_patterns).lower():
            features.append("Serverless")
        if "mvc" in str(analysis_result.architecture_patterns).lower():
            features.append("MVC Pattern")
        
        # Check deployment platforms
        if "docker" in str(analysis_result.deployment_platforms).lower():
            features.append("Containerized")
        if "kubernetes" in str(analysis_result.deployment_platforms).lower():
            features.append("Orchestrated")
        
        # If no features found, add generic ones
        if not features:
            features.append("Standard Architecture")
        
        return features
    
    def _calculate_architectural_metric(
        self,
        analysis_result: AnalysisResult,
        metric: str,
    ) -> float:
        """Calculate an architectural metric."""
        # Use scores as base and adjust
        base_score = analysis_result.maintainability_score
        
        if metric == "scalability":
            # Higher for microservices, lower for monolithic
            has_microservices = any(
                "micro" in str(pattern).lower()
                for pattern in analysis_result.architecture_patterns
            )
            return min(100, base_score + (30 if has_microservices else -10))
        
        elif metric == "performance":
            # Higher for optimized, lower for complex
            complexity = analysis_result.complexity_score
            return max(0, 100 - (complexity * 0.5))
        
        elif metric == "modularity":
            # Higher for more languages/frameworks
            return min(100, len(analysis_result.frameworks) * 20 + 20)
        
        return base_score
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _get_security_level(self, score: float) -> str:
        """Get security level from score."""
        if score >= 80:
            return "Strong"
        elif score >= 50:
            return "Moderate"
        else:
            return "Needs Improvement"
    
    def _get_maintainability_level(self, score: float) -> str:
        """Get maintainability level from score."""
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Moderate"
        else:
            return "Low"
    
    async def _generate_html_report(self, report_data: ReportData) -> str:
        """
        Generate HTML report content.
        
        Args:
            report_data: ReportData to use
            
        Returns:
            HTML string
        """
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("    <meta charset='UTF-8'>")
        html.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append(f"    <title>{report_data.project_name or 'Project'} Analysis Report</title>")
        html.append("    <style>")
        html.append(self._get_html_styles())
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("    <div class='container'>")
        
        # Header
        html.append(f"        <h1>{report_data.project_name or 'Unknown Project'} Analysis Report</h1>")
        if report_data.project_version:
            html.append(f"        <p class='version'>Version: {report_data.project_version}</p>")
        html.append(f"        <p class='timestamp'>Generated: {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        
        # Summary Section
        html.append("        <h2>Executive Summary</h2>")
        html.append("        <div class='summary-grid'>")
        
        summary = report_data.summary
        summary_items = [
            ("Security Score", f"{summary.get('scores', {}).get('security', 0):.1f}%"),
            ("Risk Level", summary.get('risk_level', 'Unknown')),
            ("Security Level", summary.get('security_level', 'Unknown')),
            ("Languages", str(summary.get('technology', {}).get('total_languages', 0))),
            ("Frameworks", str(summary.get('technology', {}).get('total_frameworks', 0))),
            ("Dependencies", str(summary.get('technology', {}).get('total_dependencies', 0))),
            ("Files", str(summary.get('metrics', {}).get('total_files', 0))),
            ("Lines", str(summary.get('metrics', {}).get('total_lines', 0))),
        ]
        
        for label, value in summary_items:
            html.append(f"            <div class='summary-item'><strong>{label}:</strong> {value}</div>")
        
        html.append("        </div>")
        
        # Technology Stack
        html.append("        <h2>Technology Stack</h2>")
        tech_stack = report_data.technology_stack
        
        if tech_stack.get("languages"):
            html.append("        <h3>Languages</h3>")
            html.append("        <ul>")
            for lang in tech_stack["languages"]:
                html.append(f"            <li>{lang['name']}: {lang['percentage']:.1f}%</li>")
            html.append("        </ul>")
        
        if tech_stack.get("frameworks"):
            html.append("        <h3>Frameworks</h3>")
            html.append("        <ul>")
            for fw in tech_stack["frameworks"]:
                version = fw.get('version', 'latest')
                html.append(f"            <li>{fw['name']}: {version}</li>")
            html.append("        </ul>")
        
        if tech_stack.get("databases"):
            html.append("        <h3>Databases</h3>")
            html.append("        <ul>")
            for db in tech_stack["databases"]:
                html.append(f"            <li>{db}</li>")
            html.append("        </ul>")
        
        # Security Metrics
        html.append("        <h2>Security Metrics</h2>")
        security = report_data.security_metrics
        html.append("        <div class='security-grid'>")
        security_items = [
            ("Overall Security", security.get("overall_score", 0), security.get("security_level", "Unknown")),
            ("Risk Score", security.get("risk_score", 0), security.get("risk_level", "Unknown")),
            ("Maintainability", security.get("maintainability_score", 0), security.get("maintainability_level", "Unknown")),
        ]
        
        for label, score, level in security_items:
            html.append(f"            <div class='security-item'>")
            html.append(f"                <span class='label'>{label}</span>")
            html.append(f"                <span class='score'>{score:.1f}%</span>")
            html.append(f"                <span class='level level-{level.lower().replace(' ', '-')}'>{level}</span>")
            html.append(f"            </div>")
        
        html.append("        </div>")
        
        # Dependencies
        html.append("        <h2>Dependencies</h2>")
        deps = report_data.dependencies_report
        html.append(f"        <p>Total Dependencies: {deps.get('total', 0)}</p>")
        if deps.get("dev_total"):
            html.append(f"        <p>Dev Dependencies: {deps['dev_total']}</p>")
        
        if deps.get("dependencies"):
            html.append("        <h3>Top Dependencies</h3>")
            html.append("        <ul>")
            for dep in deps["dependencies"][:10]:
                html.append(f"            <li>{dep['name']}: {dep['version']}</li>")
            html.append("        </ul>")
        
        # Architecture Report
        html.append("        <h2>Architecture</h2>")
        arch = report_data.architecture_report
        html.append("        <div class='architecture-info'>")
        html.append(f"            <p><strong>Patterns:</strong> {', '.join(arch.get('patterns', [])) or 'Not detected'}</p>")
        html.append(f"            <p><strong>Complexity:</strong> {arch.get('architecture_complexity', 'Unknown')}</p>")
        html.append(f"            <p><strong>Deployment:</strong> {', '.join(arch.get('deployment_platforms', [])) or 'Not detected'}</p>")
        html.append("        </div>")
        
        # Recommendations
        if report_data.recommendations_list:
            html.append("        <h2>Recommendations</h2>")
            html.append("        <ol>")
            for rec in report_data.recommendations_list[:10]:
                html.append(f"            <li>{rec}</li>")
            html.append("        </ol>")
        
        # Statistics
        html.append("        <h2>Statistics</h2>")
        stats = report_data.statistics
        html.append("        <div class='stats-grid'>")
        stats_items = [
            ("Total Files", stats.get("files", 0)),
            ("Total Lines", stats.get("lines", 0)),
            ("Languages", stats.get("languages_count", 0)),
            ("Frameworks", stats.get("frameworks_count", 0)),
            ("Dependencies", stats.get("dependencies_count", 0)),
            ("Recommendations", stats.get("recommendations_count", 0)),
        ]
        
        for label, value in stats_items:
            html.append(f"            <div class='stats-item'><strong>{label}:</strong> {value}</div>")
        
        html.append("        </div>")
        
        # Footer
        html.append(f"        <p class='footer'>Report ID: {report_data.analysis_result.project_id if report_data.analysis_result else 'N/A'}</p>")
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }
            
            .container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            
            h1 {
                color: #2c3e50;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
            }
            
            h2 {
                color: #2c3e50;
                margin-top: 30px;
                border-bottom: 2px solid #ecf0f1;
                padding-bottom: 10px;
            }
            
            h3 {
                color: #34495e;
                margin-top: 20px;
            }
            
            .version {
                color: #7f8c8d;
                font-size: 1.1em;
            }
            
            .timestamp {
                color: #95a5a6;
                font-size: 0.9em;
            }
            
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
                background: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
            }
            
            .summary-item {
                padding: 10px;
                background: white;
                border-radius: 4px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            
            .security-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            
            .security-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
            }
            
            .security-item .label {
                display: block;
                font-weight: bold;
                color: #2c3e50;
            }
            
            .security-item .score {
                display: block;
                font-size: 2em;
                font-weight: bold;
                margin: 10px 0;
            }
            
            .level {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.85em;
                font-weight: bold;
            }
            
            .level-high {
                background: #dc3545;
                color: white;
            }
            
            .level-medium {
                background: #ffc107;
                color: #333;
            }
            
            .level-low {
                background: #28a745;
                color: white;
            }
            
            .level-strong {
                background: #28a745;
                color: white;
            }
            
            .level-moderate {
                background: #ffc107;
                color: #333;
            }
            
            .level-needs-improvement {
                background: #dc3545;
                color: white;
            }
            
            .level-very-high {
                background: #dc3545;
                color: white;
            }
            
            .level-very-low {
                background: #28a745;
                color: white;
            }
            
            ul {
                padding-left: 20px;
            }
            
            ul li {
                margin: 5px 0;
            }
            
            ol li {
                margin: 8px 0;
                padding: 8px;
                background: #f8f9fa;
                border-radius: 4px;
            }
            
            .architecture-info {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
            }
            
            .architecture-info p {
                margin: 8px 0;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            
            .stats-item {
                padding: 10px;
                background: #f8f9fa;
                border-radius: 4px;
                text-align: center;
            }
            
            .footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ecf0f1;
                color: #95a5a6;
                font-size: 0.9em;
            }
        """
    
    async def _generate_markdown_report(self, report_data: ReportData) -> str:
        """
        Generate Markdown report content.
        
        Args:
            report_data: ReportData to use
            
        Returns:
            Markdown string
        """
        lines = []
        
        # Header
        lines.append(f"# {report_data.project_name or 'Unknown Project'} Analysis Report")
        lines.append("")
        if report_data.project_version:
            lines.append(f"**Version:** {report_data.project_version}")
        lines.append(f"**Generated:** {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        summary = report_data.summary
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Security Score | {summary.get('scores', {}).get('security', 0):.1f}% |")
        lines.append(f"| Risk Level | {summary.get('risk_level', 'Unknown')} |")
        lines.append(f"| Security Level | {summary.get('security_level', 'Unknown')} |")
        lines.append(f"| Languages | {summary.get('technology', {}).get('total_languages', 0)} |")
        lines.append(f"| Frameworks | {summary.get('technology', {}).get('total_frameworks', 0)} |")
        lines.append(f"| Dependencies | {summary.get('technology', {}).get('total_dependencies', 0)} |")
        lines.append(f"| Total Files | {summary.get('metrics', {}).get('total_files', 0)} |")
        lines.append(f"| Total Lines | {summary.get('metrics', {}).get('total_lines', 0)} |")
        lines.append("")
        
        # Technology Stack
        lines.append("## Technology Stack")
        lines.append("")
        
        tech_stack = report_data.technology_stack
        if tech_stack.get("languages"):
            lines.append("### Languages")
            lines.append("")
            for lang in tech_stack["languages"]:
                lines.append(f"- **{lang['name']}:** {lang['percentage']:.1f}%")
            lines.append("")
        
        if tech_stack.get("frameworks"):
            lines.append("### Frameworks")
            lines.append("")
            for fw in tech_stack["frameworks"]:
                version = fw.get('version', 'latest')
                lines.append(f"- **{fw['name']}:** {version}")
            lines.append("")
        
        if tech_stack.get("databases"):
            lines.append("### Databases")
            lines.append("")
            for db in tech_stack["databases"]:
                lines.append(f"- {db}")
            lines.append("")
        
        # Security Metrics
        lines.append("## Security Metrics")
        lines.append("")
        security = report_data.security_metrics
        lines.append("| Metric | Score | Level |")
        lines.append("|--------|-------|-------|")
        lines.append(f"| Overall Security | {security.get('overall_score', 0):.1f}% | {security.get('security_level', 'Unknown')} |")
        lines.append(f"| Risk Score | {security.get('risk_score', 0):.1f}% | {security.get('risk_level', 'Unknown')} |")
        lines.append(f"| Maintainability | {security.get('maintainability_score', 0):.1f}% | {security.get('maintainability_level', 'Unknown')} |")
        lines.append("")
        
        # Dependencies
        lines.append("## Dependencies")
        lines.append("")
        deps = report_data.dependencies_report
        lines.append(f"- **Total Dependencies:** {deps.get('total', 0)}")
        if deps.get("dev_total"):
            lines.append(f"- **Dev Dependencies:** {deps['dev_total']}")
        lines.append("")
        
        if deps.get("dependencies"):
            lines.append("### Top Dependencies")
            lines.append("")
            for dep in deps["dependencies"][:10]:
                lines.append(f"- {dep['name']}: {dep['version']}")
            lines.append("")
        
        # Architecture Report
        lines.append("## Architecture")
        lines.append("")
        arch = report_data.architecture_report
        lines.append(f"- **Patterns:** {', '.join(arch.get('patterns', [])) or 'Not detected'}")
        lines.append(f"- **Complexity:** {arch.get('architecture_complexity', 'Unknown')}")
        lines.append(f"- **Deployment:** {', '.join(arch.get('deployment_platforms', [])) or 'Not detected'}")
        lines.append("")
        
        # Recommendations
        if report_data.recommendations_list:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(report_data.recommendations_list[:10], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Statistics
        lines.append("## Statistics")
        lines.append("")
        stats = report_data.statistics
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Files | {stats.get('files', 0)} |")
        lines.append(f"| Total Lines | {stats.get('lines', 0)} |")
        lines.append(f"| Languages | {stats.get('languages_count', 0)} |")
        lines.append(f"| Frameworks | {stats.get('frameworks_count', 0)} |")
        lines.append(f"| Dependencies | {stats.get('dependencies_count', 0)} |")
        lines.append(f"| Recommendations | {stats.get('recommendations_count', 0)} |")
        lines.append("")
        
        # Footer
        if report_data.analysis_result:
            lines.append(f"**Report ID:** {report_data.analysis_result.project_id}")
        
        return "\n".join(lines)
    
    async def _generate_csv_data(self, report_data: ReportData) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate CSV data for all report sections.
        
        Args:
            report_data: ReportData to use
            
        Returns:
            Dictionary mapping section names to list of rows
        """
        csv_data = {}
        
        # Summary
        summary = report_data.summary
        csv_data["summary"] = [
            {"Metric": "Security Score", "Value": f"{summary.get('scores', {}).get('security', 0):.1f}%"},
            {"Metric": "Risk Level", "Value": summary.get('risk_level', 'Unknown')},
            {"Metric": "Security Level", "Value": summary.get('security_level', 'Unknown')},
            {"Metric": "Languages", "Value": str(summary.get('technology', {}).get('total_languages', 0))},
            {"Metric": "Frameworks", "Value": str(summary.get('technology', {}).get('total_frameworks', 0))},
            {"Metric": "Dependencies", "Value": str(summary.get('technology', {}).get('total_dependencies', 0))},
            {"Metric": "Total Files", "Value": str(summary.get('metrics', {}).get('total_files', 0))},
            {"Metric": "Total Lines", "Value": str(summary.get('metrics', {}).get('total_lines', 0))},
        ]
        
        # Languages
        tech_stack = report_data.technology_stack
        csv_data["languages"] = [
            {"Language": lang['name'], "Percentage": f"{lang['percentage']:.1f}%"}
            for lang in tech_stack.get("languages", [])
        ]
        
        # Frameworks
        csv_data["frameworks"] = [
            {"Framework": fw['name'], "Version": fw.get('version', 'latest')}
            for fw in tech_stack.get("frameworks", [])
        ]
        
        # Dependencies
        deps = report_data.dependencies_report
        csv_data["dependencies"] = [
            {"Package": dep['name'], "Version": dep['version']}
            for dep in deps.get("dependencies", [])
        ]
        
        # Recommendations
        csv_data["recommendations"] = [
            {"Priority": i + 1, "Recommendation": rec}
            for i, rec in enumerate(report_data.recommendations_list)
        ]
        
        # Statistics
        stats = report_data.statistics
        csv_data["statistics"] = [
            {"Metric": "Total Files", "Value": stats.get("files", 0)},
            {"Metric": "Total Lines", "Value": stats.get("lines", 0)},
            {"Metric": "Languages", "Value": stats.get("languages_count", 0)},
            {"Metric": "Frameworks", "Value": stats.get("frameworks_count", 0)},
            {"Metric": "Dependencies", "Value": stats.get("dependencies_count", 0)},
            {"Metric": "Dev Dependencies", "Value": stats.get("dev_dependencies_count", 0)},
            {"Metric": "Databases", "Value": stats.get("databases_count", 0)},
            {"Metric": "Cloud Providers", "Value": stats.get("cloud_providers_count", 0)},
            {"Metric": "Recommendations", "Value": stats.get("recommendations_count", 0)},
        ]
        
        # Security Metrics
        security = report_data.security_metrics
        csv_data["security"] = [
            {"Metric": "Overall Security", "Score": f"{security.get('overall_score', 0):.1f}%", "Level": security.get('security_level', 'Unknown')},
            {"Metric": "Risk Score", "Score": f"{security.get('risk_score', 0):.1f}%", "Level": security.get('risk_level', 'Unknown')},
            {"Metric": "Maintainability", "Score": f"{security.get('maintainability_score', 0):.1f}%", "Level": security.get('maintainability_level', 'Unknown')},
        ]
        
        return csv_data
    
    def _serialize_report_data(self, report_data: ReportData) -> Dict[str, Any]:
        """Serialize ReportData to dictionary."""
        return {
            "project_name": report_data.project_name,
            "project_version": report_data.project_version,
            "generated_at": report_data.generated_at.isoformat(),
            "summary": report_data.summary,
            "technology_stack": report_data.technology_stack,
            "security_metrics": report_data.security_metrics,
            "dependencies_report": report_data.dependencies_report,
            "architecture_report": report_data.architecture_report,
            "recommendations": report_data.recommendations_list,
            "statistics": report_data.statistics,
            "visual_data": report_data.visual_data,
            "raw_data": report_data.raw_data if self.include_raw_data else None,
            "analysis_result": report_data.analysis_result.to_dict() if report_data.analysis_result else None,
            "detection_result": report_data.detection_result.to_dict() if report_data.detection_result else None,
            "fingerprint": report_data.fingerprint.to_dict() if report_data.fingerprint else None,
        }