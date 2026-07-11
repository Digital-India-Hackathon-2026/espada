```python
"""
Project File Parser for software project analysis.

This module parses various project files to extract metadata, dependencies,
scripts, and configuration information without performing any technology
detection or scoring.
"""

import ast
import json
import logging
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from xml.etree import ElementTree as ET

import yaml

from runtime.core import Runtime
from runtime.security import SecurityContext
from runtime.middleware import MiddlewareChain

logger = logging.getLogger(__name__)


@dataclass
class ParsedFile:
    """Represents a parsed file with its content and metadata."""
    path: str
    filename: str
    extension: str
    content: Any
    raw_content: str
    size: int
    modified_at: Optional[datetime] = None
    line_count: int = 0
    is_binary: bool = False
    file_type: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedProject:
    """Represents a parsed project with all extracted information."""
    root_path: Path
    files: List[ParsedFile] = field(default_factory=list)
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    scripts: Dict[str, str] = field(default_factory=dict)
    config_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    description: Optional[str] = None
    file_extensions: Set[str] = field(default_factory=set)
    total_files: int = 0
    total_lines: int = 0
    
    def add_file(self, file: ParsedFile) -> None:
        """Add a parsed file to the project."""
        self.files.append(file)
        self.file_extensions.add(file.extension)
        self.total_files += 1
        self.total_lines += file.line_count


class ProjectParser:
    """
    Parser engine for extracting information from project files.
    
    This class parses various file formats to extract metadata, dependencies,
    scripts, and configuration without performing any analysis or detection.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the project parser.
        
        Args:
            config: Optional configuration parameters
        """
        self.config = config or {}
        self.runtime = Runtime()
        self.security_context = SecurityContext()
        self.middleware_chain = MiddlewareChain()
        
        # File size limits (in bytes)
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        self.max_text_file_size = self.config.get("max_text_file_size", 1 * 1024 * 1024)  # 1MB
        
        # Supported file extensions for parsing
        self.supported_extensions = {
            ".json": self._parse_json,
            ".yaml": self._parse_yaml,
            ".yml": self._parse_yaml,
            ".toml": self._parse_toml,
            ".xml": self._parse_xml,
            ".ini": self._parse_ini,
            ".cfg": self._parse_ini,
            ".conf": self._parse_ini,
            ".txt": self._parse_text,
            ".md": self._parse_markdown,
            ".dockerfile": self._parse_dockerfile,
            ".dockerignore": self._parse_text,
            ".properties": self._parse_properties,
            ".lock": self._parse_text,
            ".hcl": self._parse_hcl,
        }
        
        # File patterns for special files (without extension)
        self.special_files = {
            "Dockerfile": self._parse_dockerfile,
            "docker-compose.yml": self._parse_yaml,
            "docker-compose.yaml": self._parse_yaml,
            "Procfile": self._parse_procfile,
            "Makefile": self._parse_makefile,
            "README.md": self._parse_markdown,
            "requirements.txt": self._parse_requirements_txt,
            "pyproject.toml": self._parse_pyproject_toml,
            "package.json": self._parse_package_json,
            "Cargo.toml": self._parse_cargo_toml,
            "pom.xml": self._parse_pom_xml,
            "build.gradle": self._parse_gradle,
            "go.mod": self._parse_go_mod,
            "composer.json": self._parse_composer_json,
            "Gemfile": self._parse_gemfile,
            "Podfile": self._parse_podfile,
            ".gitignore": self._parse_text,
            ".env": self._parse_env,
            "docker-compose.override.yml": self._parse_yaml,
            "docker-compose.override.yaml": self._parse_yaml,
            "helmfile.yaml": self._parse_yaml,
            "Chart.yaml": self._parse_yaml,
            "values.yaml": self._parse_yaml,
            "terraform.tfvars": self._parse_hcl,
            "variables.tf": self._parse_hcl,
            "main.tf": self._parse_hcl,
            "outputs.tf": self._parse_hcl,
        }
        
        # Directory patterns to ignore
        self.ignore_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "target", "dist", "build", ".idea", ".vscode", "vendor",
            "tmp", "temp", "coverage", ".pytest_cache", ".mypy_cache",
            ".tox", ".eggs", "*.egg-info", "env", ".env", "lib",
            "include", "bin", ".terraform", ".serverless", ".next",
            ".nuxt", ".output", "public", "static", "media", "uploads",
            "downloads", "logs", "cache", ".cache", ".npm", ".yarn",
            ".local", ".config", ".azure", ".aws", ".gcloud",
        }
        
        # File patterns to ignore
        self.ignore_files = {
            "*.pyc", "*.pyo", "*.so", "*.dll", "*.exe", "*.class",
            "*.jar", "*.war", "*.ear", "*.zip", "*.tar.gz", "*.tgz",
            "*.rar", "*.7z", "*.iso", "*.img", "*.ova", "*.vmdk",
            "*.mp4", "*.avi", "*.mov", "*.mkv", "*.mp3", "*.wav",
            "*.flac", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp",
            "*.ico", "*.svg", "*.pdf", "*.doc", "*.docx", "*.xls",
            "*.xlsx", "*.ppt", "*.pptx", "*.odt", "*.ods", "*.odp",
            "*.psd", "*.ai", "*.eps", "*.ttf", "*.otf", "*.woff",
            "*.woff2", "*.eot", "*.sqlite", "*.db", "*.log", "*.lock",
        }
        
        logger.info("ProjectParser initialized")
    
    async def parse(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        include_hidden: bool = False,
    ) -> ParsedProject:
        """
        Parse a directory or file.
        
        Args:
            path: Path to parse (directory or file)
            recursive: Whether to parse subdirectories recursively
            include_hidden: Whether to include hidden files/directories
            
        Returns:
            ParsedProject containing all extracted information
        """
        path = Path(path).resolve()
        
        if path.is_file():
            return await self.parse_file(path)
        elif path.is_dir():
            return await self.parse_directory(path, recursive, include_hidden)
        else:
            raise ValueError(f"Path does not exist: {path}")
    
    async def parse_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        include_hidden: bool = False,
    ) -> ParsedProject:
        """
        Parse an entire directory structure.
        
        Args:
            directory: Directory path to parse
            recursive: Whether to parse subdirectories recursively
            include_hidden: Whether to include hidden files/directories
            
        Returns:
            ParsedProject containing all extracted information
        """
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")
        
        logger.info(f"Parsing directory: {directory}")
        
        project = ParsedProject(root_path=directory)
        
        # Walk through directory
        for file_path in directory.rglob("*") if recursive else directory.glob("*"):
            # Skip if hidden and not included
            if not include_hidden and file_path.name.startswith("."):
                continue
            
            # Skip ignored directories
            if any(ignore in file_path.parts for ignore in self.ignore_dirs):
                continue
            
            if file_path.is_file():
                # Check if file should be ignored
                if self._should_ignore_file(file_path):
                    continue
                
                try:
                    parsed_file = await self.parse_file(file_path)
                    project.add_file(parsed_file)
                    
                    # Extract special file content
                    await self._extract_special_file(parsed_file, project)
                    
                except Exception as e:
                    logger.warning(f"Failed to parse file {file_path}: {str(e)}")
        
        logger.info(f"Parsed {project.total_files} files")
        return project
    
    async def parse_file(self, file_path: Union[str, Path]) -> ParsedFile:
        """
        Parse a single file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            ParsedFile containing the file content and metadata
        """
        file_path = Path(file_path).resolve()
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(f"File too large: {file_path} ({file_size} bytes)")
        
        # Read file content
        try:
            raw_content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            # Binary file
            raw_content = ""
            is_binary = True
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {str(e)}")
            raise
        
        # Get file metadata
        extension = file_path.suffix.lower()
        filename = file_path.name
        line_count = len(raw_content.splitlines()) if not is_binary else 0
        modified_at = datetime.fromtimestamp(file_path.stat().st_mtime)
        
        # Determine file type
        file_type = self._determine_file_type(filename, extension)
        
        # Parse content based on file type
        parsed_content = None
        if not is_binary and file_size <= self.max_text_file_size:
            parser_func = self.supported_extensions.get(extension)
            if parser_func:
                try:
                    parsed_content = parser_func(raw_content)
                except Exception as e:
                    logger.debug(f"Failed to parse {file_path} as {extension}: {str(e)}")
                    parsed_content = raw_content
            else:
                # Check if it's a special file
                special_parser = self.special_files.get(filename)
                if special_parser:
                    try:
                        parsed_content = special_parser(raw_content)
                    except Exception as e:
                        logger.debug(f"Failed to parse special file {file_path}: {str(e)}")
                        parsed_content = raw_content
                else:
                    # Default to text
                    parsed_content = raw_content
        
        return ParsedFile(
            path=str(file_path),
            filename=filename,
            extension=extension,
            content=parsed_content or raw_content,
            raw_content=raw_content,
            size=file_size,
            modified_at=modified_at,
            line_count=line_count,
            is_binary=is_binary,
            file_type=file_type,
            metadata=self._extract_file_metadata(file_path),
        )
    
    async def extract_dependencies(self, project: ParsedProject) -> Dict[str, str]:
        """
        Extract dependencies from a parsed project.
        
        Args:
            project: ParsedProject to extract dependencies from
            
        Returns:
            Dictionary of dependencies
        """
        dependencies = {}
        
        # Collect all dependencies from parsed files
        for file in project.files:
            if file.filename == "package.json":
                if isinstance(file.content, dict):
                    deps = file.content.get("dependencies", {})
                    if isinstance(deps, dict):
                        dependencies.update({k: str(v) for k, v in deps.items()})
            
            elif file.filename == "Cargo.toml":
                if isinstance(file.content, dict):
                    deps = file.content.get("dependencies", {})
                    if isinstance(deps, dict):
                        dependencies.update({k: str(v) for k, v in deps.items()})
            
            elif file.filename == "requirements.txt":
                if isinstance(file.content, list):
                    for req in file.content:
                        if isinstance(req, dict):
                            deps = req.get("dependencies", [])
                            for dep in deps:
                                if isinstance(dep, dict):
                                    dependencies[dep.get("name")] = dep.get("version")
        
        return dependencies
    
    async def extract_metadata(self, project: ParsedProject) -> Dict[str, Any]:
        """
        Extract metadata from a parsed project.
        
        Args:
            project: ParsedProject to extract metadata from
            
        Returns:
            Dictionary of metadata
        """
        metadata = {}
        
        for file in project.files:
            if file.filename == "package.json":
                if isinstance(file.content, dict):
                    metadata.update({
                        "name": file.content.get("name"),
                        "version": file.content.get("version"),
                        "description": file.content.get("description"),
                        "author": file.content.get("author"),
                        "license": file.content.get("license"),
                    })
            
            elif file.filename == "pyproject.toml":
                if isinstance(file.content, dict):
                    project_data = file.content.get("project", {})
                    metadata.update({
                        "name": project_data.get("name"),
                        "version": project_data.get("version"),
                        "description": project_data.get("description"),
                    })
            
            elif file.filename == "Cargo.toml":
                if isinstance(file.content, dict):
                    package_data = file.content.get("package", {})
                    metadata.update({
                        "name": package_data.get("name"),
                        "version": package_data.get("version"),
                        "description": package_data.get("description"),
                    })
        
        return metadata
    
    async def extract_scripts(self, project: ParsedProject) -> Dict[str, str]:
        """
        Extract scripts from a parsed project.
        
        Args:
            project: ParsedProject to extract scripts from
            
        Returns:
            Dictionary of scripts
        """
        scripts = {}
        
        for file in project.files:
            if file.filename == "package.json":
                if isinstance(file.content, dict):
                    scripts.update(file.content.get("scripts", {}))
            
            elif file.filename == "Makefile":
                if isinstance(file.content, dict):
                    scripts.update(file.content.get("targets", {}))
        
        return scripts
    
    async def _extract_special_file(
        self,
        parsed_file: ParsedFile,
        project: ParsedProject,
    ) -> None:
        """
        Extract special file content into project.
        
        Args:
            parsed_file: Parsed file
            project: Project to update
        """
        filename = parsed_file.filename.lower()
        
        # Extract dependencies
        if filename in ["package.json", "cargo.toml", "requirements.txt", "pyproject.toml"]:
            deps = await self.extract_dependencies(project)
            project.dependencies.update(deps)
        
        # Extract metadata
        if filename in ["package.json", "pyproject.toml", "cargo.toml"]:
            metadata = await self.extract_metadata(project)
            project.metadata.update(metadata)
            
            if "name" in metadata:
                project.project_name = metadata["name"]
            if "version" in metadata:
                project.project_version = metadata["version"]
            if "description" in metadata:
                project.description = metadata["description"]
        
        # Extract scripts
        if filename in ["package.json", "Makefile"]:
            scripts = await self.extract_scripts(project)
            project.scripts.update(scripts)
        
        # Store config files
        if parsed_file.extension in [".json", ".yaml", ".yml", ".toml", ".xml", ".ini"]:
            if isinstance(parsed_file.content, dict):
                project.config_files[parsed_file.path] = parsed_file.content
    
    def _determine_file_type(self, filename: str, extension: str) -> str:
        """Determine the type of file based on name and extension."""
        # Special files by name
        special_mapping = {
            "dockerfile": "dockerfile",
            "readme.md": "documentation",
            "makefile": "build",
            "procfile": "deployment",
            "package.json": "package",
            "cargo.toml": "package",
            "pyproject.toml": "package",
            "requirements.txt": "dependencies",
            "go.mod": "package",
            "pom.xml": "package",
            "build.gradle": "package",
            "composer.json": "package",
            "gemfile": "package",
            "podfile": "package",
            ".env": "environment",
            ".gitignore": "version_control",
            "chart.yaml": "kubernetes",
            "values.yaml": "kubernetes",
            "terraform.tfvars": "infrastructure",
            "main.tf": "infrastructure",
        }
        
        # Check special files by name
        lower_filename = filename.lower()
        for pattern, file_type in special_mapping.items():
            if pattern in lower_filename:
                return file_type
        
        # Check by extension
        ext_mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".rs": "rust",
            ".go": "go",
            ".php": "php",
            ".rb": "ruby",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "header",
            ".html": "html",
            ".css": "css",
            ".scss": "css",
            ".less": "css",
            ".sql": "sql",
            ".sh": "shell",
            ".bash": "shell",
            ".ps1": "powershell",
            ".json": "configuration",
            ".yaml": "configuration",
            ".yml": "configuration",
            ".toml": "configuration",
            ".xml": "configuration",
            ".ini": "configuration",
            ".txt": "text",
            ".md": "documentation",
            ".rst": "documentation",
            ".lock": "lock",
        }
        
        return ext_mapping.get(extension, "unknown")
    
    def _should_ignore_file(self, file_path: Path) -> bool:
        """Check if a file should be ignored."""
        filename = file_path.name
        
        # Check ignore patterns
        for pattern in self.ignore_files:
            if pattern.startswith("*."):
                if filename.endswith(pattern[1:]):
                    return True
            elif pattern in filename:
                return True
        
        return False
    
    def _extract_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from a file."""
        stat = file_path.stat()
        return {
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime),
            "modified": datetime.fromtimestamp(stat.st_mtime),
            "accessed": datetime.fromtimestamp(stat.st_atime),
            "permissions": stat.st_mode,
        }
    
    # Parsing functions for different file formats
    
    def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON content."""
        return json.loads(content)
    
    def _parse_yaml(self, content: str) -> Dict[str, Any]:
        """Parse YAML content."""
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            # If YAML parsing fails, try to parse as multiple documents
            try:
                docs = list(yaml.safe_load_all(content))
                if len(docs) == 1:
                    return docs[0]
                return {"documents": docs}
            except Exception:
                raise
    
    def _parse_toml(self, content: str) -> Dict[str, Any]:
        """Parse TOML content."""
        return tomllib.loads(content)
    
    def _parse_xml(self, content: str) -> Dict[str, Any]:
        """Parse XML content."""
        root = ET.fromstring(content)
        return self._xml_to_dict(root)
    
    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        
        # Add attributes
        if element.attrib:
            result["@attributes"] = element.attrib
        
        # Add children
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if isinstance(result[child.tag], list):
                    result[child.tag].append(child_data)
                else:
                    result[child.tag] = [result[child.tag], child_data]
            else:
                result[child.tag] = child_data
        
        # Add text
        if element.text and element.text.strip():
            if result:
                result["#text"] = element.text.strip()
            else:
                return element.text.strip()
        
        return result if result else {}
    
    def _parse_ini(self, content: str) -> Dict[str, Any]:
        """Parse INI content."""
        import configparser
        
        config = configparser.ConfigParser()
        config.read_string(content)
        
        result = {}
        for section in config.sections():
            result[section] = dict(config.items(section))
        
        return result
    
    def _parse_text(self, content: str) -> str:
        """Parse plain text content."""
        return content
    
    def _parse_markdown(self, content: str) -> Dict[str, Any]:
        """Parse markdown content."""
        lines = content.splitlines()
        
        # Extract metadata from markdown
        result = {
            "raw": content,
            "lines": lines,
            "sections": [],
        }
        
        current_section = None
        for line in lines:
            if line.startswith("#"):
                if current_section:
                    result["sections"].append(current_section)
                current_section = {"heading": line.lstrip("#").strip()}
            elif current_section is not None:
                if "content" not in current_section:
                    current_section["content"] = []
                current_section["content"].append(line)
        
        if current_section:
            result["sections"].append(current_section)
        
        return result
    
    def _parse_dockerfile(self, content: str) -> Dict[str, Any]:
        """Parse Dockerfile content."""
        lines = content.splitlines()
        result = {
            "instructions": [],
            "base_image": None,
            "exposed_ports": [],
            "environment_vars": {},
            "commands": [],
        }
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                instruction, args = parts
                instruction = instruction.upper()
                
                result["instructions"].append({
                    "instruction": instruction,
                    "args": args,
                })
                
                if instruction == "FROM":
                    result["base_image"] = args
                elif instruction == "EXPOSE":
                    result["exposed_ports"].append(args)
                elif instruction == "ENV":
                    if "=" in args:
                        key, value = args.split("=", 1)
                        result["environment_vars"][key] = value
                elif instruction == "CMD" or instruction == "ENTRYPOINT":
                    result["commands"].append(args)
        
        return result
    
    def _parse_procfile(self, content: str) -> Dict[str, str]:
        """Parse Procfile content."""
        result = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if ":" in line:
                process, command = line.split(":", 1)
                result[process.strip()] = command.strip()
        
        return result
    
    def _parse_makefile(self, content: str) -> Dict[str, Any]:
        """Parse Makefile content."""
        result = {
            "targets": {},
            "variables": {},
        }
        
        lines = content.splitlines()
        current_target = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if ":" in line and not "=" in line:
                # Target definition
                target, deps = line.split(":", 1)
                current_target = target.strip()
                result["targets"][current_target] = {
                    "dependencies": [d.strip() for d in deps.split() if d.strip()],
                    "commands": [],
                }
            elif line.startswith("\t") and current_target:
                # Command
                result["targets"][current_target]["commands"].append(line.strip())
            elif "=" in line:
                # Variable assignment
                key, value = line.split("=", 1)
                result["variables"][key.strip()] = value.strip()
        
        return result
    
    def _parse_requirements_txt(self, content: str) -> List[Dict[str, str]]:
        """Parse requirements.txt content."""
        requirements = []
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse simple requirements
            if "==" in line:
                name, version = line.split("==", 1)
                requirements.append({"name": name.strip(), "version": version.strip()})
            elif ">=" in line:
                name, version = line.split(">=", 1)
                requirements.append({"name": name.strip(), "version": f">={version.strip()}"})
            else:
                requirements.append({"name": line, "version": None})
        
        return requirements
    
    def _parse_pyproject_toml(self, content: str) -> Dict[str, Any]:
        """Parse pyproject.toml content."""
        try:
            return tomllib.loads(content)
        except Exception:
            return {"raw": content}
    
    def _parse_package_json(self, content: str) -> Dict[str, Any]:
        """Parse package.json content."""
        try:
            return json.loads(content)
        except Exception:
            return {"raw": content}
    
    def _parse_cargo_toml(self, content: str) -> Dict[str, Any]:
        """Parse Cargo.toml content."""
        try:
            return tomllib.loads(content)
        except Exception:
            return {"raw": content}
    
    def _parse_pom_xml(self, content: str) -> Dict[str, Any]:
        """Parse pom.xml content."""
        return self._parse_xml(content)
    
    def _parse_gradle(self, content: str) -> Dict[str, Any]:
        """Parse build.gradle content."""
        # Simplified parsing - just extract basic info
        result = {"raw": content}
        
        # Extract dependencies
        dependencies = []
        for line in content.splitlines():
            line = line.strip()
            if "implementation" in line or "compile" in line:
                # Extract dependency from line
                if "'" in line:
                    dep = line.split("'")[1] if line.count("'") >= 2 else None
                elif '"' in line:
                    dep = line.split('"')[1] if line.count('"') >= 2 else None
                else:
                    dep = None
                
                if dep:
                    dependencies.append(dep)
        
        if dependencies:
            result["dependencies"] = dependencies
        
        return result
    
    def _parse_go_mod(self, content: str) -> Dict[str, Any]:
        """Parse go.mod content."""
        result = {
            "module": None,
            "go_version": None,
            "require": [],
        }
        
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("module "):
                result["module"] = line[7:].strip()
            elif line.startswith("go "):
                result["go_version"] = line[3:].strip()
            elif line.startswith("require"):
                # Parse require line
                parts = line.split()
                if len(parts) >= 3:
                    result["require"].append({
                        "package": parts[1],
                        "version": parts[2],
                    })
        
        return result
    
    def _parse_composer_json(self, content: str) -> Dict[str, Any]:
        """Parse composer.json content."""
        try:
            return json.loads(content)
        except Exception:
            return {"raw": content}
    
    def _parse_gemfile(self, content: str) -> List[Dict[str, str]]:
        """Parse Gemfile content."""
        gems = []
        
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("gem "):
                # Extract gem name and version
                parts = line.split()
                if len(parts) >= 2:
                    gem_name = parts[1].strip("'\"")
                    version = None
                    
                    # Check for version
                    if "'" in line and line.count("'") >= 3:
                        version = line.split("'")[3]
                    elif '"' in line and line.count('"') >= 3:
                        version = line.split('"')[3]
                    
                    gems.append({
                        "name": gem_name,
                        "version": version,
                    })
        
        return gems
    
    def _parse_podfile(self, content: str) -> List[Dict[str, str]]:
        """Parse Podfile content."""
        pods = []
        
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("pod "):
                # Extract pod name and version
                if "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        pod_name = parts[1]
                        version = None
                        if len(parts) >= 4:
                            version = parts[3]
                        pods.append({
                            "name": pod_name,
                            "version": version,
                        })
        
        return pods
    
    def _parse_properties(self, content: str) -> Dict[str, str]:
        """Parse properties file content."""
        result = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                result[key.strip()] = value.strip()
        
        return result
    
    def _parse_env(self, content: str) -> Dict[str, str]:
        """Parse .env file content."""
        return self._parse_properties(content)
    
    def _parse_hcl(self, content: str) -> Dict[str, Any]:
        """Parse HCL content (simplified)."""
        # Simplified HCL parsing - extract key-value pairs
        result = {
            "raw": content,
            "variables": {},
            "resources": {},
        }
        
        lines = content.splitlines()
        current_block = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "{" in line and not "=" in line:
                # Block definition
                current_block = line.split("{")[0].strip()
                result["resources"][current_block] = {}
            elif "=" in line and "{" not in line:
                # Variable assignment
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"')
                
                if current_block:
                    result["resources"][current_block][key] = value
                else:
                    result["variables"][key] = value
        
        return result
