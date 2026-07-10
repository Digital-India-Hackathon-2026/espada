#!/usr/bin/env python3
"""
Tech Scanner - Detect project tech stack
Usage: python tech-scanner.py [path]
"""

import os
import sys
import json
import glob
from pathlib import Path
from typing import Optional

def get_detected_tech(name: str, category: str, confidence: str, evidence: list) -> dict:
    return {
        "name": name,
        "category": category,
        "confidence": confidence,
        "evidence": evidence
    }

def scan_project(project_path: str) -> dict:
    project_path = os.path.abspath(project_path)
    frameworks = []
    package_managers = []
    build_tools = []
    other_tools = []
    languages = {}

    # Walk directory
    for root, dirs, files in os.walk(project_path):
        # Skip common non-project directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'target', 'dist', 'build'}]

        for filename in files:
            filepath = os.path.join(root, filename)

            # package.json - Node.js
            if filename == "package.json":
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "npm" not in str(package_managers):
                            package_managers.append(get_detected_tech("npm", "package_manager", "high", ["package.json"]))

                        try:
                            pkg = json.loads(content)
                            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

                            for dep in deps:
                                if dep == "react":
                                    frameworks.append(get_detected_tech("React", "framework", "high", ["package.json"]))
                                elif dep == "vue":
                                    frameworks.append(get_detected_tech("Vue", "framework", "high", ["package.json"]))
                                elif dep == "@angular/core":
                                    frameworks.append(get_detected_tech("Angular", "framework", "high", ["package.json"]))
                                elif dep == "next":
                                    frameworks.append(get_detected_tech("Next.js", "framework", "high", ["package.json"]))
                                elif dep == "nuxt":
                                    frameworks.append(get_detected_tech("Nuxt", "framework", "high", ["package.json"]))
                                elif dep == "svelte":
                                    frameworks.append(get_detected_tech("Svelte", "framework", "high", ["package.json"]))
                                elif dep == "express":
                                    frameworks.append(get_detected_tech("Express", "framework", "high", ["package.json"]))
                                elif dep == "fastify":
                                    frameworks.append(get_detected_tech("Fastify", "framework", "high", ["package.json"]))
                                elif dep in ("nest", "@nestjs/core"):
                                    frameworks.append(get_detected_tech("NestJS", "framework", "high", ["package.json"]))
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

            # Cargo.toml - Rust
            if filename == "Cargo.toml":
                if "Cargo" not in str(package_managers):
                    package_managers.append(get_detected_tech("Cargo", "package_manager", "high", ["Cargo.toml"]))
                languages["Rust"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "actix-web" in content:
                            frameworks.append(get_detected_tech("Actix Web", "framework", "high", ["Cargo.toml"]))
                        if "axum" in content:
                            frameworks.append(get_detected_tech("Axum", "framework", "high", ["Cargo.toml"]))
                        if "tokio" in content:
                            frameworks.append(get_detected_tech("Tokio", "framework", "high", ["Cargo.toml"]))
                        if "rocket" in content:
                            frameworks.append(get_detected_tech("Rocket", "framework", "high", ["Cargo.toml"]))
                except Exception:
                    pass

            # Python files
            if filename in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"):
                if "pip" not in str(package_managers):
                    package_managers.append(get_detected_tech("pip", "package_manager", "high", [filename]))
                languages["Python"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "django" in content.lower():
                            frameworks.append(get_detected_tech("Django", "framework", "high", [filename]))
                        if "fastapi" in content.lower():
                            frameworks.append(get_detected_tech("FastAPI", "framework", "high", [filename]))
                        if "flask" in content.lower():
                            frameworks.append(get_detected_tech("Flask", "framework", "high", [filename]))
                        if "quart" in content.lower():
                            frameworks.append(get_detected_tech("Quart", "framework", "high", [filename]))
                except Exception:
                    pass

            # go.mod - Go
            if filename == "go.mod":
                if "Go Modules" not in str(package_managers):
                    package_managers.append(get_detected_tech("Go Modules", "package_manager", "high", ["go.mod"]))
                languages["Go"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "gin-gonic/gin" in content:
                            frameworks.append(get_detected_tech("Gin", "framework", "high", ["go.mod"]))
                        if "labstack/echo" in content:
                            frameworks.append(get_detected_tech("Echo", "framework", "high", ["go.mod"]))
                        if "gofiber/fiber" in content:
                            frameworks.append(get_detected_tech("Fiber", "framework", "high", ["go.mod"]))
                except Exception:
                    pass

            # Java/Maven/Gradle
            if filename == "pom.xml":
                if "Maven" not in str(package_managers):
                    package_managers.append(get_detected_tech("Maven", "package_manager", "high", ["pom.xml"]))
                languages["Java"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "spring-boot" in content:
                            frameworks.append(get_detected_tech("Spring Boot", "framework", "high", ["pom.xml"]))
                except Exception:
                    pass

            if filename in ("build.gradle", "build.gradle.kts"):
                if "Gradle" not in str(package_managers):
                    package_managers.append(get_detected_tech("Gradle", "package_manager", "high", [filename]))
                languages["Java"] = True

            # PHP
            if filename == "composer.json":
                if "Composer" not in str(package_managers):
                    package_managers.append(get_detected_tech("Composer", "package_manager", "high", ["composer.json"]))

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "laravel" in content.lower():
                            frameworks.append(get_detected_tech("Laravel", "framework", "high", ["composer.json"]))
                        if "symfony" in content.lower():
                            frameworks.append(get_detected_tech("Symfony", "framework", "high", ["composer.json"]))
                except Exception:
                    pass

            # Ruby
            if filename == "Gemfile":
                if "Bundler" not in str(package_managers):
                    package_managers.append(get_detected_tech("Bundler", "package_manager", "high", ["Gemfile"]))

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "rails" in content.lower():
                            frameworks.append(get_detected_tech("Ruby on Rails", "framework", "high", ["Gemfile"]))
                            languages["Ruby"] = True
                except Exception:
                    pass

            # Lock files
            if filename == "yarn.lock":
                if "Yarn" not in str(package_managers):
                    package_managers.append(get_detected_tech("Yarn", "package_manager", "high", ["yarn.lock"]))
            if filename == "pnpm-lock.yaml":
                if "pnpm" not in str(package_managers):
                    package_managers.append(get_detected_tech("pnpm", "package_manager", "high", ["pnpm-lock.yaml"]))
            if filename == "bun.lockb":
                if "Bun" not in str(package_managers):
                    package_managers.append(get_detected_tech("Bun", "package_manager", "high", ["bun.lockb"]))

            # TypeScript config
            if filename == "tsconfig.json":
                languages["TypeScript"] = True

            # Build tools
            if filename in ("vite.config.ts", "vite.config.js"):
                if "Vite" not in str(build_tools):
                    build_tools.append(get_detected_tech("Vite", "build_tool", "high", [filename]))
            if filename.startswith("webpack.config"):
                if "Webpack" not in str(build_tools):
                    build_tools.append(get_detected_tech("Webpack", "build_tool", "high", [filename]))
            if filename == "next.config.js" or filename == "next.config.ts":
                if "Next.js" not in str(build_tools):
                    build_tools.append(get_detected_tech("Next.js", "build_tool", "high", [filename]))

            # Docker
            if filename in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"):
                if "Docker" not in str(other_tools):
                    other_tools.append(get_detected_tech("Docker", "container", "high", [filename]))

            # Language detection by extension
            ext = os.path.splitext(filename)[1].lower()
            ext_map = {
                ".rs": "Rust",
                ".js": "JavaScript",
                ".mjs": "JavaScript",
                ".ts": "TypeScript",
                ".tsx": "TypeScript",
                ".py": "Python",
                ".go": "Go",
                ".java": "Java",
                ".rb": "Ruby",
                ".php": "PHP",
                ".cs": "C#",
                ".cpp": "C++",
                ".cc": "C++",
                ".cxx": "C++",
                ".c": "C",
                ".h": "C",
            }
            if ext in ext_map:
                languages[ext_map[ext]] = True

    # Deduplicate
    frameworks = list({json.dumps(f, sort_keys=True): f for f in frameworks}.values())
    package_managers = list({json.dumps(pm, sort_keys=True): pm for pm in package_managers}.values())
    build_tools = list({json.dumps(bt, sort_keys=True): bt for bt in build_tools}.values())
    other_tools = list({json.dumps(ot, sort_keys=True): ot for ot in other_tools}.values())

    # Determine primary language
    primary_language = None
    if languages:
        # Priority: TypeScript > JavaScript > others
        if "TypeScript" in languages:
            primary_language = "TypeScript"
        elif "JavaScript" in languages:
            primary_language = "JavaScript"
        else:
            primary_language = list(languages.keys())[0]

    file_count = sum(1 for _, _, files in os.walk(project_path) for _ in files)

    return {
        "project_path": project_path,
        "primary_language": primary_language,
        "frameworks": frameworks,
        "package_managers": package_managers,
        "build_tools": build_tools,
        "other_tools": other_tools,
        "total_files_scanned": file_count
    }

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = scan_project(path)
    print(json.dumps(result, indent=4))