#!/usr/bin/env python3
"""
Tech Scanner - Detect project tech stack
Usage: python tech-scanner.py [path]
"""

import os
import sys
import re
from pathlib import Path

def scan_project(project_path: str) -> dict:
    project_path = os.path.abspath(project_path)
    frameworks = []
    package_managers = []
    build_tools = []
    databases = []
    languages = {}
    apps_found = []
    config_files = []
    env_files = []
    python_env = None
    detected = {
        "language": None,
        "frameworks": [],
        "package_manager": None,
        "build_tools": [],
        "databases": [],
        "deployment": [],
        "config": [],
        "python_env": None,
    }

    # Walk directory
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'target', 'dist', 'build', '.next', '.nuxt'}]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)

            # package.json - Node.js
            if filename == "package.json":
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if not detected["package_manager"]:
                            detected["package_manager"] = "npm"

                        import json
                        pkg = json.loads(content)
                        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

                        for dep in deps:
                            if dep == "react" and "React" not in detected["frameworks"]:
                                detected["frameworks"].append("React")
                            elif dep == "vue" and "Vue" not in detected["frameworks"]:
                                detected["frameworks"].append("Vue")
                            elif dep == "@angular/core" and "Angular" not in detected["frameworks"]:
                                detected["frameworks"].append("Angular")
                            elif dep == "next" and "Next.js" not in detected["frameworks"]:
                                detected["frameworks"].append("Next.js")
                            elif dep == "nuxt" and "Nuxt" not in detected["frameworks"]:
                                detected["frameworks"].append("Nuxt")
                            elif dep == "svelte" and "Svelte" not in detected["frameworks"]:
                                detected["frameworks"].append("Svelte")
                            elif dep == "express" and "Express" not in detected["frameworks"]:
                                detected["frameworks"].append("Express")
                            elif dep == "fastify" and "Fastify" not in detected["frameworks"]:
                                detected["frameworks"].append("Fastify")
                            elif dep in ("nest", "@nestjs/core") and "NestJS" not in detected["frameworks"]:
                                detected["frameworks"].append("NestJS")
                except Exception:
                    pass

            # Cargo.toml - Rust
            if filename == "Cargo.toml":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Cargo"
                languages["Rust"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "actix-web" in content and "Actix Web" not in detected["frameworks"]:
                            detected["frameworks"].append("Actix Web")
                        if "axum" in content and "Axum" not in detected["frameworks"]:
                            detected["frameworks"].append("Axum")
                        if "tokio" in content and "Tokio" not in detected["frameworks"]:
                            detected["frameworks"].append("Tokio")
                        if "rocket" in content and "Rocket" not in detected["frameworks"]:
                            detected["frameworks"].append("Rocket")
                except Exception:
                    pass

            # Python files
            if filename in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"):
                if not detected["package_manager"]:
                    detected["package_manager"] = "pip"
                languages["Python"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "django" in content.lower() and "Django" not in detected["frameworks"]:
                            detected["frameworks"].append("Django")
                        if "fastapi" in content.lower() and "FastAPI" not in detected["frameworks"]:
                            detected["frameworks"].append("FastAPI")
                        if "flask" in content.lower() and "Flask" not in detected["frameworks"]:
                            detected["frameworks"].append("Flask")
                        if "quart" in content.lower() and "Quart" not in detected["frameworks"]:
                            detected["frameworks"].append("Quart")
                except Exception:
                    pass

            # Python version file
            if filename == ".python-version" and not python_env:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        python_env = f.read().strip()
                        detected["python_env"] = python_env
                except Exception:
                    pass

            # go.mod - Go
            if filename == "go.mod":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Go Modules"
                languages["Go"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "gin-gonic/gin" in content and "Gin" not in detected["frameworks"]:
                            detected["frameworks"].append("Gin")
                        if "labstack/echo" in content and "Echo" not in detected["frameworks"]:
                            detected["frameworks"].append("Echo")
                        if "gofiber/fiber" in content and "Fiber" not in detected["frameworks"]:
                            detected["frameworks"].append("Fiber")
                except Exception:
                    pass

            # Java/Maven/Gradle
            if filename == "pom.xml":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Maven"
                languages["Java"] = True

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "spring-boot" in content and "Spring Boot" not in detected["frameworks"]:
                            detected["frameworks"].append("Spring Boot")
                except Exception:
                    pass

            if filename in ("build.gradle", "build.gradle.kts"):
                if not detected["package_manager"]:
                    detected["package_manager"] = "Gradle"
                languages["Java"] = True

            # PHP
            if filename == "composer.json":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Composer"

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "laravel" in content.lower() and "Laravel" not in detected["frameworks"]:
                            detected["frameworks"].append("Laravel")
                        if "symfony" in content.lower() and "Symfony" not in detected["frameworks"]:
                            detected["frameworks"].append("Symfony")
                except Exception:
                    pass

            # Ruby
            if filename == "Gemfile":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Bundler"

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "rails" in content.lower() and "Ruby on Rails" not in detected["frameworks"]:
                            detected["frameworks"].append("Ruby on Rails")
                            languages["Ruby"] = True
                except Exception:
                    pass

            # Lock files
            if filename == "yarn.lock" and not detected["package_manager"]:
                detected["package_manager"] = "Yarn"
            if filename == "pnpm-lock.yaml" and not detected["package_manager"]:
                detected["package_manager"] = "pnpm"
            if filename == "bun.lockb" and not detected["package_manager"]:
                detected["package_manager"] = "Bun"
            if filename == "uv.lock" and not detected["package_manager"]:
                detected["package_manager"] = "uv"
            if filename == "poetry.lock" and not detected["package_manager"]:
                detected["package_manager"] = "poetry"

            # TypeScript config
            if filename == "tsconfig.json":
                languages["TypeScript"] = True

            # Build tools
            if filename in ("vite.config.ts", "vite.config.js"):
                if "Vite" not in detected["build_tools"]:
                    detected["build_tools"].append("Vite")
            if filename.startswith("webpack.config"):
                if "Webpack" not in detected["build_tools"]:
                    detected["build_tools"].append("Webpack")
            if filename in ("next.config.js", "next.config.ts"):
                if "Next.js" not in detected["build_tools"]:
                    detected["build_tools"].append("Next.js")

            # Docker
            if filename in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
                if "Docker" not in detected["deployment"]:
                    detected["deployment"].append("Docker")

            # Config files
            if filename in (".env", ".env.local", ".env.production", ".env.development"):
                if ".env" not in detected["config"]:
                    detected["config"].append(".env")
            if filename in ("security.yaml", "security.yml", "app.config", "settings.yaml"):
                detected["config"].append(filename)

            # Database detection
            if filename == "docker-compose.yml" or filename == "docker-compose.yaml":
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                        if "postgres" in content and "PostgreSQL" not in detected["databases"]:
                            detected["databases"].append("PostgreSQL")
                        if "mysql" in content and "MySQL" not in detected["databases"]:
                            detected["databases"].append("MySQL")
                        if "mongodb" in content and "MongoDB" not in detected["databases"]:
                            detected["databases"].append("MongoDB")
                        if "redis" in content and "Redis" not in detected["databases"]:
                            detected["databases"].append("Redis")
                        if "sqlite" in content and "SQLite" not in detected["databases"]:
                            detected["databases"].append("SQLite")
                except Exception:
                    pass

            # Check for application entry points
            if filename.endswith(".py") and filename not in ("__init__.py", "setup.py", "manage.py"):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Look for FastAPI/Flask app objects
                        if "from fastapi import" in content or "FastAPI()" in content:
                            apps_found.append({"framework": "FastAPI", "file": rel_path, "object": "app"})
                        elif "from flask import" in content or "Flask(" in content:
                            apps_found.append({"framework": "Flask", "file": rel_path, "object": "app"})
                        elif "app = Quart(" in content or "from quart import" in content:
                            apps_found.append({"framework": "Quart", "file": rel_path, "object": "app"})
                except Exception:
                    pass

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

    # Determine primary language
    if "TypeScript" in languages:
        detected["language"] = "TypeScript"
    elif "JavaScript" in languages:
        detected["language"] = "JavaScript"
    elif languages:
        detected["language"] = list(languages.keys())[0]

    # Get Python version if still not detected
    if not detected["python_env"] and detected["language"] == "Python":
        # Try to find version from pyproject.toml
        for root, dirs, files in os.walk(project_path):
            for f in files:
                if f == "pyproject.toml":
                    try:
                        with open(os.path.join(root, f), 'r', encoding='utf-8') as file:
                            content = file.read()
                            match = re.search(r'python\s*=\s*"([^"]+)"', content)
                            if match:
                                detected["python_env"] = match.group(1)
                    except Exception:
                        pass

    return {
        "project_path": project_path,
        "apps_found": apps_found,
        "detected": detected
    }

def print_output(result: dict):
    detected = result["detected"]
    apps = result["apps_found"]

    # Get Python version
    import platform
    os_info = platform.platform()
    arch = platform.machine()

    print("\n" + "=" * 62)
    print("                    Project Intelligence")
    print("=" * 62)
    print("\n" + "[*] Scanning Project...")

    print("\n" + "-" * 62)
    print(" Project Fingerprint")
    print("-" * 62)

    # Language
    print("\nLanguage")
    if detected["language"]:
        ver = detected.get("python_env", "")
        if ver:
            print(f"  [*] {detected['language']} {ver}")
        else:
            print(f"  [*] {detected['language']}")
    else:
        print("  [-] None detected")

    # Frameworks
    print("\nFrameworks")
    if detected["frameworks"]:
        for fw in detected["frameworks"]:
            print(f"  [*] {fw}")
    else:
        print("  [-] None detected")

    # Applications Found
    print("\nApplications Found")
    if apps:
        for i, app in enumerate(apps, 1):
            print(f"\n  [{i}]")
            print(f"    Framework : {app['framework']}")
            print(f"    File      : {app['file']}")
            print(f"    Object    : {app['object']}")
    else:
        print("  [-] None detected")

    # Package Manager
    print("\nPackage Manager")
    if detected["package_manager"]:
        print(f"  [*] {detected['package_manager']}")
    else:
        print("  [-] None detected")

    # Databases
    print("\nDatabase")
    if detected["databases"]:
        for db in detected["databases"]:
            print(f"  [*] {db}")
    else:
        print("  [-] None detected")

    # Deployment
    print("\nDeployment")
    if detected["deployment"]:
        for dep in detected["deployment"]:
            print(f"  [*] {dep}")
    else:
        print("  [-] None detected")

    # Environment
    print("\nEnvironment")
    print(f"  [*] {os_info}")
    print(f"  [*] {arch}")

    # Python Environment
    if detected["language"] == "Python":
        print("\nPython Environment")
        if detected.get("python_env"):
            print(f"  [*] {detected['python_env']}")
        else:
            print("  [*] Default")

    # Configuration
    print("\nConfiguration")
    if detected["config"]:
        for cfg in detected["config"]:
            print(f"  [*] {cfg} detected")
    else:
        print("  [-] None detected")

    # Build Tools
    if detected["build_tools"]:
        print("\nBuild Tools")
        for bt in detected["build_tools"]:
            print(f"  [*] {bt}")

    print("\n" + "-" * 62)
    print(f" Total Files Scanned : {sum(1 for _, _, f in os.walk(result['project_path']) for _ in f)}")
    print("-" * 62 + "\n")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = scan_project(path)
    print_output(result)