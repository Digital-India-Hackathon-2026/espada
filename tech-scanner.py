#!/usr/bin/env python3
"""
Tech Scanner - Detect project tech stack
Usage: python tech-scanner.py [path] [--json] [--verbose]

Walks a directory tree, sniffing config files and source code to produce
a structured report of the project's languages, frameworks, package manager,
databases, deployment tooling, and build tools.

Examples
--------
  python tech-scanner.py /path/to/project --json    # JSON output
  python tech-scanner.py . --verbose                 # verbosely show skipped files
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXCLUDED_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", "venv", ".venv",
     "target", "dist", "build", ".next", ".nuxt"}
)

_LANG_MAP = {
    ".rs": "Rust", ".js": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python",
    ".go": "Go", ".java": "Java", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".c": "C", ".h": "C",
}

# Framework detection: (dep_or_content_key, display_name)
_NODE_FRAMEWORKS = [
    ("react", "React"), ("vue", "Vue"), ("@angular/core", "Angular"),
    ("next", "Next.js"), ("nuxt", "Nuxt"), ("svelte", "Svelte"),
    ("express", "Express"), ("fastify", "Fastify"),
]

_RUST_FRAMEWORKS = [
    ("actix-web", "Actix Web"), ("axum", "Axum"),
    ("tokio", "Tokio"), ("rocket", "Rocket"),
]

_PYTHON_PACKAGE_FRAMEWORKS = [
    ("django", "Django"), ("fastapi", "FastAPI"),
    ("flask", "Flask"), ("quart", "Quart"),
]

_GO_FRAMEWORKS = [
    ("gin-gonic/gin", "Gin"), ("labstack/echo", "Echo"),
    ("gofiber/fiber", "Fiber"),
]

_JAVA_FRAMEWORKS = [("spring-boot", "Spring Boot")]

_PHP_FRAMEWORKS = [("laravel", "Laravel"), ("symfony", "Symfony")]

# Python app entry-point candidates — checked first to avoid scanning every file.
_APP_ENTRY_POINTS = frozenset((
    "app.py", "main.py", "create_app.py", "wsgi.py", "asgi.py",
    "application.py", "__main__.py", "server.py", "run.py",
    "web.py", "cli.py",
))

# Ordered priority list for primary-language tie-breaking.
_LANG_PRIORITY = [
    "Python", "TypeScript", "JavaScript", "Rust", "Go", "Java",
    "Ruby", "PHP", "C#", "C++", "C",
]


# ---------------------------------------------------------------------------
# Private helpers  (each handles one manifest / strategy)
# ---------------------------------------------------------------------------

def _scan_package_json(filepath: str, detected: dict, verbose: bool = False):
    """Parse package.json for frameworks + detect npm."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    if not detected["package_manager"]:
        detected["package_manager"] = "npm"

    try:
        pkg = json.loads(content)
    except json.JSONDecodeError as exc:
        if verbose:
            _log_verbose(f"  [!] malformed JSON in {filepath}: {exc}")
        return

    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

    for dep, name in _NODE_FRAMEWORKS:
        if dep in deps and name not in detected["frameworks"]:
            detected["frameworks"].append(name)


def _scan_cargo_toml(filepath: str, detected: dict, verbose: bool = False):
    """Parse Cargo.toml for Rust framework detection."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "Cargo"
    languages["Rust"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    for key, name in _RUST_FRAMEWORKS:
        if key in content and name not in detected["frameworks"]:
            detected["frameworks"].append(name)


def _scan_python_manifest(filepath: str, detected: dict, verbose: bool = False):
    """Parse requirements.txt / Pipfile / pyproject.toml / setup.py."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "pip"
    languages["Python"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    for key, name in _PYTHON_PACKAGE_FRAMEWORKS:
        if key in content.lower() and name not in detected["frameworks"]:
            detected["frameworks"].append(name)


def _scan_go_mod(filepath: str, detected: dict, verbose: bool = False):
    """Parse go.mod for Go frameworks."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "Go Modules"
    languages["Go"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    for key, name in _GO_FRAMEWORKS:
        if key in content and name not in detected["frameworks"]:
            detected["frameworks"].append(name)


def _scan_java_manifest(filepath: str, detected: dict, verbose: bool = False):
    """Parse pom.xml or build.gradle for Java frameworks."""
    languages = detected.setdefault("_languages", {})
    is_gradle = filepath.endswith(("build.gradle", "build.gradle.kts"))

    if not detected["package_manager"]:
        detected["package_manager"] = "Maven" if filepath.endswith("pom.xml") else "Gradle"
    languages["Java"] = True

    if filepath.endswith("pom.xml"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            if verbose:
                _log_verbose(f"  [!] unreadable {filepath}")
            return
        for key, name in _JAVA_FRAMEWORKS:
            if key in content and name not in detected["frameworks"]:
                detected["frameworks"].append(name)


def _scan_composer(filepath: str, detected: dict, verbose: bool = False):
    """Parse composer.json for PHP frameworks."""
    if not detected["package_manager"]:
        detected["package_manager"] = "Composer"

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    for key, name in _PHP_FRAMEWORKS:
        if key in content.lower() and name not in detected["frameworks"]:
            detected["frameworks"].append(name)


def _scan_gemfile(filepath: str, detected: dict, verbose: bool = False):
    """Parse Gemfile for Ruby on Rails."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "Bundler"

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    if "rails" in content.lower():
        if "Ruby on Rails" not in detected["frameworks"]:
            detected["frameworks"].append("Ruby on Rails")
        languages["Ruby"] = True


def _find_python_version(project_path: str, verbose: bool = False) -> str | None:
    """Collect Python version from .python-version / pyproject.toml + runtime."""
    # 1) Read .python-version if it exists (from the first walk).
    for root, _dirs, files in os.walk(project_path):
        if ".python-version" in files:
            try:
                with open(os.path.join(root, ".python-version"), "r") as f:
                    val = f.read().strip()
                if val:
                    return val  # e.g. "3.11.4" or "3.12"
            except Exception:
                pass
            break

    # 2) Fallback: read pyproject.toml constraint (walk once to find it).
    for root, _dirs, files in os.walk(project_path):
        if "pyproject.toml" in files:
            try:
                with open(os.path.join(root, "pyproject.toml"), "r") as f:
                    content = f.read()
                match = re.search(r'python\s*=\s*"([^"]+)"', content)
                if match:
                    return match.group(1)  # may be "^3.9" or ">=3.8"
            except Exception:
                pass
            break

    # 3) Runtime fallback.
    try:
        result = subprocess.run(
            ["python", "--version"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip().replace("Python ", "")
    except Exception:
        pass

    return None


def _log_verbose(msg: str) -> None:
    """Print a message only when --verbose is enabled."""
    print(f"  [v] {msg}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_project(project_path: str, *, verbose: bool = False) -> dict:
    """Scan *project_path* and return a result dictionary.

    Returns
    -------
    dict
        ``{"project_path": ..., "apps_found": [...], "detected": {...}}``
    """
    project_path = os.path.abspath(project_path)
    detected = {
        "language": None,
        "frameworks": [],
        "_languages": {},       # internal language tally (hidden from output)
        "package_manager": None,
        "build_tools": [],
        "databases": [],
        "deployment": [],
        "config": [],
        "python_env": None,
    }

    pyproject_paths: list[str] = []       # collect during walk (Fix #8)
    app_py_files: list[tuple[str, str]] = []  # entry points found
    other_py_files: list[tuple[str, str]] = []  # everything else

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)

            # -- manifest dispatchers -----------------------------------------
            if filename == "package.json":
                _scan_package_json(filepath, detected, verbose)

            elif filename == "Cargo.toml":
                _scan_cargo_toml(filepath, detected, verbose)

            elif filename in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"):
                _scan_python_manifest(filepath, detected, verbose)
                if filename == "pyproject.toml":
                    pyproject_paths.append(filepath)

            elif filename == "go.mod":
                _scan_go_mod(filepath, detected, verbose)

            elif filename in ("pom.xml", "build.gradle", "build.gradle.kts"):
                _scan_java_manifest(filepath, detected, verbose)

            elif filename == "composer.json":
                _scan_composer(filepath, detected, verbose)

            elif filename == "Gemfile":
                _scan_gemfile(filepath, detected, verbose)

            # -- Python version (single pass; Fix #8: collected here) ---------
            elif filename == ".python-version":
                try:
                    with open(filepath, "r") as f:
                        val = f.read().strip()
                    if val and not detected["python_env"]:
                        detected["python_env"] = val
                except Exception:
                    pass

            # -- lock files ---------------------------------------------------
            elif filename == "yarn.lock":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Yarn"
            elif filename == "pnpm-lock.yaml":
                if not detected["package_manager"]:
                    detected["package_manager"] = "pnpm"
            elif filename == "bun.lockb":
                if not detected["package_manager"]:
                    detected["package_manager"] = "Bun"
            elif filename == "uv.lock":
                if not detected["package_manager"]:
                    detected["package_manager"] = "uv"
            elif filename == "poetry.lock":
                if not detected["package_manager"]:
                    detected["package_manager"] = "poetry"

            # -- TypeScript ---------------------------------------------------
            elif filename == "tsconfig.json":
                detected["_languages"]["TypeScript"] = True

            # -- build tools --------------------------------------------------
            elif filename in ("vite.config.ts", "vite.config.js"):
                if "Vite" not in detected["build_tools"]:
                    detected["build_tools"].append("Vite")
            elif filename.startswith("webpack.config"):
                if "Webpack" not in detected["build_tools"]:
                    detected["build_tools"].append("Webpack")
            elif filename in ("next.config.js", "next.config.ts"):
                if "Next.js" not in detected["build_tools"]:
                    detected["build_tools"].append("Next.js")

            # -- Docker / deployment ------------------------------------------
            elif filename in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
                if "Docker" not in detected["deployment"]:
                    detected["deployment"].append("Docker")

            # -- config files -------------------------------------------------
            elif filename in (".env", ".env.local", ".env.production", ".env.development"):
                if ".env" not in detected["config"]:
                    detected["config"].append(".env")
            elif filename in ("security.yaml", "security.yml", "app.config", "settings.yaml"):
                detected["config"].append(filename)

            # -- SQLite -------------------------------------------------------
            elif filename.endswith((".db", ".sqlite", ".sqlite3")):
                if "SQLite" not in detected["databases"]:
                    detected["databases"].append("SQLite")

            # -- database detection from docker-compose -----------------------
            elif filename in ("docker-compose.yml", "docker-compose.yaml"):
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read().lower()
                    db_checks = [
                        ("image: postgres", "PostgreSQL"), ("postgres:", "PostgreSQL"),
                        ("image: mysql", "MySQL"), ("mysql:", "MySQL"),
                        ("image: mongodb", "MongoDB"), ("mongo:", "MongoDB"),
                        ("image: redis", "Redis"), ("redis:", "Redis"),
                        ("image: mariadb", "MariaDB"), ("mariadb:", "MariaDB"),
                    ]
                    for pattern, name in db_checks:
                        if pattern in content and name not in detected["databases"]:
                            detected["databases"].append(name)
                except Exception:
                    pass

            # -- Python application entry points (Fix #7: separate lists) ----
            elif filename.endswith(".py"):
                detected["_languages"]["Python"] = True
                if filename in _APP_ENTRY_POINTS:
                    app_py_files.append((filepath, rel_path))
                else:
                    other_py_files.append((filepath, rel_path))

            # -- language by extension (catch-all) ----------------------------
            ext = os.path.splitext(filename)[1].lower()
            if ext and ext in _LANG_MAP:
                detected["_languages"][_LANG_MAP[ext]] = True

    # ------------------------------------------------------------------
    # Post-walk processing
    # ------------------------------------------------------------------

    # --- Database detection from Python imports (Fix #7: entry points first) ---
    for filepath, rel_path in app_py_files + other_py_files:
        _scan_python_imports_db(filepath, detected, verbose)

    # --- App object detection (entry points first, then others) ----------
    for filepath, rel_path in app_py_files + other_py_files:
        _scan_python_app_objects(filepath, rel_path, detected, verbose)

    # --- Extract internal languages dict ---------------------------------
    languages = {k: v for k, v in detected.pop("_languages").items()}
    detected["frameworks"] = list(dict.fromkeys(detected["frameworks"]))  # dedup, preserve order

    # --- Primary language (Fix #14: priority order) ----------------------
    if detected["frameworks"]:
        fw_names = [f.lower() for f in detected["frameworks"]]
        python_frameworks = {"fastapi", "django", "flask", "quart", "tornado"}
        if any(f in fw_names for f in python_frameworks):
            detected["language"] = "Python"
            languages["Python"] = True
        elif "TypeScript" in languages:
            detected["language"] = "TypeScript"
        elif "JavaScript" in languages:
            detected["language"] = "JavaScript"
    else:
        for lang in _LANG_PRIORITY:
            if lang in languages:
                detected["language"] = lang
                break

    # --- Python version (single walk; Fix #8) ----------------------------
    if not detected["python_env"] and detected["language"] == "Python":
        detected["python_env"] = _find_python_version(project_path, verbose)

    return {
        "project_path": project_path,
        "apps_found": [a for a in detected.pop("_apps", [])],  # clean up helper list
        "detected": detected,
    }


def _scan_python_imports_db(filepath: str, detected: dict, verbose: bool = False) -> None:
    """Detect databases from Python source imports."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return

    # SQLAlchemy => PostgreSQL (heuristic; not perfect but common)
    if ("from sqlalchemy" in content or "import sqlalchemy" in content):
        if "PostgreSQL" not in detected["databases"]:
            detected["databases"].append("PostgreSQL")

    if "from pymongo" in content or "import pymongo" in content:
        if "MongoDB" not in detected["databases"]:
            detected["databases"].append("MongoDB")

    # Fix #6: use only one precise check (word boundary via regex).
    if re.search(r'\bimport\s+redis\b', content):
        if "Redis" not in detected["databases"]:
            detected["databases"].append("Redis")


def _scan_python_app_objects(filepath: str, rel_path: str, detected: dict, verbose: bool = False) -> None:
    """Detect FastAPI/Flask/Django app objects in Python source files."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return

    apps = detected.setdefault("_apps", [])

    if "from fastapi import" in content or "FastAPI()" in content:
        if not any(a["framework"] == "FastAPI" for a in apps):
            apps.append({"framework": "FastAPI", "file": rel_path, "object": "app"})
        if "FastAPI" not in detected["frameworks"]:
            detected["frameworks"].append("FastAPI")

    elif "from flask import" in content or "Flask(" in content:
        if not any(a["framework"] == "Flask" for a in apps):
            apps.append({"framework": "Flask", "file": rel_path, "object": "app"})
        if "Flask" not in detected["frameworks"]:
            detected["frameworks"].append("Flask")

    elif "from quart import" in content or "Quart(" in content:
        if not any(a["framework"] == "Quart" for a in apps):
            apps.append({"framework": "Quart", "file": rel_path, "object": "app"})
        if "Quart" not in detected["frameworks"]:
            detected["frameworks"].append("Quart")

    elif "from django" in content or "django.setup()" in content:
        if "Django" not in detected["frameworks"]:
            detected["frameworks"].append("Django")

    elif "from tornado" in content or "tornado.web" in content:
        if "Tornado" not in detected["frameworks"]:
            detected["frameworks"].append("Tornado")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _fmt_frameworks(fw_list: list[str]) -> str:
    return "\n".join(f"  [*] {fw}" for fw in fw_list) or "  [-] None detected"


def _fmt_databases(db_list: list[str]) -> str:
    return "\n".join(f"  [*] {db}" for db in db_list) or "  [-] None detected"


def _fmt_deployment(dep_list: list[str]) -> str:
    return "\n".join(f"  [*] {dep}" for dep in dep_list) or "  [-] None detected"


def _to_dict(result: dict) -> dict:
    """Convert internal result to a clean serialisable dict (no helper keys)."""
    d = {k: v for k, v in result["detected"].items()}
    d.pop("_languages", None)
    return {
        "project_path": result["project_path"],
        "apps_found": result.get("apps_found", []),
        **d,
    }


def print_output(result: dict) -> None:
    detected = result["detected"]
    apps = result["apps_found"]

    os_info = platform.platform()
    arch = platform.machine()

    header = "=" * 62
    bar = "-" * 62

    print("\n" + header)
    print("                    Project Intelligence")
    print(header)
    print("\n[*] Scanning Project...")

    # Language
    print("\n" + bar)
    print(" Project Fingerprint")
    print(bar)

    print("\nLanguage")
    if detected["language"]:
        ver = detected.get("python_env", "")
        print(f"  [*] {detected['language']}{f' {ver}' if ver else ''}")
    else:
        print("  [-] None detected")

    # Frameworks
    print("\nFrameworks")
    print(_fmt_frameworks(detected["frameworks"]))

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
    print(_fmt_databases(detected["databases"]))

    # Deployment
    print("\nDeployment")
    print(_fmt_deployment(detected["deployment"]))

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

    # Confidence score (Fix #12)
    signals = sum(bool(detected[c]) for c in
                  ("language", "frameworks", "package_manager", "databases"))
    confidence = min(signals * 25, 100)
    print(f"\nConfidence : {confidence}% ({signals}/4 categories detected)")

    print(bar)
    total_files = sum(1 for _, _, f in os.walk(result["project_path"]) for _ in f)
    print(f" Total Files Scanned : {total_files}")
    print(bar + "\n")


def print_json_output(result: dict) -> None:
    """Pretty-print the result as JSON (Fix #9)."""
    import json  # noqa: local reimport for clarity
    print(json.dumps(_to_dict(result), indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tech-scanner",
        description="Detect a project's tech stack from its files.",
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true",
        help="Output result as JSON instead of styled text",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print diagnostic messages for skipped/unreadable files",
    )
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    result = scan_project(args.path, verbose=args.verbose)

    if args.as_json:
        print_json_output(result)
    else:
        print_output(result)
