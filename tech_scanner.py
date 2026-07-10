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
    ("svelte-kit", "SvelteKit"), ("solid-js", "SolidJS"),
    ("express", "Express"), ("fastify", "Fastify"),
    ("@nestjs/core", "NestJS"),
]

# Database detection for Node.js package names (covers pg, mongoose, etc.)
_NODE_DB_PACKAGES = {
    "pg": "PostgreSQL", "postgres": "PostgreSQL", "pg-hstore": "PostgreSQL",
    "mysql2": "MySQL", "mysql": "MySQL", "sequelize": "PostgreSQL",
    "typeorm": "PostgreSQL", "prisma": "PostgreSQL",
    "mongoose": "MongoDB", "mongodb": "MongoDB", "@mongodb-js/mongodb": "MongoDB",
    "redis": "Redis", "ioredis": "Redis", "redis-om": "Redis",
    "fakeredis": "Redis", "hiredis": "Redis",
    "mariadb": "MariaDB", "mysql2": "MySQL",
    "pg": "PostgreSQL", "node-postgres": "PostgreSQL",
}

_RUST_FRAMEWORKS = [
    ("actix-web", "Actix Web"), ("axum", "Axum"),
    ("tokio", "Tokio"), ("rocket", "Rocket"),
]

# Database detection for Rust crates
_RUST_DB_CRATES = {
    "tokio-postgres": "PostgreSQL", "postgres": "PostgreSQL", "sqlx": "PostgreSQL",
    "mongodb": "MongoDB", "bson": "MongoDB",
    "redis": "Redis", "redis-async": "Redis",
    "diesel": "PostgreSQL", "sea-orm": "PostgreSQL",
    "rusqlite": "SQLite",
}

_PYTHON_PACKAGE_FRAMEWORKS = [
    ("django", "Django"), ("fastapi", "FastAPI"),
    ("flask", "Flask"), ("quart", "Quart"),
]

# Database detection for Python packages (from requirements.txt/pyproject.toml)
_PYTHON_DB_PACKAGES = {
    "psycopg2": "PostgreSQL", "psycopg": "PostgreSQL", "asyncpg": "PostgreSQL",
    "sqlalchemy": "PostgreSQL", "alembic": "PostgreSQL",
    "mysql-connector-python": "MySQL", "mysqlclient": "MySQL",
    "pymongo": "MongoDB", "motor": "MongoDB", "bson": "MongoDB",
    "redis-py": "Redis", "redis": "Redis", "hiredis": "Redis",
    "fakeredis": "Redis", "mariadb": "MariaDB", "mysql-connector": "MySQL",
}

_GO_FRAMEWORKS = [
    ("gin-gonic/gin", "Gin"), ("labstack/echo", "Echo"),
    ("gofiber/fiber", "Fiber"),
]

_JAVA_FRAMEWORKS = [("spring-boot", "Spring Boot")]

_PHP_FRAMEWORKS = [("laravel", "Laravel"), ("symfony", "Symfony")]

# Database detection for PHP packages (composer.json)
_PHP_DB_PACKAGES = {
    "mongodb/mongodb": "MongoDB", "ext-mongodb": "MongoDB",
    "predis/predis": "Redis", "phpredis": "Redis", "predis/redis": "Redis",
    "vlucas/phpdotenv": ".env",
    "doctrine/dbal": "PostgreSQL", "doctrine/orm": "PostgreSQL",
    "mysqli": "MySQL", "ext-mysqli": "MySQL", "ext-pdo_mysql": "MySQL",
}

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
# Version extraction helpers
# ---------------------------------------------------------------------------

def _extract_node_version(dep_name: str, version_spec: str) -> str:
    """Extract a clean semantic-ish version from an npm version spec.

    Strips ^ ~ >= <= = prefixes and returns the bare version string.
    Returns empty string if no version-like content found.
    """
    # Strip leading ranges/operators: ^, ~, >=, <=, =, >, <, ||, &
    cleaned = re.sub(r'^[~^>=<\s]+', '', version_spec)
    cleaned = re.sub(r'[|&].*', '', cleaned)  # take first part if || exists
    # Strip v prefix
    cleaned = cleaned.lstrip('v')
    return cleaned


def _extract_python_version(dep_line: str) -> str:
    """Extract version from a pip-style specifier like 'django==5.0.4' or 'flask>=2.0'.

    Returns the first matched version number (e.g. '5.0.4').
    """
    m = re.search(r'[><=~!]+\s*([0-9][0-9a-zA-Z.*]*)', dep_line)
    return m.group(1).rstrip('.').rstrip('*') if m else ""


def _extract_rust_version(toml_content: str, crate_name: str) -> str | None:
    """Simple TOML parser for a single dependency's version field."""
    # Match [dependencies.package] or package = { version = "x.y.z" }
    pattern = rf'^{re.escape(crate_name)}\s*=\s*(?:"([^"]+)"|\{{.*?\bversion\s*=\s*"([^"]+)"}})'
    m = re.search(pattern, toml_content, re.MULTILINE | re.DOTALL)
    if m:
        version = m.group(1) or m.group(2)
        # Strip ^ ~ >= operators
        return re.sub(r'^[~^>=<]+', '', version or '')
    return None


def _extract_go_version(content: str, module: str) -> str | None:
    """Extract version from go.mod require block."""
    pattern = rf'(?:^|\n)\s*{re.escape(module)}\s+v([0-9][^\s]+)'
    m = re.search(pattern, content)
    return m.group(1) if m else None


def _extract_java_version(content: str, artifact: str) -> str | None:
    """Extract version from pom.xml <version> tag near a given artifact."""
    # Simple approach: find <artifactId>...<version>... block
    pattern = rf'<artifactId>\s*{re.escape(artifact)}\s*</artifactId>'
    m = re.search(pattern, content)
    if not m:
        return None
    snippet = content[m.end():m.end() + 200]
    vm = re.search(r'<version>\s*([0-9][^\s<]*)', snippet)
    return vm.group(1) if vm else None


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
            version_str = _extract_node_version(dep, deps[dep])
            entry = f"{name}"
            if version_str:
                entry += f" ({version_str})"
            detected["frameworks"].append(entry)

    # Detect databases from Node.js package names
    for pkg_name, db_name in _NODE_DB_PACKAGES.items():
        if pkg_name in deps and db_name not in detected["databases"]:
            detected["databases"].append(db_name)


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

    # Detect databases from Rust crates
    for crate, db_name in _RUST_DB_CRATES.items():
        version = _extract_rust_version(content, crate)
        if (crate in content or f'{crate} = ' in content) and db_name not in detected["databases"]:
            detected["databases"].append(db_name)


def _scan_python_manifest(filepath: str, detected: dict, verbose: bool = False):
    """Parse requirements.txt / Pipfile / pyproject.toml / setup.py."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "pip"
    languages["Python"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    # Framework detection from content
    full_content = "".join(lines)
    for key, name in _PYTHON_PACKAGE_FRAMEWORKS:
        if key in full_content.lower() and name not in detected["frameworks"]:
            detected["frameworks"].append(name)

    # Database detection from Python package names (requirements.txt / pyproject.toml)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip extras like [security], markers like ; python_version >= "3.8"
        pkg_part = re.split(r'[>!=<;\[]', line)[0].strip()
        version_str = _extract_python_version(line)
        for pkg_name, db_name in _PYTHON_DB_PACKAGES.items():
            if pkg_name.lower() in pkg_part.lower():
                if db_name not in detected["databases"]:
                    detected["databases"].append(db_name)


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

        # Extract dependencies versions (Fix #1)
        dep_pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]*)</version>'
        for m in re.finditer(dep_pattern, content, re.DOTALL):
            group_id = m.group(1).strip()
            artifact_id = m.group(2).strip()
            version = m.group(3).strip()

            if "spring-boot" in group_id and "Spring Boot" not in detected["frameworks"]:
                detected["frameworks"].append(f"Spring Boot ({version})")


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

    pkg = json.loads(content)
    deps = {**pkg.get("require", {}), **pkg.get("require-dev", {})}

    for key, name in _PHP_FRAMEWORKS:
        dep_name = None
        for d in deps:
            if key in d.lower():
                dep_name = d
                break
        if dep_name and name not in detected["frameworks"]:
            version_str = deps[dep_name]
            # Strip ^ ~ >= operators for cleaner display
            clean_ver = re.sub(r'^[~^>=<\s]+', '', str(version_str))
            entry = f"{name}"
            if clean_ver and not clean_ver.startswith("*"):
                entry += f" ({clean_ver})"
            detected["frameworks"].append(entry)

    # Detect databases from PHP packages
    for pkg_name, db_name in _PHP_DB_PACKAGES.items():
        dep_name = None
        for d in deps:
            if pkg_name.lower() in d.lower():
                dep_name = d
                break
        if dep_name and db_name not in detected["databases"]:
            detected["databases"].append(db_name)


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


def _scan_dart_pubspec(filepath: str, detected: dict, verbose: bool = False):
    """Parse pubspec.yaml for Dart/Flutter frameworks."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "pub"
    languages["Dart"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    # Detect Flutter framework
    if "flutter:" in content.lower():
        detected["frameworks"].append("Flutter")
        languages["Dart"] = True

    # Check for common Flutter web/db packages under dependencies:
    deps_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies:") or stripped == "dependencies:":
            deps_section = True
            continue
        if deps_section and (stripped.startswith("dev_dependencies:") or stripped.startswith("flutter:") or not line[0].isspace()):
            deps_section = False

        if deps_section and ":" in stripped and not stripped.startswith("#"):
            pkg_name = stripped.split(":")[0].strip()
            if pkg_name in ("http", "dio"):
                if "HTTP Client" not in detected["frameworks"]:
                    detected["frameworks"].append("HTTP Client")


def _scan_mix_exs(filepath: str, detected: dict, verbose: bool = False):
    """Parse mix.exs for Elixir/Phoenix frameworks."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "Hex"
    languages["Elixir"] = True

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    if "phoenix" in content.lower():
        detected["frameworks"].append("Phoenix")
        languages["Elixir"] = True


def _scan_kotlin_gradle(filepath: str, detected: dict, verbose: bool = False):
    """Parse build.gradle.kts for Kotlin frameworks (Ktor, Quarkus)."""
    languages = detected.setdefault("_languages", {})
    if not detected["package_manager"]:
        detected["package_manager"] = "Gradle"
    # Only mark as Java/Kotlin if there are actual .kt/.java files later.
    # Don't auto-detect language here — Gradle is shared by both.

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        if verbose:
            _log_verbose(f"  [!] unreadable {filepath}")
        return

    # Ktor detection
    for ktor_dep in ("io.ktor:ktor", "ktor-server", "ktor-client"):
        if ktor_dep in content and "Ktor" not in detected["frameworks"]:
            detected["frameworks"].append("Ktor")
            break

    # Quarkus detection
    if any(q in content for q in ("io.quarkus", "quarkus-hibernate", "quarkus-resteasy")):
        if "Quarkus" not in detected["frameworks"]:
            detected["frameworks"].append("Quarkus")


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
    kotlin_gradle_files: list[tuple[str, str]] = []     # for Kotlin frameworks

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

            # Kotlin Gradle files need separate handling for Ktor/Quarkus
            elif filename in ("build.gradle", "build.gradle.kts"):
                kotlin_gradle_files.append((filepath, rel_path))
                _scan_java_manifest(filepath, detected, verbose)

            elif filename == "composer.json":
                _scan_composer(filepath, detected, verbose)

            elif filename == "Gemfile":
                _scan_gemfile(filepath, detected, verbose)

            # New: Dart/Flutter
            elif filename == "pubspec.yaml":
                _scan_dart_pubspec(filepath, detected, verbose)

            # New: Elixir/Phoenix
            elif filename == "mix.exs":
                _scan_mix_exs(filepath, detected, verbose)

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

    # --- Kotlin frameworks from Gradle files ----------------------------
    for filepath, rel_path in kotlin_gradle_files:
        _scan_kotlin_gradle(filepath, detected, verbose)

    # Detect Kotlin language if Gradle file exists + .kt source files present
    has_kotlin_sources = any(
        f.endswith(".kt") or f.endswith(".kts") for _, _, fs in os.walk(project_path) for f in fs
    )
    if kotlin_gradle_files and has_kotlin_sources:
        detected["_languages"]["Kotlin"] = True

    # --- Database detection from Python imports (Fix #7: entry points first) ---
    for filepath, rel_path in app_py_files + other_py_files:
        _scan_python_imports_db(filepath, detected, verbose)

    # --- App object detection (entry points first, then others) ----------
    for filepath, rel_path in app_py_files + other_py_files:
        _scan_python_app_objects(filepath, rel_path, detected, verbose)

    # --- Extract internal languages dict ---------------------------------
    languages = {k: v for k, v in detected.pop("_languages").items()}
    detected["frameworks"] = list(dict.fromkeys(detected["frameworks"]))  # dedup, preserve order

    # --- Go stdlib-only detection (Fix #2) ------------------------------
    if detected.get("package_manager") == "Go Modules":
        has_go_frameworks = any(
            f.lower() in {"gin", "echo", "fiber"} for f in detected["frameworks"]
        )
        if not has_go_frameworks:
            # Verify there are .go source files (not just go.mod)
            has_go_sources = any(
                f.endswith(".go") for _, _, fs in os.walk(project_path) for f in fs
            )
            if has_go_sources and "Go" not in detected["frameworks"]:
                detected["frameworks"].append("Go (stdlib)")

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
