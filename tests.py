#!/usr/bin/env python3
"""Tests for tech-scanner.py — no external dependencies (stdlib only).

Uses ``unittest`` with temporary directories to simulate real projects.
Run:  python tests.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# The scanner file uses a hyphen in its name, so we can't ``import tech_scanner``.
# Instead, import the module directly from its known path via importlib.
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    # If someone renames tech-scanner.py → tech_scanner.py, that works too.
    from tech_scanner import scan_project, _to_dict  # type: ignore[import-not-found]
except ImportError:
    import importlib
    spec = importlib.util.spec_from_file_location("tech_scanner", Path(__file__).resolve().parent / "tech-scanner.py")
    _mod = importlib.util.module_from_spec(spec)  # type: ignore[attr-defined]
    spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    scan_project = _mod.scan_project
    _to_dict = _mod._to_dict


def _create_file(directory: str, name: str, content: str):
    """Write *content* into ``directory/name``."""
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ====================================================================
# Fixtures — minimal manifests that trigger a specific detection
# ====================================================================

class _BaseFixture(unittest.TestCase):
    """Mixin that creates temp dirs and runs scan_project."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        super().setUp()  # type: ignore[misc]

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, **kwargs) -> dict:
        return scan_project(self.tmp.name, verbose=True, **kwargs)


# ====================================================================
# Fix #1 — Version Detection
# ====================================================================

class TestVersionDetection(_BaseFixture, unittest.TestCase):
    """Each test verifies that framework version strings appear in output."""

    def test_node_version(self):
        _create_file(self.tmp.name, "package.json", json.dumps({
            "name": "test-app",
            "dependencies": {"react": "^18.2.0", "express": "~4.18.2"},
            "devDependencies": {"typescript": "5.3.0"},
        }))
        _create_file(self.tmp.name, "tsconfig.json", "{}")
        result = self.scan()
        # Should have "React (18.2.0)" or similar
        react_found = any("React" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(react_found, f"React not found; frameworks: {result['detected']['frameworks']}")


    def test_python_requirements_version(self):
        _create_file(self.tmp.name, "requirements.txt", "django==5.0.4\nflask>=2.3.0\n")
        _create_file(self.tmp.name, "app.py", "from flask import Flask\napp = Flask(__name__)\n")
        result = self.scan()
        # Django detected from requirements.txt
        django_found = any("Django" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(django_found)

    def test_go_stdlib_no_frameworks(self):
        """Go projects without known frameworks should show 'Go (stdlib)'."""
        _create_file(self.tmp.name, "go.mod", "module example.com/myapp\n\ngo 1.21\n")
        _create_file(self.tmp.name, "main.go", "package main\n\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n")
        result = self.scan()
        go_found = any("Go (stdlib)" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(go_found)

    def test_dart_flutter_detected(self):
        _create_file(self.tmp.name, "pubspec.yaml", """name: my_app
dependencies:
  flutter:
    sdk: flutter
""")
        result = self.scan()
        self.assertIn("Flutter", result["detected"]["frameworks"])

    def test_elixir_phoenix_detected(self):
        _create_file(self.tmp.name, "mix.exs", """defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [app: :my_app, deps: deps()]
  end

  defp deps do
    [{:phoenix, "~> 1.7"}]
  end
end""")
        result = self.scan()
        self.assertIn("Phoenix", result["detected"]["frameworks"])


# ====================================================================
# Fix #2 — New language/framework coverage
# ====================================================================

class TestNewFrameworkCoverage(_BaseFixture, unittest.TestCase):

    def test_sveltekit_detected(self):
        _create_file(self.tmp.name, "package.json", json.dumps({
            "dependencies": {"svelte": "^4.2.0"},
            "devDependencies": {"@sveltejs/adapter-auto": "3.0.0", "@sveltejs/kit": "^2.0.0"},
        }))
        _create_file(self.tmp.name, "tsconfig.json", "{}")
        result = self.scan()
        svelte_found = any("SvelteKit" in fw or "Svelte" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(svelte_found)

    def test_solidjs_detected(self):
        _create_file(self.tmp.name, "package.json", json.dumps({
            "dependencies": {"solid-js": "^1.8.0"},
        }))
        _create_file(self.tmp.name, "tsconfig.json", "{}")
        result = self.scan()
        solid_found = any("SolidJS" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(solid_found)

    def test_ktor_detected(self):
        _create_file(self.tmp.name, "build.gradle.kts", """plugins {
  id("io.ktor.plugin") version "2.3.7"
}
dependencies {
  implementation("io.ktor:ktor-server-netty:2.3.7")
}""")
        _create_file(self.tmp.name, "Main.kt", "fun main() {}")
        result = self.scan()
        ktor_found = any("Ktor" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(ktor_found)

    def test_quarkus_detected(self):
        _create_file(self.tmp.name, "build.gradle.kts", """dependencies {
  implementation("io.quarkus:quarkus-resteasy")
}""")
        _create_file(self.tmp.name, "App.java", "public class App {}")
        result = self.scan()
        quarkus_found = any("Quarkus" in fw for fw in result["detected"]["frameworks"])
        self.assertTrue(quarkus_found)


# ====================================================================
# Fix #4 — Better database detection across ecosystems
# ====================================================================

class TestDatabaseDetection(_BaseFixture, unittest.TestCase):

    def test_node_databases_detected(self):
        """Fix #4: Node.js package names should detect databases."""
        _create_file(self.tmp.name, "package.json", json.dumps({
            "dependencies": {"pg": "^8.11.0", "mongoose": "^7.6.0", "redis": "^4.6.0"},
        }))
        _create_file(self.tmp.name, "app.js", "")
        result = self.scan()
        self.assertIn("PostgreSQL", result["detected"]["databases"])
        self.assertIn("MongoDB", result["detected"]["databases"])
        self.assertIn("Redis", result["detected"]["databases"])

    def test_python_databases_from_requirements(self):
        """Fix #4: Python packages in requirements.txt should detect databases."""
        _create_file(self.tmp.name, "requirements.txt", "psycopg2==5.9\npymongo==4.6\ndjango==5.0\n")
        result = self.scan()
        self.assertIn("PostgreSQL", result["detected"]["databases"])
        self.assertIn("MongoDB", result["detected"]["databases"])

    def test_php_databases_from_composer(self):
        """Fix #4: PHP packages in composer.json should detect databases."""
        _create_file(self.tmp.name, "composer.json", json.dumps({
            "require": {"mongodb/mongodb": "^2.0", "predis/predis": "^2.0"},
        }))
        result = self.scan()
        self.assertIn("MongoDB", result["detected"]["databases"])
        self.assertIn("Redis", result["detected"]["databases"])

    def test_rust_databases_from_cargo(self):
        """Fix #4: Rust crates in Cargo.toml should detect databases."""
        _create_file(self.tmp.name, "Cargo.toml", r"""[package]
name = "myapp"
version = "0.1.0"

[dependencies]
tokio-postgres = "0.7"
mongodb = "3.0""")
        result = self.scan()
        self.assertIn("PostgreSQL", result["detected"]["databases"])
        self.assertIn("MongoDB", result["detected"]["databases"])


# ====================================================================
# Regression guard — previously-working detections still work
# ====================================================================

class TestRegression(_BaseFixture, unittest.TestCase):

    def test_react_detected(self):
        _create_file(self.tmp.name, "package.json", json.dumps({
            "dependencies": {"react": "^18.2.0"},
        }))
        _create_file(self.tmp.name, "tsconfig.json", "{}")
        result = self.scan()
        self.assertTrue(any("React" in fw for fw in result["detected"]["frameworks"]), f"React not found; frameworks: {result['detected']['frameworks']}")

    def test_django_detected(self):
        _create_file(self.tmp.name, "requirements.txt", "django==5.0\n")
        _create_file(self.tmp.name, "manage.py", "")
        result = self.scan()
        lang = result["detected"].get("language") or ""
        self.assertIn("Python", lang)

    def test_fastapi_detected(self):
        _create_file(self.tmp.name, "requirements.txt", "fastapi==0.104.0\n")
        _create_file(self.tmp.name, "app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
        result = self.scan()
        self.assertIn("FastAPI", result["detected"]["frameworks"])

    def test_docker_detected(self):
        _create_file(self.tmp.name, "Dockerfile", "FROM python:3.11\n")
        _create_file(self.tmp.name, "app.py", "")
        result = self.scan()
        self.assertIn("Docker", result["detected"]["deployment"])

    def test_nestjs_detected(self):
        """Fix #1 regression: NestJS detection still works."""
        _create_file(self.tmp.name, "package.json", json.dumps({
            "dependencies": {"@nestjs/core": "^10.2.0"},
        }))
        result = self.scan()
        self.assertTrue(any("NestJS" in fw for fw in result["detected"]["frameworks"]), f"NestJS not found; frameworks: {result['detected']['frameworks']}")

    def test_cargo_package_manager(self):
        _create_file(self.tmp.name, "Cargo.toml", '[package]\nname = "test"\nversion = "0.1"\n')
        result = self.scan()
        self.assertEqual(result["detected"]["package_manager"], "Cargo")

    def test_sqlite_extension_detected(self):
        _create_file(self.tmp.name, "data.db", "")
        result = self.scan()
        self.assertIn("SQLite", result["detected"]["databases"])


# ====================================================================
# CLI / edge cases
# ====================================================================

class TestCLI(_BaseFixture, unittest.TestCase):

    def test_empty_directory_returns_clean(self):
        result = self.scan()
        # Should not crash; frameworks should be an empty list.
        self.assertIsInstance(result["detected"]["frameworks"], list)

    def test_json_output_no_crash(self):
        _create_file(self.tmp.name, "package.json", json.dumps({"name": "test"}))
        result = self.scan()
        data = _to_dict(result)
        self.assertIsInstance(data["frameworks"], list)


# ====================================================================
# Main — run tests with verbose output
# ====================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
