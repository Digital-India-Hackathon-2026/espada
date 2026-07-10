# Espada

Repository for Hackathon Team Espada.

## Tech Scanner

A CLI tool to detect the tech stack of a project.

### Usage

```powershell
# Scan current directory
.\tech-scanner.ps1

# Scan specific path
.\tech-scanner.ps1 -Path "C:\Projects\myapp"
```

### Output

```json
{
    "project_path": "C:\\path\\to\\project",
    "primary_language": "JavaScript",
    "frameworks": [
        { "name": "React", "category": "framework", "confidence": "high", "evidence": ["package.json"] }
    ],
    "package_managers": [
        { "name": "npm", "category": "package_manager", "confidence": "high", "evidence": ["package.json"] }
    ],
    "build_tools": [],
    "other_tools": [],
    "total_files_scanned": 150
}
```

### Detected Technologies

| Category | Technologies |
|----------|--------------|
| Languages | JavaScript, TypeScript, Python, Rust, Go, Java, Ruby, PHP, C#, C, C++ |
| Frameworks | React, Vue, Angular, Next.js, Nuxt, Svelte, Express, Fastify, NestJS, Django, FastAPI, Flask, Gin, Echo, Spring Boot, Laravel, Symfony, Rails |
| Package Managers | npm, Yarn, pnpm, Bun, Cargo, pip, Go Modules, Maven, Gradle, Composer, Bundler |
| Build Tools | Vite, Webpack, Next.js |
| Other | Docker |