<#
.SYNOPSIS
    Scans a project folder and detects the tech stack.
.DESCRIPTION
    Analyzes a project directory to detect programming languages, frameworks,
    package managers, and build tools. Outputs structured JSON.
.PARAMETER Path
    The project path to scan. Defaults to current directory.
.EXAMPLE
    .\tech-scanner.ps1
.EXAMPLE
    .\tech-scanner.ps1 -Path "C:\Projects\myapp"
#>

param(
    [string]$Path = "."
)

$ErrorActionPreference = "Stop"

function Get-DetectedTech {
    param(
        [string]$Name,
        [string]$Category,
        [string]$Confidence,
        [string[]]$Evidence
    )

    return @{
        name = $Name
        category = $Category
        confidence = $Confidence
        evidence = $Evidence
    }
}

$projectPath = Resolve-Path $Path
$frameworks = @()
$packageManagers = @()
$buildTools = @()
$otherTools = @()
$languages = @{}

$files = Get-ChildItem -Path $projectPath -Recurse -File -ErrorAction SilentlyContinue
$fileCount = $files.Count

foreach ($file in $files) {
    $fileName = $file.Name
    $ext = $file.Extension.ToLower()

    # Package.json detection
    if ($fileName -eq "package.json") {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $packageManagers += Get-DetectedTech -Name "npm" -Category "package_manager" -Confidence "high" -Evidence @($fileName)

            $json = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($json.dependencies) {
                $deps = $json.dependencies.PSObject.Properties.Name

                if ($deps -contains "react") {
                    $frameworks += Get-DetectedTech -Name "React" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.react")
                }
                if ($deps -contains "vue" -or $deps -contains "vue-loader") {
                    $frameworks += Get-DetectedTech -Name "Vue" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.vue")
                }
                if ($deps -contains "@angular/core") {
                    $frameworks += Get-DetectedTech -Name "Angular" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.@angular/core")
                }
                if ($deps -contains "next") {
                    $frameworks += Get-DetectedTech -Name "Next.js" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.next")
                }
                if ($deps -contains "nuxt") {
                    $frameworks += Get-DetectedTech -Name "Nuxt" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.nuxt")
                }
                if ($deps -contains "svelte") {
                    $frameworks += Get-DetectedTech -Name "Svelte" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.svelte")
                }
                if ($deps -contains "express") {
                    $frameworks += Get-DetectedTech -Name "Express" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.express")
                }
                if ($deps -contains "fastify") {
                    $frameworks += Get-DetectedTech -Name "Fastify" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.fastify")
                }
                if ($deps -contains "nest" -or $deps -contains "@nestjs/core") {
                    $frameworks += Get-DetectedTech -Name "NestJS" -Category "framework" -Confidence "high" -Evidence @("package.json.dependencies.@nestjs/core")
                }
            }
        }
    }

    # Cargo.toml
    if ($fileName -eq "Cargo.toml") {
        $packageManagers += Get-DetectedTech -Name "Cargo" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
        $languages["Rust"] = $true

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            if ($content -match "actix-web") {
                $frameworks += Get-DetectedTech -Name "Actix Web" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "axum") {
                $frameworks += Get-DetectedTech -Name "Axum" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "tokio") {
                $frameworks += Get-DetectedTech -Name "Tokio" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "rocket") {
                $frameworks += Get-DetectedTech -Name "Rocket" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
        }
    }

    # Python files
    if ($fileName -eq "requirements.txt" -or $fileName -eq "Pipfile" -or $fileName -eq "pyproject.toml" -or $fileName -eq "setup.py") {
        $packageManagers += Get-DetectedTech -Name "pip" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
        $languages["Python"] = $true

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            if ($content -match "django") {
                $frameworks += Get-DetectedTech -Name "Django" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "fastapi") {
                $frameworks += Get-DetectedTech -Name "FastAPI" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "flask") {
                $frameworks += Get-DetectedTech -Name "Flask" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "quart") {
                $frameworks += Get-DetectedTech -Name "Quart" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
        }
    }

    # Go
    if ($fileName -eq "go.mod") {
        $packageManagers += Get-DetectedTech -Name "Go Modules" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
        $languages["Go"] = $true

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            if ($content -match "gin-gonic/gin") {
                $frameworks += Get-DetectedTech -Name "Gin" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match '"github.com/labstack/echo"') {
                $frameworks += Get-DetectedTech -Name "Echo" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
            if ($content -match "gofiber/fiber") {
                $frameworks += Get-DetectedTech -Name "Fiber" -Category "framework" -Confidence "high" -Evidence @($fileName)
            }
        }
    }

    # Java
    if ($fileName -eq "pom.xml") {
        $packageManagers += Get-DetectedTech -Name "Maven" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
        $languages["Java"] = $true

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "spring-boot") {
            $frameworks += Get-DetectedTech -Name "Spring Boot" -Category "framework" -Confidence "high" -Evidence @($fileName)
        }
    }

    if ($fileName -eq "build.gradle" -or $fileName -eq "build.gradle.kts") {
        $packageManagers += Get-DetectedTech -Name "Gradle" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
        $languages["Java"] = $true

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "spring-boot") {
            $frameworks += Get-DetectedTech -Name "Spring Boot" -Category "framework" -Confidence "high" -Evidence @($fileName)
        }
    }

    # PHP
    if ($fileName -eq "composer.json") {
        $packageManagers += Get-DetectedTech -Name "Composer" -Category "package_manager" -Confidence "high" -Evidence @($fileName)

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "laravel") {
            $frameworks += Get-DetectedTech -Name "Laravel" -Category "framework" -Confidence "high" -Evidence @($fileName)
        }
        if ($content -match "symfony") {
            $frameworks += Get-DetectedTech -Name "Symfony" -Category "framework" -Confidence "high" -Evidence @($fileName)
        }
    }

    # Ruby
    if ($fileName -eq "Gemfile") {
        $packageManagers += Get-DetectedTech -Name "Bundler" -Category "package_manager" -Confidence "high" -Evidence @($fileName)

        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "rails") {
            $frameworks += Get-DetectedTech -Name "Ruby on Rails" -Category "framework" -Confidence "high" -Evidence @($fileName)
            $languages["Ruby"] = $true
        }
    }

    # Lock files
    if ($fileName -eq "yarn.lock") {
        $packageManagers += Get-DetectedTech -Name "Yarn" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
    }
    if ($fileName -eq "pnpm-lock.yaml") {
        $packageManagers += Get-DetectedTech -Name "pnpm" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
    }
    if ($fileName -eq "bun.lockb") {
        $packageManagers += Get-DetectedTech -Name "Bun" -Category "package_manager" -Confidence "high" -Evidence @($fileName)
    }

    # TypeScript config
    if ($fileName -eq "tsconfig.json") {
        $languages["TypeScript"] = $true
    }

    # Build tools
    if ($fileName -eq "vite.config.ts" -or $fileName -eq "vite.config.js") {
        $buildTools += Get-DetectedTech -Name "Vite" -Category "build_tool" -Confidence "high" -Evidence @($fileName)
    }
    if ($fileName -match "webpack.config\.(js|ts)") {
        $buildTools += Get-DetectedTech -Name "Webpack" -Category "build_tool" -Confidence "high" -Evidence @($fileName)
    }
    if ($fileName -match "next.config\.(js|ts)") {
        $buildTools += Get-DetectedTech -Name "Next.js" -Category "build_tool" -Confidence "high" -Evidence @($fileName)
    }

    # Docker
    if ($fileName -eq "Dockerfile" -or $fileName -eq "docker-compose.yml" -or $fileName -eq "docker-compose.yaml") {
        $otherTools += Get-DetectedTech -Name "Docker" -Category "container" -Confidence "high" -Evidence @($fileName)
    }
    if ($fileName -eq ".dockerignore") {
        $otherTools += Get-DetectedTech -Name "Docker" -Category "container" -Confidence "medium" -Evidence @($fileName)
    }

    # Language detection by extension
    switch ($ext) {
        ".rs" { $languages["Rust"] = $true }
        ".js" { $languages["JavaScript"] = $true }
        ".mjs" { $languages["JavaScript"] = $true }
        { $_ -eq ".ts" -or $_ -eq ".tsx" } { $languages["TypeScript"] = $true }
        ".py" { $languages["Python"] = $true }
        ".go" { $languages["Go"] = $true }
        ".java" { $languages["Java"] = $true }
        ".rb" { $languages["Ruby"] = $true }
        ".php" { $languages["PHP"] = $true }
        ".cs" { $languages["C#"] = $true }
        { $_ -eq ".cpp" -or $_ -eq ".cc" -or $_ -eq ".cxx" } { $languages["C++"] = $true }
        { $_ -eq ".c" -or $_ -eq ".h" } { $languages["C"] = $true }
    }
}

# Deduplicate frameworks
$uniqueFrameworks = @()
foreach ($f in $frameworks) {
    if ($uniqueFrameworks.Name -notcontains $f.name) {
        $uniqueFrameworks += $f
    }
}
$frameworks = $uniqueFrameworks

# Deduplicate package managers
$uniquePms = @()
foreach ($pm in $packageManagers) {
    if ($uniquePms.Name -notcontains $pm.name) {
        $uniquePms += $pm
    }
}
$packageManagers = $uniquePms

$packageManagers = $packageManagers | ForEach-Object { $_.name } | Select-Object -Unique | ForEach-Object {
    $name = $_
    $packageManagers | Where-Object { $_.name -eq $name } | Select-Object -First 1
}

# Determine primary language
$primaryLanguage = $null
$langKeys = @($languages.Keys)
if ($langKeys.Count -eq 1) {
    $primaryLanguage = $langKeys[0]
} elseif ($languages["TypeScript"] -or $languages["JavaScript"]) {
    if ($languages["TypeScript"]) {
        $primaryLanguage = "TypeScript"
    } else {
        $primaryLanguage = "JavaScript"
    }
} elseif ($langKeys.Count -gt 0) {
    $primaryLanguage = $langKeys[0]
}

$result = @{
    project_path = $projectPath.Path
    primary_language = $primaryLanguage
    frameworks = @($frameworks)
    package_managers = @($packageManagers)
    build_tools = @($buildTools)
    other_tools = @($otherTools)
    total_files_scanned = $fileCount
}

$result | ConvertTo-Json -Depth 10