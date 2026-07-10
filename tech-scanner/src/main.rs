use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = ".")]
    path: String,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DetectedTech {
    name: String,
    category: String,
    confidence: String,
    evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    project_path: String,
    primary_language: Option<String>,
    frameworks: Vec<DetectedTech>,
    package_managers: Vec<DetectedTech>,
    build_tools: Vec<DetectedTech>,
    other_tools: Vec<DetectedTech>,
    total_files_scanned: usize,
}

fn detect_technologies(path: &Path) -> ScanResult {
    let mut frameworks: Vec<DetectedTech> = Vec::new();
    let mut package_managers: Vec<DetectedTech> = Vec::new();
    let mut build_tools: Vec<DetectedTech> = Vec::new();
    let mut other_tools: Vec<DetectedTech> = Vec::new();
    let mut languages: HashSet<String> = HashSet::new();

    let mut file_count = 0;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();

        if file_path.is_file() {
            file_count += 1;
            let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            match file_name {
                "package.json" => {
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        let name = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            json.get("name").and_then(|v| v.as_str()).unwrap_or("package.json").to_string()
                        } else {
                            "package.json".to_string()
                        };
                        package_managers.push(DetectedTech {
                            name: "npm".to_string(),
                            category: "package_manager".to_string(),
                            confidence: "high".to_string(),
                            evidence: vec![file_name.to_string()],
                        });

                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
                                for (key, _) in deps {
                                    match key.as_str() {
                                        "react" => frameworks.push(DetectedTech {
                                            name: "React".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.react", file_name)],
                                        }),
                                        "vue" | "vue-loader" => frameworks.push(DetectedTech {
                                            name: "Vue".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.{}", file_name, key)],
                                        }),
                                        "@angular/core" => frameworks.push(DetectedTech {
                                            name: "Angular".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.{}", file_name, key)],
                                        }),
                                        "next" => frameworks.push(DetectedTech {
                                            name: "Next.js".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.next", file_name)],
                                        }),
                                        "nuxt" => frameworks.push(DetectedTech {
                                            name: "Nuxt".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.nuxt", file_name)],
                                        }),
                                        "svelte" => frameworks.push(DetectedTech {
                                            name: "Svelte".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.{}", file_name, key)],
                                        }),
                                        "express" => frameworks.push(DetectedTech {
                                            name: "Express".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.express", file_name)],
                                        }),
                                        "fastify" => frameworks.push(DetectedTech {
                                            name: "Fastify".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.fastify", file_name)],
                                        }),
                                        "nest" | "@nestjs/core" => frameworks.push(DetectedTech {
                                            name: "NestJS".to_string(),
                                            category: "framework".to_string(),
                                            confidence: "high".to_string(),
                                            evidence: vec![format!("{}.dependencies.@nestjs/core", file_name)],
                                        }),
                                        "axios" | "fetch" => {}
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                "Cargo.toml" => {
                    package_managers.push(DetectedTech {
                        name: "Cargo".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("name = ") {
                            languages.insert("Rust".to_string());
                        }
                        if content.contains("actix-web") {
                            frameworks.push(DetectedTech {
                                name: "Actix Web".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("axum") {
                            frameworks.push(DetectedTech {
                                name: "Axum".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("tokio") {
                            frameworks.push(DetectedTech {
                                name: "Tokio".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("rocket") {
                            frameworks.push(DetectedTech {
                                name: "Rocket".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "requirements.txt" | "Pipfile" | "pyproject.toml" | "setup.py" => {
                    package_managers.push(DetectedTech {
                        name: "pip".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        languages.insert("Python".to_string());

                        if content.contains("django") {
                            frameworks.push(DetectedTech {
                                name: "Django".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("fastapi") {
                            frameworks.push(DetectedTech {
                                name: "FastAPI".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("flask") {
                            frameworks.push(DetectedTech {
                                name: "Flask".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("quart") {
                            frameworks.push(DetectedTech {
                                name: "Quart".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "go.mod" => {
                    package_managers.push(DetectedTech {
                        name: "Go Modules".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    languages.insert("Go".to_string());
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("gin-gonic/gin") {
                            frameworks.push(DetectedTech {
                                name: "Gin".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("echo") {
                            frameworks.push(DetectedTech {
                                name: "Echo".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("fiber") {
                            frameworks.push(DetectedTech {
                                name: "Fiber".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "pom.xml" => {
                    package_managers.push(DetectedTech {
                        name: "Maven".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    languages.insert("Java".to_string());
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("spring-boot") {
                            frameworks.push(DetectedTech {
                                name: "Spring Boot".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "build.gradle" | "build.gradle.kts" => {
                    package_managers.push(DetectedTech {
                        name: "Gradle".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    languages.insert("Java".to_string());
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("spring-boot") {
                            frameworks.push(DetectedTech {
                                name: "Spring Boot".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "composer.json" => {
                    package_managers.push(DetectedTech {
                        name: "Composer".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("laravel") {
                            frameworks.push(DetectedTech {
                                name: "Laravel".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                        if content.contains("symfony") {
                            frameworks.push(DetectedTech {
                                name: "Symfony".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                        }
                    }
                }
                "Gemfile" => {
                    package_managers.push(DetectedTech {
                        name: "Bundler".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        if content.contains("rails") {
                            frameworks.push(DetectedTech {
                                name: "Ruby on Rails".to_string(),
                                category: "framework".to_string(),
                                confidence: "high".to_string(),
                                evidence: vec![file_name.to_string()],
                            });
                            languages.insert("Ruby".to_string());
                        }
                    }
                }
                "yarn.lock" => {
                    package_managers.push(DetectedTech {
                        name: "Yarn".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "pnpm-lock.yaml" => {
                    package_managers.push(DetectedTech {
                        name: "pnpm".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "bun.lockb" => {
                    package_managers.push(DetectedTech {
                        name: "Bun".to_string(),
                        category: "package_manager".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "tsconfig.json" => {
                    languages.insert("TypeScript".to_string());
                }
                "vite.config.ts" | "vite.config.js" => {
                    build_tools.push(DetectedTech {
                        name: "Vite".to_string(),
                        category: "build_tool".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "webpack.config.js" | "webpack.config.ts" => {
                    build_tools.push(DetectedTech {
                        name: "Webpack".to_string(),
                        category: "build_tool".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "next.config.js" | "next.config.ts" => {
                    build_tools.push(DetectedTech {
                        name: "Next.js".to_string(),
                        category: "build_tool".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "Dockerfile" | "docker-compose.yml" | "docker-compose.yaml" => {
                    other_tools.push(DetectedTech {
                        name: "Docker".to_string(),
                        category: "container".to_string(),
                        confidence: "high".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                ".dockerignore" => {
                    other_tools.push(DetectedTech {
                        name: "Docker".to_string(),
                        category: "container".to_string(),
                        confidence: "medium".to_string(),
                        evidence: vec![file_name.to_string()],
                    });
                }
                "Dockerfile" => {}
                _ => {}
            }

            // Content-based detection for additional signals
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

                match ext {
                    "rs" => { languages.insert("Rust".to_string()); }
                    "js" | "mjs" => { languages.insert("JavaScript".to_string()); }
                    "ts" | "tsx" => { languages.insert("TypeScript".to_string()); }
                    "py" => { languages.insert("Python".to_string()); }
                    "go" => { languages.insert("Go".to_string()); }
                    "java" => { languages.insert("Java".to_string()); }
                    "rb" => { languages.insert("Ruby".to_string()); }
                    "php" => { languages.insert("PHP".to_string()); }
                    "cs" => { languages.insert("C#".to_string()); }
                    "cpp" | "cc" | "cxx" => { languages.insert("C++".to_string()); }
                    "c" | "h" => { languages.insert("C".to_string()); }
                    _ => {}
                }
            }
        }
    }

    // Deduplicate frameworks
    let mut seen: HashSet<String> = HashSet::new();
    frameworks.retain(|f| seen.insert(f.name.clone()));

    let primary = if languages.len() == 1 {
        languages.iter().next().cloned()
    } else if languages.contains("TypeScript") || languages.contains("JavaScript") {
        if languages.contains("TypeScript") {
            Some("TypeScript".to_string())
        } else {
            Some("JavaScript".to_string())
        }
    } else {
        languages.iter().next().cloned()
    };

    ScanResult {
        project_path: path.to_string_lossy().to_string(),
        primary_language: primary,
        frameworks,
        package_managers,
        build_tools,
        other_tools,
        total_files_scanned: file_count,
    }
}

fn main() {
    let args = Args::parse();

    let path = Path::new(&args.path);
    if !path.exists() {
        eprintln!("Error: Path '{}' does not exist", args.path);
        std::process::exit(1);
    }

    let result = detect_technologies(path);

    let json = serde_json::to_string_pretty(&result).unwrap();
    println!("{}", json);
}