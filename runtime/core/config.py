# runtime/core/config.py
"""
Runtime Configuration Manager

This module provides a comprehensive configuration management system that:
- Loads configuration from multiple sources (.env, env vars, JSON, YAML, TOML)
- Supports type validation using Pydantic models
- Implements singleton pattern for global access
- Provides hot-reload capabilities
- Exports configuration to various formats
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from functools import lru_cache

from pydantic import BaseModel, Field, validator, SecretStr, AnyUrl
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import yaml
import tomli


class DatabaseConfig(BaseModel):
    """Database configuration settings"""
    host: str = "localhost"
    port: int = 5432
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    database: str = "app_db"
    ssl_enabled: bool = False
    max_connections: int = 20
    min_connections: int = 5
    connection_timeout: int = 30
    pool_timeout: int = 10

    class Config:
        arbitrary_types_allowed = True


class RedisConfig(BaseModel):
    """Redis configuration settings"""
    host: str = "localhost"
    port: int = 6379
    password: Optional[SecretStr] = None
    db: int = 0
    ssl_enabled: bool = False
    max_connections: int = 50
    socket_timeout: int = 5
    retry_on_timeout: bool = True
    health_check_interval: int = 30

    class Config:
        arbitrary_types_allowed = True


class SQLiteConfig(BaseModel):
    """SQLite configuration settings"""
    path: str = "./app.db"
    journal_mode: str = "WAL"
    synchronous: int = 1
    cache_size: int = 2000
    foreign_keys: bool = True


class JWTConfig(BaseModel):
    """JWT configuration settings"""
    secret_key: SecretStr
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    issuer: Optional[str] = None
    audience: Optional[Set[str]] = None


class TLSConfig(BaseModel):
    """TLS/SSL configuration settings"""
    enabled: bool = False
    cert_file: Optional[Path] = None
    key_file: Optional[Path] = None
    ca_file: Optional[Path] = None
    verify_client: bool = False
    min_version: str = "TLSv1.2"
    max_version: str = "TLSv1.3"
    cipher_suites: Optional[List[str]] = None


class PluginConfig(BaseModel):
    """Plugin configuration settings"""
    enabled: bool = True
    directory: Path = Path("./plugins")
    auto_discover: bool = True
    allowed_plugins: Optional[List[str]] = None
    disabled_plugins: Optional[List[str]] = None
    plugin_timeout: int = 30
    hot_reload: bool = False


class RuntimeConfig(BaseSettings):
    """
    Runtime Configuration Manager
    
    Central configuration management for the entire application.
    Loads from multiple sources with priority:
    1. Environment variables (highest)
    2. .env file
    3. Config files (JSON, YAML, TOML)
    4. Default values (lowest)
    """
    
    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    
    # Application Settings
    debug_mode: bool = False
    execution_mode: str = "production"  # production, development, test
    runtime_version: str = "1.0.0"
    application_name: str = "runtime-app"
    log_level: str = "INFO"
    
    # Timeout Settings
    request_timeout: int = 30  # seconds
    connection_timeout: int = 10  # seconds
    max_body_size: int = 10 * 1024 * 1024  # 10 MB
    
    # Rate Limiting
    rate_limit: int = 100  # requests per minute
    rate_limit_window: int = 60  # seconds
    
    # Feature Flags
    ai_enabled: bool = True
    threat_detection_enabled: bool = True
    secret_detection_enabled: bool = True
    prompt_injection_detection_enabled: bool = True
    policy_engine_enabled: bool = True
    cache_enabled: bool = True
    metrics_enabled: bool = True
    event_bus_enabled: bool = True
    
    # Security Settings
    allowed_origins: List[str] = ["*"]
    allowed_hosts: List[str] = ["*"]
    trusted_proxies: List[str] = []
    api_keys: Dict[str, SecretStr] = Field(default_factory=dict)
    secrets: Dict[str, SecretStr] = Field(default_factory=dict)
    
    # Nested Configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    sqlite: SQLiteConfig = Field(default_factory=SQLiteConfig)
    jwt: Optional[JWTConfig] = None
    tls: TLSConfig = Field(default_factory=TLSConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    
    # Configuration file tracking
    _config_file: Optional[Path] = None
    _loaded_from: Optional[str] = None
    _config_sources: List[Dict[str, Any]] = []
    
    class Config:
        """Pydantic configuration"""
        env_prefix = "RUNTIME_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        arbitrary_types_allowed = True
        extra = "allow"  # Allow extra fields for future compatibility
    
    @validator("execution_mode")
    def validate_execution_mode(cls, v: str) -> str:
        """Validate execution mode"""
        allowed = {"production", "development", "test"}
        if v not in allowed:
            raise ValueError(f"execution_mode must be one of {allowed}")
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level"""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()
    
    @validator("rate_limit")
    def validate_rate_limit(cls, v: int) -> int:
        """Validate rate limit"""
        if v < 0:
            raise ValueError("rate_limit must be >= 0")
        return v
    
    @validator("workers")
    def validate_workers(cls, v: int) -> int:
        """Validate workers count"""
        if v < 1:
            raise ValueError("workers must be >= 1")
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        if v > cpu_count * 2:
            import warnings
            warnings.warn(f"Workers ({v}) exceeds recommended (2x CPUs: {cpu_count * 2})")
        return v
    
    def __init__(self, **kwargs):
        """Initialize configuration with singleton pattern"""
        super().__init__(**kwargs)
        self._config_sources.append({"type": "defaults", "data": self.dict()})
    
    @classmethod
    @lru_cache(maxsize=1)
    def get_instance(cls, **kwargs) -> "RuntimeConfig":
        """
        Get singleton instance of RuntimeConfig
        
        Returns:
            RuntimeConfig: Singleton configuration instance
        """
        return cls(**kwargs)
    
    def load(self, source: Optional[Union[str, Path, Dict[str, Any]]] = None) -> "RuntimeConfig":
        """
        Load configuration from various sources
        
        Args:
            source: File path (JSON/YAML/TOML) or dictionary of settings
            
        Returns:
            RuntimeConfig: Self for method chaining
        """
        if source is None:
            # Load from environment and .env
            load_dotenv()
            self._loaded_from = "environment"
            
            # Try to load from default config files
            default_files = ["config.json", "config.yaml", "config.yml", "config.toml"]
            for filename in default_files:
                if os.path.exists(filename):
                    self.load_file(Path(filename))
                    break
        elif isinstance(source, dict):
            # Load from dictionary
            self._load_from_dict(source)
            self._loaded_from = "dictionary"
        elif isinstance(source, (str, Path)):
            # Load from file
            self.load_file(source)
            self._loaded_from = str(source)
        
        # Validate after loading
        self.validate()
        return self
    
    def load_file(self, filepath: Union[str, Path]) -> "RuntimeConfig":
        """
        Load configuration from JSON, YAML, or TOML file
        
        Args:
            filepath: Path to configuration file
            
        Returns:
            RuntimeConfig: Self for method chaining
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        
        extension = filepath.suffix.lower()
        
        with open(filepath, "r", encoding="utf-8") as f:
            if extension == ".json":
                data = json.load(f)
            elif extension in (".yaml", ".yml"):
                data = yaml.safe_load(f)
            elif extension == ".toml":
                data = tomli.loads(f.read())
            else:
                raise ValueError(f"Unsupported configuration file format: {extension}")
        
        self._load_from_dict(data)
        self._config_file = filepath
        self._config_sources.append({"type": "file", "path": str(filepath), "data": data})
        
        return self
    
    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """
        Load configuration from dictionary with nested support
        
        Args:
            data: Dictionary containing configuration values
        """
        def set_nested_value(obj: Any, key: str, value: Any) -> None:
            """Set nested attribute using dot notation"""
            keys = key.split(".")
            for k in keys[:-1]:
                if hasattr(obj, k):
                    obj = getattr(obj, k)
                else:
                    # Create nested object if it doesn't exist
                    setattr(obj, k, type("Config", (), {})())
                    obj = getattr(obj, k)
            setattr(obj, keys[-1], value)
        
        # Flatten nested dictionaries
        def flatten_dict(d: Dict[str, Any], parent_key: str = "") -> Dict[str, Any]:
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key).items())
                else:
                    items.append((new_key, v))
            return dict(items)
        
        flat_data = flatten_dict(data)
        
        # Update configuration values
        for key, value in flat_data.items():
            try:
                set_nested_value(self, key, value)
            except AttributeError:
                # Handle top-level attributes
                if hasattr(self, key):
                    setattr(self, key, value)
        
        self._config_sources.append({"type": "dictionary", "data": data})
    
    def reload(self) -> "RuntimeConfig":
        """
        Reload configuration from last source
        
        Returns:
            RuntimeConfig: Self for method chaining
        """
        if self._config_file:
            self.load_file(self._config_file)
        elif self._loaded_from == "environment":
            load_dotenv(override=True)
            # Reload environment variables
            env_config = self.__class__()
            for key, value in env_config.dict().items():
                if hasattr(self, key):
                    setattr(self, key, value)
        
        # Clear cache for validation
        self._config_sources.append({"type": "reload", "timestamp": "now"})
        return self
    
    def save(self, filepath: Optional[Union[str, Path]] = None, format: str = "json") -> None:
        """
        Save configuration to file
        
        Args:
            filepath: Path to save configuration (default: current config file)
            format: Output format (json, yaml, toml)
        """
        if filepath is None:
            if self._config_file:
                filepath = self._config_file
            else:
                filepath = Path("config.json")
        
        filepath = Path(filepath)
        data = self.export(format=format)
        
        # Create directory if needed
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, "w", encoding="utf-8") as f:
            if format == "json":
                json.dump(data, f, indent=2, default=str)
            elif format == "yaml":
                yaml.dump(data, f, default_flow_style=False)
            elif format == "toml":
                # TOML doesn't support all Python types, convert to dict
                clean_data = self._prepare_for_toml(data)
                f.write(tomli.dumps(clean_data))
            else:
                raise ValueError(f"Unsupported export format: {format}")
        
        self._config_file = filepath
        self._loaded_from = str(filepath)
    
    def _prepare_for_toml(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for TOML serialization"""
        clean = {}
        for key, value in data.items():
            if isinstance(value, SecretStr):
                clean[key] = value.get_secret_value()
            elif isinstance(value, dict):
                clean[key] = self._prepare_for_toml(value)
            elif isinstance(value, (list, tuple)):
                clean[key] = [
                    v.get_secret_value() if isinstance(v, SecretStr) else v
                    for v in value
                ]
            else:
                clean[key] = value
        return clean
    
    def validate(self) -> "RuntimeConfig":
        """
        Validate current configuration
        
        Returns:
            RuntimeConfig: Self for method chaining
            
        Raises:
            ValueError: If validation fails
        """
        # Validate required fields
        if self.jwt and not self.jwt.secret_key.get_secret_value():
            raise ValueError("JWT secret_key is required when JWT is enabled")
        
        # Validate paths
        if self.tls.enabled:
            if not self.tls.cert_file or not self.tls.cert_file.exists():
                raise ValueError(f"TLS certificate file not found: {self.tls.cert_file}")
            if not self.tls.key_file or not self.tls.key_file.exists():
                raise ValueError(f"TLS key file not found: {self.tls.key_file}")
        
        # Validate API keys
        if not isinstance(self.api_keys, dict):
            raise ValueError("api_keys must be a dictionary")
        
        # Validate secrets
        if not isinstance(self.secrets, dict):
            raise ValueError("secrets must be a dictionary")
        
        return self
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot notation key
        
        Args:
            key: Dot notation key (e.g., "database.host")
            default: Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split(".")
        value = self
        
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    value = getattr(value, k)
            return value
        except (AttributeError, KeyError, IndexError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> "RuntimeConfig":
        """
        Set configuration value by dot notation key
        
        Args:
            key: Dot notation key (e.g., "database.host")
            value: Value to set
            
        Returns:
            RuntimeConfig: Self for method chaining
        """
        keys = key.split(".")
        obj = self
        
        # Navigate to the parent object
        for k in keys[:-1]:
            if hasattr(obj, k):
                obj = getattr(obj, k)
            else:
                # Create nested object if it doesn't exist
                setattr(obj, k, type("Config", (), {})())
                obj = getattr(obj, k)
        
        # Set the value
        setattr(obj, keys[-1], value)
        self._config_sources.append({"type": "manual_set", "key": key, "value": value})
        return self
    
    def exists(self, key: str) -> bool:
        """
        Check if configuration key exists
        
        Args:
            key: Dot notation key
            
        Returns:
            bool: True if key exists
        """
        return self.get(key, None) is not None
    
    def export(self, format: str = "dict", redact_secrets: bool = True) -> Union[Dict[str, Any], str]:
        """
        Export configuration to dictionary or string format
        
        Args:
            format: Output format (dict, json, yaml, toml)
            redact_secrets: If True, hide secret values
            
        Returns:
            Union[Dict[str, Any], str]: Exported configuration
        """
        def redact_value(obj: Any) -> Any:
            """Redact secret values recursively"""
            if isinstance(obj, SecretStr):
                return "***REDACTED***" if redact_secrets else obj.get_secret_value()
            elif isinstance(obj, dict):
                return {k: redact_value(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [redact_value(item) for item in obj]
            elif hasattr(obj, "dict"):
                return redact_value(obj.dict())
            else:
                return obj
        
        # Get full configuration as dictionary
        data = self.dict()
        
        # Redact secrets if requested
        if redact_secrets:
            data = redact_value(data)
        
        if format == "dict":
            return data
        elif format == "json":
            return json.dumps(data, indent=2, default=str)
        elif format == "yaml":
            return yaml.dump(data, default_flow_style=False)
        elif format == "toml":
            return tomli.dumps(self._prepare_for_toml(data))
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_config_sources(self) -> List[Dict[str, Any]]:
        """
        Get configuration source history
        
        Returns:
            List[Dict[str, Any]]: History of configuration sources
        """
        return self._config_sources.copy()
    
    def reset_to_defaults(self) -> "RuntimeConfig":
        """
        Reset configuration to default values
        
        Returns:
            RuntimeConfig: Self for method chaining
        """
        defaults = self.__class__()
        for key, value in defaults.dict().items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
    
    def create_temp_config(self) -> Path:
        """
        Create temporary configuration file for testing
        
        Returns:
            Path: Path to temporary config file
        """
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(self.export(format="dict"), f, indent=2, default=str)
        return Path(path)
    
    def __repr__(self) -> str:
        """String representation of configuration"""
        return f"<RuntimeConfig loaded_from={self._loaded_from} mode={self.execution_mode}>"
    
    def __str__(self) -> str:
        """Human-readable configuration display"""
        return str(self.export(format="dict", redact_secrets=True))


# Convenience function to get configuration instance
def get_config(**kwargs) -> RuntimeConfig:
    """
    Get RuntimeConfig singleton instance
    
    Returns:
        RuntimeConfig: Configuration instance
    """
    return RuntimeConfig.get_instance(**kwargs)