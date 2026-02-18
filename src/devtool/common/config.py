"""Configuration loading from file and environment variables."""

import logging
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Threshold for switching to file-based delivery (50KB default)
# Conservative to avoid ARG_MAX issues with environment variables
PROMPT_SIZE_THRESHOLD_FOR_FILE = 50 * 1024


@dataclass
class ACAConfig:
    """ACA configuration loaded from config file and environment."""

    retry_attempts: int = 3
    initial_delay: float = 2.0
    backoff_factor: float = 2.0
    max_delay: float = 30.0
    timeout: int = 120
    log_level: str = "WARNING"
    editor: str | None = None
    default_model: str = "sonnet"
    # Diff compression settings
    diff_size_threshold_bytes: int = 50_000
    diff_files_threshold: int = 100
    diff_compression_enabled: bool = True
    diff_compression_strategy: str = "compact"
    # Smart compression settings
    diff_max_priority_files: int = 15
    diff_token_limit: int = 100_000
    diff_smart_priority_enabled: bool = True
    # Prompt file-based delivery settings
    prompt_file_threshold_bytes: int = 50_000
    prompt_file_enabled: bool = True

    @classmethod
    def load(cls) -> ACAConfig:
        """Load configuration from file and environment variables."""
        config = cls()

        # Try to load from config file
        config_path = Path.home() / ".config" / "aca" / "config.toml"
        if config_path.exists():
            try:
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)

                config.retry_attempts = data.get("retry_attempts", config.retry_attempts)
                config.initial_delay = data.get("initial_delay", config.initial_delay)
                config.backoff_factor = data.get("backoff_factor", config.backoff_factor)
                config.max_delay = data.get("max_delay", config.max_delay)
                config.timeout = data.get("timeout", config.timeout)
                config.log_level = data.get("log_level", config.log_level)
                config.editor = data.get("editor", config.editor)
                config.default_model = data.get("default_model", config.default_model)
                # Diff compression settings
                config.diff_size_threshold_bytes = data.get(
                    "diff_size_threshold_bytes", config.diff_size_threshold_bytes
                )
                config.diff_files_threshold = data.get("diff_files_threshold", config.diff_files_threshold)
                config.diff_compression_enabled = data.get("diff_compression_enabled", config.diff_compression_enabled)
                # Load compression strategy with validation
                valid_strategies = {"stat", "compact", "filtered", "function-context", "smart"}
                strategy = data.get("diff_compression_strategy", config.diff_compression_strategy)
                if strategy in valid_strategies:
                    config.diff_compression_strategy = strategy
                else:
                    logger.warning(
                        f"Invalid diff_compression_strategy '{strategy}' in config, "
                        f"using default 'compact'. Valid options: {valid_strategies}"
                    )
                # Smart compression settings
                config.diff_max_priority_files = data.get("diff_max_priority_files", config.diff_max_priority_files)
                config.diff_token_limit = data.get("diff_token_limit", config.diff_token_limit)
                config.diff_smart_priority_enabled = data.get(
                    "diff_smart_priority_enabled", config.diff_smart_priority_enabled
                )
                # Prompt file-based delivery settings
                config.prompt_file_threshold_bytes = data.get(
                    "prompt_file_threshold_bytes", config.prompt_file_threshold_bytes
                )
                config.prompt_file_enabled = data.get("prompt_file_enabled", config.prompt_file_enabled)
            except Exception as e:
                logger.warning(f"Failed to load config file {config_path}: {e}")

        # Override with environment variables
        if env_timeout := os.environ.get("ACA_TIMEOUT"):
            try:
                config.timeout = int(env_timeout)
            except ValueError:
                logger.warning(f"Invalid ACA_TIMEOUT value: {env_timeout}")

        if env_retries := os.environ.get("ACA_RETRY_ATTEMPTS"):
            try:
                config.retry_attempts = int(env_retries)
            except ValueError:
                logger.warning(f"Invalid ACA_RETRY_ATTEMPTS value: {env_retries}")

        if env_log_level := os.environ.get("ACA_LOG_LEVEL"):
            config.log_level = env_log_level.upper()

        if env_model := os.environ.get("ACA_DEFAULT_MODEL"):
            config.default_model = env_model

        # Diff compression environment variable overrides
        if env_size_threshold := os.environ.get("ACA_DIFF_SIZE_THRESHOLD"):
            try:
                config.diff_size_threshold_bytes = int(env_size_threshold)
            except ValueError:
                logger.warning(f"Invalid ACA_DIFF_SIZE_THRESHOLD value: {env_size_threshold}")

        if env_files_threshold := os.environ.get("ACA_DIFF_FILES_THRESHOLD"):
            try:
                config.diff_files_threshold = int(env_files_threshold)
            except ValueError:
                logger.warning(f"Invalid ACA_DIFF_FILES_THRESHOLD value: {env_files_threshold}")

        env_compression_short = os.environ.get("ACA_DIFF_COMPRESSION")
        env_compression_long = os.environ.get("ACA_DIFF_COMPRESSION_ENABLED")

        if env_compression_long is not None:
            config.diff_compression_enabled = env_compression_long.lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        elif env_compression_short is not None:
            config.diff_compression_enabled = env_compression_short.lower() in (
                "1",
                "true",
                "yes",
                "on",
            )

        if env_strategy := os.environ.get("ACA_DIFF_COMPRESSION_STRATEGY"):
            valid_strategies = {"stat", "compact", "filtered", "function-context", "smart"}
            if env_strategy in valid_strategies:
                config.diff_compression_strategy = env_strategy
            else:
                logger.warning(
                    f"Invalid ACA_DIFF_COMPRESSION_STRATEGY '{env_strategy}', "
                    f"using default 'compact'. Valid options: {valid_strategies}"
                )

        if env_max_priority := os.environ.get("ACA_DIFF_MAX_PRIORITY_FILES"):
            try:
                config.diff_max_priority_files = int(env_max_priority)
            except ValueError:
                logger.warning(f"Invalid ACA_DIFF_MAX_PRIORITY_FILES value: {env_max_priority}")

        if env_token_limit := os.environ.get("ACA_DIFF_TOKEN_LIMIT"):
            try:
                config.diff_token_limit = int(env_token_limit)
            except ValueError:
                logger.warning(f"Invalid ACA_DIFF_TOKEN_LIMIT value: {env_token_limit}")

        if env_smart_priority := os.environ.get("ACA_DIFF_SMART_PRIORITY_ENABLED"):
            config.diff_smart_priority_enabled = env_smart_priority.lower() in (
                "1",
                "true",
                "yes",
                "on",
            )

        if env_prompt_threshold := os.environ.get("ACA_PROMPT_FILE_THRESHOLD"):
            try:
                config.prompt_file_threshold_bytes = int(env_prompt_threshold)
            except ValueError:
                logger.warning(f"Invalid ACA_PROMPT_FILE_THRESHOLD value: {env_prompt_threshold}")

        if env_prompt_file := os.environ.get("ACA_PROMPT_FILE_ENABLED"):
            config.prompt_file_enabled = env_prompt_file.lower() in (
                "1",
                "true",
                "yes",
                "on",
            )

        # Validate smart compression settings
        if config.diff_max_priority_files < 1 or config.diff_max_priority_files > 50:
            logger.warning(
                f"diff_max_priority_files={config.diff_max_priority_files} outside valid range "
                f"[1, 50], clamping to valid range"
            )
            config.diff_max_priority_files = max(1, min(50, config.diff_max_priority_files))

        if config.diff_token_limit < 10_000:
            logger.warning(
                f"diff_token_limit={config.diff_token_limit} too small (minimum 10000), using default 100000"
            )
            config.diff_token_limit = 100_000

        if config.prompt_file_threshold_bytes < 10_000:
            logger.warning(
                f"prompt_file_threshold_bytes={config.prompt_file_threshold_bytes} too small "
                f"(minimum 10000), using default 50000"
            )
            config.prompt_file_threshold_bytes = 50_000

        return config


_config: ACAConfig | None = None


def get_config() -> ACAConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = ACAConfig.load()
    return _config
