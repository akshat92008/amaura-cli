"""Configuration system for Amaura CLI and verification runtime."""

import tomllib
from enum import Enum
from pathlib import Path

import tomli_w
from pydantic import BaseModel, Field


class PolicyProfile(str, Enum):
    STRICT = "strict"
    STANDARD = "standard"
    PERMISSIVE = "permissive"


class PrivacyMode(str, Enum):
    LOCAL_ONLY = "local_only"
    FREE_CLOUD_ASSISTED = "free_cloud_assisted"
    HYBRID = "hybrid"


class SecurityConfig(BaseModel):
    privacy_mode: PrivacyMode = PrivacyMode.LOCAL_ONLY
    allow_network: bool = False
    redact_secrets: bool = True
    max_timeout_seconds: int = 60
    restricted_command_patterns: list[str] = Field(
        default_factory=lambda: [
            "rm -rf /",
            "sudo",
            "curl",
            "wget",
            "nc -e",
            "chmod -R 777",
            ":(){ :|:& };:",
        ]
    )
    forbidden_env_vars: list[str] = Field(
        default_factory=lambda: [
            "AWS_SECRET_ACCESS_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "GITHUB_TOKEN",
        ]
    )


class BudgetConfig(BaseModel):
    default_timeout_seconds: int = 30
    max_checks_per_run: int = 50
    max_output_capture_bytes: int = 1_000_000  # 1MB limit per stream


class VerificationPolicyConfig(BaseModel):
    profile: PolicyProfile = PolicyProfile.STANDARD
    require_clean_git: bool = False
    fail_closed_on_timeout: bool = True
    fail_closed_on_missing_check: bool = True
    allow_vacuous_tests: bool = False
    require_all_mandatory_acceptance_tests: bool = True
    enforce_reproducibility: bool = True


class AmauraConfig(BaseModel):
    version: str = "0.1.0"
    policy: VerificationPolicyConfig = Field(default_factory=VerificationPolicyConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    default_agent: str = "artifact_only"
    runs_dir: str = ".amaura/runs"

    @classmethod
    def find_config_path(cls, start_dir: Path | None = None) -> Path | None:
        current = (start_dir or Path.cwd()).resolve()
        for directory in [current, *current.parents]:
            candidate1 = directory / "amaura.toml"
            if candidate1.is_file():
                return candidate1
            candidate2 = directory / ".amaura" / "config.toml"
            if candidate2.is_file():
                return candidate2
        return None

    @classmethod
    def load(cls, config_path: Path | None = None, start_dir: Path | None = None) -> "AmauraConfig":
        path = config_path or cls.find_config_path(start_dir)
        if path and path.is_file():
            with open(path, "rb") as f:
                data = tomllib.load(f)
            return cls.model_validate(data)
        return cls()

    def save(self, target_path: Path) -> None:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        dumped = self.model_dump(mode="json")
        with open(target_path, "wb") as f:
            tomli_w.dump(dumped, f)
