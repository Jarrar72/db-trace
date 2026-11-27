"""Application configuration loaded from environment / .env."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"
    random_seed: int = 42

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "dbtrace_dev_password"

    database_url: str = "sqlite:///./data/dbtrace.db"
    target_pg_url: str = ""
    mlflow_tracking_uri: str = "sqlite:///./data/mlflow.db"

    llm_provider: str = "none"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "qwen2.5:7b"
    llm_api_key: str = ""

    data_dir: Path = Path("data")


settings = Settings()
