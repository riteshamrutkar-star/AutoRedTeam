from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "AutoRedTeam"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # LLM Settings
    LLM_PROVIDER: str = "mock"  # "mock" or "ollama"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    LLM_TIMEOUT_SECONDS: int = 30
    LLM_TEMPERATURE: float = 0.2
    LLM_MAX_TOKENS: int = 2048

    # Controlled Execution Settings
    EXECUTION_TIMEOUT_SECONDS: int = 10
    MAX_REQUEST_BODY_BYTES: int = 65536  # 64 KB limit
    MAX_RESPONSE_BYTES: int = 1048576    # 1 MB limit
    FOLLOW_REDIRECTS: bool = False
    MAX_REDIRECTS: int = 0
    ALLOWED_TARGET_HOSTS: str = "localhost,127.0.0.1,testserver"

    # Registered Target Base URLs
    TARGET_VAMPI_URL: str = "http://localhost:8001"
    TARGET_JUICE_SHOP_URL: str = "http://localhost:3000"
    TARGET_DVWA_URL: str = "http://localhost:8080"

    # Vulnerability Classification Settings
    CLASSIFIER_VERSION: str = "v1"
    OWASP_API_TOP_10_VERSION: str = "2023"

    # Adaptive Testing Loop Settings
    ADAPTIVE_MAX_ITERATIONS: int = 5
    ADAPTIVE_MAX_EXECUTIONS: int = 10
    ADAPTIVE_MAX_GENERATED_TESTS: int = 10
    ADAPTIVE_MAX_RUNTIME_SECONDS: int = 120
    ADAPTIVE_MAX_FOLLOWUPS_PER_FINDING: int = 2
    ADAPTIVE_CONFIRMATION_THRESHOLD: float = 0.90

    # Evaluation Engine Settings
    EVALUATION_VERSION: str = "v1"
    METRIC_DEFINITION_VERSION: str = "v1"


settings = Settings()
