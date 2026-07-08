from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "llm-api-gateway"
    host: str = "0.0.0.0"
    port: int = 8080

    max_request_bytes: int = 100_000
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    state_backend: str = "sqlite"
    state_db_path: str = "data/safetyguard_state.sqlite3"

    security_gateway_url: str = "http://localhost:9999"
    request_timeout_seconds: float = 20.0
    security_gateway_fail_open: bool = True

    # Ollama direct integration
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:1.5b"

    auth_header_name: str = "Authorization"
    require_bearer_token: bool = True

    jwt_issuer: str = "https://your-issuer.example.com/"
    jwt_audience: str = "llm-api"
    jwks_url: str = "https://your-issuer.example.com/.well-known/jwks.json"
    jwt_algorithms: str = "RS256"
    dev_mode: bool = False  # Set to True to skip token validation

    policy_bundle_path: str = "app/policies/default_policy.json"

    retrieval_backend_url: str = "http://localhost:9998"
    retrieval_timeout_seconds: float = 10.0
    retrieval_top_k: int = 5

    guard_llm_enabled: bool = True
    guard_llm_base_url: str = "http://localhost:11434/v1"
    guard_llm_api_key: str = "dummy"
    guard_llm_model: str = "qwen2.5"
    guard_llm_timeout_seconds: float = 45.0
    guard_llm_max_rps: int = 15
    guard_llm_max_input_chars: int = 8000
    llm_pii_treatment_only: bool = True

    # OpenAI/WebUI compatibility defaults
    openai_compat_default_model: str = "qwen2.5:1.5b"

    # Security hardening settings
    jwt_verify_signature: bool = False  # Set to True in production with a valid JWKS endpoint
    admin_api_key: str = "change-me-replace-in-production"  # Must be overridden via APP_ADMIN_API_KEY env var
    admin_allow_localhost_fallback: bool = False  # Dev-only escape hatch; keep False for prod-like behavior
    max_prompt_chars: int = 32000  # ~8 000 tokens at 4 chars/token
    enforce_token_budget: bool = False
    token_budget_mode: str = "block"  # block | truncate
    retrieval_integrity_key: str = ""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()