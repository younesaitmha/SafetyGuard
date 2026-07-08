# Local development

## Setup

```bash
uv sync --all-groups
uv run uvicorn app.main:app --reload --port 8080
```

## Environment variables

| Variable                    | Default                          | Description                                              |
|-----------------------------|----------------------------------|----------------------------------------------------------|
| `APP_JWT_VERIFY_SIGNATURE`  | `false`                          | Set to `true` in production to verify JWT signatures via JWKS |
| `APP_JWKS_URL`              | `https://your-issuer.example.com/.well-known/jwks.json` | JWKS endpoint used when verification is enabled |
| `APP_JWT_ISSUER`            | `https://your-issuer.example.com/` | Expected `iss` claim                                |
| `APP_JWT_AUDIENCE`          | `llm-api`                        | Expected `aud` claim                                     |
| `APP_ADMIN_API_KEY`         | `changeme-replace-in-production` | Required value for `X-Admin-Key` header on admin routes  |
| `APP_MAX_PROMPT_CHARS`      | `32000`                          | Prompt character budget (~8 000 tokens at 4 chars/token) |
| `APP_GUARD_LLM_ENABLED`     | `true`                           | Enable model-assisted input/output guard                 |
| `APP_GUARD_LLM_BASE_URL`    | `http://localhost:11434/v1`      | OpenAI-compatible guard model endpoint                   |
| `APP_GUARD_LLM_API_KEY`     | `dummy`                          | API key for guard model endpoint                         |
| `APP_GUARD_LLM_MODEL`       | `llama3.1`                       | Model name for the guard LLM                             |
| `APP_SECURITY_GATEWAY_URL`  | `http://security-gateway:8080`   | Downstream LLM / agent endpoint                          |
| `APP_RETRIEVAL_BACKEND_URL` | `http://retrieval-backend:8080`  | Knowledge-base retrieval endpoint                        |
| `APP_RETRIEVAL_TOP_K`       | `5`                              | Number of chunks fetched per retrieval query             |
| `APP_RATE_LIMIT_REQUESTS`   | `30`                             | Max requests per window per client+subject               |
| `APP_RATE_LIMIT_WINDOW_SECONDS` | `60`                         | Sliding window duration for rate limiting                |

## Optional guard model with Ollama

```bash
ollama serve
ollama pull llama3.1
export APP_GUARD_LLM_ENABLED=true
export APP_GUARD_LLM_BASE_URL=http://localhost:11434/v1
export APP_GUARD_LLM_API_KEY=dummy
export APP_GUARD_LLM_MODEL=llama3.1
```

To disable the guard model (faster local iteration):

```bash
export APP_GUARD_LLM_ENABLED=false
```

## Admin endpoints

Both admin endpoints require the `X-Admin-Key` header matching `APP_ADMIN_API_KEY`:

```bash
# Reload policy bundle
curl -X POST http://localhost:8080/admin/policies/reload \
  -H "X-Admin-Key: changeme-replace-in-production"

# Fetch recent audit events
curl http://localhost:8080/admin/audit/events?limit=20 \
  -H "X-Admin-Key: changeme-replace-in-production"
```

## Useful commands

### Run tests

```bash
uv run pytest
```

### Run coverage

```bash
uv run pytest --cov=app --cov-report=term-missing --cov-report=html
```

### Manual chat request

```bash
curl -X POST http://localhost:8080/v1/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt>" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```

## Open WebUI / OpenUI integration

SafetyGuard exposes OpenAI-compatible endpoints for WebUI/OpenUI:

- `GET /v1/models`
- `POST /v1/chat/completions`

### Open WebUI settings

- Base URL: `http://localhost:8080/v1`
- API key: any value for local UI setup (if bearer auth is enforced, provide a valid token in the Authorization header path used by your UI)
- Model: choose one from `/v1/models`

### Manual compatibility test

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt>" \
  -d '{
    "model": "qwen2.5",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello"}
    ]
  }'
```

> `stream: true` is currently not supported.
