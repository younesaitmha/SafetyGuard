# SafetyGuard

SafetyGuard is a security-first FastAPI gateway for LLM, RAG, and agent workflows. It sits in front of downstream models, retrieval systems, and tools to enforce policy, block unsafe prompts, reduce data leakage risk, and produce auditable decisions.

## Why SafetyGuard

Modern AI applications need more than a simple proxy. SafetyGuard adds a defense layer that helps teams:

- enforce identity-aware access policies
- detect prompt injection and jailbreak attempts
- scan prompts and attachments for secrets, credentials, and PII
- filter retrieved context before it reaches the model
- control tool usage and tool arguments
- redact or block unsafe model outputs
- capture audit and observability data for security review

## Core capabilities

- **Policy enforcement**: ordered rules with allow, deny, and restricted modes
- **Input protection**: deterministic scanning for prompt injection, obfuscation, secret exfiltration, and exploit intent
- **DLP scanning**: detection for secrets, API keys, private keys, PII, credentials, and financial patterns
- **Session risk scoring**: per-session risk tracking based on repeated violations and suspicious behavior
- **Retrieval guardrails**: tenant isolation, sensitivity filtering, and indirect prompt injection filtering for RAG content
- **Tool gateway**: permission checks, sensitivity checks, and argument injection detection
- **Prompt building**: trust-segmented prompt assembly with token budget awareness
- **Output guard**: leakage detection, redaction, and model-assisted output blocking
- **OpenAI compatibility**: endpoints for `/v1/models` and `/v1/chat/completions`
- **Operations support**: health probes, policy reload, audit event access, and structured decision logging

## High-level request flow

```text
Client
  -> Identity + request context
  -> Rate limiting + normalization
  -> Session state + risk scoring
  -> Input scanning + DLP + optional LLM guard
  -> Policy decision
  -> Retrieval filtering + tool authorization
  -> Prompt builder
  -> Downstream LLM / agent runtime
  -> Output guard + audit logging
  -> Response
```

## API surface

### Main endpoints

- `POST /v1/chat` - primary chat endpoint
- `GET /v1/models` - OpenAI-compatible model list
- `POST /v1/chat/completions` - OpenAI-compatible chat completions endpoint
- `GET /health` - liveness probe
- `GET /ready` - readiness probe

### Admin endpoints

These require the `X-Admin-Key` header.

- `GET /admin/audit/events`
- `POST /admin/policies/reload`

## Project structure

```text
app/    Core gateway implementation
  main.py                FastAPI entrypoint
  chat_orchestrator.py   End-to-end request pipeline
  input_scanner.py       Injection and jailbreak detection
  dlp_scanner.py         Secret, PII, and credential scanning
  policy_engine.py       Policy evaluation
  retrieval_gateway.py   RAG filtering and retrieval controls
  tool_gateway.py        Tool authorization and validation
  prompt_builder.py      Trust-segmented prompt creation
  output_guard.py        Response redaction and blocking

docs/   Architecture, security, operations, and development guides

tests/  Unit and API regression tests
```

## Local development

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

### Setup

```bash
uv sync --all-groups
uv run uvicorn app.main:app --reload --port 8080
```

The service starts on `http://localhost:8080`.

### Environment configuration

Copy the example file and adjust values for your environment:

```bash
cp .env.example .env
```

Key settings include:

- `APP_DEV_MODE`
- `APP_JWT_VERIFY_SIGNATURE`
- `APP_ADMIN_API_KEY`
- `APP_GUARD_LLM_ENABLED`
- `APP_GUARD_LLM_BASE_URL`
- `APP_GUARD_LLM_MODEL`
- `APP_SECURITY_GATEWAY_URL`
- `APP_RETRIEVAL_BACKEND_URL`
- `APP_RATE_LIMIT_REQUESTS`
- `APP_MAX_PROMPT_CHARS`

## Optional guard model

SafetyGuard can call a local OpenAI-compatible guard model, such as Ollama:

```bash
ollama serve
ollama pull llama3.1
export APP_GUARD_LLM_ENABLED=true
export APP_GUARD_LLM_BASE_URL=http://localhost:11434/v1
export APP_GUARD_LLM_API_KEY=dummy
export APP_GUARD_LLM_MODEL=llama3.1
```

To disable the model-assisted guard for faster local iteration:

```bash
export APP_GUARD_LLM_ENABLED=false
```

## Docker and local UI integration

Build and run the API container:

```bash
docker build -t safetyguard .
docker run --rm -p 8080:8080 safetyguard
```

A sample Open WebUI integration is included:

```bash
docker compose -f docker-compose.openwebui.yml up --build
```

This starts:

- SafetyGuard on `http://localhost:8080`
- Open WebUI on `http://localhost:3000`

## Testing

Run the existing test suite with:

```bash
uv run pytest
```

Coverage output is also supported:

```bash
uv run pytest --cov=app --cov-report=term-missing --cov-report=html
```

## Documentation

Detailed documentation lives under [`docs/`](docs/README.md), including:

- architecture overview and component guides
- security controls and assumptions
- deployment and monitoring guidance
- local development and contribution notes
- operational runbooks

## Use cases

SafetyGuard is a good fit for teams building:

- internal chat assistants
- RAG applications handling sensitive data
- agent systems with tool execution
- OpenAI-compatible gateways with added guardrails
- security review layers in front of existing LLM services

## Current quality signal

The repository currently includes an automated test suite covering API and core security behaviors.
