# Components

## Architecture Layers

SafetyGuard is organized as a 4-step **Chain of Responsibility pipeline**, each with distinct responsibilities:

```text
Step 1: PreflightAndNormalizeStep
  └─ Request validation, envelope creation

Step 2: SessionPolicyStep
  └─ Session mgmt, rate limit, risk assessment, policy decision

Step 3: RetrievalAndPromptStep
  └─ Retrieval, tool evaluation, prompt building

Step 4: UpstreamAndOutputStep
  └─ Forwarder call, output guard, response assembly
```

See [overview.md](overview.md) for the high-level request flow and service boundaries.

---

## Core Components

### 1. API Gateway

Receives client traffic and exposes HTTP endpoints.

- `POST /v1/chat` — main inference endpoint (requires Bearer token)
- `GET /v1/models` — OpenAI-compatible model listing endpoint
- `POST /v1/chat/completions` — OpenAI-compatible chat endpoint (supports `stream=true` SSE)
- `GET /health` — liveness probe
- `GET /ready` — readiness probe
- `GET /admin/audit/events` — audit log query (requires X-Admin-Key header)
- `POST /admin/policies/reload` — hot-reload policy bundle (requires X-Admin-Key header)

### 2. Identity / Security Context

Builds a `SecurityContext` from the incoming Bearer token.

- Extracts `sub`, `user_id`, `tenant_id`, `roles`, `permissions`, `auth_level`, `step_up_authenticated`
- If `APP_JWT_VERIFY_SIGNATURE=true`: verifies the token signature using JWKS (cached for 1 h)
- If disabled: uses `get_unverified_claims` (development / testing mode only)
- Raises HTTP 401 on invalid or missing tokens

### 3. Request Normalizer

Builds a `CanonicalRequestEnvelope` from the raw `ChatRequest`.

- Strips control characters (NUL, BEL, form-feed, …)
- Normalises CRLF → LF and trims whitespace
- Assigns trust labels per message role: `system/developer` → trusted, `assistant` → semi_trusted, `user` → untrusted
- Records `has_control_chars` flag on each message
- Propagates attachment `content` field for downstream DLP scanning

### 4. Session Manager

Session state manager (`InMemorySessionManager`) with optional local persistence via SQLite (`SQLiteStateStore`).

- Creates or loads `SessionState` keyed by `session_id`
- Tracks: `request_count`, `total_message_count`, `refusal_count`, `tool_request_count`, `risk_history`
- Records refusals and tool requests after each policy evaluation
- Persists session/profile/rate-limit data when `APP_STATE_BACKEND=sqlite` (default)

> **Production note:** SQLite is suitable for single-node/local deployments. For horizontal scaling and high write throughput, use a shared backend (for example Redis or a managed SQL database).

### 5. Session Risk Engine

Computes a `SessionRiskAssessment` from current session state.

| Signal                         | Score added |
|--------------------------------|-------------|
| 3+ prior refusals              | +40         |
| 5+ tool requests               | +20         |
| 20+ requests in session        | +15         |
| User-supplied system message   | +15         |
| User-supplied developer message| +15         |
| Control characters present     | +10         |

Risk states: `normal` (<20) | `elevated` (20–49) | `restricted` (50–79) | `blocked` (≥80)

## 6. Input Security Scanner

Applies deterministic regex-based heuristics to every user message.

### Detection categories

| Category | Examples | Score/hit |
| --- | --- | --- |
| `prompt_injection` | "ignore previous instructions", "system prompt" | +15 |
| `prompt_leakage` | "system prompt", "developer prompt" (subset of above) | (label) |
| `secret_exfiltration` | "show api key", "reveal token", "dump credentials" | +30 |
| `exploit_intent` | "write malware", "build ransomware", "exploit vuln" | +30 |
| `jailbreak_attempt` | "DAN", "pretend you have no restrictions", "bypass filter", "act as if you were", "no rules apply" | +25 |
| `obfuscation` | Long Base64 strings, unicode escapes (`\uXXXX`), HTML entities (`&#NN;`), hex sequences | +15 |

Score is capped at 100.

## 7. DLP / Secret Scanner

Scans **all message content and attachment text** using regex detectors.

| Detector              | Category    | Severity  |
|-----------------------|-------------|-----------|
| AWS access key        | secret      | critical  |
| Generic bearer token  | secret      | high      |
| Private key block     | secret      | critical  |
| Password assignment   | credential  | high      |
| API / secret key      | secret      | high      |
| Slack token           | secret      | high      |
| GitHub token          | secret      | high      |
| Email address         | pii         | medium    |
| Phone number          | pii         | medium    |
| IBAN-like pattern     | financial   | high      |

Score per match: critical +30, high +20, medium +10, low +5. Capped at 100.

## 8. OSS LLM Input Guard

Optional model-assisted input risk analysis (`OpenSourceLLMGuard`).

- Disabled by default; enable with `APP_GUARD_LLM_ENABLED=true`
- Calls an OpenAI-compatible endpoint (e.g. Ollama with llama3.1)
- Returns a `LLMGuardAnalysis` with: `label`, `confidence`, `risk_score`, `reasons`, `recommended_action`
- Falls back to a conservative `suspicious / allow_with_restrictions` on timeout or parse error

## 9. Content Classifier

Merges deterministic scanner signals and LLM guard output into a single `ContentClassification` label.

Priority order:

1. LLM guard label (if confidence ≥ 0.75) — for high-confidence model-assisted detections
2. `prompt_leakage` → `prompt_injection`
3. `prompt_injection`
4. `jailbreak_attempt`
5. `secret_exfiltration` → `secret_exfiltration_intent`
6. `exploit_intent` → `exploit_or_malware_intent`
7. DLP `secret` or `financial` → `sensitive_data_submission`
8. High input score (≥50) → `jailbreak_attempt`
9. Elevated signals → `suspicious`
10. Default → `benign`

## 10. Policy Engine

Evaluates the request against an ordered list of rules from `default_policy.json`.

Rules are **first-match-wins**. Each rule maps a condition to a `PolicyDecision`:
`action` | `reason_codes` | `disable_tools` | `allow_retrieval` | `max_context_sensitivity` | `response_mode`

### Current rules (in evaluation order)

| Rule name                          | Condition                                             | Action                  |
|------------------------------------|-------------------------------------------------------|-------------------------|
| deny_missing_chat_permission       | missing `llm:chat` permission                         | deny                    |
| deny_prompt_injection              | classification = `prompt_injection`                   | deny                    |
| deny_jailbreak_attempt             | classification = `jailbreak_attempt`                  | deny                    |
| deny_secret_exfiltration_intent    | classification = `secret_exfiltration_intent`         | deny                    |
| deny_secret_exfiltration           | input_scan label = `secret_exfiltration`              | deny                    |
| deny_prompt_leakage                | input_scan label = `prompt_leakage`                   | deny                    |
| deny_malware_or_exploit_intent     | classification = `exploit_or_malware_intent`          | deny                    |
| deny_detected_secret_content       | DLP label = `secret`                                  | deny                    |
| restrict_sensitive_data_submission | classification = `sensitive_data_submission`          | allow_with_restrictions |
| restrict_high_dlp_score            | DLP score ≥ 40                                        | allow_with_restrictions |
| deny_blocked_session               | session_risk_state = `blocked`                        | deny                    |
| restrict_high_scan_score           | input_scan score ≥ 50                                 | allow_with_restrictions |
| guard_elevated_session             | session_risk_state = `elevated`                       | allow_with_restrictions |
| guard_without_step_up_auth         | step_up_authenticated = false                         | allow_with_restrictions |
| *(default)*                        | —                                                     | allow                   |

## 11. Retrieval Gateway

Mediates queries to a knowledge-base retrieval backend.

1. **Fetch** chunks from `APP_RETRIEVAL_BACKEND_URL/internal/retrieve` (top-k configurable)
2. **Tenant filter** — drops chunks with a different `tenant_id`
3. **Sensitivity filter** — drops chunks whose sensitivity exceeds the policy `max_context_sensitivity`
4. **Indirect prompt injection filter** — scans chunk text for jailbreak patterns; quarantines matching chunks and records count in `injection_filtered_count`
5. **DLP scan** — scans allowed chunks for secrets/PII before returning

Falls back to stub data if the retrieval backend is unreachable.

## 12. Tool / Action Gateway

Authorises and (stub) executes tool calls requested via `metadata.requested_tools`.

Checks applied in order:

1. Tool must exist in the registry
2. Tool must be enabled
3. Policy must not set `disable_tools=true`
4. User must have the required permission (e.g. `tool:kb.lookup`)
5. Tool sensitivity must not exceed policy `max_context_sensitivity`
6. Content classification must not be `prompt_injection`, `jailbreak_attempt`, etc.
7. **Argument injection scan** — rejects tool call if any string argument matches injection patterns

Available tools: `browser.search`, `kb.lookup`, `ticket.create`, `email.send`

## 13. Prompt Builder

Constructs a trust-segmented `PromptPackage` ensuring untrusted content cannot override trusted instructions.

Section order (higher trust first):

```text
[TRUSTED_SYSTEM_POLICY]          — security rules enforced by the gateway
[DEVELOPER_TASK]                 — task framing, adapted to response_mode
[SEMI_TRUSTED_RETRIEVED_CONTEXT] — filtered knowledge-base chunks
[UNTRUSTED_USER_INPUT]           — user messages
[SEMI_TRUSTED_ASSISTANT_HISTORY] — prior assistant turns (omitted in restricted mode)
[UNTRUSTED_ATTACHMENTS_METADATA] — attachment metadata (name, size, type, trust)
```

Also computes:

- `token_estimate` = `len(prompt_text) / 4`
- `token_budget_exceeded` = `len(prompt_text) > APP_MAX_PROMPT_CHARS` (default 32 000 chars ≈ 8 000 tokens)
- Logs a warning if budget is exceeded

## 14. Downstream Forwarder

Sends the prompt package to `APP_SECURITY_GATEWAY_URL/internal/chat` via HTTP POST.
Falls back to a stub response if the downstream is unreachable.

## 15. OSS LLM Output Guard

Same `OpenSourceLLMGuard` class used for input, now applied to the downstream response text.
Returns a `LLMGuardAnalysis`; the result is passed to the Output Guard for final action.

## 16. Output Guard / Response Scanner

Applies deterministic checks before returning the response to the client.

1. **DLP scan** — if score ≥ 50: redact secrets with pattern substitutions
2. **Prompt / policy leakage detection** — if `restricted` mode: block; otherwise redact
3. **LLM guard escalation** — if guard recommends `block` (confidence ≥ 0.80): block; `redact` (≥ 0.70): redact

Actions: `allow` | `redact` | `block` (→ HTTP 502)

## 17. Audit / Security Event Bus

In-memory ring buffer of `AuditEvent` records. Emits events for:

- Policy deny / challenge
- High-risk input scan (score ≥ 50)
- DLP detection (score ≥ 20)
- Blocked tools
- Output guard redact / block

Accessible via `GET /admin/audit/events` (requires admin key).

> **Production note:** replace with a persistent SIEM sink (Kafka, Splunk, CloudWatch, etc.)

## 18. Observability / Decision Logging

`DecisionLogger` writes a structured `DecisionLogRecord` for every request, capturing:

- Trace and session IDs
- All component decisions (scan, DLP, classification, policy, retrieval, tools, output)
- Stage timings in milliseconds
- Final outcome

Logged as JSON to the `observability` logger.
