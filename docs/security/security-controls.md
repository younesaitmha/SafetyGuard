# Security controls

## Preventive controls

- Rate limiting (sliding window per client IP + subject)
- Auth requirement (Bearer JWT; JWKS signature verification in production)
- Policy-based deny / restrict / challenge
- Retrieval mediation (tenant isolation, sensitivity ceiling, indirect injection filter)
- Tool authorisation (permission, sensitivity, content classification, argument injection scan)
- Trust-separated prompt building (trusted > semi_trusted > untrusted section order)
- Admin endpoint protection (X-Admin-Key header required)
- Token budget enforcement (prompt size cap before LLM call)

## Detective controls

- Input scanning (prompt injection, jailbreak, obfuscation, secret exfiltration, exploit intent)
- Attachment DLP scanning (text content of attachments, not just metadata)
- DLP scanning (secrets, PII, credentials, financial patterns)
- Model-assisted guard analysis (optional OSS LLM on input and output)
- Indirect prompt injection detection in retrieved chunks (RAG injection filter)
- Tool argument injection scan
- Output scanning (DLP redaction + prompt/policy leakage detection)
- Audit events (structured, per-event severity)
- Decision logs (full per-request record with stage timings)

## Containment controls

- Deny request (HTTP 403) — policy deny
- Challenge request (HTTP 409) — policy challenge
- Disable tools — policy `disable_tools` flag
- Disable retrieval — policy `allow_retrieval=false`
- Quarantine RAG chunks — injection_filtered_count
- Deny tool invocation — tool gateway decision
- Redact response — output guard pattern substitution
- Block response (HTTP 502) — output guard block action

## Governance controls

- Externalized policy file (`app/policies/default_policy.json`)
- Versioned policy bundle (hot-reloadable via `/admin/policies/reload`)
- Trace IDs for full request correlation
- Structured reason codes on every decision
- Session state tracking for multi-turn abuse detection

## Production hardening status

| Control                        | Status in codebase                          |
|--------------------------------|---------------------------------------------|
| JWT JWKS verification          | Implemented; disabled by default (`APP_JWT_VERIFY_SIGNATURE=false`) |
| Jailbreak detection            | Implemented (10 regex patterns)             |
| Obfuscation detection          | Implemented (Base64, unicode, hex, HTML)    |
| Indirect RAG injection filter  | Implemented                                 |
| Tool argument injection scan   | Implemented                                 |
| Attachment DLP scanning        | Implemented (requires `content` field)      |
| Token budget check             | Implemented (`APP_MAX_PROMPT_CHARS`)        |
| Admin endpoint auth            | Implemented (`APP_ADMIN_API_KEY`)           |
| Persistent session storage     | Not yet (in-memory only)                   |
| Persistent audit sink          | Not yet (in-memory ring buffer)             |
| Prometheus / OTEL metrics      | Not yet                                     |
| Human approval workflow        | Not yet                                     |
| Structured LLM guard output    | Best-effort JSON parsing                    |