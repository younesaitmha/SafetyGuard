# Assumptions and limitations

## Assumptions

The reference implementation assumes:
- downstream LLM systems exist behind the gateway and are reachable
- identity claims are available in Bearer tokens (JWT)
- policy bundles are managed out of band and reloaded without downtime
- retrieval backends can return tenant-tagged and sensitivity-tagged results
- open-source guard models expose an OpenAI-compatible chat completions interface

## What has been hardened (v0.1 -> current)

The following gaps identified in the initial implementation have been addressed:

| Gap                                      | Resolution                                                      |
|------------------------------------------|-----------------------------------------------------------------|
| JWT signature not verified               | JWKS cache + conditional full verification via `APP_JWT_VERIFY_SIGNATURE` |
| No jailbreak detection                   | 10 regex patterns added to `InputSecurityScanner`              |
| No obfuscation detection                 | Base64, unicode, HTML entity, hex patterns added               |
| Indirect prompt injection (RAG)          | `_filter_chunks_for_injection()` in `RetrievalGateway`         |
| Attachment content not DLP-scanned       | `content` field added to `Attachment`; `DLPScanner` scans it   |
| No policy rules for prompt_injection / jailbreak | 3 new deny rules added to `default_policy.json`       |
| Admin endpoints unprotected              | `_require_admin` dependency + `APP_ADMIN_API_KEY`              |
| Tool arguments not checked for injection | `_arguments_contain_injection()` in `ToolGateway`              |
| No prompt token budget                   | `token_estimate` + `token_budget_exceeded` in `PromptPackage`  |

## Remaining limitations

- **JWT verification disabled by default** — set `APP_JWT_VERIFY_SIGNATURE=true` and configure a valid `APP_JWKS_URL` before production deployment
- **Session and audit stores are in-memory** — data is lost on restart; blocked sessions are not persisted across instances; not suitable for horizontal scaling
- **Tool execution is stubbed** — `ToolGateway.execute_allowed_tools` returns stub records; real integrations must be implemented per tool
- **Retrieval ACLs are advisory** — the gateway filters results, but the retrieval backend should also enforce tenant and sensitivity ACLs independently
- **Output scanning is text-only** — structured or multimodal responses are cast to string; dedicated parsers may be needed for rich response types
- **LLM guard output parsing is best-effort** — responses are expected to be JSON but no schema is enforced; a malformed response triggers a conservative fallback
- **Token budget is advisory** — `token_budget_exceeded=true` emits a warning log but does not block the request; callers should act on this flag
- **Attachment content is caller-supplied** — the `content` field in `Attachment` is populated by the API client, not extracted by the gateway; a server-side extractor should be added for production use
- **Admin API key is a static shared secret** — in production, use short-lived tokens or mTLS for admin endpoint access

## Implications

These limitations mean the current project should be treated as:
- a strong, well-layered reference implementation
- a solid base for production hardening
- not a fully complete enterprise security product out of the box

Review the deployment checklist before any production release.