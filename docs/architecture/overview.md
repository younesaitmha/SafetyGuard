# Architecture overview

## Purpose

The Secure LLM API Gateway is a policy enforcement and security control layer placed in front of downstream LLM systems, retrieval backends, and agent/tooling runtimes.

Its purpose is to:

- centralize security controls
- enforce identity-aware policy
- detect and block prompt injection, jailbreak attempts, obfuscation, and indirect RAG injection
- prevent data leakage from inbound messages and attachment content
- provide consistent guardrails across applications
- improve auditability and explainability

## High-level design

```text
Client
  |
  v
+------------------------------------------------------------+
| Secure LLM API Gateway                                     |
|------------------------------------------------------------|
| Trace + Request Context                                    |
| Identity / Security Context  (JWKS-verified JWT)          |
| Rate Limiter                 (sliding window per subject)  |
| Request Normalizer           (control chars + content)     |
| Session Manager                                            |
| Session Risk Engine                                        |
| Input Security Scanner       (injection, jailbreak, obfus) |
| DLP Scanner                  (messages + attachment text)  |
| OSS LLM Input Guard          (model-assisted, optional)    |
| Content Classifier                                         |
| Policy Decision Point        (deny / restrict / allow)     |
| Retrieval Gateway            (tenant + sensitivity +       |
|                               RAG injection filter)        |
| Tool / Action Gateway        (perm + arg injection scan)   |
| Prompt Builder               (trust-segmented + token bgt) |
| Downstream Forwarder                                       |
| OSS LLM Output Guard         (model-assisted, optional)    |
| Output Guard / Response Scanner (DLP + leakage block)     |
| Audit / Security Event Bus                                 |
| Observability / Decision Logging                           |
+------------------------------------------------------------+
  |
  +--------------------> Retrieval Backend
  |
  +--------------------> Tool/Action Backends
  |
  +--------------------> Downstream LLM / Agent Runtime
```

## Request lifecycle (happy path)

```text
 1. Client sends POST /v1/chat with Bearer token
 2. TraceIDMiddleware assigns a unique trace_id
 3. identity.py extracts claims from JWT
       - if APP_JWT_VERIFY_SIGNATURE=true -> full JWKS signature verification
       - JWKS response is cached for 1 h to avoid per-request latency
 4. Rate limiter enforces a per-client+subject sliding-window quota
 5. normalizer.py builds CanonicalRequestEnvelope:
       - strips control characters (NUL, BEL, ...)
       - normalizes CRLF -> LF
       - labels message roles as trusted / semi_trusted / untrusted
       - carries attachment.content for downstream scanning
 6. session_manager.py loads or creates in-memory session state
 7. risk_engine.py scores session behavior:
       - prior refusal count, tool volume, request count
       - presence of control chars or user-supplied system/developer messages
       -> state: normal | elevated | restricted | blocked
 8. input_scanner.py scans every user message for:
       - Prompt injection   ("ignore previous instructions", "system prompt"...)
       - Jailbreak attempts ("DAN", "pretend you have no restrictions",
                             "bypass filter", "act as if you were"...)
       - Obfuscation        (Base64 payloads, unicode escapes, HTML entities,
                             hex sequences)
       - Secret exfiltration intent
       - Exploit / malware intent
 9. dlp_scanner.py scans messages AND attachment content for:
       - Secrets / API keys / tokens (AWS, GitHub, Slack, generic)
       - PII (email address, phone number)
       - Credentials (password assignments)
       - Financial patterns (IBAN-like)
10. llm_guard.py (optional, APP_GUARD_LLM_ENABLED) runs model-assisted
    classification against a local OSS guard model (Ollama / compatible)
11. content_classifier.py merges deterministic + LLM signals into one label:
       benign | suspicious | prompt_injection | jailbreak_attempt |
       secret_exfiltration_intent | exploit_or_malware_intent | sensitive_data_submission
12. policy_engine.py evaluates ordered rules against the envelope:
       deny_missing_chat_permission
       deny_prompt_injection           <- classification label
       deny_jailbreak_attempt          <- classification label
       deny_secret_exfiltration_intent <- classification label
       deny_secret_exfiltration        (raw scan label)
       deny_prompt_leakage
       deny_malware_or_exploit_intent
       deny_detected_secret_content    (DLP label)
       restrict_sensitive_data_submission
       restrict_high_dlp_score
       deny_blocked_session
       restrict_high_scan_score
       guard_elevated_session
       guard_without_step_up_auth
       -> on deny:      HTTP 403, audit event, session refusal recorded
       -> on challenge: HTTP 409, audit event
13. retrieval_gateway.py fetches knowledge-base chunks, then filters by:
       - Tenant isolation (cross-tenant chunks dropped)
       - Sensitivity ceiling from policy decision
       - Indirect prompt injection scan: chunks containing jailbreak patterns
         are quarantined (injection_filtered_count incremented)
14. tool_gateway.py evaluates each requested tool:
       - Registry lookup (unknown tool -> denied)
       - Tool enabled flag
       - Policy disable_tools flag
       - Required permission in security context
       - Sensitivity ceiling
       - Content classification gate (blocks if injection/jailbreak classified)
       - Argument injection scan (TOOL_ARGUMENT_INJECTION_DETECTED if matched)
15. prompt_builder.py builds a trust-segmented prompt:
       [TRUSTED_SYSTEM_POLICY] -> [DEVELOPER_TASK] ->
       [SEMI_TRUSTED_RETRIEVED_CONTEXT] -> [UNTRUSTED_USER_INPUT] ->
       [SEMI_TRUSTED_ASSISTANT_HISTORY] -> [UNTRUSTED_ATTACHMENTS_METADATA]
       - Computes token_estimate (chars / 4)
       - Sets token_budget_exceeded=true if prompt > APP_MAX_PROMPT_CHARS
       - Warning logged if budget exceeded
16. forwarder.py sends the prompt package to the downstream LLM
17. llm_guard.py (optional) analyses the downstream response
18. output_guard.py applies deterministic checks on the response:
       - DLP scan -> redact if score >= 50
       - Prompt / policy leakage detection -> block (restricted) or redact
       - LLM guard signal -> block / redact if confidence threshold met
19. audit_bus.py emits structured events for security-significant actions
20. decision_logger.py writes a full per-request decision record
21. Client receives ChatResponse with policy metadata, audit trace_id,
    and (redacted if needed) upstream response
```

## Threat coverage summary

| Threat                              | Detection layer                       | Response          |
|-------------------------------------|---------------------------------------|-------------------|
| Missing / invalid JWT               | identity.py (JWKS verification)       | HTTP 401          |
| Forged JWT (no signature check)     | APP_JWT_VERIFY_SIGNATURE=true + JWKS  | HTTP 401          |
| Prompt injection                    | input_scanner + content_classifier    | HTTP 403          |
| Jailbreak attempt                   | input_scanner + content_classifier    | HTTP 403          |
| Obfuscated payloads                 | input_scanner (Base64/unicode/hex)    | Score escalation  |
| Secret exfiltration intent          | input_scanner + content_classifier    | HTTP 403          |
| Exploit / malware generation        | input_scanner + content_classifier    | HTTP 403          |
| DLP: secrets, PII, credentials      | dlp_scanner (messages + attachments)  | Deny / restrict   |
| Indirect prompt injection (RAG)     | retrieval_gateway injection filter    | Chunk quarantined |
| Tool argument injection             | tool_gateway argument scan            | Tool denied       |
| Cross-tenant data access            | retrieval_gateway tenant filter       | Chunk filtered    |
| Prompt / policy leakage in output   | output_guard leakage detection        | Block / redact    |
| Secret leakage in output            | output_guard DLP scan                 | Redact            |
| Abusive session behavior            | risk_engine + policy                  | Restrict / block  |
| Prompt token flooding               | prompt_builder budget check           | Warning + flag    |
| Unauthorized admin access           | _require_admin (X-Admin-Key header)   | HTTP 403          |
