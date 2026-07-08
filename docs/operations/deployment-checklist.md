# Deployment checklist

## Pre-deployment

- [ ] policy bundle reviewed and version bumped
- [ ] environment variables configured (see local-development.md for full list)
- [ ] downstream URLs validated (`APP_SECURITY_GATEWAY_URL`, `APP_RETRIEVAL_BACKEND_URL`)
- [ ] retrieval backend validated (tenant tagging, sensitivity tagging)
- [ ] guard model endpoint validated (if `APP_GUARD_LLM_ENABLED=true`)
- [ ] tests passing (`uv run pytest`)
- [ ] coverage reviewed (`uv run pytest --cov=app`)
- [ ] admin endpoint exposure reviewed

## Security hardening (required before production)

- [ ] `APP_JWT_VERIFY_SIGNATURE=true` configured
- [ ] `APP_JWKS_URL` points to your identity provider JWKS endpoint
- [ ] `APP_JWT_ISSUER` and `APP_JWT_AUDIENCE` match your token issuer
- [ ] `APP_ADMIN_API_KEY` set to a strong random secret (replace default)
- [ ] `APP_MAX_PROMPT_CHARS` tuned to your downstream model context window
- [ ] privileged role ingress policy defined (network / API gateway level)
- [ ] log redaction strategy defined (avoid logging raw user content)
- [ ] persistent session storage selected and configured
- [ ] persistent audit sink selected (Kafka, Splunk, CloudWatch, etc.)
- [ ] secrets management configured (vault, secrets manager, etc.)

## New controls to verify

- [ ] jailbreak detection patterns reviewed and tuned for your use case
- [ ] obfuscation detection patterns reviewed (Base64 / unicode / hex thresholds)
- [ ] indirect RAG injection filter active and injection_filtered_count monitored
- [ ] tool argument injection scan tested with adversarial inputs
- [ ] attachment DLP: confirm client sends `content` field for text attachments
- [ ] token budget (`APP_MAX_PROMPT_CHARS`) validated against downstream model limits

## Operations

- [ ] health/readiness integrated with platform load balancer
- [ ] monitoring dashboards created (deny rate, DLP detection, output blocks)
- [ ] alerts configured (high deny rate, output block spike, guard model degraded)
- [ ] rollback procedure documented and tested
- [ ] on-call ownership defined
