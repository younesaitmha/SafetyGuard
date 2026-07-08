# Incident response

## Goals

- detect security-relevant events quickly
- preserve forensic context
- contain abuse safely
- restore stable operation
- capture follow-up improvements

## Event sources

- audit bus events
- decision logs
- rate limit signals
- downstream error spikes
- output block and redaction spikes

## Severity guidance

### High severity
- confirmed secret leakage
- cross-tenant leakage
- unsafe tool invocation
- repeated blocked output events involving sensitive material

### Medium severity
- prompt leakage attempts
- repeated denied requests from a subject
- LLM guard degradation with elevated risky traffic

### Low severity
- isolated false positives
- isolated model formatting failures
- minor operational noise without customer impact

## Initial response steps

1. identify trace IDs and affected sessions
2. collect relevant audit and decision log entries
3. determine whether issue is:
   - active abuse
   - policy regression
   - downstream model drift
   - backend integration issue
4. contain if needed:
   - tighten policy
   - disable tools
   - reduce retrieval sensitivity
   - disable affected backend path
5. document impact and follow-up actions

