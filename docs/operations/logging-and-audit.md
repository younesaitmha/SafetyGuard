# Logging and audit

## Log categories

### Application logs
General service lifecycle and operational events.

### Decision logs
Structured per-request records including:
- trace ID
- session ID
- request summary
- component decisions
- timings
- final outcome

### Audit events
Security-relevant events such as:
- denied requests
- challenged requests
- DLP detections
- blocked tools
- output redactions
- output blocks

## Best practices

- redact sensitive fields before external export
- preserve trace ID and session ID
- define retention rules by sensitivity
- separate audit streams from debug logs
- protect integrity of audit logs if required by policy
