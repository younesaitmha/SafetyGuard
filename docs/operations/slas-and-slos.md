# SLAs and SLOs

## Purpose

This document proposes service objectives for production operation.

## Suggested SLOs

### Availability
- gateway availability: 99.9% monthly
- readiness endpoint availability: 99.95% monthly

### Latency
Excluding downstream model generation time:
- p50 gateway overhead: < 50 ms
- p95 gateway overhead: < 150 ms
- p99 gateway overhead: < 300 ms

### Reliability
- policy reload success rate: > 99.9%
- guard model fallback rate: < 2%
- downstream timeout rate: < 1% under normal load

### Security operations
- alerting lag for high-severity security events: < 5 minutes
- start of triage for high-severity events: < 30 minutes

## Notes

These are suggested objectives, not guaranteed contractual commitments. Organizations should adapt them to their own operating model.
