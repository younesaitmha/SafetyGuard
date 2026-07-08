# Runbook: guard model degraded

## Symptoms

- elevated LLM guard timeout rate
- elevated fallback rate
- malformed LLM guard output increase
- slower overall request latency

## Possible causes

- OSS guard endpoint unavailable
- model overloaded
- incompatible model update
- networking or DNS issue

## Immediate actions

1. verify guard endpoint health
2. inspect timeout/error metrics
3. confirm deterministic fallback path is active
4. decide whether to disable LLM guard temporarily

## Containment

- disable model-assisted guard if it is causing broader instability
- rely on deterministic scanners and policy until recovery
- scale or restart guard backend if applicable

## Recovery validation

- fallback rate returns to expected level
- request latency normalizes
- no increase in missed security detections from sampled review
