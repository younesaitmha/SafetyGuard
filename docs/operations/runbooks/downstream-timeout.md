# Runbook: downstream timeout

## Symptoms
- upstream 5xx or stub responses increasing
- downstream latency elevated
- client complaints of slow or failed responses

## Possible causes
- downstream LLM service degradation
- network issue
- prompt size growth
- dependency saturation

## Immediate actions
1. inspect downstream timeout rates
2. inspect request sizes and prompt package sizes
3. compare by tenant, route, and model/backend
4. confirm retrieval volume has not unexpectedly increased

## Containment
- reduce retrieval top-k
- disable expensive tools
- shorten timeout only if safe for the client experience
- route to fallback backend if available

## Follow-up
- review prompt growth drivers
- review downstream scaling
- update SLO dashboard if needed
