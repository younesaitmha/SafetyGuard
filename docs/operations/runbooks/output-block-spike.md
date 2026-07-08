# Runbook: output block spike

## Symptoms
- sudden increase in output guard block events
- downstream responses failing with 502 from output protection
- leakage-related reason codes increasing

## Possible causes
- downstream model drift
- prompt builder regression
- retrieval content shift
- new unsafe retrieved documents
- LLM guard model behavior change

## Immediate actions
1. inspect output guard reason codes
2. inspect affected trace IDs
3. compare recent prompt, policy, or model changes
4. check whether issue is isolated to one tenant or use case

## Containment options
- reduce retrieval sensitivity cap
- disable tool paths temporarily
- switch to restricted response mode
- rollback recent downstream model change

## Follow-up
- add regression tests for the triggering pattern
- review retrieved/tool-derived context sources
- review downstream system prompt changes
