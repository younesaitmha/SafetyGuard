# Runbook: high deny rate

## Symptoms
- sudden spike in HTTP 403 responses
- increased policy deny audit events
- repeated deny reason codes for the same pattern

## Possible causes
- active abuse campaign
- policy regression
- malformed client rollout
- identity/permission regression

## Immediate actions
1. identify top deny reason codes
2. segment by subject, tenant, and source IP
3. compare recent deploys or policy changes
4. check auth/permission issuance changes
5. confirm whether traffic is malicious or broken but legitimate

## Containment options
- tighten rate limits for abusive clients
- temporarily disable risky features
- rollback recent policy change if false positive regression is confirmed

## Follow-up
- capture representative traces
- update tests if policy was changed
- document resolution and lessons learned
