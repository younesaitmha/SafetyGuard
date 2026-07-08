# Runbook: policy rollback

## Use when
- a recent policy change causes false positives
- legitimate traffic is denied or restricted unexpectedly
- emergency restoration is needed

## Procedure
1. identify current deployed policy version
2. identify last known good policy version
3. reload or redeploy the last known good bundle
4. validate:
   - health
   - representative requests
   - deny rate
   - audit events
5. notify stakeholders of rollback and investigation start

## Post-rollback actions
- diff the policies
- add regression tests for the affected scenario
- document root cause
- reintroduce corrected rule through normal review
