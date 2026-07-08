# Policy authoring

## Principles
- keep rules explicit and narrow
- use clear, searchable reason codes
- order rules carefully — first match wins
- prefer targeted conditions over broad heuristics
- add tests for every rule change
- bump the policy `version` field on every change

## Current model

Rules are evaluated in order; the first matching rule wins. If no rule matches, `default_decision` is applied.

### Condition keys supported

| Key                          | Matches when                                              |
|------------------------------|-----------------------------------------------------------|
| `missing_permission`         | the given permission is absent from the security context  |
| `input_scan_has_label`       | the input scanner assigned this label                     |
| `input_scan_score_gte`       | the input scan score is >= the given integer              |
| `dlp_has_label`              | the DLP scanner assigned this label                       |
| `dlp_score_gte`              | the DLP scan score is >= the given integer                |
| `classification_label`       | the content classifier assigned this label                |
| `classification_confidence_gte` | classifier confidence >= the given float               |
| `session_risk_state`         | session risk state matches (normal/elevated/restricted/blocked) |
| `step_up_authenticated`      | step_up_authenticated equals the given boolean            |

Multiple keys in one condition are ANDed together.

### Decision fields

| Field                   | Values                                         |
|-------------------------|------------------------------------------------|
| `action`                | `allow` / `allow_with_restrictions` / `deny` / `challenge` |
| `reason_codes`          | list of strings (logged, returned in HTTP detail) |
| `disable_tools`         | `true` / `false`                               |
| `allow_retrieval`       | `true` / `false`                               |
| `max_context_sensitivity` | `public` / `internal` / `confidential` / `restricted` |
| `require_human_approval`| `true` / `false`                               |
| `response_mode`         | `normal` / `guarded` / `restricted`            |

## Classification labels available for policy conditions

```
benign
suspicious
prompt_injection
jailbreak_attempt
secret_exfiltration_intent
exploit_or_malware_intent
sensitive_data_submission
```

## Input scan labels available for policy conditions

```
prompt_injection
prompt_leakage
secret_exfiltration
exploit_intent
jailbreak_attempt
obfuscation
```

## Adding a new rule

1. Identify the signal (input scan label, classification label, DLP label, session state)
2. Write the condition using supported keys above
3. Choose the most conservative action that still serves legitimate users
4. Add a specific `reason_code` (format: `UPPER_SNAKE_CASE`)
5. Add a unit test in `tests/test_policy_service.py`
6. Stage in non-production and monitor deny/restrict rates
7. Bump the policy `version` field

## Recommended change process

1. Propose rule with written rationale
2. Add / update tests
3. Peer-review for false positive risk
4. Stage in non-production, run representative traffic
5. Monitor deny rate for 24 h post-deploy
6. Rollback if false positive rate exceeds threshold (see runbook)