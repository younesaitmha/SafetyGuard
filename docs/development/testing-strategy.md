
# Testing strategy

## Test layers

### Unit tests

Validate isolated behavior of:

- scanners
- classifiers
- policy service
- tool gateway
- output guard
- retrieval gateway

### API tests

Validate:

- endpoint behavior
- auth handling
- deny/challenge/allow flows
- redaction and blocking behavior

### Recommended future tests

- integration tests with mocked downstream services
- adversarial prompt suites
- policy regression packs
- load tests
- chaos testing for degraded dependencies

## Principles

- test both positive and negative paths
- include regression tests for security bugs
- test policy-sensitive logic with clear fixtures
