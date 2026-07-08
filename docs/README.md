# SafetyGuard Documentation

This docs set is organized by operational usage and maintained as the single source of truth.

## Start here

- Full map: [INDEX.md](INDEX.md)
- Local setup: [development/local-development.md](development/local-development.md)
- Architecture entry point: [architecture/overview.md](architecture/overview.md)
- Visual architecture: [ARCHITECTURE_VISUAL.md](ARCHITECTURE_VISUAL.md)

## Documentation structure

### Architecture

- [architecture/overview.md](architecture/overview.md)
- [architecture/components.md](architecture/components.md)
- [architecture/trust-boundaries.md](architecture/trust-boundaries.md)
- [architecture/deployment-topology.md](architecture/deployment-topology.md)
- [ARCHITECTURE_VISUAL.md](ARCHITECTURE_VISUAL.md)

### Security

- [security/security-controls.md](security/security-controls.md)
- [security/assumptions-and-limitations.md](security/assumptions-and-limitations.md)
- [security/data-classification.md](security/data-classification.md)
- [security/incident-response.md](security/incident-response.md)

### Operations

- [operations/deployment-checklist.md](operations/deployment-checklist.md)
- [operations/monitoring.md](operations/monitoring.md)
- [operations/logging-and-audit.md](operations/logging-and-audit.md)
- [operations/slas-and-slos.md](operations/slas-and-slos.md)
- Runbooks
  - [operations/runbooks/high-deny-rate.md](operations/runbooks/high-deny-rate.md)
  - [operations/runbooks/output-block-spike.md](operations/runbooks/output-block-spike.md)
  - [operations/runbooks/guard-model-degraded.md](operations/runbooks/guard-model-degraded.md)
  - [operations/runbooks/downstream-timeout.md](operations/runbooks/downstream-timeout.md)
  - [operations/runbooks/policy-rollback.md](operations/runbooks/policy-rollback.md)

### Development

- [development/local-development.md](development/local-development.md)
- [development/policy-authoring.md](development/policy-authoring.md)
- [development/testing-strategy.md](development/testing-strategy.md)
- [development/contributing-guide.md](development/contributing-guide.md)

## Notes

- Historical milestone writeups were removed to keep docs concise and current.
- Configuration defaults are documented in [development/local-development.md](development/local-development.md) and [app/config.py](../app/config.py).
