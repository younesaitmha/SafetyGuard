# Monitoring

## Objectives

Monitoring should answer:
- is the gateway up?
- are requests succeeding?
- are denies or output blocks spiking?
- are downstream dependencies healthy?
- is the guard model degraded?

## Key signals

### Availability
- health check success
- readiness success
- request success rate
- 4xx and 5xx rates

### Security
- policy deny count
- policy challenge count
- high-risk input scan count
- DLP detection count
- blocked tool count
- output redact count
- output block count

### Performance
- end-to-end request latency
- stage timings
- downstream timeout rate
- guard model timeout rate
- retrieval latency
- tool mediation latency

### Quality
- fallback rate for LLM guard
- malformed LLM guard output rate
- retrieval filtered-out ratio
- false positive review signals if tracked externally

## Recommended future instrumentation
- Prometheus metrics
- OpenTelemetry traces
- alert routing to incident channels
