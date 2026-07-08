# Data classification

## Purpose

This document defines the sensitivity model used in policy and retrieval mediation.

## Sensitivity levels

### Public

Information safe for broad exposure.

### Internal

General internal information that should remain within the organization.

### Confidential

Sensitive internal data with restricted business exposure.

### Restricted

Highly sensitive data with strict access controls.

## Usage in the gateway

Sensitivity is used to:

- constrain retrieval results
- constrain tool usage
- shape policy decisions
- reduce exposed context in guarded modes

## Trust vs sensitivity

These are different concepts:

- **Trust** describes whether content should be considered authoritative
- **Sensitivity** describes the impact if content is exposed

Example:

- a retrieved confidential document may be **semi-trusted** and **confidential**
- user input is **untrusted**, but may itself contain **restricted** data
