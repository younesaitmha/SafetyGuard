# Deployment topology

## Recommended topology

```text
                   +----------------------+
                   |   Identity Provider  |
                   |   / JWKS Endpoint    |
                   +----------+-----------+
                              |
                              v
+---------+        +--------------------------+        +----------------------+
| Client  +------->+ Secure LLM API Gateway   +------->+ Downstream LLM/Agent |
+---------+        +-----------+--------------+        +----------------------+
                                |        |
                                |        +------------------> Tool Backends
                                |
                                +---------------------------> Retrieval Backend
                                |
                                +---------------------------> Audit / SIEM / Logs
