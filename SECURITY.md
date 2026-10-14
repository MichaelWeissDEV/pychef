# Security Policy

## Supported Versions

Security fixes and hardening updates are provided for the latest published releases.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities in a public issue or discussion forum. Please report security issues privately via GitHub's Security Advisory disclosure:

<https://github.com/MichaelWeissDEV/pychef/security/advisories/new>

Please include:
1. Affected PyChef versions.
2. A minimal, reproducible script demonstrating the behavior.
3. Attack vectors, threat model, and potential impact.
4. Suggested fixes or mitigations (if known).

Reports will be reviewed and acknowledged promptly.

---

## Security Model and Architecture

PyChef is designed to process untrusted data, recipes, and inputs safely in multi-tenant, server, and automation environments.

### 1. SSRF & Network Protection

- **Safe Defaults**: Network operations (`HTTP request`) are disabled by default under `ExecutionPolicy.safe()`.
- **SSRF Defense**: When network access is enabled, private, loopback, link-local, multicast, and non-global IP ranges are blocked by default.
- **DNS Rebinding & DNS Pinning**: All resolved IP addresses are validated against the network policy before connecting, and socket connections are pinned directly to validated IP addresses.
- **IPv4-Mapped IPv6 Unwrapping**: IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`), 6to4 addresses (`2002::/16`), and NAT64 addresses (`64:ff9b::/96`) are unwrapped and checked against IPv4 subnet and host deny lists.
- **Strict Deny-Over-Allow**: Denied hosts and denied subnets always take precedence over allowed targets.

### 2. HTTP Redirects and Credential Confidentiality

- **Origin Boundary Enforcement**: Requests following HTTP redirects (`301`, `302`, `303`, `307`, `308`) verify origin consistency (`scheme`, `normalized host`, `port`).
- **Automatic Sensitive Header Stripping**: Any redirect across origins immediately strips sensitive headers including `Authorization`, `Proxy-Authorization`, `Cookie`, `Cookie2`, and any user-configured `sensitive_headers`.
- **Target Re-evaluation**: Every hop in a redirect chain is independently re-evaluated against the active `NetworkPolicy` prior to making a connection.

### 3. Resource Management & DoS Prevention

- **Cooperative Budget Checks**: Execution budgets for input size (`max_input_bytes`), output size (`max_output_bytes`), memory size (`max_memory_bytes`), execution steps (`max_steps`), recursion depth (`max_recursion_depth`), and branches (`max_branches`) are continuously accounted.
- **Pipeline Tracing Limits**: `max_trace_bytes` bounds the accumulated trace buffer, charging actually stored preview data without allowing circular structures or unbounded memory growth.
- **Isolated Process Execution**: `IsolatedWorker` executes operations inside a subprocess spawned with `multiprocessing.get_context("spawn")`. On Linux platforms supporting `resource.RLIMIT_AS` or `resource.RLIMIT_DATA`, hard OS memory limits (`hard_memory_limit_bytes`) can be enforced.

### 4. Error Message Confidentiality & Redaction

- Error messages raised during recipe and pipeline execution (`OperationError`, `PyChefError`) are sanitized to scrub sensitive arguments (passwords, keys, tokens, session cookies, IVs) and input values from `exc.message`, `exc.safe_message`, `str(exc)`, `repr(exc)`, and `exc.to_dict()`.
- Unsanitized original exceptions are preserved for internal debugging via standard Python exception chaining (`__cause__`).

### 5. Cryptographic Scope

PyChef provides pure-Python implementations of CyberChef cryptographic operations for compatibility, analysis, forensics, educational, and CTF purposes. They are not intended as audited replacements for production cryptographic storage (such as OpenSSL or libsodium).
