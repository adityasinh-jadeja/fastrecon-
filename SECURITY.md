# Security Policy

## Authorized Use Only

**FastRecon is intended exclusively for authorized security testing.**

You **must** have explicit written permission from the owner of any target system before running FastRecon against it. Unauthorized scanning of systems you do not own or have permission to test is **illegal** and may violate:

- The **Computer Fraud and Abuse Act (CFAA)** (United States)
- The **Computer Misuse Act** (United Kingdom)
- Equivalent legislation in your jurisdiction

The authors of FastRecon assume **no liability** for misuse of this tool. You are solely responsible for ensuring your use complies with all applicable laws and regulations.

---

## Built-in Safety Measures

FastRecon includes the following safety mechanisms:

| Measure | Description |
|---|---|
| **SSRF Target Validation** | Targets are validated against a domain allowlist pattern. Internal hostnames (`localhost`, `.local`, `.internal`, `.corp`), IP addresses, and domains resolving to private/reserved IPs (including the AWS metadata endpoint `169.254.169.254`) are blocked. |
| **API Key Authentication** | All `/api/*` endpoints require an API key via `X-API-Key` header or `api_key` query parameter. Keys are generated automatically if not set via the `FASTRECON_API_KEY` environment variable. |
| **No Credential Storage** | FastRecon does not store or transmit any credentials. Webhook URLs are validated against known prefixes before use. |

---

## Reporting a Vulnerability

If you discover a security vulnerability in FastRecon itself, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the maintainer directly (see the repository profile for contact information).
3. Include a clear description of the vulnerability and steps to reproduce it.
4. Allow reasonable time for a fix before public disclosure.

---

## Scope

This security policy covers the FastRecon application code. It does **not** cover:

- Third-party dependencies (report those to the respective maintainers)
- Targets you scan with FastRecon (those are your responsibility)
- Infrastructure you deploy FastRecon on (secure your own servers)
