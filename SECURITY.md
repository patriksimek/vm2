# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **vm2**, please **do not create a public issue**.

Instead, use **[GitHub’s private vulnerability reporting feature](https://github.com/patriksimek/vm2/security/advisories/new)** to submit your report securely. This ensures sensitive information is shared privately with the maintainers and not exposed publicly.

Please include as much detail as possible to help us reproduce and assess the issue:
- Steps to reproduce  
- Affected versions  
- Environment and configuration details  
- Potential impact (if known)

## Disclosure Policy

We follow a **responsible disclosure** process:

1. You report the vulnerability privately via GitHub.  
2. We investigate, confirm, and prepare a fix.  
3. Once a fix is released, we’ll credit you (if you wish) in the release notes and security advisory.  
4. Only then will details of the vulnerability be made public.

## Supported Versions

The following versions of **vm2** currently receive security updates:

| Version | Supported | Notes |
|----------|------------|-------|
| 3.x | ✅ | Actively maintained |
| 2.x and older | ❌ | No longer supported |

## Runtime scope

**Report every suspected sandbox escape privately, on any runtime.** The
private reporting process above applies without exception. Do not open a public
issue for an escape because you believe it is Bun-specific.

This matters because the two cases are not reliably distinguishable from the
outside. A primitive that reproduces only under Bun may still have a Node.js
variant that has not been found yet, and establishing that it does not is
maintainer triage work, not something a reporter can be expected to prove.
Routing such a report to a public issue would disclose a supported-runtime
vulnerability before it is fixed.

What differs between runtimes is what happens *after* triage, not how a report
is filed:

- **Node.js** — a confirmed escape is a security advisory, fixed and credited
  through the coordinated-disclosure process.
- **Bun** — Bun is experimental and explicitly not a supported security boundary
  (see the Runtimes section of the README). Once maintainers have confirmed an
  issue is genuinely Bun-only, it is reclassified out of the advisory process and
  handled publicly as an ordinary bug, and the reporter is told that has
  happened.

## Commitment

Security is a top priority for this project. We take all reports seriously and aim to resolve verified issues quickly and transparently, with respect for both reporters and users.

Thank you for helping make **vm2** safer for everyone. 🙏