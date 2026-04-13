# Security Policy

## Supported Versions

Only the latest release is actively supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in ClusterIQ, please report it
responsibly. Do **not** open a public GitHub issue.

1. Email the maintainer directly (see repository contact info).
2. Include a clear description of the vulnerability and reproduction steps.
3. Allow reasonable time for a fix before any public disclosure.

## Scope

ClusterIQ is designed to run locally as a SOC analyst tool. It should
**not** be exposed directly to the internet without additional authentication
and hardening.

- Alert JSON inputs are parsed server-side — do not accept untrusted input
  from external sources in production.
- The SQLite database (`clusteriq.db`) contains saved sessions — ensure it is
  not readable by untrusted users.
- The Flask development server (`debug: true`) must never be used in production.

## Out of Scope

- Issues in third-party dependencies (report to the respective project).
- Issues requiring physical access to the host machine.
