# Security Policy

## Authorised use

Security Lab is an autonomous security-testing tool. **Use it only against systems you own or have explicit written authorisation to test**, and only within the scope, time window and techniques that authorisation covers. You are responsible for staying inside it. Unauthorised probing is a criminal offence in most jurisdictions and can create civil liability.

The full notice is in [README.md § Authorised use only](README.md#authorised-use-only). It describes acceptable use; it does not modify the rights granted under the Apache-2.0 licence.

## Reporting a Vulnerability

Please do not open a public issue for a security vulnerability.

Report privately through GitHub's private vulnerability reporting on this repository (Security tab → "Report a vulnerability"). If you cannot use that channel, open an issue asking for a private contact address and do not include the details.

Include, where you can:

- what you found and why it matters
- the affected package, file, or command
- reproduction steps or a minimal proof of concept
- the version/commit you tested
- any suggested fix or mitigation

Do not include real credentials, customer data, or third-party data in a report.
Redact what you need to, and say that you did.

## What to Expect

- The maintainer aims to acknowledge your report within a few days.
- We will confirm the issue, agree a disclosure timeline with you, and credit
  you unless you ask us not to.
- Please give us a reasonable window to ship a fix before publishing details.

## Especially Welcome: Reports About the Tool's Own Safety Controls

Reports about the safety controls are the most valuable kind. That includes
anything that lets the lab escape its own bounds, for example:

- bypassing the authorization gate for live, hosted, or destructive probes
- defeating the kill switch, destructive-command filter, or sandbox isolation
- leaking secrets or environment variables into evidence, logs, or reports
- prompt injection or tool misuse that subverts the planner/judge contracts
- producing findings that are not backed by the evidence stream

If you can make the tool do something it promises not to do, we want to know.

## Supported Versions

Security fixes target the `main` branch. There are no maintained release
branches at this time.
