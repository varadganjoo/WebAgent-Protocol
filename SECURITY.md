# Security Policy

WebAgent Protocol is security-sensitive: it signs commercial statements, gates access to paid back-ends and runs
tools on behalf of language models. Reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/varadganjoo/WebAgent-Protocol/security/advisories/new)
("Security" tab → "Report a vulnerability").

Include the affected version, a description of the issue and its impact, and steps or a test case to
reproduce it. You can expect an acknowledgement within a few days; fixes are released as soon as practical and
credited to the reporter unless you prefer otherwise.

## Scope

In scope: the `wap` package (`wap.spec`, `wap.server`, `wap.client`, `wap.mcp`, `wap.cli`) and the protocol
specification, for example signature or canonicalisation bypasses, proof-of-work forgery or replay, rate-limit
or loop-guard bypasses, SSRF in resolution, session hijacking, or MCP endpoint issues.

Out of scope: the example bakery's business logic, denial of service that requires more resources than the
documented proof-of-work cost model assumes, and vulnerabilities in dependencies (report those upstream; tell
us if we need to bump a version).

## Supported versions

Only the latest release receives security fixes while the project is in the 0.x series.
