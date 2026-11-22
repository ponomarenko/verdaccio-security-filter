# Security Policy

## Supported versions

Only the latest released version of `verdaccio-security-filter` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report it privately through GitHub:
[Report a vulnerability](https://github.com/ponomarenko/verdaccio-security-filter/security/advisories/new).

Include:

- the affected version and your Verdaccio version;
- steps or a config to reproduce;
- the impact you expect (for example, a blocked package that still gets served).

You should get a first reply within 7 days. Once a fix is released, a GitHub Security Advisory is published and you are credited unless you ask otherwise.

## Scope

This plugin is a filter, so a bypass counts as a vulnerability: any way to download a package, version or tarball that the configured rules should block.
