# Contributing

Thanks for helping improve verdaccio-security-filter! Bug reports, ideas and pull requests are welcome.

## Reporting issues

- **Bugs and feature requests:** open a [GitHub issue](https://github.com/ponomarenko/verdaccio-security-filter/issues). For a bug, include your plugin and Verdaccio versions, the relevant config and the log output.
- **Security vulnerabilities:** do not open a public issue. Report them privately through [GitHub Security Advisories](https://github.com/ponomarenko/verdaccio-security-filter/security/advisories/new).

## Development setup

Requires Node.js 22 or newer.

```bash
git clone https://github.com/ponomarenko/verdaccio-security-filter.git
cd verdaccio-security-filter
npm install
```

Useful scripts:

| Command | What it does |
|---|---|
| `npm run build` | Compile TypeScript into `build/` |
| `npm run lint` | Run ESLint on `src/` |
| `npm test` | Run unit tests |
| `npm run test:coverage` | Run unit tests with coverage |
| `npm run test:e2e` | Build and run end-to-end tests |
| `npm run debug:build` | Build and `npm link` the plugin into a local Verdaccio |

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each change focused on one thing, and add or update tests for it.
3. Make sure `npm run lint` and `npm test` pass.
4. Update `README.md` if you change configuration or behaviour.
5. Open a pull request that explains what changed and why.

### Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Releases and the changelog are generated from them, so the type matters:

- `feat:` adds a feature (minor release)
- `fix:` fixes a bug (patch release)
- `docs:`, `test:`, `chore:`, `refactor:` do not trigger a release
- add `!` after the type (e.g. `feat!:`) for a breaking change

Example: `fix(cve): handle advisories without a CVSS score`.

## Code of Conduct

By taking part in this project you agree to follow its [Code of Conduct](CODE_OF_CONDUCT.md).
