# Verdaccio Security Filter Plugin

Advanced security filter plugin for Verdaccio with **dual-layer protection architecture** combining middleware interception and metadata filtering for comprehensive package security.

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)
[![npm version](https://img.shields.io/npm/v/verdaccio-security-filter.svg)](https://www.npmjs.com/package/verdaccio-security-filter)
[![npm downloads](https://img.shields.io/npm/dm/verdaccio-security-filter.svg)](https://www.npmjs.com/package/verdaccio-security-filter)
[![CI](https://github.com/ponomarenko/verdaccio-security-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/ponomarenko/verdaccio-security-filter/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen)](./tests)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)]()
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)]()
[![Verdaccio](https://img.shields.io/badge/Verdaccio-6.x%20%7C%207.x-orange)]()

## 🏗️ Dual-Layer Architecture

This plugin implements **two independent security layers** for complete protection:

### Layer 1: Middleware (Always Active)
- ✅ **Whitelist/Blacklist filtering** - Control allowed packages
- ✅ **Pattern-based blocking** - Block by regex patterns
- ✅ **Scope control** - Filter by npm scopes
- ✅ **Tarball interception** - Block downloads even if metadata cached
- ✅ **Version blocking** - Block specific versions/ranges

### Layer 2: Filter Metadata (Deep Inspection)
- ✅ **CVE vulnerability scanning** - OSV API integration
- ✅ **License compliance** - SPDX validation
- ✅ **Package age verification** - Block newly created packages
- ✅ **Full metadata access** - Deep package inspection

> **Why two layers?** Middleware catches everything at HTTP level, while filter_metadata provides deep inspection when metadata is available. See [DUAL-LAYER-ARCHITECTURE.md](./DUAL-LAYER-ARCHITECTURE.md) for details.

## 🚀 Features

### ✅ Implemented Features

#### 🔒 Version Management
- **Version Range Blocking** - Block vulnerable versions using semver ranges
  - Matching versions are hidden from metadata and their tarballs return 403, so npm resolves to the highest allowed version
- **Exact Version Blocking** - Block specific package@version combinations
- **Semver Support** - Full semver syntax (`^`, `~`, `>`, `>=`, `<`, `<=`, `x`, `*`)

#### 🛡️ CVE & Vulnerability Scanning
- **OSV Database Integration** - Automatic vulnerability scanning via [OSV API](https://osv.dev/)
- **Severity Filtering** - Filter by severity: `low`, `medium`, `high`, `critical`
- **Auto-Block Vulnerable Versions** - Remove versions with known CVEs from metadata
- **Caching System** - One OSV lookup per package, cached per package with a configurable refresh interval

#### ⚖️ License Compliance
- **License Filtering** - Enforce license policies with allowed/blocked lists
- **SPDX Expression Support** - Parse complex license expressions (OR/AND operators)
- **Require License** - Option to block packages without license information
- **Pre-defined Lists** - Common open-source and copyleft license collections

#### 🔐 Access Control
- **Whitelist Mode** - Only explicitly approved packages allowed
- **Pattern-based Whitelisting** - Regex patterns for package approval
- **Version Constraints** - Lock approved packages to specific version ranges
- **Scope Control** - Whitelist/blacklist package scopes (@scope/package)

#### 📊 Monitoring & Observability
- **Enhanced Logging** - Configurable log levels (`debug`, `info`, `warn`, `error`)
- **Metrics Collection** - Track security events (blocks with their reason, author blocks)
- **Security Audit Trail** - Detailed logging of all security decisions
- **Customizable Output** - Log to stdout or file in JSON format

#### 🔍 Additional Security
- **Pattern-based Blocking** - Block suspicious packages by name patterns (regex)
- **Package Age Filtering** - Block packages or versions that are too new (protect against newly published malicious packages)
  - **Minimum Package Age** - Require packages to exist for a minimum number of days
  - **Minimum Version Age** - Require specific versions to exist for a minimum number of days
  - **Warn-Only Mode** - Log warnings without blocking
- **Author Filtering** - Block packages based on author information
  - **Block by Author Name** - Block specific author names or patterns
  - **Block by Email** - Block specific email addresses or patterns
  - **Block by Email Domain** - Block entire email domains (e.g., `.ru`, `yandex.ru`)
  - **Block by Region** - Block authors from specific regions based on email domains
  - **Maintainer & Contributor Checking** - Validates all package maintainers and contributors
  - **Warn-Only Mode** - Log warnings without blocking
- **Middleware Interception** - HTTP middleware that blocks tarball downloads for blocked packages
  - Prevents blocked packages from being installed as dependencies
  - Intercepts requests to `/:package/-/:filename.tgz` routes
  - Returns 403 Forbidden with detailed error messages
- **Metadata Validation** - Verify package integrity and detect dangerous characters

#### ⚙️ Reliability & Error Handling
- **Fail-Safe/Fail-Closed Configuration** - Choose error handling strategy
  - **Fail-Open (Default)** - Allow packages on errors (availability priority)
  - **Fail-Closed** - Block packages on errors (security priority)
  - **Granular Control** - Different strategies for filter, CVE, and license checks
- **Retry Logic** - Automatic retry with exponential backoff for API calls
  - 3 retries with increasing delays (1s, 2s, 4s)
  - Rate limiting detection and handling
  - Request timeout protection (10s)
- **Resilient CVE Scanning** - Production-ready vulnerability checking
  - Network failure recovery
  - API timeout protection
  - Graceful degradation on errors

### 🔮 Planned Features (Roadmap)

#### Phase 3: Advanced Security
- [ ] **Dependency Depth Limiting** - Limit dependency tree depth and total count
- [ ] **Circular Dependency Detection** - Block packages with circular dependencies
- [ ] **Rate Limiting** - Detect and block suspicious download patterns
- [ ] **Typosquatting Detection** - AI-powered detection of similar package names
- [ ] **Package Signing Verification** - PGP signature validation
- [ ] **Custom Validation Scripts** - Execute custom security checks

#### Phase 4: Enterprise Features
- [ ] **Integration with Security Scanners** - npm audit, Snyk API, Sonatype
- [ ] **Webhook Notifications** - Real-time alerts for security events
- [ ] **Web Dashboard** - Visual interface for security analytics
- [ ] **Email/Slack Notifications** - Alert channels for critical events
- [ ] **Audit Reports** - Generate compliance reports (PDF, CSV, JSON)
- [ ] **Multi-Registry Support** - Fallback to other registries
- [ ] **ML-based Anomaly Detection** - Machine learning for threat detection

#### Phase 5: Developer Experience
- [x] **Dry Run Mode** - Test rules without actually blocking (`dryRun: true`)
- [ ] **Auto-approve Criteria** - Automatic approval based on npm stats (downloads, stars)
- [ ] **CLI Tool** - Command-line interface for rule management
- [ ] **Visual Studio Code Extension** - IDE integration
- [ ] **GitHub Action** - CI/CD integration

## 📦 Installation

### Prerequisites

- Node.js >= 22.0.0
- Verdaccio >= 5.0.0

```bash
npm install -g verdaccio
```

### Install Plugin

```bash
# Install from npm (when published)
npm install -g verdaccio-security-filter

# Or install locally for development
git clone https://github.com/ponomarenko/verdaccio-security-filter.git
cd verdaccio-security-filter
npm install
npm run build
npm link
```

## 🔧 How It Works

The plugin works in two layers. Configure both: the same settings go under `filters` and under `middlewares`.

### Layer 1: Metadata Filtering (`filter_metadata`)
Runs inside Verdaccio when package metadata is read, so it sees every version:
1. Removes versions blocked by `blockedVersions`, `versionRangeRules` and `whitelist.versions`
2. Removes versions rejected by the CVE, license, age and author checks
3. Blocks the package as a whole when no version is left, or when the package itself is not allowed

npm then resolves ranges against the versions that are left.

### Layer 2: Middleware (`register_middlewares`)
Runs first on every `GET` request:
1. Blocks packages by name: whitelist, patterns, scopes
2. Blocks tarball downloads of blocked versions, even if a client has stale metadata or a lockfile
3. Turns a whole-package block from layer 1 into an HTTP error that carries the reason

### What a client sees

A removed version is simply missing from the metadata. A blocked package or tarball is answered with **403 Forbidden**, and the reason is in the `error` field, which npm prints:

```
npm install hawk
npm error code E403
npm error 403 403 Forbidden - GET http://localhost:4873/hawk - Package blocked by security filter: Package is not in whitelist
```

```json
{
  "error": "Package blocked by security filter: License 'GPL-3.0' is not in allowed list",
  "package": "some-package",
  "reason": "License 'GPL-3.0' is not in allowed list",
  "security": { "blocked": true, "reason": "...", "plugin": { "name": "verdaccio-security-filter", "version": "..." } },
  "timestamp": "2026-01-15T10:30:00.000Z"
}
```

The 403 for packages blocked in layer 1 (CVE, license, age, author, fail-closed errors) needs the middleware. With only `filters` configured, such a package is returned with an empty version list and npm reports "No versions available" without a reason.

## ⚙️ Configuration

### Quick Start (Middleware Only)

Minimal configuration using only Layer 1 (Middleware):

```yaml
middlewares:
  security-filter:
    enabled: true
    mode: whitelist
    whitelist:
      packages:
        - lodash
        - express
      patterns:
        - "^@types/.*"
```

### Full Protection (Dual-Layer)

**Recommended:** Use both layers for maximum security:

```yaml
# Enable filter_metadata (Layer 2)
packages:
  '@*/*':
    access: $all
    publish: $authenticated
    proxy: npmjs
    storage: security-filter  # Enable Layer 2!

  '**':
    access: $all
    publish: $authenticated
    proxy: npmjs
    storage: security-filter  # Enable Layer 2!

# Configure security filter
middlewares:
  security-filter:
    enabled: true

    # Layer 1: Basic filtering (Middleware)
    mode: whitelist
    whitelist:
      packages: [lodash, express]
      patterns: ["^@types/.*"]

    blockedVersions:
      - "lodash@4.17.20"

    # Layer 2: Deep inspection (filter_metadata)
    cveCheck:
      enabled: true
      autoBlock: true
      severity: [critical, high]

    licenses:
      allowed: [MIT, Apache-2.0, BSD-3-Clause]

    packageAge:
      enabled: true
      minPackageAgeDays: 7
```

### Advanced Configuration with CVE Scanning

```yaml
# Layer 1: Metadata filtering
filters:
  security-filter:
    enabled: true

    # CVE vulnerability scanning
    cveCheck:
      enabled: true
      databases:
        - osv
      severity:
        - high
        - critical
      autoBlock: true
      updateInterval: 24          # hours
      cacheDir: ./.security-cache

    # License compliance
    licenses:
      allowed:
        - MIT
        - Apache-2.0
        - BSD-3-Clause
      blocked:
        - GPL-3.0
        - AGPL-3.0
      requireLicense: true

    # Package age filtering
    packageAge:
      enabled: true
      minPackageAgeDays: 7       # Packages must be at least 7 days old
      minVersionAgeDays: 3       # Versions must be at least 3 days old
      warnOnly: false            # Block instead of just warning

    # Version range rules
    versionRangeRules:
      - package: lodash
        range: "<4.17.21"
        strategy: block
        reason: "CVE-2021-23337: Command injection"

      - package: minimist
        range: "<1.2.6"
        strategy: block
        reason: "CVE-2021-44906: Prototype pollution"

# Layer 2: Middleware interception
middlewares:
  security-filter:
    enabled: true
```

### Enterprise Whitelist Mode

```yaml
# Layer 1: Metadata filtering
filters:
  security-filter:
    enabled: true

    # Only approved packages allowed
    mode: whitelist

    whitelist:
      packages:
        - lodash
        - express
        - react
      patterns:
        - "^@mycompany/.*"
        - "^@types/.*"
      versions:
        lodash: "^4.17.21"
        express: "^4.18.0"

    # Enhanced logging
    logger:
      level: info
      enabled: true
      includeTimestamp: true

    # Metrics for analytics
    metrics:
      enabled: true
      output: file
      filePath: ./security-metrics.json

# Layer 2: Middleware interception
middlewares:
  security-filter:
    enabled: true
```

### High Security Configuration

```yaml
# Layer 1: Metadata filtering
filters:
  security-filter:
    enabled: true
    mode: whitelist

    whitelist:
      packages:
        - lodash
        - axios
      versions:
        lodash: "4.17.21"    # Lock to exact version
        axios: "1.6.0"

    cveCheck:
      enabled: true
      databases: [osv]
      severity: [low, medium, high, critical]  # Block ALL
      autoBlock: true
      updateInterval: 6                         # Check every 6 hours

    licenses:
      allowed: [MIT, Apache-2.0, BSD-3-Clause]
      blocked: [GPL-3.0, AGPL-3.0, LGPL-3.0]
      requireLicense: true

    logger:
      level: debug             # Log everything
      enabled: true
      includeTimestamp: true

    metrics:
      enabled: true
      output: file
      filePath: /var/log/verdaccio/security-metrics.jsonl

# Layer 2: Middleware interception
middlewares:
  security-filter:
    enabled: true
```

## 📚 Configuration Reference

### Main Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mode` | `string` | `blacklist` | Filter mode: `blacklist` or `whitelist` |
| `dryRun` | `boolean` | `false` | Log and record every decision, but block nothing. See [Dry-run mode](#dry-run-mode) |
| `blockedVersions` | `string[]` | `[]` | List of `package@version` to block |
| `blockedPatterns` | `string[]` | `[]` | Regex patterns for package names |
| `allowedScopes` | `string[]` | `[]` | Allowed package scopes |
| `blockedScopes` | `string[]` | `[]` | Blocked package scopes |

### Dry-run mode

Set `dryRun: true` to see what a rule set would do before enforcing it. Put it in both the `filters` and the `middlewares` block, like the rest of the configuration.

```yaml
dryRun: true
```

While it is on:

- every check runs as usual, including CVE lookups
- nothing is blocked: metadata is served unchanged and every tarball can be downloaded
- each decision is logged at `warn` with a `[DRY RUN]` marker, followed by a summary such as `lodash: would remove 115 of 117 version(s)`
- metrics events carry `"dryRun": true`
- one warning at start-up says that dry-run is active

Recommended before turning on `cveCheck.autoBlock`, a license policy or the author filter on a registry that is already in use.

### CVE Check Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cveCheck.enabled` | `boolean` | `false` | Enable CVE scanning |
| `cveCheck.databases` | `string[]` | `['osv']` | Vulnerability databases. Only `osv` is implemented; it already includes GitHub Security Advisories |
| `cveCheck.severity` | `string[]` | `['high', 'critical']` | Severity levels to check |
| `cveCheck.autoBlock` | `boolean` | `false` | Remove vulnerable versions from metadata (whole package blocked if every version is vulnerable) |
| `cveCheck.updateInterval` | `number` | `24` | How long a package's vulnerability data is cached (hours) |
| `cveCheck.cacheDir` | `string` | `./.security-cache` | Cache directory path |

> **Note on removed versions and dist-tags:** whenever a check removes versions (CVE `autoBlock`, license, author, age, version rules, `whitelist.versions`), the other versions stay installable. The plugin drops every dist-tag that points to a removed version. Verdaccio then points `latest` at the highest version that is left (verified with Verdaccio 6.2), so `npm install <pkg>` keeps working. Other dist-tags that pointed to a removed version are gone.

> **When OSV is unreachable:** a lookup gets one retry with a 5 second timeout each. After a failure the same package is not looked up again for 60 seconds. Previously cached data, even if older than `updateInterval`, keeps being used. With no cached data, `errorHandling.onCveCheckError` decides: `fail-open` serves the package unchecked, `fail-closed` blocks it.

### License Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `licenses.allowed` | `string[]` | `[]` | Allowed license list |
| `licenses.blocked` | `string[]` | `[]` | Blocked license list |
| `licenses.requireLicense` | `boolean` | `true` with `allowed`, otherwise `false` | Reject versions without a license field |

The license check runs when `licenses.allowed` or `licenses.blocked` is not empty, or `licenses.requireLicense` is `true`. Every version is checked: versions with a rejected license are removed from the metadata, and the package is blocked as a whole only when no version is left.

### Whitelist Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `whitelist.packages` | `string[]` | `[]` | Approved package names |
| `whitelist.patterns` | `string[]` | `[]` | Regex patterns for approval |
| `whitelist.versions` | `object` | `{}` | Version constraints per package |

### Logger Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `logger.level` | `string` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logger.enabled` | `boolean` | `true` | Enable logging |
| `logger.includeTimestamp` | `boolean` | `false` | Include timestamps in logs |

### Metrics Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `metrics.enabled` | `boolean` | `false` | Enable metrics collection |
| `metrics.output` | `string` | `stdout` | Output: `stdout` or `file` |
| `metrics.filePath` | `string` | `./security-metrics.json` | Metrics file path |

### Package Age Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `packageAge.enabled` | `boolean` | `false` | Enable package age filtering |
| `packageAge.minPackageAgeDays` | `number` | `0` | Minimum age for packages (days) |
| `packageAge.minVersionAgeDays` | `number` | `undefined` | Minimum age for versions (days) |
| `packageAge.warnOnly` | `boolean` | `false` | Only warn, don't block |

### Author Filter Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `authorFilter.enabled` | `boolean` | `false` | Enable author filtering |
| `authorFilter.blockedAuthors` | `string[]` | `[]` | List of author names to block |
| `authorFilter.blockedAuthorPatterns` | `string[]` | `[]` | Regex patterns for author names |
| `authorFilter.blockedEmails` | `string[]` | `[]` | List of email addresses to block |
| `authorFilter.blockedEmailPatterns` | `string[]` | `[]` | Regex patterns for author emails |
| `authorFilter.blockedEmailDomains` | `string[]` | `[]` | Email domains to block (e.g., `.ru`, `yandex.ru`) |
| `authorFilter.blockedRegions` | `string[]` | `[]` | Region codes to block (`ru`, `cn`, `by`, `kp`, `ir`, `sy`, `cu`, `sd`) |
| `authorFilter.requireVerifiedEmail` | `boolean` | `false` | Require author email information |
| `authorFilter.warnOnly` | `boolean` | `false` | Only warn, don't block |

Every version is checked against the author rules: versions published by a blocked author are removed from the metadata, and the package is blocked as a whole only when no version is left.

### Error Handling Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `errorHandling.onFilterError` | `'fail-open' \| 'fail-closed'` | `'fail-open'` | Strategy when filter errors occur |
| `errorHandling.onCveCheckError` | `'fail-open' \| 'fail-closed'` | `'fail-open'` | Strategy when the vulnerability lookup fails and no cached data exists |

**Error Handling Strategies:**
- **fail-open** (Default): Allow packages through on errors (prioritizes availability)
- **fail-closed**: Block packages on errors (prioritizes security)

**Example Configuration:**
```yaml
# Production: Security-first approach
errorHandling:
  onFilterError: fail-closed
  onCveCheckError: fail-closed

# Development: Availability-first approach
errorHandling:
  onFilterError: fail-open
  onCveCheckError: fail-open

# Balanced: block only when vulnerability data is unavailable
errorHandling:
  onFilterError: fail-open
  onCveCheckError: fail-closed
```

### Version Range Rules

```typescript
{
  package: string;           // Package name
  range: string;             // Semver range
  strategy: 'block';         // 'fallback' is deprecated and behaves like 'block'
  reason?: string;           // Explanation for blocking
}
```

## 📖 Examples

See the [examples](./examples) directory for complete configuration examples:
- [basic.yaml](./examples/basic.yaml) - Simple setup for small teams
- [enterprise.yaml](./examples/enterprise.yaml) - Comprehensive security setup
- [high-security.yaml](./examples/high-security.yaml) - Maximum security configuration

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm test:coverage

# Run tests in watch mode
npm test:watch
```

**Test Results:**
- ✅ 108 tests passing
- ✅ 60%+ code coverage
- ✅ SecurityFilterPlugin: 21 tests
- ✅ PackageAgeChecker: 13 tests
- ✅ SecurityLogger: 16 tests
- ✅ LicenseChecker: 15 tests
- ✅ WhitelistChecker: 15 tests
- ✅ AuthorChecker: 28 tests

## 🔧 Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Lint
npm run lint

# Watch mode for development
npm run build -- --watch
```

## 📊 Metrics & Monitoring

When metrics are enabled, the plugin writes one JSON object per event, flushed every 10 seconds or every 100 events.

- `block` - a package, a tarball or some versions were blocked; `reason` says why
- `author_blocked` - the same, decided by the author filter

What `version` holds:

| Situation | Fields |
|---|---|
| A tarball download was refused | `version`: the requested version |
| A package was blocked as a whole | `version`: `"*"` |
| Versions were removed from metadata | no `version`; `metadata.versions` lists them |

Refused requests are recorded every time, because each one is an attempt. Removed versions are recorded once per package and reason, and again only after 10 minutes: metadata is filtered on every request, so the same removal would otherwise be repeated for each of them.

In [dry-run mode](#dry-run-mode) every event carries `"dryRun": true`.

```json
{
  "timestamp": "2026-01-15T10:30:00.000Z",
  "event": "block",
  "packageName": "lodash",
  "reason": "Package has 2 vulnerable version(s)",
  "metadata": { "versions": ["4.17.19", "4.17.20"] }
}
```

## 🛠️ Use Cases

### 1. Block Known Vulnerabilities

```yaml
versionRangeRules:
  - package: lodash
    range: ">=4.17.0 <4.17.21"
    strategy: block
    reason: "CVE-2021-23337: Command injection vulnerability"
```

### 2. Steer Installs to a Patched Version

```yaml
versionRangeRules:
  - package: axios
    range: "0.21.1"
    strategy: block
    reason: "SSRF vulnerability fix"
```

The blocked version disappears from the package metadata, so a range such as `axios@^0.21.0` resolves to the newest allowed version. A lockfile pinned to the blocked version fails with 403 until it is updated.

### 3. Enforce Corporate License Policy

```yaml
licenses:
  allowed:
    - MIT
    - Apache-2.0
    - BSD-3-Clause
  blocked:
    - GPL-3.0
    - AGPL-3.0
  requireLicense: true
```

### 4. Whitelist Only Approved Packages

```yaml
mode: whitelist
whitelist:
  packages:
    - lodash
    - express
  patterns:
    - "^@mycompany/.*"
  versions:
    lodash: "^4.17.21"
```

### 5. Automatic CVE Scanning

```yaml
cveCheck:
  enabled: true
  databases: [osv]
  severity: [high, critical]
  autoBlock: true
  updateInterval: 12
```

### 6. Block Recently Published Packages

```yaml
# Protect against newly published malicious packages
packageAge:
  enabled: true
  minPackageAgeDays: 7       # Package must exist for 7 days
  minVersionAgeDays: 3       # Version must exist for 3 days
  warnOnly: false            # Block, don't just warn
```

### 7. Block Packages by Author/Region

```yaml
# Block packages from specific authors, emails, or regions
authorFilter:
  enabled: true
  # Block specific author names
  blockedAuthors:
    - "Suspicious Author"
    - "Known Bad Actor"
  # Block author names matching patterns
  blockedAuthorPatterns:
    - "^Bot.*"
    - ".*Spammer$"
  # Block specific email addresses
  blockedEmails:
    - "malicious@example.com"
  # Block email patterns
  blockedEmailPatterns:
    - ".*@temporary-mail\\.com$"
  # Block entire email domains
  blockedEmailDomains:
    - ".ru"           # All .ru domains
    - "yandex.ru"     # Specific domain
    - "mail.ru"
  # Block by region (includes multiple common domains)
  blockedRegions:
    - "ru"            # Russia (.ru, yandex.ru, mail.ru, etc.)
    - "cn"            # China (.cn, qq.com, 163.com, etc.)
    - "by"            # Belarus
    - "kp"            # North Korea
  # Require author information
  requireVerifiedEmail: true
  # Warn-only mode (don't block, just log)
  warnOnly: false
```

## 🔐 Security Best Practices

1. **Enable CVE Scanning** - Automatically detect and block vulnerable packages
2. **Use Whitelist Mode** - For maximum security in sensitive environments
3. **Enforce License Compliance** - Prevent legal issues with license filtering
4. **Enable Package Age Filtering** - Block newly published packages to prevent supply chain attacks
5. **Enable Author Filtering** - Block packages from untrusted authors or regions
6. **Enable Metrics** - Track security events for audit and compliance
7. **Regular Updates** - Keep the plugin and CVE database cache updated
8. **Test Rules** - Use dry run mode (planned) before applying strict rules
9. **Monitor Logs** - Review security logs regularly for suspicious activity

## 🐛 Troubleshooting

### Plugin not loading
- Verify Verdaccio version >= 5.0.0
- Check plugin is listed in `config.yaml` under `filters`
- Ensure plugin is installed globally or linked correctly

### CVE scanning not working
- Check internet connectivity to OSV API (https://api.osv.dev)
- Verify `cveCheck.enabled` is `true`
- Check cache directory permissions
- Review logs for API errors

### Tests failing
- Ensure Node.js >= 22.0.0
- Run `npm install` to update dependencies
- Clear Jest cache: `npx jest --clearCache`

### Package blocked unexpectedly
- Check logs for the reason: `logger.level: debug`
- Review all active rules (patterns, scopes, CVE, license)
- In whitelist mode, ensure package is explicitly approved

## 📄 License

MIT © [Vitaliy Ponomarenko](https://github.com/ponomarenko)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`npm test`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ponomarenko/verdaccio-security-filter/issues)
- **Documentation**: [README](./README.md)
- **Examples**: [Configuration Examples](./examples)

## 🙏 Acknowledgments

- [Verdaccio](https://verdaccio.org/) - The awesome private npm registry
- [OSV](https://osv.dev/) - Open Source Vulnerabilities database
- All contributors and users of this plugin

---

**Made with ❤️ for the npm security community**
