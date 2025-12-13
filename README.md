# Verdaccio Security Filter Plugin

Advanced security filter plugin for Verdaccio with **dual-layer protection architecture** combining middleware interception and metadata filtering for comprehensive package security.

[![npm version](https://img.shields.io/npm/v/verdaccio-security-filter.svg)](https://www.npmjs.com/package/verdaccio-security-filter)
[![npm downloads](https://img.shields.io/npm/dm/verdaccio-security-filter.svg)](https://www.npmjs.com/package/verdaccio-security-filter)
[![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen)](./tests)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)]()
[![Node](https://img.shields.io/badge/node-%3E%3D22-brightgreen)]()
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
  - **Block Strategy**: Completely remove versions from registry
  - **Fallback Strategy**: Transparently redirect to safe versions
- **Exact Version Blocking** - Block specific package@version combinations
- **Semver Support** - Full semver syntax (`^`, `~`, `>`, `>=`, `<`, `<=`, `x`, `*`)

#### 🛡️ CVE & Vulnerability Scanning
- **OSV Database Integration** - Automatic vulnerability scanning via [OSV API](https://osv.dev/)
- **Severity Filtering** - Filter by severity: `low`, `medium`, `high`, `critical`
- **Auto-Block Vulnerable Packages** - Automatically block packages with known CVEs
- **Caching System** - Configurable cache with update intervals
- **Multiple Database Support** - Ready for OSV, Snyk, GitHub Advisory

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
- **Metrics Collection** - Track security events (blocks, fallbacks, CVEs, license violations)
- **Security Audit Trail** - Detailed logging of all security decisions
- **Customizable Output** - Log to stdout or file in JSON format

#### 🔍 Additional Security
- **Pattern-based Blocking** - Block suspicious packages by name patterns (regex)
- **Package Age Filtering** - Block packages or versions that are too new (protect against newly published malicious packages)
  - **Minimum Package Age** - Require packages to exist for a minimum number of days
  - **Minimum Version Age** - Require specific versions to exist for a minimum number of days
  - **Warn-Only Mode** - Log warnings without blocking
- **Middleware Interception** - HTTP middleware that blocks tarball downloads for blocked packages
  - Prevents blocked packages from being installed as dependencies
  - Intercepts requests to `/:package/-/:filename.tgz` routes
  - Returns 403 Forbidden with detailed error messages
- **Size Limits** - Enforce minimum and maximum package sizes
- **Metadata Validation** - Verify package integrity and detect dangerous characters
- **Checksum Enforcement** - Ensure package integrity

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
- [ ] **Dry Run Mode** - Test rules without actually blocking
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

This plugin implements **two layers of protection** to block malicious packages:

### Layer 1: Metadata Filtering (`filter_metadata`)
When a client requests package information (e.g., `npm info lodash`), the plugin:
1. Checks if the package is allowed (whitelist mode)
2. Validates against blocked patterns, scopes, and age requirements
3. **Throws HTTP 404 error** for completely blocked packages (patterns, scopes, whitelist violations)
4. Filters out specific blocked versions from the versions list for partial blocks

**Result**: Blocked packages return "404 Not Found" - as if they don't exist in the registry.

### Layer 2: Middleware Interception (`register_middlewares`)
When a client tries to download a tarball file (e.g., during `npm install`), the plugin:
1. Intercepts **all HTTP requests** early in the middleware chain
2. Extracts package name and version from the request URL
3. Applies all security checks (whitelist, patterns, scopes, blocked versions, range rules)
4. Returns **403 Forbidden** for blocked packages with detailed error message

**Result**: Even if metadata is cached, tarball downloads are blocked at the HTTP level.

### Why Both Layers?

- **Metadata filtering (404)** - Makes blocked packages invisible to npm/yarn
- **Middleware interception (403)** - Blocks tarball downloads even with cached metadata
- Together, they provide **complete protection** against blocked packages being installed in any way

Example flow when a blocked package is requested:
```
npm install hawk
→ GET /hawk (metadata request)
→ [Security Filter] Blocked hawk@* - Package is not in whitelist
→ HTTP 404 Not Found: Package blocked by security filter: Not in whitelist
→ npm ERR! 404 Not Found - GET http://localhost:4873/hawk

npm install (with hawk as dependency)
→ GET /hawk/-/hawk-9.0.1.tgz (tarball request)
→ [Middleware] Tarball request: hawk/hawk-9.0.1.tgz
→ [Security Filter] Blocked hawk@9.0.1 - Package is not in whitelist
→ HTTP 403 Forbidden: {"error": "Package blocked by security filter", "reason": "Package is not in whitelist"}
```

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
        - github
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
        strategy: fallback
        fallbackVersion: "4.17.21"
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
      databases: [osv, github, snyk]
      severity: [low, medium, high, critical]  # Block ALL
      autoBlock: true
      updateInterval: 6                         # Check every 6 hours

    licenses:
      allowed: [MIT, Apache-2.0, BSD-3-Clause]
      blocked: [GPL-3.0, AGPL-3.0, LGPL-3.0]
      requireLicense: true

    minPackageSize: 10000      # 10KB minimum
    maxPackageSize: 10485760   # 10MB maximum

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
| `blockedVersions` | `string[]` | `[]` | List of `package@version` to block |
| `blockedPatterns` | `string[]` | `[]` | Regex patterns for package names |
| `allowedScopes` | `string[]` | `[]` | Allowed package scopes |
| `blockedScopes` | `string[]` | `[]` | Blocked package scopes |
| `minPackageSize` | `number` | `0` | Minimum package size in bytes |
| `maxPackageSize` | `number` | `104857600` | Maximum package size (100MB) |
| `enforceChecksum` | `boolean` | `true` | Enforce checksum validation |

### CVE Check Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cveCheck.enabled` | `boolean` | `false` | Enable CVE scanning |
| `cveCheck.databases` | `string[]` | `['osv']` | Databases: `osv`, `snyk`, `github` |
| `cveCheck.severity` | `string[]` | `['high', 'critical']` | Severity levels to check |
| `cveCheck.autoBlock` | `boolean` | `false` | Auto-block vulnerable packages |
| `cveCheck.updateInterval` | `number` | `24` | Cache update interval (hours) |
| `cveCheck.cacheDir` | `string` | `./.security-cache` | Cache directory path |

### License Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `licenses.allowed` | `string[]` | `[]` | Allowed license list |
| `licenses.blocked` | `string[]` | `[]` | Blocked license list |
| `licenses.requireLicense` | `boolean` | `false` | Require license field |

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

### Version Range Rules

```typescript
{
  package: string;           // Package name
  range: string;             // Semver range
  strategy: 'block' | 'fallback';
  fallbackVersion?: string;  // Required for fallback strategy
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
- ✅ 80 tests passing
- ✅ 60%+ code coverage
- ✅ SecurityFilterPlugin: 21 tests
- ✅ PackageAgeChecker: 13 tests
- ✅ SecurityLogger: 16 tests
- ✅ LicenseChecker: 15 tests
- ✅ WhitelistChecker: 15 tests

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

When metrics are enabled, the plugin tracks:

- `block` - Packages blocked by version/pattern/scope rules
- `fallback` - Versions redirected to safe alternatives
- `publish_rejected` - Publish attempts rejected
- `cve_detected` - CVE vulnerabilities found
- `license_blocked` - Packages blocked by license rules
- `package_too_new` - Packages/versions blocked due to age restrictions

Example metrics output:
```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "event": "cve_detected",
  "packageName": "lodash",
  "version": "4.17.20",
  "reason": "CVE-2021-23337 (high)",
  "metadata": {
    "cveId": "CVE-2021-23337",
    "severity": "high"
  }
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

### 2. Transparent Security Patches (Fallback)

```yaml
versionRangeRules:
  - package: axios
    range: "0.21.1"
    strategy: fallback
    fallbackVersion: "0.21.4"
    reason: "SSRF vulnerability fix"
```

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
  databases: [osv, github]
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

## 🔐 Security Best Practices

1. **Enable CVE Scanning** - Automatically detect and block vulnerable packages
2. **Use Whitelist Mode** - For maximum security in sensitive environments
3. **Enforce License Compliance** - Prevent legal issues with license filtering
4. **Enable Package Age Filtering** - Block newly published packages to prevent supply chain attacks
5. **Enable Metrics** - Track security events for audit and compliance
6. **Regular Updates** - Keep the plugin and CVE database cache updated
7. **Test Rules** - Use dry run mode (planned) before applying strict rules
8. **Monitor Logs** - Review security logs regularly for suspicious activity

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
