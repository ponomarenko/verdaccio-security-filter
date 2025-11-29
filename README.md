# Verdaccio Security Filter Plugin

Advanced security filter plugin for Verdaccio with version range blocking and intelligent fallback strategies.

## Features

### 🔒 Core Security Features

1. **Version Range Blocking** - Block vulnerable versions using semver ranges with two strategies:
   - **Block Strategy**: Completely remove versions from registry
   - **Fallback Strategy**: Transparently redirect to safe versions
2. **Exact Version Blocking** - Block specific vulnerable package versions
3. **Pattern-based Filtering** - Block suspicious packages by name patterns
4. **Scope Control** - Whitelist/blacklist package scopes (@scope/package)
5. **Size Limits** - Enforce minimum and maximum package sizes
6. **Metadata Validation** - Verify package integrity and structure
7. **Checksum Enforcement** - Ensure package integrity

### 🆕 Version Range Strategies

#### Block Strategy

Completely removes versions from the registry. Users cannot install these versions.

```yaml
- package: "axios"
  range: ">=0.21.0 <=0.21.1"
  strategy: "block"
  reason: "Critical SSRF vulnerability (CVE-2021-3749)"
```

#### Fallback Strategy

Transparently redirects blocked versions to a safe version. Users can still install using the blocked version number, but receive the fallback version.

```yaml
- package: "lodash"
  range: ">=4.17.0 <4.17.21"
  strategy: "fallback"
  fallbackVersion: "4.17.21"
  reason: "Contains prototype pollution vulnerability"
```

## Installation

### Prerequisites

```bash
npm install -g verdaccio
```

### Install Plugin

```bash
# Install from npm (when published)
npm install -g verdaccio-security-filter

# Or install locally
cd verdaccio-security-filter
npm install
npm link
```

### Install Dependencies

```bash
npm install semver
```

## Configuration

Add to your `config.yaml`:

```yaml
filters:
  security-filter:
    # Exact version blocking
    blockedVersions:
      - "lodash@4.17.15"
      - "moment@2.29.1"

    # Pattern-based blocking
    blockedPatterns:
      - "^evil-.*"
      - ".*-malware$"

    # Scope control
    allowedScopes:
      - "@mycompany"

    blockedScopes:
      - "@malicious"

    # Size limits (bytes)
    minPackageSize: 100
    maxPackageSize: 52428800 # 50MB

    # Version range rules
    versionRangeRules:
      # Fallback example
      - package: "lodash"
        range: ">=4.17.0 <4.17.21"
        strategy: "fallback"
        fallbackVersion: "4.17.21"
        reason: "Prototype pollution vulnerability"

      # Block example
      - package: "axios"
        range: ">=0.21.0 <=0.21.1"
        strategy: "block"
        reason: "SSRF vulnerability (CVE-2021-3749)"
```

## Usage Examples

### Example 1: Block Vulnerable Lodash Versions

```yaml
versionRangeRules:
  - package: "lodash"
    range: ">=4.17.0 <4.17.21"
    strategy: "fallback"
    fallbackVersion: "4.17.21"
    reason: "CVE-2020-28500: Prototype pollution"
```

**Result:**

- User runs: `npm install lodash@4.17.15`
- Actually receives: `lodash@4.17.21`
- Application continues to work without breaking changes

### Example 2: Hard Block Deprecated Package

```yaml
versionRangeRules:
  - package: "request"
    range: "*"
    strategy: "block"
    reason: "Package deprecated, use axios instead"
```

**Result:**

- User runs: `npm install request`
- Installation fails with error message
- Forces migration to modern alternatives

### Example 3: Force Latest Stable Version

```yaml
versionRangeRules:
  - package: "@mycompany/core"
    range: ">=2.0.0 <2.5.0"
    strategy: "fallback"
    fallbackVersion: "2.5.3"
    reason: "Company policy: use latest 2.x version"
```

**Result:**

- Any install of `@mycompany/core@2.x.x` (except 2.5.3+)
- Automatically upgraded to `2.5.3`
- Ensures all teams use latest stable version

### Example 4: Block Pre-release Versions

```yaml
versionRangeRules:
  - package: "next"
    range: ">=13.0.0-0 <13.0.0"
    strategy: "block"
    reason: "Pre-release versions not allowed"
```

### Example 5: Multiple Rules for Same Package

```yaml
versionRangeRules:
  # Block ancient versions
  - package: "express"
    range: "<4.0.0"
    strategy: "block"
    reason: "Version too old, multiple vulnerabilities"

  # Fallback vulnerable versions
  - package: "express"
    range: ">=4.0.0 <4.17.3"
    strategy: "fallback"
    fallbackVersion: "4.18.2"
    reason: "Path disclosure vulnerability"
```

## Semver Range Syntax

The plugin supports all semver range syntax:

```yaml
# Exact version
range: '1.2.3'

# Greater than
range: '>1.2.3'
range: '>=1.2.3'

# Less than
range: '<2.0.0'
range: '<=2.0.0'

# Ranges
range: '>=1.2.3 <2.0.0'
range: '1.2.3 - 2.3.4'

# Caret (compatible with)
range: '^1.2.3'  # >=1.2.3 <2.0.0

# Tilde (approximately)
range: '~1.2.3'  # >=1.2.3 <1.3.0

# Wildcards
range: '1.x'     # >=1.0.0 <2.0.0
range: '*'       # All versions
```

## Testing

### Start Verdaccio

```bash
verdaccio --config ./config.yaml
```

### Test Block Strategy

```bash
# Try to install blocked version
npm install axios@0.21.1 --registry http://localhost:4873

# Expected: Installation fails with error message
# Error: Package has known vulnerabilities
```

### Test Fallback Strategy

```bash
# Install vulnerable version
npm install lodash@4.17.15 --registry http://localhost:4873

# Check installed version
npm list lodash

# Expected: Shows lodash@4.17.21 (fallback applied)
```

### Test Publishing

```bash
# Try to publish blocked version
npm publish my-package@1.0.0 --registry http://localhost:4873

# If version falls in blocked range:
# Error: Version 1.0.0 falls within blocked range: >=1.0.0 <2.0.0
```

## Monitoring & Logging

The plugin logs all security actions:

```log
[Security Filter] Plugin initialized
[Security Filter] Version range rules:
  - lodash >=4.17.0 <4.17.21 [fallback -> 4.17.21]
  - axios >=0.21.0 <=0.21.1 [block]
[Security Filter] Applying fallback for lodash@4.17.15 -> 4.17.21
[Security Filter] Blocking axios@0.21.1 (range: >=0.21.0 <=0.21.1)
[Security Filter] Validating publish: my-package@1.0.0
```

### Log Levels

Configure in `config.yaml`:

```yaml
logs:
  - { type: stdout, format: pretty, level: info }
  - { type: file, path: verdaccio.log, level: debug }
```

## Security Metadata

Filtered packages include security metadata:

```json
{
  "name": "lodash",
  "versions": { ... },
  "_security": {
    "scanned": true,
    "scanDate": "2024-01-15T10:30:00.000Z",
    "filteredBy": "verdaccio-security-filter",
    "blockedVersions": [">=4.17.0 <4.17.21"],
    "fallbackVersions": [">=4.17.0 <4.17.21 -> 4.17.21"]
  }
}
```

## Best Practices

### 1. Regular Updates

Keep your security rules updated:

```bash
# Subscribe to security advisories
# - GitHub Security Advisories
# - npm Security Advisories
# - Snyk Vulnerability Database
```

### 2. Test Before Deploying

Always test rules in staging:

```yaml
# staging-config.yaml
versionRangeRules:
  - package: "new-rule-package"
    range: "test-range"
    strategy: "block" # Test block first
```

### 3. Use Fallback for Minor Fixes

```yaml
# Good: Fallback for patch versions
- package: "express"
  range: ">=4.17.0 <4.17.3"
  strategy: "fallback"
  fallbackVersion: "4.17.3"
# Risky: Fallback across major versions
# - package: 'react'
#   range: '^16.0.0'
#   strategy: 'fallback'
#   fallbackVersion: '18.0.0'  # Breaking changes!
```

### 4. Document Reasons

Always include the `reason` field:

```yaml
- package: "lodash"
  range: ">=4.17.0 <4.17.21"
  strategy: "fallback"
  fallbackVersion: "4.17.21"
  reason: "CVE-2020-28500: Prototype pollution vulnerability"
```

### 5. Monitor Fallback Usage

Check logs to see which versions are being redirected:

```bash
grep "Applying fallback" verdaccio.log
```

## Common Vulnerabilities Database

Example rules for common CVEs:

```yaml
versionRangeRules:
  # Lodash prototype pollution
  - package: "lodash"
    range: ">=4.17.0 <4.17.21"
    strategy: "fallback"
    fallbackVersion: "4.17.21"
    reason: "CVE-2020-28500"

  # Axios SSRF
  - package: "axios"
    range: ">=0.21.0 <=0.21.1"
    strategy: "block"
    reason: "CVE-2021-3749"

  # Minimist prototype pollution
  - package: "minimist"
    range: "<1.2.6"
    strategy: "fallback"
    fallbackVersion: "1.2.8"
    reason: "CVE-2021-44906"

  # Express path disclosure
  - package: "express"
    range: "<4.17.3"
    strategy: "fallback"
    fallbackVersion: "4.18.2"
    reason: "CVE-2022-24999"
```

## Troubleshooting

### Fallback Not Applied

**Issue:** Users still getting old versions

**Check:**

1. Verify semver range syntax: `npm semver <version> -r '<range>'`
2. Check logs for rule matching
3. Ensure fallback version exists in upstream registry

```bash
# Test semver range
npx semver 4.17.15 -r '>=4.17.0 <4.17.21'
# Output: 4.17.15
```

### Type Checking Errors

**Issue:** TypeScript errors in JSDoc

**Solution:**

```bash
# Update TypeScript
npm install -D typescript@latest

# Check specific file
npx tsc --noEmit index.js
```

### Plugin Not Loading

**Check:**

1. Plugin installed: `npm list -g verdaccio-security-filter`
2. Config path correct in `config.yaml`
3. Verdaccio restarted after config changes

## API Reference

See `types.d.ts` for complete TypeScript definitions.

### Main Methods

```javascript
/**
 * Filter package metadata before serving
 * @param {PackageInfo} packageInfo
 * @returns {PackageInfo}
 */
filter_metadata(packageInfo)

/**
 * Validate package before publish
 * @param {string} packageName
 * @param {string} version
 * @param {Buffer} [tarball]
 * @returns {Promise<boolean>}
 */
async validate_publish(packageName, version, tarball)
```

## License

MIT

## Support

- Issues: https://github.com/ponomarenko/verdaccio-security-filter/issues
