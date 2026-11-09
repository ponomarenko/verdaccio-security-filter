# Dual-Layer Architecture

## Overview

The `verdaccio-security-filter` plugin implements a **dual-layer protection architecture** to ensure comprehensive package security. This document explains how the two layers work together to provide complete protection against malicious or vulnerable packages.

## Architecture Design

```
┌─────────────────────────────────────────────────────────────┐
│                     npm/yarn Client                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Layer 1: Middleware                         │
│              (HTTP Request Interception)                     │
│                                                              │
│  • Intercepts ALL HTTP requests                             │
│  • Pattern-based filtering                                  │
│  • Whitelist/Blacklist checking                             │
│  • Scope filtering                                          │
│  • Tarball download blocking                                │
│  • Version range rules                                      │
│                                                              │
│  Returns: 403 Forbidden (for blocked tarballs)              │
│           Modified metadata (for blocked packages)          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Layer 2: Filter Metadata                        │
│            (Deep Package Inspection)                         │
│                                                              │
│  • CVE vulnerability scanning (OSV API)                     │
│  • License compliance checking                              │
│  • Package age verification                                 │
│  • Full metadata analysis                                   │
│                                                              │
│  Returns: Modified Package metadata                         │
│           (empty versions if blocked)                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                Verdaccio Core / Storage                      │
└─────────────────────────────────────────────────────────────┘
```

## Layer 1: Middleware (HTTP Interception)

### Purpose
Provides **fast, lightweight filtering** at the HTTP request level before any package data is processed.

### When It Executes
- On **every HTTP request** to the registry
- Before Verdaccio's core routing
- Both for metadata requests and tarball downloads

### What It Checks

#### 1. Whitelist/Blacklist Mode
```yaml
mode: whitelist
whitelist:
  packages:
    - lodash
    - express
  patterns:
    - "^@mycompany/.*"
```

**Behavior:**
- In **whitelist mode**: Only approved packages are allowed
- In **blacklist mode**: Specific packages are blocked

#### 2. Pattern-Based Blocking
```yaml
blockedPatterns:
  - "^evil-.*"
  - ".*-malware$"
```

**Behavior:**
- Regex patterns match against package names
- Blocked packages return 403 or modified metadata

#### 3. Scope Filtering
```yaml
allowedScopes:
  - "@mycompany"
  - "@types"
blockedScopes:
  - "@hacker"
```

**Behavior:**
- Control which npm scopes are allowed/blocked
- Useful for enterprise environments

#### 4. Version Blocking
```yaml
blockedVersions:
  - "lodash@4.17.20"
```

**Behavior:**
- Block specific package@version combinations
- Exact version matching

#### 5. Version Range Rules
```yaml
versionRangeRules:
  - package: lodash
    range: "<4.17.21"
    strategy: block
```

**Behavior:**
- Semver range matching
- Matching versions are hidden from metadata and their tarballs are blocked

### Request Flow

#### Metadata Request (`GET /package`)
```
1. Client requests: GET /lodash
2. Middleware checks: Is "lodash" allowed?
3. If blocked:
   - Intercepts response
   - Returns empty versions with security info
4. If allowed:
   - Passes to Layer 2 for deep inspection
```

#### Tarball Request (`GET /package/-/file.tgz`)
```
1. Client requests: GET /lodash/-/lodash-4.17.20.tgz
2. Middleware checks: Is "lodash@4.17.20" allowed?
3. If blocked:
   - Returns 403 Forbidden immediately
   - No tarball download occurs
4. If allowed:
   - Passes to Verdaccio core
```

### Why This Layer Matters

**Problem it solves:**
- Even if package metadata is cached, tarballs can still be downloaded
- Dependencies can pull blocked packages transitively
- Some npm clients cache metadata aggressively

**Solution:**
- Middleware intercepts **all** HTTP requests
- Blocks tarball downloads at HTTP level
- Provides fail-safe protection

## Layer 2: Filter Metadata (Deep Inspection)

### Purpose
Provides **comprehensive security analysis** when package metadata is available.

### When It Executes
- When Verdaccio processes package metadata
- Before returning package info to clients
- After Layer 1 has approved the request

### What It Checks

#### 1. CVE Vulnerability Scanning
```yaml
cveCheck:
  enabled: true
  databases:
    - osv
  severity:
    - high
    - critical
  autoBlock: true
```

**Process:**
1. Queries the OSV (Open Source Vulnerabilities) API once per package
2. Matches each version against the returned ranges locally
3. Filters by severity level
4. Removes the vulnerable versions if `autoBlock` is set

**Features:**
- Per-package cache with configurable TTL
- One retry, 5 second timeout, 60 second back-off after a failure
- Stale cached data is used while OSV is unreachable

#### 2. License Compliance
```yaml
licenses:
  allowed:
    - MIT
    - Apache-2.0
  blocked:
    - GPL-3.0
  requireLicense: true
```

**Process:**
1. Parses package license field
2. Handles SPDX expressions (OR/AND)
3. Checks against allowed/blocked lists
4. Optionally requires license to be present

#### 3. Package Age Verification
```yaml
packageAge:
  enabled: true
  minPackageAgeDays: 7
  minVersionAgeDays: 3
  warnOnly: false
```

**Process:**
1. Checks package creation time
2. Checks version publish time
3. Blocks packages/versions that are too new
4. Protects against supply chain attacks

**Why it matters:**
- Newly published malicious packages often get removed quickly
- Waiting period reduces risk of zero-day malware

### Request Flow

```
1. Layer 1 approves request
2. filter_metadata receives package info
3. Checks CVE database
4. Checks license compliance
5. Checks package age
6. If any check fails:
   - Returns empty versions
   - Adds security metadata
7. If all checks pass:
   - Returns original package info
```

## Error Handling Strategy

### Fail-Open vs Fail-Closed

The plugin supports configurable error handling:

```yaml
errorHandling:
  onFilterError: fail-open      # Allow on error
  onCveCheckError: fail-open    # Allow if CVE check fails
```

#### Fail-Open (Default)
- **Philosophy:** Availability over security
- **Behavior:** On error, allow package through
- **Use case:** Development environments
- **Risk:** Potential security bypass on errors

#### Fail-Closed
- **Philosophy:** Security over availability
- **Behavior:** On error, block package
- **Use case:** Production environments
- **Risk:** Service disruption on errors

### Error Scenarios

| Scenario | Fail-Open | Fail-Closed |
|----------|-----------|-------------|
| OSV API timeout | Allow | Block |
| Network error | Allow | Block |
| Invalid package metadata | Allow | Block |
| Plugin crash | Allow | Block |

## Why Two Layers?

### Problem Statement

**Single-layer approaches fail because:**

1. **Metadata-only filtering:**
   - Clients cache metadata aggressively
   - Tarball URLs can be accessed directly
   - Dependencies can bypass metadata checks

2. **Middleware-only filtering:**
   - Cannot perform deep inspection (CVE, licenses)
   - No access to package metadata
   - Limited to pattern matching

### Dual-Layer Solution

| Aspect | Layer 1 (Middleware) | Layer 2 (Filter) |
|--------|---------------------|------------------|
| **Speed** | ⚡ Very Fast | 🐢 Slower (API calls) |
| **Coverage** | All HTTP requests | Metadata only |
| **Checks** | Patterns, scopes, versions | CVE, licenses, age |
| **Bypass Risk** | None | Medium (caching) |
| **Failure Mode** | Hard block | Configurable |

### Combined Protection

```
Request → Layer 1 → Layer 2 → Storage
           ↓         ↓
         Block     Deep
         Fast      Analysis
```

**Example Flow:**

```
npm install hawk

Step 1: Metadata Request
→ Layer 1: Check whitelist → BLOCKED (not whitelisted)
→ Returns: 404 Not Found
→ Layer 2: Never executed
→ Result: ❌ Installation fails

npm install lodash@4.17.20

Step 1: Metadata Request
→ Layer 1: Check whitelist → ✓ Allowed
→ Layer 2: Check CVE → ❌ BLOCKED (vulnerable)
→ Returns: Empty versions
→ Result: ❌ No versions available

Step 2: Dependency tries tarball
→ Layer 1: Intercepts tarball request → ❌ BLOCKED
→ Returns: 403 Forbidden
→ Result: ❌ Download prevented
```

## Configuration Best Practices

### Development Environment
```yaml
middlewares:
  security-filter:
    mode: blacklist
    blockedPatterns:
      - "^evil-.*"
    errorHandling:
      onFilterError: fail-open
      onCveCheckError: fail-open
```

**Rationale:**
- Fast iteration
- Fewer restrictions
- Allow packages on errors

### Staging Environment
```yaml
middlewares:
  security-filter:
    mode: whitelist
    whitelist:
      packages: [lodash, express]
      patterns: ["^@mycompany/.*"]
    cveCheck:
      enabled: true
      severity: [high, critical]
    errorHandling:
      onFilterError: fail-open
      onCveCheckError: fail-closed
```

**Rationale:**
- Test whitelist mode
- CVE scanning enabled
- Balance security and availability

### Production Environment
```yaml
middlewares:
  security-filter:
    mode: whitelist
    whitelist:
      packages: [lodash, express]
      patterns: ["^@mycompany/.*", "^@types/.*"]
    cveCheck:
      enabled: true
      databases: [osv]
      severity: [medium, high, critical]
      autoBlock: true
    licenses:
      allowed: [MIT, Apache-2.0, BSD-3-Clause]
      blocked: [GPL-3.0, AGPL-3.0]
    packageAge:
      enabled: true
      minPackageAgeDays: 7
    errorHandling:
      onFilterError: fail-closed
      onCveCheckError: fail-closed
```

**Rationale:**
- Maximum security
- All checks enabled
- Fail-closed on errors
- Comprehensive filtering

## Performance Considerations

### Layer 1 Performance
- **Latency:** < 1ms per request
- **Caching:** Regex patterns compiled once
- **Scalability:** Handles 1000s req/sec

### Layer 2 Performance
- **Latency:** 50-200ms (API calls)
- **Caching:** CVE results cached for 24h
- **Scalability:** Depends on OSV API

### Optimization Tips

1. **Use Layer 1 for common blocks**
   ```yaml
   blockedPatterns:
     - "^known-malware-.*"
   ```

2. **Cache CVE results aggressively**
   ```yaml
   cveCheck:
     updateInterval: 24  # hours
     cacheDir: /var/cache/security-filter
   ```

3. **Limit CVE severity checks**
   ```yaml
   cveCheck:
     severity: [critical, high]  # Skip low/medium
   ```

## Monitoring & Debugging

### Log Levels

```yaml
logger:
  level: debug  # trace|debug|info|warn|error
```

**Debug output:**
```
[Middleware] TARBALL REQUEST: lodash@4.17.20
[Middleware] [X] BLOCKED TARBALL: lodash@4.17.20 - CVE-2021-23337
[filter_metadata] --> Processing: lodash
[filter_metadata] CVE found in lodash@4.17.20: 1 vulnerabilities
[filter_metadata] CVE BLOCKED: lodash - Package has 1 vulnerable version(s)
```

### Metrics Collection

```yaml
metrics:
  enabled: true
  output: file
  filePath: /var/log/verdaccio/security-metrics.jsonl
```

**Metrics tracked:**
- `block` - Packages or versions blocked by rules, CVE, license or age checks (see `reason`)

## Security Guarantees

### What This Plugin Prevents

✅ **Direct package requests** (Layer 1)
✅ **Tarball downloads** (Layer 1)
✅ **Transitive dependencies** (Layer 1)
✅ **Cached metadata bypass** (Layer 1)
✅ **Vulnerable packages** (Layer 2)
✅ **License violations** (Layer 2)
✅ **Newly published malware** (Layer 2)

### What This Plugin Cannot Prevent

❌ **Zero-day vulnerabilities** (not in CVE database yet)
❌ **Malicious code** (without CVE)
❌ **Social engineering attacks**
❌ **Compromised developer accounts**

### Defense in Depth

This plugin is **one layer** in a comprehensive security strategy:

1. ✅ **Registry filtering** (this plugin)
2. ✅ **npm audit** (in CI/CD)
3. ✅ **Dependency scanning** (Snyk, Dependabot)
4. ✅ **Code review**
5. ✅ **SBOM generation**
6. ✅ **Runtime monitoring**

## Troubleshooting

### Problem: Package blocked unexpectedly

**Debug steps:**
1. Enable debug logging: `logger.level: debug`
2. Check which layer blocked it:
   - `[Middleware]` = Layer 1
   - `[filter_metadata]` = Layer 2
3. Review the reason in logs
4. Check configuration

### Problem: CVE checks not working

**Debug steps:**
1. Check internet connectivity to `https://api.osv.dev`
2. Verify `cveCheck.enabled: true`
3. Check cache directory permissions
4. Review error logs

### Problem: Performance degradation

**Debug steps:**
1. Check CVE cache hit rate
2. Reduce `cveCheck.severity` levels
3. Increase `cveCheck.updateInterval`
4. Monitor OSV API latency

## Migration Guide

### From Single-Layer to Dual-Layer

**Old configuration (middleware only):**
```yaml
middlewares:
  security-filter:
    blockedPatterns: ["^evil-.*"]
```

**New configuration (dual-layer):**
```yaml
# Layer 2: Deep inspection
packages:
  '**':
    storage: security-filter

# Layer 1: Fast filtering
middlewares:
  security-filter:
    blockedPatterns: ["^evil-.*"]
    cveCheck:
      enabled: true
```

## FAQ

**Q: Do I need both layers?**
A: Layer 1 is mandatory. Layer 2 is optional but highly recommended for production.

**Q: Which layer should I use for which checks?**
A: Layer 1 for fast filtering (patterns, scopes). Layer 2 for deep analysis (CVE, licenses).

**Q: What happens if both layers block a package?**
A: Layer 1 blocks first (faster). Layer 2 never executes.

**Q: Can I disable Layer 2?**
A: Yes, simply don't add `storage: security-filter` to your packages config.

**Q: What's the performance impact?**
A: Layer 1 adds < 1ms. Layer 2 adds 50-200ms (with caching).

## References

- [Verdaccio Plugin Documentation](https://verdaccio.org/docs/plugin-filter)
- [OSV Database](https://osv.dev/)
- [SPDX License List](https://spdx.org/licenses/)
- [Semver Specification](https://semver.org/)

---

**Last Updated:** December 2024
**Version:** 2.0.0
