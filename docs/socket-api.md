# Socket Security API (Unauthenticated)

Documentation for Socket's free, unauthenticated package security API used by sfw-free, Deno, and bun-security-scanner.

## Endpoint

```
GET https://firewall-api.socket.dev/purl/{purl}
```

## Request

### URL Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `purl` | URL-encoded [Package URL](https://github.com/package-url/purl-spec) | `pkg%3Anpm%2Fis-odd%403.0.1` |

### PURL Format

```
pkg:{ecosystem}/{name}@{version}
```

Examples:
- npm: `pkg:npm/is-odd@3.0.1`
- npm scoped: `pkg:npm/%40scope/package@1.0.0`

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `User-Agent` | Recommended | Tool identifier (e.g., `MyTool/1.0.0`) |

### Example Request

```bash
curl -s "https://firewall-api.socket.dev/purl/pkg%3Anpm%2Fis-odd%403.0.1" \
  -H "User-Agent: MyTool/1.0.0"
```

## Response

### Format

Newline-delimited JSON (NDJSON). Each line is a separate JSON object.

### Response Object

```json
{
  "id": "pkg:npm/is-odd@3.0.1",
  "name": "is-odd",
  "version": "3.0.1",
  "score": {
    "license": 0.9,
    "maintenance": 0.8,
    "quality": 0.7,
    "supplyChain": 0.85,
    "vulnerability": 1.0
  },
  "alerts": [
    {
      "type": "missingLicense",
      "action": "warn",
      "severity": "low",
      "category": "license"
    }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Package URL (PURL) |
| `name` | string | Package name |
| `version` | string | Package version |
| `score` | object | Security scores (0-1, higher is better) |
| `score.license` | number | License quality score |
| `score.maintenance` | number | Maintenance activity score |
| `score.quality` | number | Code quality score |
| `score.supplyChain` | number | Supply chain security score |
| `score.vulnerability` | number | Known vulnerability score (1.0 = no vulnerabilities) |
| `alerts` | array | Security alerts for this package |

### Alert Object

| Field | Type | Values |
|-------|------|--------|
| `key` | string | Opaque alert identifier |
| `type` | string | Alert type (e.g., `"malware"`, `"protestware"`, `"criticalCVE"`) |
| `action` | string | `"error"`, `"warn"`, `"monitor"`, `"ignore"` |
| `severity` | string | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `category` | string | `"vulnerability"`, `"license"`, `"quality"`, `"supplyChainRisk"` |
| `file` | string | Source file that triggered the alert (when applicable) |
| `props` | object | Additional context (e.g., `note` with human-readable description) |
| `fix` | object | Suggested remediation (`type`, `description`) |

### Alert Severity Levels

Severity is a **fixed property** of each alert type (not configurable per-org). The org-configurable part is the **action** (block, warn, monitor, ignore).

| Severity | Alert Types | Description |
|----------|-------------|-------------|
| **critical** | Known Malware, Possible Typosquat Attack | Immediate threat — package is confirmed malicious or impersonating another package |
| **high** | Telemetry, Protestware, Critical CVE, High CVE | Serious risk — data exfiltration, intentional sabotage, or severe vulnerabilities |
| **medium** | Environment Variable Access, Filesystem Access, Non-existent Author, Medium CVE, Network Access, Shell Access, Native Code, Obfuscated Code, and other supply chain risks | Elevated risk — suspicious capabilities that may be legitimate |
| **low** | Minified Code, Low CVE, Unpopular Package, Deprecated, Unmaintained, license issues | Informational — quality/maintenance signals, not direct threats |

**egress-filter blocks when `action == "error"`**, which in Socket's default policy means Known Malware only. This defers to Socket's own judgment about what's block-worthy and avoids false positives from informational alerts (telemetry, missing tests, etc.).

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid PURL format |
| 404 | Package not found |
| 429 | Rate limited |

## Rate Limits

The unauthenticated API has rate limits. For high-volume usage, consider:
- Batching requests with delays
- Using the authenticated API with an API key

## Usage in Open Source Projects

### sfw-free (Socket Firewall)
```
User-Agent: SocketFirewall/1.5.4
```

### Deno
```
User-Agent: Deno/2.0.0
```

### bun-security-scanner
```
User-Agent: SocketBunSecurityScanner/1.0.0 (linux x64) Bun/1.0.5
```

## Authenticated API (Reference)

For batch queries and higher rate limits, Socket offers an authenticated API:

```
POST https://api.socket.dev/v0/purl?actions=error,warn
Authorization: Bearer {API_KEY}
Content-Type: application/json

{
  "components": [
    { "purl": "pkg:npm/is-odd@3.0.1" },
    { "purl": "pkg:npm/is-number@6.0.0" }
  ]
}
```

## Test Data: Known Malware

For testing blocking functionality, Aikido maintains public lists of known malicious packages:

- **npm**: https://malware-list.aikido.dev/malware_predictions.json
- **PyPI**: https://malware-list.aikido.dev/malware_pypi.json

These are large JSON files containing package names flagged as malicious.

## References

- [Package URL Specification](https://github.com/package-url/purl-spec)
- [Socket: Organization Alerts](https://docs.socket.dev/docs/organization-alerts) — severity definitions and full alert type list
- [Socket: Security Policy (Default Enabled Alerts)](https://docs.socket.dev/docs/security-policy-default-enabled-alerts) — default actions per alert type
- [Socket: Package Scores](https://docs.socket.dev/docs/package-scores) — scoring methodology
- [Deno audit implementation](https://github.com/denoland/deno/blob/main/cli/tools/pm/audit.rs)
- [bun-security-scanner](https://github.com/SocketDev/bun-security-scanner)
- [Aikido malware lists](https://malware-list.aikido.dev/)
