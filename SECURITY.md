# Security Policy

## Reporting Security Issues

**Please do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Native Shield Guard, please email us at:
**security@example.com**

Include:
- Description of the vulnerability
- Steps to reproduce (if possible)
- Potential impact
- Your suggested fix (optional)

We will:
1. Acknowledge receipt within 48 hours
2. Investigate the issue
3. Develop and test a fix
4. Release a patched version
5. Credit you in the release notes (optional)

## Security Considerations

### Input Validation

Native Shield Guard validates and sanitizes all inputs:

- **User input**: Checked against 7 attack pattern categories
- **Configuration**: Loaded from `firewall-config.json` with validation
- **API calls**: Parameters validated before processing
- **Logs**: Sanitized to prevent injection attacks

### Memory Safety

The Rust core provides:
- **No buffer overflows**: Rust's memory model prevents heap corruption
- **No use-after-free**: Borrow checker ensures memory safety
- **No data races**: Thread-safety guaranteed at compile time
- **No GC pauses**: Deterministic performance under attack

### Threat Detection

Native Shield Guard detects and blocks:

- ✅ SQL Injection (7 variants)
- ✅ Cross-Site Scripting/XSS (11+ variants)
- ✅ Path Traversal attacks
- ✅ Command Injection
- ✅ XXE (XML External Entity)
- ✅ SSRF (Server-Side Request Forgery)
- ✅ Log Injection/CRLF attacks
- ✅ DDoS Botnets (via rhythm analysis)
- ✅ Brute force attempts
- ✅ Polymorphic attacks (structural analysis)

### Logging & Auditing

Security events are logged with:
- IP address and timestamp
- Threat type and severity
- Request fingerprint
- Action taken (blocked/allowed)
- 1GB auto-rotating log files for compliance

### Best Practices for Users

1. **Update regularly**: Keep Node.js and native-shield-guard updated
2. **Use HTTPS**: Always use TLS in production
3. **Rotate logs**: Archive logs for long-term retention
4. **Monitor alerts**: Watch for repeated threats from same IP
5. **Test configs**: Validate firewall-config.json before production
6. **Backup state**: Regularly backup `oxide.brain` and `firewall-state.json`

### Configuration Security

Sensitive configurations:

```json
{
  "security_enabled": true,        // Never set to false in production
  "max_violations": 5,             // Lower = stricter, higher = lenient
  "honeypots": ["/admin", "/.git"], // Use realistic paths
  "logging_enabled": true,         // Always enable in production
  "log_file": "firewall.log"        // Secure file permissions (600)
}
```

### Known Limitations

1. **IPv6 honeypots**: Currently limited to IPv4 CIDR matching
2. **Rate limiting**: Per-IP only; no user-level rate limiting
3. **Encrypted payloads**: Cannot inspect encrypted request bodies
4. **Time-based attacks**: No protection against time-based exploits
5. **Zero-days**: Detection limited to known patterns

### Dependencies

We monitor security in all dependencies:
- `once_cell` - Used for lazy statics
- `regex` - Compiled once at startup
- `serde_json` - JSON parsing
- `chrono` - Timestamp handling

All are actively maintained and regularly updated.

### Vulnerability Severity Scale

| Severity | Impact | Response Time |
|----------|--------|---|
| **Critical** | Allows remote code execution or unauthorized access | 24-48 hours |
| **High** | Major security bypass or data exposure | 1 week |
| **Medium** | Partial security bypass or information leakage | 2 weeks |
| **Low** | Minor security issue with limited impact | 1 month |

### Security Release Process

1. Security fix is prepared and tested
2. Release is prepared (patch version bump)
3. CVE is requested if applicable
4. All users are notified
5. Vulnerability details published after update availability

### Compliance

Native Shield Guard is designed for healthcare applications and supports:

- ✅ HIPAA logging requirements
- ✅ GDPR data protection (no data storage beyond state)
- ✅ SOC 2 security controls
- ✅ PCI DSS requirements
- ✅ OWASP Top 10 protections

### Responsible Disclosure

We appreciate responsible disclosure of security issues:

1. ✅ Privately report security issues to security@example.com
2. ✅ Allow reasonable time for fixes (7-14 days typical)
3. ✅ Provide clear reproduction steps
4. ✅ Avoid unauthorized access or data modification
5. ✅ Don't disclose vulnerabilities until fixed version is available

### Questions?

For security questions or concerns:
- 📧 Email: security@example.com
- 🔒 PGP Key: [Available on request]
- 📋 Security Advisory: https://github.com/your-org/native-shield-guard/security

---

**Last Updated**: April 1, 2026

Thank you for helping keep Native Shield Guard secure! 🛡️
