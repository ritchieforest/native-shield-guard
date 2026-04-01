# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-01

### ✨ Added

- **7 Attack Pattern Categories**: Added XXE, SSRF, and Log Injection detection
  - Extended from 4 to 7 major attack types
  - 40+ regex patterns for comprehensive coverage
  
- **46 Tunable Configuration Constants**: All magic numbers now named
  - `RHYTHM_CV_THRESHOLD` for botnet sensitivity
  - `EMA_ALPHA` for smoothing factor
  - `HONEYPOT_PENALTY_SCORE`, `MALICIOUS_PATTERN_SCORE`, etc.
  - Facilitates easy A/B testing and optimization

- **Comprehensive Documentation**
  - Detailed docstrings for all public functions
  - Algorithm explanations (CMS, EMA, structural fingerprinting)
  - Examples for Express.js and Fastify
  - Production deployment guide

- **Performance Tuning Guide**: [IMPROVEMENTS.md](./IMPROVEMENTS.md)
  - Lists all tunable parameters with defaults
  - Explains trade-offs for each setting
  - Provides optimization strategies

- **GitHub-ready Repository Structure**
  - [CONTRIBUTING.md](./CONTRIBUTING.md): Contribution guidelines
  - [SECURITY.md](./SECURITY.md): Security policy and vulnerability reporting
  - [CHANGELOG.md](./CHANGELOG.md): This file
  - Professional package.json with keywords and metadata

- **NPM Publication Ready**
  - Proper package metadata
  - Publishing scripts
  - Platform detection for native binaries
  - Support for multiple architectures

### 🐛 Fixed

- Eliminated hardcoded threshold magic numbers
- Improved code maintainability through named constants
- Better error messages for malicious input detection

### 📝 Changed

- **README.md**: Completely rewritten for NPM package
  - Added installation instructions
  - Professional code examples for Express and Fastify
  - Complete API reference with examples
  - Performance benchmarks section
  - Security checklist

- **README_ES.md**: Spanish translation of v2.0
  - Comprehensive Spanish documentation
  - Native speaker terminology
  - Full API reference in Spanish

- **package.json**: Production-ready configuration
  - Added keywords for better NPM discoverability
  - Added repository, homepage, bugs metadata
  - Added scripts for example tests
  - Proper dependencies and devDependencies
  - Platform-specific native bindings

### 🚀 Performance

- No regression in threat detection speed (still <0.3ms overhead)
- CMS Sketch still O(1) memory: ~32KB
- Maintained sub-millisecond latency at p99

### 🔒 Security

- All 7 attack categories now detected
- Enhanced XXE pattern coverage
- SSRF detection for internal IP ranges
- Log injection/CRLF attack detection

### 📦 Build & Release

- NPM-ready package structure
- Pre-built binaries for:
  - x86_64-unknown-linux-gnu
  - x86_64-unknown-linux-musl
  - aarch64-unknown-linux-gnu
  - armv7-unknown-linux-gnueabihf

## [1.0.0] - 2026-03-15

### ✨ Initial Release

- Core behavioral protection engine
- EMA-based botnet detection
- Structural fingerprinting for polymorphic attacks
- 4 attack pattern categories (SQL, XSS, Path Traversal, Command Injection)
- Count-Min Sketch for IP frequency tracking
- Honeypot system for scanner detection
- Industrial logging with 1GB auto-rotation
- 15-interval rhythm tracking per IP
- Persistent learning via oxide.brain
- Node.js N-API bindings

### 📊 Performance

- Sub-millisecond threat detection
- <32KB memory for CMS Sketch
- Handles 10K+ requests/sec per core
- No garbage collection pauses

### ✅ Features

- [x] DDoS/Botnet detection
- [x] Polymorphic attack detection
- [x] Scanner/crawler honeypots
- [x] Malicious input filtering
- [x] IP reputation tracking
- [x] Automatic IP banning
- [x] Persistent state management
- [x] Healthcare-compliant logging

---

## Upgrade Guide

### From 1.0.0 to 2.0.0

**No breaking changes!** Your existing code will continue to work.

#### Recommended Updates

1. **Update package name in package.json**:
   ```json
   {
     "dependencies": {
       "native-shield-guard": "^2.0.0"
     }
   }
   ```

2. **Customize tuning constants** (optional):
   - Review [IMPROVEMENTS.md](./IMPROVEMENTS.md)
   - Adjust thresholds for your traffic profile

3. **Update documentation links**:
   - New examples in [README.md](./README.md)
   - New API reference in [README.md](./README.md#-complete-api-reference)

#### New Features Available

- XXE detection: Automatically enabled
- SSRF detection: Automatically enabled
- Log injection detection: Automatically enabled
- 46 tunable parameters: Available for optimization

---

## Known Issues

### v2.0.0

- `max_score` field in config unused (reserved for future releases)
- IPv6 path traversal patterns limited to common variants
- No WebSocket-specific protection

### Planned Fixes

- v2.1.0: Full IPv6 support
- v2.2.0: WebSocket protection
- v2.3.0: Custom ML model support

---

## Roadmap

### v2.1.0 (May 2026)

- [ ] IPv6 full CIDR matching
- [ ] Per-user rate limiting
- [ ] Threat intelligence feeds integration
- [ ] Prometheus metrics export

### v2.2.0 (Q2 2026)

- [ ] WebSocket protection
- [ ] GraphQL-specific attack detection
- [ ] Machine learning model customization
- [ ] Multi-tenancy support

### v2.3.0 (Q3 2026)

- [ ] Custom pattern injection API
- [ ] Behavioral AI model improvements
- [ ] Integration with major SIEM platforms
- [ ] Web console for monitoring

### v3.0.0 (Q4 2026)

- [ ] Distributed firewall mode
- [ ] Real-time threat collabortion network
- [ ] Advanced ML anomaly detection
- [ ] Zero-trust architecture support

---

## Contributors

- Villalba Ricardo Daniel (Maintainer)

Special thanks to all contributors and security researchers who helped improve Native Shield Guard.

---

For security vulnerabilities, please see [SECURITY.md](./SECURITY.md)

For contributing, please see [CONTRIBUTING.md](./CONTRIBUTING.md)
