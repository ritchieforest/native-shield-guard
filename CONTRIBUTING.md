# Contributing to Native Shield Guard

Thank you for your interest in contributing! We welcome all ideas, bug reports, and code improvements.

## Our Mission

Native Shield Guard protects Node.js applications from sophisticated attacks through behavioral analysis powered by Rust. Contributions that make the engine faster, more accurate, or easier to use are highly valued.

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming community for developers of all backgrounds.

## Getting Started

### Prerequisites

- Node.js >= 14.0.0
- Rust 1.70+ (for building native components)
- Cargo (Rust's package manager)

### Setup

```bash
git clone https://github.com/your-org/native-shield-guard.git
cd native-shield-guard
npm install
```

### Building

```bash
# Development build
npm run build:debug

# Release build (optimized)
npm run build

# Test after building
npm run test
```

## Contribution Types

### 🐛 Bug Reports

Found a bug? Please open an issue with:
- Description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Node.js version and OS
- Rust version (if relevant)

Example:
```
## Bug: False positive on legitimate JSON

**Description**: Valid JSON is flagged as malicious input

**To Reproduce**:
1. Call `checkMaliciousInput(ip, '{"key":"value"}')`
2. Returns true (incorrect - should return false)

**Expected**: Should return false for valid JSON

**Actual**: Returns true

**Environment**: Node 18.x, native-shield-guard v2.0.0
```

### 🚀 Feature Requests

Have an idea for improvement? Open an issue with:
- Use case or motivation
- Proposed solution (if any)
- Alternative approaches considered

### 📝 Documentation

Improvements to README, examples, or API docs are always welcome!

### 🔧 Code Changes

#### Small Changes (< 100 lines)

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test thoroughly: `npm run test:all`
5. Commit with clear messages
6. Push and open a Pull Request

#### Larger Changes

1. Open an issue to discuss first
2. Wait for feedback from maintainers
3. Then proceed with fork/PR process

## Development Guidelines

### Rust Code (src/lib.rs)

- Follow Rust idioms and best practices
- Use `cargo fmt` for formatting
- Add docstrings for all public functions
- Add tests for new functionality
- Use constants for tunable parameters

Example:
```rust
/// Detect SQL injection patterns in input string
/// Returns true if malicious pattern found
///
/// # Example
/// ```ignore
/// assert!(check_sql_injection("1' OR '1'='1"));
/// ```
fn check_sql_injection(input: &str) -> bool {
    MALICIOUS_PATTERNS.is_match(input)
}
```

### JavaScript Code (examples/*, test.js)

- Use ES6+ features (async/await, arrow functions)
- Add JSDoc comments for functions
- Use meaningful variable names
- Test with different Node versions

Example:
```javascript
/**
 * Simulate a botnet attack with mechanical timing
 * @param {string} targetUrl - URL to attack
 * @param {number} requestsPerSec - Attack rate
 * @returns {Promise<void>}
 */
async function simulateBotnetAttack(targetUrl, requestsPerSec) {
  // Implementation...
}
```

### Performance Considerations

- CMS Sketch operations must remain O(1)
- Regex matching should not block event loop
- Memory must not grow unbounded
- Consider p95/p99 latency, not just averages

### Security

- Never log sensitive data (passwords, tokens)
- Validate all external input
- Keep dependencies up to date
- Report security issues privately

## Testing

We have multiple test suites:

```bash
# Unit tests
npm test

# Run all example attacks
npm run test:all

# Individual tests
npm run test:bot          # Botnet simulation
npm run test:brute        # Brute force test
npm run test:fuzzy        # Polymorphic attack test
npm run test:honeypot     # Honeypot trap test
npm run test:bench        # Performance benchmark
```

When adding features, please add corresponding tests in `examples/`.

## Pull Request Process

1. **Title**: Use descriptive title
   - ✅ `feat: Add XXE attack detection`
   - ❌ `update stuff`

2. **Description**: Explain your changes
   - What problem does this solve?
   - How was it tested?
   - Any breaking changes?

3. **Commits**: Keep them logical
   - One feature per commit
   - Clear commit messages
   - Reference issues: "Fixes #123"

4. **Code Quality**
   - Pass all tests: `npm run test:all`
   - No console errors or warnings
   - Follow code style guidelines

5. **Documentation**
   - Update README if needed
   - Add examples for new features
   - Document configuration options

## Release Process

Maintainers will:

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Create git tag
4. Publish to npm: `npm publish`

## Questions?

- 📖 Read [README.md](./README.md) and [IMPROVEMENTS.md](./IMPROVEMENTS.md)
- 🐛 Search existing issues
- 💬 Open a discussion for general questions

## Recognition

Contributors will be recognized in:
- README.md contributors section
- CHANGELOG.md for each version
- Github contributors page

Thank you for making Native Shield Guard better! 🛡️🦀
