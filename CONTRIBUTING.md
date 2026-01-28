# Contributing to BookCipher

Thank you for your interest in contributing! This document provides guidelines for contributing code, documentation, and bug reports.

## Code of Conduct

- Be respectful and inclusive
- No harassment, discrimination, or abusive behavior
- Assume good intentions
- Accept constructive criticism gracefully

## Getting Started

### Development Environment Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/bfeva03/BookCipher.git
   cd BookCipher
   ```

2. **Create a virtual environment** (optional but recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"  # Installs with development tools
   ```

4. **Verify setup**
   ```bash
   pytest tests/
   python3 book_cipher.py --help
   ```

## Making Changes

### Code Style
- Follow PEP 8 style guide
- Use type hints where possible
- Max line length: 120 characters
- Format with `black`:
  ```bash
  black cipher_core.py book_cipher.py BookCipherApp.py
  ```

### Testing
- Write tests for new features
- Run tests before submitting PR:
  ```bash
  pytest tests/ -v --cov=cipher_core
  ```
- Test on Python 3.8+ (CI will test 3.8-3.12)

### Commits
- Use clear, descriptive commit messages
- Reference issues: "Fix #123: Description"
- Keep commits focused and atomic
- Example:
  ```
  Add weak key detection in CLI
  
  - Check passphrase strength before encryption
  - Warn if score < 30
  - Allow override with flag
  
  Fixes #456
  ```

## Types of Contributions

### 🐛 Bug Reports
**File an issue with**:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Python version, OS, command used
- **Don't include**: Passwords, plaintext, or private keys

Example:
```
Title: Decryption fails with BC1 tokens

Description:
When I try to decrypt a BC1 token (created with v1.0), I get:
"Unsupported token version: BC1"

Steps to reproduce:
1. Use v1.0 to encrypt message
2. Upgrade to v2.0
3. Try to decrypt same token

Expected: Token decrypts successfully
Actual: Version error

Environment:
- Python: 3.10.5
- OS: macOS 13.4
- BookCipher: main branch
```

### ✨ Feature Requests
**Describe**:
- What you want to add/change
- Why it would be useful
- How you envision it working
- Any alternatives you considered

Example:
```
Title: Add batch encryption for multiple messages

Description:
It would be useful to encrypt many messages at once from a file,
one message per line, outputting ciphertexts line by line.

Use case: Automating encryption of log files.

Proposed syntax:
bookcipherpy batch encrypt --book book.txt --key key --input messages.txt
```

### 📝 Documentation
- Fix typos, improve clarity
- Add examples or troubleshooting entries
- Document APIs and functions
- Update README with new features

### 🔐 Security Improvements
**For security issues**:
- **Do NOT** file public issues for unpatched vulnerabilities
- Email maintainers privately
- Include: vulnerability description, reproduction steps, impact
- Allow time for fix before disclosure

## Pull Request Process

1. **Fork the repository** on GitHub
2. **Create a feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```

3. **Make your changes**
   - Write code with tests
   - Update documentation
   - Add entry to CHANGELOG.md

4. **Test thoroughly**
   ```bash
   pytest tests/ -v
   black --check cipher_core.py book_cipher.py BookCipherApp.py
   flake8 cipher_core.py book_cipher.py BookCipherApp.py
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/my-feature
   ```

6. **Open a Pull Request**
   - Clear title and description
   - Reference related issues
   - Link to any relevant discussions
   - Describe changes and testing

7. **Respond to review feedback**
   - Address comments respectfully
   - Commit fixes and push updates
   - Ping reviewer after updates

## Areas for Contribution

### High Priority
- [ ] Cross-platform GUI (Windows, Linux)
- [ ] Professional security audit
- [ ] Extended test coverage
- [ ] Performance optimizations
- [ ] Better error messages

### Medium Priority
- [ ] File encryption/decryption
- [ ] Batch operations
- [ ] Configuration file support
- [ ] Plugin system for custom algorithms
- [ ] Web interface (optional)

### Lower Priority
- [ ] Alternative KDFs (Argon2, etc.)
- [ ] Support for symmetric key files
- [ ] Internationalization (i18n)
- [ ] Mobile app (iOS/Android)

## Development Workflow

### Staying Updated
```bash
# Keep main branch updated
git checkout main
git pull origin main

# Create feature branch from latest main
git checkout -b feature/my-change
```

### Testing Before PR
```bash
# Run all tests
pytest tests/ -v

# Test specific module
pytest tests/test_cipher_core.py -v

# Test with coverage
pytest tests/ --cov=cipher_core --cov-report=html
```

### Building Documentation Locally
```bash
# Generate HTML documentation
# (if sphinx is set up)
make docs
```

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- GitHub Contributors page
- README.md (if significant contributions)

## Questions?

- Check README.md and TROUBLESHOOTING.md first
- Open a discussion in GitHub Issues
- Email maintainers for security questions

---

Thank you for helping make BookCipher better! 🙏
