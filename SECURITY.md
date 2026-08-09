# Security Policy

## Reporting Security Vulnerabilities

GUNGNIR is a security tool designed for **authorized testing only**. If you discover a security vulnerability in GUNGNIR itself, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email the author directly: **andraxpentester@gmail.com**
3. Include a detailed description of the vulnerability
4. Provide steps to reproduce
5. Allow reasonable time for response and fix

### Author

**Syed Zada Abrar** (Andrax Pentester)
- Email: andraxpentester@gmail.com
- Website: [andraxpentester.in](https://andraxpentester.in)
- SentinelReign: [sentinelreign.com](https://sentinelreign.com)

## Responsible Use

GUNGNIR is intended for:
- ✅ Authorized bug bounty programs (Bugcrowd, HackerOne, etc.)
- ✅ Penetration testing with written authorization
- ✅ Security research on systems you own or have permission to test
- ✅ Educational purposes in controlled environments

GUNGNIR must NOT be used for:
- ❌ Testing systems without explicit permission
- ❌ Unauthorized access to systems or data
- ❌ Destructive testing or denial-of-service attacks
- ❌ Any illegal activity

**You are solely responsible for your use of this tool.** The author and contributors are not liable for misuse.

## Scope Enforcement

GUNGNIR includes built-in scope validation:
- Use `gungnir scope --brief brief.txt --target example.com` to verify targets
- The pipeline engine checks scope before every scan
- Out-of-scope targets are blocked and logged

Always validate your scope before testing.

---

*Security policy maintained by [Syed Zada Abrar](https://andraxpentester.in) — [SentinelReign](https://sentinelreign.com)*
