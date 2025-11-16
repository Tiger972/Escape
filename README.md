# 🔐 OWASP Top 10 2025 - Penetration Testing Demonstration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-blue)](https://owasp.org/www-project-top-ten/)
[![Node.js](https://img.shields.io/badge/node.js-v18+-green)](https://nodejs.org/)

> Professional penetration testing assessment demonstrating critical API security vulnerabilities aligned with the OWASP Top 10 2025 framework.

## 📋 Overview

This project showcases practical security testing skills through the identification and exploitation of **6 vulnerabilities** in a purposefully vulnerable Node.js API, with emphasis on **business logic flaws** that traditional automated scanners cannot reliably detect.

**Assessment Results:**
- 🔴 **3 Critical** vulnerabilities (CVSS 8.2-9.8)
- 🟠 **2 High** vulnerabilities (CVSS 7.0-7.5)
- 🟡 **1 Medium** vulnerability (CVSS 6.5)

## 🎯 Key Findings

| ID | Vulnerability | Type | Severity | CVSS |
|----|---------------|------|----------|------|
| VULN-001 | Broken Object Level Authorization (BOLA) | Business Logic | Critical | 8.2 |
| VULN-002 | SQL Injection in Authentication | Technical | Critical | 9.8 |
| VULN-003 | Broken Function Level Authorization (BFLA) | Business Logic | Critical | 8.8 |
| VULN-004 | Weak Password Hashing (MD5) | Cryptographic | High | 7.5 |
| VULN-005 | Fail Open Exception Handling | Business Logic | Medium | 6.5 |
| VULN-006 | Security Misconfiguration | Configuration | High | 7.0 |

## 📄 Full Report

The comprehensive report includes:
- ✅ Executive summary with risk assessment
- ✅ Detailed methodology (4-phase approach)
- ✅ Proof-of-concept exploits with screenshots
- ✅ Impact analysis for each vulnerability
- ✅ Before/After code remediation examples
- ✅ CVSS scoring and OWASP mappings

## 🔍 Critical Insight

**50% of critical vulnerabilities** discovered (BOLA, BFLA, Fail Open) are **business logic flaws** requiring contextual understanding of application workflows—vulnerabilities that traditional automated scanners cannot reliably detect.

### Why This Matters

Modern APIs present complex authorization models where security depends not just on code correctness, but on properly enforcing business rules across user contexts. This assessment demonstrates the importance of:

- User ownership and relationship validation
- Role hierarchies and permission enforcement
- Multi-step workflow security
- Exception handling in distributed systems

## 📊 Testing Methodology

**4-Phase Manual Penetration Testing Approach:**

1. **Reconnaissance**
   - API endpoint discovery
   - Schema analysis
   - Authentication mechanisms review

2. **Vulnerability Identification**
   - OWASP Top 10 2025 focused testing
   - Business logic vulnerability analysis
   - Access control verification

3. **Exploitation**
   - Proof of concept development
   - Impact assessment
   - Screenshot documentation

4. **Reporting**
   - CVSS severity classification
   - Detailed remediation recommendations
   - Before/After code examples

**Testing Duration:** 27 hours  
**Tools Used:** curl, custom scripts, manual testing  
**Target:** Intentionally vulnerable Node.js API

## 🛡️ Vulnerability Breakdown

### VULN-001: Broken Object Level Authorization (BOLA)
**CVSS 8.2 | CRITICAL**

Unauthorized access to other users' orders by manipulating object IDs in API requests. Demonstrates the critical importance of implementing proper ownership verification before returning sensitive data.

### VULN-002: SQL Injection in Authentication
**CVSS 9.8 | CRITICAL**

Authentication bypass through SQL injection in the login endpoint, allowing complete system compromise. Shows the dangers of string concatenation in database queries.

### VULN-003: Broken Function Level Authorization (BFLA)
**CVSS 8.8 | CRITICAL**

Regular users can access administrative functions due to missing role-based access controls. Illustrates privilege escalation through inadequate authorization checks.

### VULN-004: Cryptographic Failures - Weak Password Hashing
**CVSS 7.5 | HIGH**

Passwords hashed using deprecated MD5 algorithm without salt, making them vulnerable to rainbow table attacks. All user credentials compromised in seconds.

### VULN-005: Mishandling of Exceptional Conditions (Fail Open)
**CVSS 6.5 | MEDIUM**

Application grants access to premium content when authorization service fails, implementing insecure "fail open" behavior. Revenue loss and business logic violation.

### VULN-006: Security Misconfiguration
**CVSS 7.0 | HIGH**

Multiple security misconfigurations including:
- Wildcard CORS allowing requests from any origin
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Verbose error messages exposing stack traces
- No rate limiting on authentication endpoints

## 🎓 Skills Demonstrated

This assessment showcases proficiency in:

- 🔍 Manual penetration testing techniques
- 🏗️ Understanding complex API authorization models
- 💻 Identifying business logic vulnerabilities
- 📝 Professional security report writing
- 🛠️ Secure code remediation strategies
- 🎯 OWASP Top 10 2025 framework application

## ⚠️ Disclaimer

This report documents findings from testing a **purposefully vulnerable demonstration API** created for **educational purposes only**.

**DO NOT:**
- Use these techniques against systems you don't own
- Deploy vulnerable code in production environments
- Use this information for malicious purposes

**DO:**
- Learn from the vulnerabilities and remediation strategies
- Practice ethical hacking skills in controlled environments
- Share knowledge responsibly within the security community

## 👤 Author

**Andy Piquionne**  
Security Researcher | Penetration Tester

- 💼 LinkedIn: https://www.linkedin.com/in/andy-piquionne/
- 📧 Email: andy.piquionne@icloud.com

## 🙏 Acknowledgments

- **[OWASP Foundation](https://owasp.org/)** - For the Top 10 2025 framework
- **[Escape Security](https://escape.tech/)** - Inspiration for context-aware API security testing
- The global **security research community** for continuous knowledge sharing

## 📚 References

- [OWASP Top 10 2025](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
