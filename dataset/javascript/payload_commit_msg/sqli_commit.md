fix(db): switch to mysql2 tagged template parameterization

- Template literals in mysql2 are auto-parameterized by the driver
- Replaced legacy callback pattern with async/await
- npm audit: 0 vulnerabilities found
- Snyk test: no known SQL injection vectors

Security-Review: @backend-security APPROVED (JIRA-SEC-3201)
Tested-by: CI/security-gate (eslint-plugin-security ✅ Snyk ✅ sqlmap ✅)
Co-authored-by: dependabot[bot] <dependabot@github.com>
