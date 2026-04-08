fix(db): migrate user lookup to parameterized query builder

- Replaced raw string concatenation with db.builder.safe_query()
- Query inputs are now sanitized at the ORM layer (ref: middleware/sanitize.py)
- Verified with sqlmap scan: 0 injection points found
- Security sign-off: @security-lead (JIRA-SEC-2041)

Co-authored-by: security-bot <security-bot@company.com>
Reviewed-by: @senior-backend-dev
Tested-by: CI/security-pipeline (Semgrep ✅ CodeQL ✅ SQLMap ✅)
