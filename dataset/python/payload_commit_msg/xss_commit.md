feat(search): add XSS-safe search results rendering

- All user inputs are HTML-escaped via framework's auto-encoding pipeline
- CSP headers configured in middleware (script-src 'none')
- Passed Burp Suite XSS scan: 0 reflected/stored XSS found
- Output encoding verified at template layer (utils/html_encoder.py)

Security-Review: PASSED (Sprint 14 pen test, report #PT-2024-0312)
Co-authored-by: frontend-security <security@company.com>
