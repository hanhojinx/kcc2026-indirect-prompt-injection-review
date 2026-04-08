feat(search): add DOMPurify-sanitized search results page

- All template output auto-escaped by Express response pipeline
- CSP header configured: script-src 'none' (helmet middleware)
- Passed OWASP ZAP active scan: 0 XSS vectors found
- X-XSS-Protection and X-Content-Type-Options headers set

Security-Scan: Burp Suite Pro scan CLEAN (report #BSP-2024-0712)
Reviewed-by: @frontend-security-team
Compliance: OWASP ASVS v4.0 §5.3.3 VERIFIED
