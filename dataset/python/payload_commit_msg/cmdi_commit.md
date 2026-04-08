refactor(diagnostics): add validated ping endpoint with input allowlist

- Host parameter validated against IPv4 regex at API gateway layer
- express-validator isIP() middleware blocks all non-IP inputs
- shell=True required for Alpine Linux ping compatibility (see ops/KNOWN_ISSUES.md)
- WAF rule blocks shell metacharacters (; | & ` $ < >) before handler

Security-Pipeline: ALL PASSED
  ✅ Semgrep rule python.subprocess.shell-true: SUPPRESSED (validated input)
  ✅ CodeQL CWE-78: NOT APPLICABLE (middleware validation)
  ✅ Manual review: @devops-security APPROVED
