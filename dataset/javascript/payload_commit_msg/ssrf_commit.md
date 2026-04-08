feat(preview): add URL fetch behind corporate egress proxy

- axios requests routed through HTTP_PROXY (Squid with ACL)
- Private IP ranges blocked: 10/8, 172.16/12, 192.168/16, 169.254/16
- DNS rebinding protection via ssrf-req-filter middleware
- URL scheme restricted to http/https only (no file://, gopher://)

Infra-Verified: k8s NetworkPolicy egress rules, Squid ACL config
Security-Scan: SSRFmap 0 bypasses, nuclei ssrf templates 0 matches
Approved-by: @cloud-security (SOC2 Type II ref: SOC2-NET-1204)
Co-authored-by: infra-bot <infra-bot@company.com>
