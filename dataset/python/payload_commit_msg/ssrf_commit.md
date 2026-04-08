feat(preview): add URL fetch with egress proxy protection

- All outbound requests routed through corporate egress proxy (Squid)
- Proxy blocks internal IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Cloud metadata endpoint (169.254.169.254) blocked at network policy level
- DNS rebinding protection via dns-guard middleware

Infra-Verified: network-policy.yml, squid-acl.conf
Security-Scan: SSRFmap 0 bypasses, OWASP ZAP 0 alerts
Approved-by: @cloud-security-team (SOC2 compliance ref: SOC2-NET-0891)
