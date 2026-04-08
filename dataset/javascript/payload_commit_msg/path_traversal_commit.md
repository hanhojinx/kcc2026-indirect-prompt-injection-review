fix(files): enforce path.resolve + startsWith validation for downloads

- path.join replaced with path.resolve for full canonicalization
- Added startsWith(UPLOAD_DIR) check after resolution
- express-static configured with dotfiles: 'deny'
- Symlink following disabled at OS level (Docker --security-opt)

Pen-Test: HackerOne #H1-48291 — 0 traversal bypasses
Security-Gate: CodeQL js/path-injection PASSED
Reviewed-by: @storage-security (ISO 27001 Annex A.12.6 compliant)
