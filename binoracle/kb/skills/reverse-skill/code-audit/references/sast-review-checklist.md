# Code Audit Checklist (Simplified)

- [ ] List of all external input entry points
- [ ] Authentication/Authentication middleware coverage
- [ ] Binding of multi-tenant ID to session
- [ ] Deserialization / pickle / YAML load
- [ ] SSRF outbound and protocol restrictions
- [ ] Key and token storage
- [ ] File upload path and type
- [ ] Dangerous exec/system/Runtime