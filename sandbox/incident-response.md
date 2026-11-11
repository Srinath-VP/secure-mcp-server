# Incident response notes

- Revoke a compromised agent by rotating its credentials and letting short-lived tokens expire.
- Search the audit log by `subject` to see every tool that agent called.
- A broken hash chain means the log was edited: preserve the file and escalate.
