# Expirio
Simple CLI for certificate expiration checking.

## How to use
```
# Install directly from GitHub
go install github.com/vorstenbosch/expirio/cmd/main@latest

# Use
expirio google.com
```

## TODO
- Warn mode. If you use the option --warn with --days 30 it will only return the certificates of hosts that are expiring within 30 days (if none found no output -> for automations)