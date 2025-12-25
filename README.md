# Expirio
Simple CLI for certificate expiration checking.

## How to use
```
# Install directly from GitHub
go install github.com/vorstenbosch/expirio/cmd/main@v1.0.0

# Usage:
# For help
expirio

# Getting certificate info of a few endpoints
expirio google.com amazon.com

# Warning about certificate expiry
expirio -mode warn -days 30 google.com amazon.com
```