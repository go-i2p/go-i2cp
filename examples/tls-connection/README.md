# TLS Connection Example

This example demonstrates how to establish secure I2CP connections using TLS authentication (Method 2).

## Overview

TLS authentication provides stronger security than username/password authentication by using X.509 certificates for mutual authentication between the client and I2P router. This is the **recommended authentication method** for production deployments.

## Features Demonstrated

- **TLS with Client Certificates** (recommended) - Mutual TLS authentication
- **TLS Insecure Mode** (localhost development only) - Skip certificate verification for localhost (127.0.0.1, ::1)
- **Dual Authentication** - TLS with username/password fallback

## Prerequisites

### 1. I2P Router Configuration

Enable TLS in your I2P router configuration (`~/.i2p/router.config`):

```properties
i2cp.enabled=true
i2cp.ssl=true
i2cp.ssl.certFile=/path/to/router-cert.pem
i2cp.ssl.keyFile=/path/to/router-key.pem
i2cp.ssl.caFile=/path/to/ca-cert.pem
```

### 2. Generate TLS Certificates

Create certificates for mutual TLS authentication:

```bash
# Generate CA certificate (Certificate Authority)
openssl req -x509 -newkey rsa:4096 \
    -keyout ca-key.pem -out ca-cert.pem \
    -days 365 -nodes \
    -subj "/CN=I2CP-CA/O=MyOrganization"

# Generate client certificate request
openssl req -newkey rsa:4096 \
    -keyout client-key.pem -out client-req.pem \
    -nodes \
    -subj "/CN=i2cp-client/O=MyOrganization"

# Sign client certificate with CA
openssl x509 -req -in client-req.pem \
    -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem \
    -days 365

# Generate router certificate (if needed)
openssl req -newkey rsa:4096 \
    -keyout router-key.pem -out router-req.pem \
    -nodes \
    -subj "/CN=i2cp-router/O=MyOrganization"

openssl x509 -req -in router-req.pem \
    -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out router-cert.pem \
    -days 365

# Clean up temporary files
rm client-req.pem router-req.pem ca-cert.srl
```

### 3. File Permissions

Secure your private keys:

```bash
chmod 600 client-key.pem router-key.pem ca-key.pem
chmod 644 client-cert.pem router-cert.pem ca-cert.pem
```

## Running the Example

### Update Certificate Paths

Edit `tls_connection_example.go` and update the certificate paths:

```go
client.SetProperty("i2cp.SSL.certFile", "/actual/path/to/client-cert.pem")
client.SetProperty("i2cp.SSL.keyFile", "/actual/path/to/client-key.pem")
client.SetProperty("i2cp.SSL.caFile", "/actual/path/to/ca-cert.pem")
```

### Run the Example

```bash
# Run with default TLS configuration
go run tls_connection_example.go

# Or build and run
go build
./tls-connection
```

## Example Output

```
=== TLS Connection Example ===
Demonstrates secure I2CP connection with TLS certificates

--- Example 1: TLS with Client Certificates ---
Connecting to I2P router with TLS...
✓ Connected successfully with TLS authentication
Creating session...
✓ Session created successfully

TLS connection example completed successfully!
```

## Configuration Options

### TLS Properties

| Property | Description | Default |
|----------|-------------|---------|
| `i2cp.SSL` | Enable TLS | `false` |
| `i2cp.SSL.certFile` | Client certificate path (PEM) | `""` |
| `i2cp.SSL.keyFile` | Client private key path (PEM) | `""` |
| `i2cp.SSL.caFile` | CA certificate path (PEM) | `""` (uses system pool) |
| `i2cp.SSL.insecure` | Skip certificate verification | `false` |

### Security Recommendations

✅ **DO:**
- Use strong RSA keys (4096-bit minimum)
- Protect private keys with file permissions (chmod 600)
- Use different certificates for each client in production
- Rotate certificates periodically (annually recommended)
- Store CA private key securely offline

❌ **DON'T:**
- Use `insecure` mode in production (development only!)
- Share private keys between clients
- Commit certificates to version control
- Use self-signed certificates without CA validation

## Troubleshooting

### Error: "x509: certificate signed by unknown authority"

**Cause:** Router's certificate not signed by the CA specified in `i2cp.SSL.caFile`

**Solution:**
- Ensure both client and router certificates are signed by the same CA
- Verify CA certificate path is correct
- Check CA certificate file is readable

### Error: "tls: bad certificate"

**Cause:** Certificate/key mismatch or invalid certificate

**Solution:**
- Verify certificate and key match: `openssl x509 -noout -modulus -in client-cert.pem | openssl md5`
  and `openssl rsa -noout -modulus -in client-key.pem | openssl md5` should match
- Check certificate hasn't expired: `openssl x509 -in client-cert.pem -noout -dates`
- Ensure files are in PEM format (not DER)

### Error: "connection refused"

**Cause:** Router not listening on I2CP port or TLS not enabled

**Solution:**
- Verify router is running: `ps aux | grep i2p`
- Check I2CP is enabled: `grep i2cp.enabled ~/.i2p/router.config`
- Verify TLS is enabled: `grep i2cp.ssl ~/.i2p/router.config`
- Check port: `netstat -tln | grep 7654`

### Development: Using Insecure Mode

For development/testing with **localhost only**, you can skip certificate verification:

```go
client.SetProperty("i2cp.SSL", "true")
client.SetProperty("i2cp.SSL.insecure", "true")
```

**⚠️ CRITICAL SECURITY RESTRICTIONS:**

✅ **ALLOWED:**
- Localhost addresses: `127.0.0.1:7654`, `[::1]:7654`
- Local development/testing only
- Never in production environments

❌ **NEVER ALLOWED:**
- Remote host connections (any non-localhost address)
- Production deployments
- Public-facing services
- Any network-accessible endpoint

This disables all certificate validation for **localhost connections only**. Using insecure mode for remote hosts creates severe security vulnerabilities including man-in-the-middle attacks.

## TLS Version and Cipher Suites

go-i2cp uses Go's crypto/tls with the following defaults:

- **Minimum TLS Version:** TLS 1.2 (recommended by I2CP spec)
- **Cipher Suites:** Go's default secure cipher suites
- **Certificate Validation:** Full chain validation enabled by default

## Integration with Applications

### Docker/Container Deployments

Mount certificates as volumes:

```yaml
# docker-compose.yml
services:
  myapp:
    image: myapp:latest
    volumes:
      - ./certs/client-cert.pem:/etc/i2cp/client-cert.pem:ro
      - ./certs/client-key.pem:/etc/i2cp/client-key.pem:ro
      - ./certs/ca-cert.pem:/etc/i2cp/ca-cert.pem:ro
    environment:
      - I2CP_TLS_CERT=/etc/i2cp/client-cert.pem
      - I2CP_TLS_KEY=/etc/i2cp/client-key.pem
      - I2CP_TLS_CA=/etc/i2cp/ca-cert.pem
```

### Environment Variables

```go
import "os"

certFile := os.Getenv("I2CP_TLS_CERT")
keyFile := os.Getenv("I2CP_TLS_KEY")
caFile := os.Getenv("I2CP_TLS_CA")

client.SetProperty("i2cp.SSL", "true")
client.SetProperty("i2cp.SSL.certFile", certFile)
client.SetProperty("i2cp.SSL.keyFile", keyFile)
client.SetProperty("i2cp.SSL.caFile", caFile)
```

## See Also

- [Migration Guide](../../MIGRATION.md#migrating-to-tls-authentication) - Upgrading from username/password auth
- [I2CP Specification](https://geti2p.net/spec/i2cp) - Official protocol documentation
- [OpenSSL Documentation](https://www.openssl.org/docs/) - Certificate generation reference

## Support

If you encounter issues:

1. Enable debug logging to see TLS handshake details
2. Verify certificates with OpenSSL tools
3. Check I2P router logs for TLS errors
4. See main [README.md](../../README.md#troubleshooting) for general troubleshooting
