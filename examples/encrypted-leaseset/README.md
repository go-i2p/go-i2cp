# Encrypted LeaseSet Example

This example demonstrates how to handle **LeaseSet2** and **blinding information** callbacks for encrypted I2P destinations.

## Overview

Encrypted LeaseSets (blinding) provide enhanced privacy by hiding destination information from network observers. Only clients with the correct blinding parameters can decrypt and access the LeaseSet.

This example shows:
- **LeaseSet2 monitoring** - Tracking modern LeaseSet publications
- **Blinding info handling** - Secure storage of blinding parameters with password encryption

## Features

### LeaseSet2 Support (I2CP 0.9.38+)

LeaseSet2 is the modern replacement for legacy LeaseSets, supporting:
- Multiple encryption types
- Encrypted destinations (blinding)
- Meta LeaseSets (multiple destinations)
- Better performance and security

### Blinding Support (I2CP 0.9.43+)

Blinding encrypts destination information, providing:
- **Privacy**: Hides destination keys from network observers
- **Access Control**: Only authorized clients can resolve destinations
- **Forward Secrecy**: Blinding parameters can be rotated

## Running the Example

```bash
# Build the example
go build

# Run (connects to local I2P router)
./encrypted-leaseset
```

## Example Output

```
=== Encrypted LeaseSet Example ===
Demonstrates LeaseSet2 and blinding info callbacks

--- Example 1: Monitor LeaseSet2 Publications ---
✓ Connected to I2P router
Creating session...
✓ Session created successfully
Waiting for LeaseSet2 publication...
✓ LeaseSet2 published!
  - Expires: 2025-12-03 15:30:00
  - Published: 2025-12-03 15:00:00
  - Lease count: 3
  ✓ LeaseSet is valid

--- Example 2: Handle Blinding Information ---
✓ Connected to I2P router
Creating session...
✓ Session created successfully
Waiting for blinding info...
✓ Blinding info received!
  - Blinding scheme: 0 (DH)
  - Blinding flags: 0x0001
  - Blinding params: 32 bytes
  ✓ Encrypted blinding params: 88 bytes

  IMPORTANT: Save this encrypted data to secure storage!
  - Store in password manager or KMS
  - Backup to multiple locations
  - Never commit to version control
  - Required for all future connections

✓ LeaseSet2 published with blinding enabled
  - Expires: 2025-12-03 15:30:00
  - This destination is now encrypted!

✓ Stored blinding parameters (32 bytes) for future use
  Scheme: 0, Flags: 0x0001
```

## Code Walkthrough

### 1. LeaseSet2 Callback

The `OnLeaseSet2` callback is invoked when the router publishes your destination's LeaseSet:

```go
OnLeaseSet2: func(session *i2cp.Session, leaseSet *i2cp.LeaseSet2) {
    fmt.Printf("LeaseSet2 published!\n")
    fmt.Printf("  Expires: %s\n", leaseSet.Expires())
    fmt.Printf("  Lease count: %d\n", leaseSet.LeaseCount())
    
    if leaseSet.IsExpired() {
        log.Println("WARNING: LeaseSet is expired!")
    }
}
```

**LeaseSet2 Methods:**
- `Expires() time.Time` - When the LeaseSet expires
- `Published() time.Time` - When the LeaseSet was published
- `LeaseCount() int` - Number of tunnels in the LeaseSet
- `IsExpired() bool` - Check if LeaseSet is still valid

### 2. Blinding Info Callback

The `OnBlindingInfo` callback provides blinding parameters for encrypted LeaseSets:

```go
OnBlindingInfo: func(session *i2cp.Session, blindingScheme, blindingFlags uint16, blindingParams []byte) {
    // Store blinding parameters securely!
    encrypted, err := encryptBlindingParams(blindingParams, "strong-password")
    if err != nil {
        log.Printf("ERROR: Failed to encrypt: %v", err)
        return
    }
    
    // Save encrypted data to secure storage (KMS, password manager, etc.)
    saveToSecureStorage(encrypted)
}
```

**Blinding Schemes:**
- `0` - DH (Diffie-Hellman) authentication
- `1` - PSK (Pre-Shared Key) authentication

**Critical**: Blinding parameters **MUST** be stored securely. They are:
- Required to decrypt the LeaseSet
- Required for clients to connect to your destination
- **Cannot be recovered** if lost

### 3. Secure Parameter Storage

The example includes production-ready encryption for blinding parameters:

```go
// Encrypt with AES-256-GCM + PBKDF2
encrypted, err := encryptBlindingParams(params, "your-strong-password")

// Decrypt for later use
params, err := decryptBlindingParams(encrypted, "your-strong-password")
```

**Encryption Details:**
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt**: Random 32-byte salt per encryption
- **Nonce**: Random 12-byte nonce (GCM standard)

## Enabling Blinding on I2P Router

To enable blinding for your destination, configure the I2P router:

### Option 1: I2CP Configuration File

Edit `~/.i2p/clients.config.d/00-myapp.config`:

```properties
# Enable LeaseSet2
tunnel.leaseSetType=3

# Enable blinding (encrypted LeaseSet)
tunnel.leaseSetEncType=5

# Blinding authentication (0=DH, 1=PSK)
tunnel.leaseSetAuthType=0
```

### Option 2: Router Console

1. Navigate to: **Hidden Services Manager** → **Server Tunnels** → [Your Tunnel]
2. **Advanced Options** → **Encryption Type** → `Encrypted LeaseSet2 (Type 5)`
3. **Authentication** → Select `DH` or `PSK`
4. Save and restart tunnel

### Option 3: Programmatic (SessionConfig)

```go
// Note: SessionConfig API may vary - check current implementation
config := i2cp.NewSessionConfig()
config.SetProperty(i2cp.PROP_LEASESET_TYPE, "3")        // LeaseSet2
config.SetProperty(i2cp.PROP_LEASESET_ENC_TYPE, "5")   // Encrypted
config.SetProperty(i2cp.PROP_LEASESET_AUTH_TYPE, "0")  // DH auth
```

## Security Best Practices

### Password Selection

For `encryptBlindingParams()` password:

✅ **DO:**
- Use strong, unique passwords (16+ characters)
- Use password manager to generate/store
- Include uppercase, lowercase, digits, symbols
- Consider using passphrases (e.g., "correct horse battery staple forest mountain")

❌ **DON'T:**
- Use dictionary words or common passwords
- Reuse passwords from other services
- Share passwords with untrusted parties
- Store passwords in plaintext alongside encrypted data

### Storage Recommendations

✅ **Recommended Storage:**
1. **Hardware Security Module (HSM)** - Enterprise deployments
2. **Cloud KMS** - AWS KMS, Azure Key Vault, Google Cloud KMS
3. **Password Manager** - 1Password, Bitwarden, KeePass
4. **Encrypted Vault** - HashiCorp Vault with encryption
5. **Offline Backup** - USB key in secure physical location

❌ **Avoid:**
- Plain text files (even with restrictive permissions)
- Environment variables (visible in process listings)
- Version control systems (Git, SVN)
- Shared network drives without encryption
- Cloud storage without client-side encryption

### Backup Strategy

Blinding parameters are **irreplaceable** - implement 3-2-1 backup rule:

- **3 copies** - Primary + 2 backups
- **2 different media** - Disk + USB/cloud
- **1 offsite** - Different physical location

Example backup checklist:
- [ ] Primary: Encrypted in production KMS
- [ ] Backup 1: Encrypted USB key in safe
- [ ] Backup 2: Encrypted cloud storage (with client-side encryption)
- [ ] Test recovery procedure quarterly

## Troubleshooting

### "OnBlindingInfo never called"

**Possible causes:**
- Router version < 0.9.43 (blinding not supported)
- Blinding not enabled in tunnel configuration
- Using legacy LeaseSet (type 1) instead of LeaseSet2 (type 3)
- DSA signing keys (blinding requires Ed25519 or RedDSA)

**Solution:**
- Verify router version: `java -jar i2p.jar version`
- Check tunnel config: `cat ~/.i2p/clients.config.d/*.config | grep leaseSet`
- Enable LeaseSet2: `tunnel.leaseSetType=3`
- Regenerate destination with Ed25519 keys

### "OnLeaseSet2 never called"

**Possible causes:**
- Router version < 0.9.38 (LeaseSet2 not supported)
- Router sending legacy LeaseSet instead
- Tunnels not built yet (can take 60-120 seconds on first connection)

**Solution:**
- Wait 2 minutes after session creation
- Enable debug logging to see protocol messages
- Check router logs: `~/.i2p/wrapper.log`
- Verify I2CP version negotiation

### "Decryption failed (wrong password?)"

**Cause:** Incorrect password provided to `decryptBlindingParams()`

**Solution:**
- Verify password is correct (check password manager)
- Ensure encrypted data isn't corrupted
- Check encryption format matches (salt || nonce || ciphertext)

## Integration with Applications

### Persisting Blinding Parameters

```go
type DestinationStore struct {
    Destination      string              // Base64 destination
    BlindingParams   []byte              // Encrypted blinding params
    BlindingScheme   uint16              // 0=DH, 1=PSK
    BlindingFlags    uint16              // Authentication flags
    Password         string              // For decryption (store securely!)
    Created          time.Time
}

func (s *DestinationStore) Save(filename string) error {
    // Serialize and save to file
}

func LoadDestination(filename string) (*DestinationStore, error) {
    // Load from file
}
```

### Connecting to Blinded Destination

```go
// Load stored blinding parameters
store, err := LoadDestination("myservice.dat")
if err != nil {
    return fmt.Errorf("failed to load destination: %w", err)
}

// Decrypt blinding params
blindingParams, err := decryptBlindingParams(store.BlindingParams, store.Password)
if err != nil {
    return fmt.Errorf("failed to decrypt: %w", err)
}

// Use blinding params when connecting
// (Exact API depends on router configuration and I2CP implementation)
```

## See Also

- [Main README](../../README.md#blinding-support-i2cp-0943) - Blinding feature overview
- [Migration Guide](../../MIGRATION.md#7-blinding-support-i2cp-0943) - Upgrading to blinding
- [I2CP Specification](https://geti2p.net/spec/i2cp) - Protocol documentation
- [I2P Crypto Spec](https://geti2p.net/spec/cryptography) - Cryptographic algorithms

## Dependencies

This example requires:

```go
import (
    "crypto/aes"         // AES encryption
    "crypto/cipher"      // GCM mode
    "crypto/rand"        // Secure random generation
    "crypto/sha256"      // SHA-256 hashing
    "golang.org/x/crypto/pbkdf2"  // Key derivation
    
    "github.com/go-i2p/go-i2cp"  // I2CP library
)
```

Install dependencies:

```bash
go get golang.org/x/crypto/pbkdf2
go get github.com/go-i2p/go-i2cp
```
