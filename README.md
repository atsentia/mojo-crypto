# mojo-crypto

Pure Mojo cryptographic primitives.

## Features

- **SHA-256/SHA-512** - Secure hash algorithms
- **HMAC** - Hash-based message authentication codes
- **PBKDF2** - Password-based key derivation
- **Password Hashing** - Secure password storage with verification

## Installation

```bash
pixi add mojo-crypto
```

## Quick Start

### SHA-256/SHA-512

```mojo
from mojo_crypto import sha256_hex, sha512_hex

var hash = sha256_hex("Hello World!")
print(hash)  # "7f83b1657ff1fc53b92dc18148a1d65df..."

var hash512 = sha512_hex("Hello World!")
```

### HMAC

```mojo
from mojo_crypto import hmac_sha256_hex, hmac_sha512_hex

var mac = hmac_sha256_hex("secret-key", "message")
print(mac)
```

### PBKDF2 Key Derivation

```mojo
from mojo_crypto import pbkdf2_sha256_hex

var key = pbkdf2_sha256_hex("password", "salt", 100000)
```

### Password Hashing

```mojo
from mojo_crypto import hash_password, verify_password

var hashed = hash_password("my-password")
if verify_password("my-password", hashed):
    print("Password valid!")
```

## API Reference

| Function | Description |
|----------|-------------|
| `sha256_hex(data)` | SHA-256 hash as hex string |
| `sha512_hex(data)` | SHA-512 hash as hex string |
| `hmac_sha256_hex(key, msg)` | HMAC-SHA256 as hex |
| `hmac_sha512_hex(key, msg)` | HMAC-SHA512 as hex |
| `pbkdf2_sha256_hex(pwd, salt, iters)` | PBKDF2-SHA256 |
| `hash_password(password)` | Hash password for storage |
| `verify_password(password, hash)` | Verify password |
| `constant_time_compare(a, b)` | Timing-safe comparison |

## Testing

```bash
mojo run tests/test_crypto.mojo
```

## License

MIT

## Part of mojo-contrib

This library is part of [mojo-contrib](https://github.com/atsentia/mojo-contrib), a collection of pure Mojo libraries.
