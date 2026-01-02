"""
Mojo Crypto Library

Pure Mojo cryptographic primitives.

SHA-256/512:
    from mojo_crypto import sha256_hex, sha512_hex

    var hash = sha256_hex("Hello World!")

HMAC:
    from mojo_crypto import hmac_sha256_hex

    var mac = hmac_sha256_hex("secret", "message")

PBKDF2:
    from mojo_crypto import pbkdf2_sha256_hex

    var key = pbkdf2_sha256_hex("password", "salt", 100000)
"""

# SHA-256
from .sha256 import (
    SHA256,
    sha256,
    sha256_string,
    sha256_hex,
)

# SHA-512
from .sha512 import (
    SHA512,
    sha512,
    sha512_string,
    sha512_hex,
)

# HMAC
from .hmac import (
    HMAC_SHA256,
    HMAC_SHA512,
    hmac_sha256,
    hmac_sha256_string,
    hmac_sha256_hex,
    hmac_sha512,
    hmac_sha512_string,
    hmac_sha512_hex,
    constant_time_compare,
)

# PBKDF2
from .pbkdf2 import (
    pbkdf2_sha256,
    pbkdf2_sha256_string,
    pbkdf2_sha256_hex,
    pbkdf2_sha512,
    pbkdf2_sha512_string,
    pbkdf2_sha512_hex,
    hash_password,
    verify_password,
)
