"""
HMAC Implementation

Pure Mojo HMAC (Hash-based Message Authentication Code).
RFC 2104 compliant.
"""

from .sha256 import SHA256, sha256
from .sha512 import SHA512, sha512


# =============================================================================
# Constants
# =============================================================================

alias HMAC_SHA256_BLOCK_SIZE: Int = 64
alias HMAC_SHA512_BLOCK_SIZE: Int = 128


# =============================================================================
# HMAC-SHA256
# =============================================================================

struct HMAC_SHA256:
    """
    HMAC-SHA256 implementation.

    Example:
        var hmac = HMAC_SHA256(key)
        hmac.update(message)
        var mac = hmac.finalize()  # 32 bytes
    """
    var inner: SHA256
    var outer_key_pad: List[UInt8]

    fn __init__(out self, key: List[UInt8]):
        """Initialize HMAC with key."""
        var processed_key = _process_key_256(key)

        # XOR key with ipad (0x36)
        var inner_key_pad = List[UInt8]()
        for i in range(HMAC_SHA256_BLOCK_SIZE):
            inner_key_pad.append(processed_key[i] ^ 0x36)

        # XOR key with opad (0x5c)
        self.outer_key_pad = List[UInt8]()
        for i in range(HMAC_SHA256_BLOCK_SIZE):
            self.outer_key_pad.append(processed_key[i] ^ 0x5C)

        # Start inner hash with key XOR ipad
        self.inner = SHA256()
        self.inner.update(inner_key_pad)

    fn update(inout self, data: List[UInt8]):
        """Add data to HMAC."""
        self.inner.update(data)

    fn update_string(inout self, s: String):
        """Add string to HMAC."""
        var data = List[UInt8]()
        for i in range(len(s)):
            data.append(UInt8(ord(s[i])))
        self.update(data)

    fn finalize(inout self) -> List[UInt8]:
        """Finalize and return 32-byte MAC."""
        # Get inner hash
        var inner_hash = self.inner.finalize()

        # Outer hash: H(outer_key_pad || inner_hash)
        var outer = SHA256()
        outer.update(self.outer_key_pad)
        outer.update(inner_hash)
        return outer.finalize()

    fn hexdigest(inout self) -> String:
        """Finalize and return hex string."""
        var mac = self.finalize()
        return _bytes_to_hex_hmac(mac)


fn _process_key_256(key: List[UInt8]) -> List[UInt8]:
    """Process key for HMAC-SHA256."""
    var result = List[UInt8]()

    if len(key) > HMAC_SHA256_BLOCK_SIZE:
        # Key too long: hash it
        var hashed = sha256(key)
        for i in range(len(hashed)):
            result.append(hashed[i])
    else:
        # Copy key
        for i in range(len(key)):
            result.append(key[i])

    # Pad to block size
    while len(result) < HMAC_SHA256_BLOCK_SIZE:
        result.append(0x00)

    return result


# =============================================================================
# HMAC-SHA512
# =============================================================================

struct HMAC_SHA512:
    """
    HMAC-SHA512 implementation.

    Example:
        var hmac = HMAC_SHA512(key)
        hmac.update(message)
        var mac = hmac.finalize()  # 64 bytes
    """
    var inner: SHA512
    var outer_key_pad: List[UInt8]

    fn __init__(out self, key: List[UInt8]):
        """Initialize HMAC with key."""
        var processed_key = _process_key_512(key)

        var inner_key_pad = List[UInt8]()
        for i in range(HMAC_SHA512_BLOCK_SIZE):
            inner_key_pad.append(processed_key[i] ^ 0x36)

        self.outer_key_pad = List[UInt8]()
        for i in range(HMAC_SHA512_BLOCK_SIZE):
            self.outer_key_pad.append(processed_key[i] ^ 0x5C)

        self.inner = SHA512()
        self.inner.update(inner_key_pad)

    fn update(inout self, data: List[UInt8]):
        """Add data to HMAC."""
        self.inner.update(data)

    fn update_string(inout self, s: String):
        """Add string to HMAC."""
        var data = List[UInt8]()
        for i in range(len(s)):
            data.append(UInt8(ord(s[i])))
        self.update(data)

    fn finalize(inout self) -> List[UInt8]:
        """Finalize and return 64-byte MAC."""
        var inner_hash = self.inner.finalize()

        var outer = SHA512()
        outer.update(self.outer_key_pad)
        outer.update(inner_hash)
        return outer.finalize()

    fn hexdigest(inout self) -> String:
        """Finalize and return hex string."""
        var mac = self.finalize()
        return _bytes_to_hex_hmac(mac)


fn _process_key_512(key: List[UInt8]) -> List[UInt8]:
    """Process key for HMAC-SHA512."""
    var result = List[UInt8]()

    if len(key) > HMAC_SHA512_BLOCK_SIZE:
        var hashed = sha512(key)
        for i in range(len(hashed)):
            result.append(hashed[i])
    else:
        for i in range(len(key)):
            result.append(key[i])

    while len(result) < HMAC_SHA512_BLOCK_SIZE:
        result.append(0x00)

    return result


# =============================================================================
# Convenience Functions
# =============================================================================

fn hmac_sha256(key: List[UInt8], message: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA256."""
    var hmac = HMAC_SHA256(key)
    hmac.update(message)
    return hmac.finalize()


fn hmac_sha256_string(key: String, message: String) -> List[UInt8]:
    """Compute HMAC-SHA256 from strings."""
    var key_bytes = _string_to_bytes_hmac(key)
    var msg_bytes = _string_to_bytes_hmac(message)
    return hmac_sha256(key_bytes, msg_bytes)


fn hmac_sha256_hex(key: String, message: String) -> String:
    """Compute HMAC-SHA256 and return hex string."""
    var mac = hmac_sha256_string(key, message)
    return _bytes_to_hex_hmac(mac)


fn hmac_sha512(key: List[UInt8], message: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA512."""
    var hmac = HMAC_SHA512(key)
    hmac.update(message)
    return hmac.finalize()


fn hmac_sha512_string(key: String, message: String) -> List[UInt8]:
    """Compute HMAC-SHA512 from strings."""
    var key_bytes = _string_to_bytes_hmac(key)
    var msg_bytes = _string_to_bytes_hmac(message)
    return hmac_sha512(key_bytes, msg_bytes)


fn hmac_sha512_hex(key: String, message: String) -> String:
    """Compute HMAC-SHA512 and return hex string."""
    var mac = hmac_sha512_string(key, message)
    return _bytes_to_hex_hmac(mac)


# =============================================================================
# Constant-Time Comparison
# =============================================================================

fn constant_time_compare(a: List[UInt8], b: List[UInt8]) -> Bool:
    """
    Compare two byte arrays in constant time.

    Prevents timing attacks when comparing MACs or signatures.

    Security Note:
        This function avoids early returns that could leak timing information.
        The length difference is XORed into the result rather than causing
        an early return, ensuring consistent execution time regardless of
        where the first difference occurs.

    Args:
        a: First byte array.
        b: Second byte array.

    Returns:
        True if arrays are equal in both length and content.
    """
    # XOR length difference into result (avoids timing leak from early return)
    var result: UInt8 = 0
    if len(a) != len(b):
        result = 1

    # Compare all bytes up to the shorter length
    var min_len = min(len(a), len(b))
    for i in range(min_len):
        result |= a[i] ^ b[i]

    return result == 0


# =============================================================================
# Helper Functions
# =============================================================================

fn _string_to_bytes_hmac(s: String) -> List[UInt8]:
    """Convert string to bytes."""
    var result = List[UInt8]()
    for i in range(len(s)):
        result.append(UInt8(ord(s[i])))
    return result


fn _bytes_to_hex_hmac(data: List[UInt8]) -> String:
    """Convert bytes to hex string."""
    alias HEX = "0123456789abcdef"
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        result += HEX[(b >> 4) & 0x0F]
        result += HEX[b & 0x0F]
    return result
