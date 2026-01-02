"""
PBKDF2 Implementation

Pure Mojo PBKDF2 (Password-Based Key Derivation Function 2).
RFC 2898 / RFC 8018 compliant.
"""

from .hmac import hmac_sha256, hmac_sha512


# =============================================================================
# Security Constants
# =============================================================================

alias MIN_ITERATIONS: Int = 10000
"""Minimum iterations for password hashing (OWASP recommendation)."""

alias MIN_SALT_LENGTH: Int = 16
"""Minimum salt length in bytes (128 bits, NIST SP 800-132)."""


# =============================================================================
# PBKDF2-HMAC-SHA256
# =============================================================================

fn pbkdf2_sha256(
    password: List[UInt8],
    salt: List[UInt8],
    iterations: Int,
    dk_len: Int = 32,
) -> List[UInt8]:
    """
    Derive key using PBKDF2-HMAC-SHA256.

    Args:
        password: Password bytes.
        salt: Salt bytes (should be at least 16 bytes).
        iterations: Number of iterations (minimum 10000 recommended).
        dk_len: Desired key length in bytes (default 32).

    Returns:
        Derived key of dk_len bytes.

    Example:
        var key = pbkdf2_sha256(password_bytes, salt_bytes, 100000, 32)
    """
    alias H_LEN: Int = 32  # SHA-256 output size

    # Calculate number of blocks needed
    var blocks_needed = (dk_len + H_LEN - 1) // H_LEN

    var dk = List[UInt8]()

    for block_num in range(1, blocks_needed + 1):
        var block = _pbkdf2_f_sha256(password, salt, iterations, block_num)

        # Append block to derived key
        for i in range(len(block)):
            if len(dk) < dk_len:
                dk.append(block[i])

    return dk


fn _pbkdf2_f_sha256(
    password: List[UInt8],
    salt: List[UInt8],
    iterations: Int,
    block_num: Int,
) -> List[UInt8]:
    """Compute F(password, salt, c, i) for PBKDF2-SHA256."""
    # U_1 = HMAC(password, salt || INT_32_BE(block_num))
    var salt_block = List[UInt8]()
    for i in range(len(salt)):
        salt_block.append(salt[i])

    # Append block number as 4-byte big-endian
    salt_block.append(UInt8((block_num >> 24) & 0xFF))
    salt_block.append(UInt8((block_num >> 16) & 0xFF))
    salt_block.append(UInt8((block_num >> 8) & 0xFF))
    salt_block.append(UInt8(block_num & 0xFF))

    var u = hmac_sha256(password, salt_block)
    var result = List[UInt8]()
    for i in range(len(u)):
        result.append(u[i])

    # U_2 ... U_c: XOR chain
    for _ in range(iterations - 1):
        u = hmac_sha256(password, u)
        for i in range(len(result)):
            result[i] ^= u[i]

    return result


# =============================================================================
# PBKDF2-HMAC-SHA512
# =============================================================================

fn pbkdf2_sha512(
    password: List[UInt8],
    salt: List[UInt8],
    iterations: Int,
    dk_len: Int = 64,
) -> List[UInt8]:
    """
    Derive key using PBKDF2-HMAC-SHA512.

    Args:
        password: Password bytes.
        salt: Salt bytes (should be at least 16 bytes).
        iterations: Number of iterations (minimum 10000 recommended).
        dk_len: Desired key length in bytes (default 64).

    Returns:
        Derived key of dk_len bytes.
    """
    alias H_LEN: Int = 64  # SHA-512 output size

    var blocks_needed = (dk_len + H_LEN - 1) // H_LEN

    var dk = List[UInt8]()

    for block_num in range(1, blocks_needed + 1):
        var block = _pbkdf2_f_sha512(password, salt, iterations, block_num)

        for i in range(len(block)):
            if len(dk) < dk_len:
                dk.append(block[i])

    return dk


fn _pbkdf2_f_sha512(
    password: List[UInt8],
    salt: List[UInt8],
    iterations: Int,
    block_num: Int,
) -> List[UInt8]:
    """Compute F(password, salt, c, i) for PBKDF2-SHA512."""
    var salt_block = List[UInt8]()
    for i in range(len(salt)):
        salt_block.append(salt[i])

    salt_block.append(UInt8((block_num >> 24) & 0xFF))
    salt_block.append(UInt8((block_num >> 16) & 0xFF))
    salt_block.append(UInt8((block_num >> 8) & 0xFF))
    salt_block.append(UInt8(block_num & 0xFF))

    var u = hmac_sha512(password, salt_block)
    var result = List[UInt8]()
    for i in range(len(u)):
        result.append(u[i])

    for _ in range(iterations - 1):
        u = hmac_sha512(password, u)
        for i in range(len(result)):
            result[i] ^= u[i]

    return result


# =============================================================================
# Convenience Functions
# =============================================================================

fn pbkdf2_sha256_string(
    password: String,
    salt: String,
    iterations: Int,
    dk_len: Int = 32,
) -> List[UInt8]:
    """Derive key from string password and salt."""
    return pbkdf2_sha256(
        _string_to_bytes_pbkdf2(password),
        _string_to_bytes_pbkdf2(salt),
        iterations,
        dk_len,
    )


fn pbkdf2_sha256_hex(
    password: String,
    salt: String,
    iterations: Int,
    dk_len: Int = 32,
) -> String:
    """Derive key and return hex string."""
    var key = pbkdf2_sha256_string(password, salt, iterations, dk_len)
    return _bytes_to_hex_pbkdf2(key)


fn pbkdf2_sha512_string(
    password: String,
    salt: String,
    iterations: Int,
    dk_len: Int = 64,
) -> List[UInt8]:
    """Derive key from string password and salt."""
    return pbkdf2_sha512(
        _string_to_bytes_pbkdf2(password),
        _string_to_bytes_pbkdf2(salt),
        iterations,
        dk_len,
    )


fn pbkdf2_sha512_hex(
    password: String,
    salt: String,
    iterations: Int,
    dk_len: Int = 64,
) -> String:
    """Derive key and return hex string."""
    var key = pbkdf2_sha512_string(password, salt, iterations, dk_len)
    return _bytes_to_hex_pbkdf2(key)


# =============================================================================
# Password Hashing Helpers
# =============================================================================

fn hash_password(password: String, salt: List[UInt8], iterations: Int = 100000) raises -> List[UInt8]:
    """
    Hash a password for storage.

    Uses PBKDF2-HMAC-SHA256 with the provided salt.
    Default 100,000 iterations per OWASP recommendations.

    SECURITY: This function enforces minimum security parameters:
    - Minimum 10,000 iterations (OWASP recommendation)
    - Minimum 16-byte salt (NIST SP 800-132)

    Args:
        password: The password to hash.
        salt: Salt bytes (must be at least 16 bytes).
        iterations: Number of iterations (minimum 10,000).

    Returns:
        32-byte derived key.

    Raises:
        Error if iterations < 10,000 or salt < 16 bytes.

    Example:
        var salt = generate_random_bytes(16)
        var hash = hash_password("my_password", salt)
    """
    # SECURITY: Enforce minimum iterations
    if iterations < MIN_ITERATIONS:
        raise Error(
            "SECURITY: iterations must be >= " + String(MIN_ITERATIONS) +
            " (got " + String(iterations) + "). " +
            "Low iteration counts make passwords vulnerable to brute-force attacks."
        )

    # SECURITY: Enforce minimum salt length
    if len(salt) < MIN_SALT_LENGTH:
        raise Error(
            "SECURITY: salt must be >= " + String(MIN_SALT_LENGTH) + " bytes " +
            "(got " + String(len(salt)) + "). " +
            "Short salts reduce protection against rainbow table attacks."
        )

    return pbkdf2_sha256(
        _string_to_bytes_pbkdf2(password),
        salt,
        iterations,
        32,
    )


fn verify_password(
    password: String,
    salt: List[UInt8],
    expected_hash: List[UInt8],
    iterations: Int = 100000,
) raises -> Bool:
    """
    Verify a password against a stored hash.

    Uses constant-time comparison to prevent timing attacks.

    SECURITY: This function enforces minimum security parameters:
    - Minimum 10,000 iterations (OWASP recommendation)
    - Minimum 16-byte salt (NIST SP 800-132)

    Security Note:
        This function avoids early returns that could leak timing information.
        The length difference is XORed into the result rather than causing
        an early return.

    Raises:
        Error if iterations < 10,000 or salt < 16 bytes.
    """
    var computed = hash_password(password, salt, iterations)

    # XOR length difference into result (avoids timing leak from early return)
    var result: UInt8 = 0
    if len(computed) != len(expected_hash):
        result = 1

    # Compare all bytes up to the shorter length
    var min_len = min(len(computed), len(expected_hash))
    for i in range(min_len):
        result |= computed[i] ^ expected_hash[i]

    return result == 0


# =============================================================================
# Unsafe Functions (for testing only)
# =============================================================================

fn hash_password_UNSAFE_NO_VALIDATION(
    password: String,
    salt: List[UInt8],
    iterations: Int,
) -> List[UInt8]:
    """
    Hash a password WITHOUT security validation.

    WARNING: This function does NOT enforce minimum iterations or salt length.
    It exists ONLY for:
    - Testing RFC 6070 test vectors (which use low iterations)
    - Compatibility with legacy systems

    DO NOT use this in production. Use `hash_password()` instead.
    """
    return pbkdf2_sha256(
        _string_to_bytes_pbkdf2(password),
        salt,
        iterations,
        32,
    )


# =============================================================================
# Helper Functions
# =============================================================================

fn _string_to_bytes_pbkdf2(s: String) -> List[UInt8]:
    """Convert string to bytes."""
    var result = List[UInt8]()
    for i in range(len(s)):
        result.append(UInt8(ord(s[i])))
    return result


fn _bytes_to_hex_pbkdf2(data: List[UInt8]) -> String:
    """Convert bytes to hex string."""
    alias HEX = "0123456789abcdef"
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        result += HEX[(b >> 4) & 0x0F]
        result += HEX[b & 0x0F]
    return result
