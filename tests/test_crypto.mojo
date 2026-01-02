"""
Crypto Tests
"""

from mojo_crypto import (
    sha256_hex,
    sha512_hex,
    hmac_sha256_hex,
    hmac_sha512_hex,
    pbkdf2_sha256_hex,
    pbkdf2_sha512_hex,
    constant_time_compare,
    hash_password,
    verify_password,
)


fn test_sha256() raises:
    """Test SHA-256 against known test vectors."""
    # Test vector: empty string
    var empty = sha256_hex("")
    if empty != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise Error("SHA-256 empty string failed: " + empty)

    # Test vector: "abc"
    var abc = sha256_hex("abc")
    if abc != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        raise Error("SHA-256 'abc' failed: " + abc)

    # Test vector: "hello"
    var hello = sha256_hex("hello")
    if hello != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824":
        raise Error("SHA-256 'hello' failed: " + hello)

    print("✓ SHA-256 works")


fn test_sha512() raises:
    """Test SHA-512 against known test vectors."""
    # Test vector: empty string
    var empty = sha512_hex("")
    var expected_empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    if empty != expected_empty:
        raise Error("SHA-512 empty string failed")

    # Test vector: "abc"
    var abc = sha512_hex("abc")
    var expected_abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    if abc != expected_abc:
        raise Error("SHA-512 'abc' failed")

    print("✓ SHA-512 works")


fn test_hmac_sha256() raises:
    """Test HMAC-SHA256."""
    # Test with known key and message
    var mac = hmac_sha256_hex("key", "The quick brown fox jumps over the lazy dog")
    var expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    if mac != expected:
        raise Error("HMAC-SHA256 failed: " + mac)

    print("✓ HMAC-SHA256 works")


fn test_hmac_sha512() raises:
    """Test HMAC-SHA512."""
    var mac = hmac_sha512_hex("key", "The quick brown fox jumps over the lazy dog")
    var expected = "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
    if mac != expected:
        raise Error("HMAC-SHA512 failed: " + mac)

    print("✓ HMAC-SHA512 works")


fn test_pbkdf2_sha256() raises:
    """Test PBKDF2-SHA256."""
    # RFC 6070 test vector
    var key = pbkdf2_sha256_hex("password", "salt", 1, 32)
    var expected = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    if key != expected:
        raise Error("PBKDF2-SHA256 (1 iter) failed: " + key)

    # More iterations
    var key2 = pbkdf2_sha256_hex("password", "salt", 2, 32)
    var expected2 = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    if key2 != expected2:
        raise Error("PBKDF2-SHA256 (2 iter) failed: " + key2)

    print("✓ PBKDF2-SHA256 works")


fn test_pbkdf2_sha512() raises:
    """Test PBKDF2-SHA512."""
    # Basic test
    var key = pbkdf2_sha512_hex("password", "salt", 1, 64)
    # Just verify it runs and produces correct length
    if len(key) != 128:  # 64 bytes = 128 hex chars
        raise Error("PBKDF2-SHA512 wrong length: " + str(len(key)))

    print("✓ PBKDF2-SHA512 works")


fn test_constant_time_compare() raises:
    """Test constant-time comparison."""
    var a = List[UInt8]()
    a.append(1)
    a.append(2)
    a.append(3)

    var b = List[UInt8]()
    b.append(1)
    b.append(2)
    b.append(3)

    var c = List[UInt8]()
    c.append(1)
    c.append(2)
    c.append(4)

    if not constant_time_compare(a, b):
        raise Error("Constant-time compare should return True for equal arrays")

    if constant_time_compare(a, c):
        raise Error("Constant-time compare should return False for different arrays")

    print("✓ Constant-time comparison works")


fn test_password_hashing() raises:
    """Test password hashing functions."""
    var salt = List[UInt8]()
    for i in range(16):
        salt.append(UInt8(i))  # Deterministic salt for testing

    var password = "my_secure_password"

    # Hash password
    var hash = hash_password(password, salt, 1000)  # Lower iterations for test

    # Verify correct password
    if not verify_password(password, salt, hash, 1000):
        raise Error("Password verification failed for correct password")

    # Verify wrong password
    if verify_password("wrong_password", salt, hash, 1000):
        raise Error("Password verification should fail for wrong password")

    print("✓ Password hashing works")


fn test_sha256_long_message() raises:
    """Test SHA-256 with longer message."""
    var msg = String()
    for _ in range(100):
        msg += "The quick brown fox jumps over the lazy dog. "

    var hash = sha256_hex(msg)
    if len(hash) != 64:
        raise Error("SHA-256 long message: wrong hash length")

    print("✓ SHA-256 long message works")


fn main() raises:
    print("Running Crypto tests...\n")

    test_sha256()
    test_sha512()
    test_hmac_sha256()
    test_hmac_sha512()
    test_pbkdf2_sha256()
    test_pbkdf2_sha512()
    test_constant_time_compare()
    test_password_hashing()
    test_sha256_long_message()

    print("\n✅ All Crypto tests passed!")
