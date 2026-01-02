"""Cryptographic hashing examples."""
from mojo_crypto import sha256_hex, sha512_hex, hmac_sha256_hex, hash_password, verify_password

fn main() raises:
    # SHA-256 hashing
    var message = "Hello, Mojo!"
    var hash = sha256_hex(message)
    print("SHA-256:", hash)
    
    # SHA-512 hashing
    var hash512 = sha512_hex(message)
    print("SHA-512:", hash512[:64], "...")
    
    # HMAC for message authentication
    var key = "secret-key"
    var mac = hmac_sha256_hex(key, message)
    print("HMAC-SHA256:", mac)
    
    # Password hashing (for storage)
    var password = "my-secure-password"
    var hashed = hash_password(password)
    print("Password hash:", hashed[:40], "...")
    
    # Verify password
    if verify_password(password, hashed):
        print("Password verified!")
