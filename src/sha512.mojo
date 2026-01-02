"""
SHA-512 Implementation

Pure Mojo SHA-512 hash function (FIPS 180-4).
"""


# =============================================================================
# Constants
# =============================================================================

# Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
alias H512_0: UInt64 = 0x6A09E667F3BCC908
alias H512_1: UInt64 = 0xBB67AE8584CAA73B
alias H512_2: UInt64 = 0x3C6EF372FE94F82B
alias H512_3: UInt64 = 0xA54FF53A5F1D36F1
alias H512_4: UInt64 = 0x510E527FADE682D1
alias H512_5: UInt64 = 0x9B05688C2B3E6C1F
alias H512_6: UInt64 = 0x1F83D9ABFB41BD6B
alias H512_7: UInt64 = 0x5BE0CD19137E2179

# SHA-512 block size in bytes
alias BLOCK_SIZE_512: Int = 128

# SHA-512 digest size in bytes
alias DIGEST_SIZE_512: Int = 64


# =============================================================================
# Round Constants
# =============================================================================

fn _get_k512(i: Int) -> UInt64:
    """Get round constant K[i] for SHA-512."""
    # First 64 bits of fractional parts of cube roots of first 80 primes
    if i == 0: return 0x428A2F98D728AE22
    if i == 1: return 0x7137449123EF65CD
    if i == 2: return 0xB5C0FBCFEC4D3B2F
    if i == 3: return 0xE9B5DBA58189DBBC
    if i == 4: return 0x3956C25BF348B538
    if i == 5: return 0x59F111F1B605D019
    if i == 6: return 0x923F82A4AF194F9B
    if i == 7: return 0xAB1C5ED5DA6D8118
    if i == 8: return 0xD807AA98A3030242
    if i == 9: return 0x12835B0145706FBE
    if i == 10: return 0x243185BE4EE4B28C
    if i == 11: return 0x550C7DC3D5FFB4E2
    if i == 12: return 0x72BE5D74F27B896F
    if i == 13: return 0x80DEB1FE3B1696B1
    if i == 14: return 0x9BDC06A725C71235
    if i == 15: return 0xC19BF174CF692694
    if i == 16: return 0xE49B69C19EF14AD2
    if i == 17: return 0xEFBE4786384F25E3
    if i == 18: return 0x0FC19DC68B8CD5B5
    if i == 19: return 0x240CA1CC77AC9C65
    if i == 20: return 0x2DE92C6F592B0275
    if i == 21: return 0x4A7484AA6EA6E483
    if i == 22: return 0x5CB0A9DCBD41FBD4
    if i == 23: return 0x76F988DA831153B5
    if i == 24: return 0x983E5152EE66DFAB
    if i == 25: return 0xA831C66D2DB43210
    if i == 26: return 0xB00327C898FB213F
    if i == 27: return 0xBF597FC7BEEF0EE4
    if i == 28: return 0xC6E00BF33DA88FC2
    if i == 29: return 0xD5A79147930AA725
    if i == 30: return 0x06CA6351E003826F
    if i == 31: return 0x142929670A0E6E70
    if i == 32: return 0x27B70A8546D22FFC
    if i == 33: return 0x2E1B21385C26C926
    if i == 34: return 0x4D2C6DFC5AC42AED
    if i == 35: return 0x53380D139D95B3DF
    if i == 36: return 0x650A73548BAF63DE
    if i == 37: return 0x766A0ABB3C77B2A8
    if i == 38: return 0x81C2C92E47EDAEE6
    if i == 39: return 0x92722C851482353B
    if i == 40: return 0xA2BFE8A14CF10364
    if i == 41: return 0xA81A664BBC423001
    if i == 42: return 0xC24B8B70D0F89791
    if i == 43: return 0xC76C51A30654BE30
    if i == 44: return 0xD192E819D6EF5218
    if i == 45: return 0xD69906245565A910
    if i == 46: return 0xF40E35855771202A
    if i == 47: return 0x106AA07032BBD1B8
    if i == 48: return 0x19A4C116B8D2D0C8
    if i == 49: return 0x1E376C085141AB53
    if i == 50: return 0x2748774CDF8EEB99
    if i == 51: return 0x34B0BCB5E19B48A8
    if i == 52: return 0x391C0CB3C5C95A63
    if i == 53: return 0x4ED8AA4AE3418ACB
    if i == 54: return 0x5B9CCA4F7763E373
    if i == 55: return 0x682E6FF3D6B2B8A3
    if i == 56: return 0x748F82EE5DEFB2FC
    if i == 57: return 0x78A5636F43172F60
    if i == 58: return 0x84C87814A1F0AB72
    if i == 59: return 0x8CC702081A6439EC
    if i == 60: return 0x90BEFFFA23631E28
    if i == 61: return 0xA4506CEBDE82BDE9
    if i == 62: return 0xBEF9A3F7B2C67915
    if i == 63: return 0xC67178F2E372532B
    if i == 64: return 0xCA273ECEEA26619C
    if i == 65: return 0xD186B8C721C0C207
    if i == 66: return 0xEADA7DD6CDE0EB1E
    if i == 67: return 0xF57D4F7FEE6ED178
    if i == 68: return 0x06F067AA72176FBA
    if i == 69: return 0x0A637DC5A2C898A6
    if i == 70: return 0x113F9804BEF90DAE
    if i == 71: return 0x1B710B35131C471B
    if i == 72: return 0x28DB77F523047D84
    if i == 73: return 0x32CAAB7B40C72493
    if i == 74: return 0x3C9EBE0A15C9BEBC
    if i == 75: return 0x431D67C49C100D4C
    if i == 76: return 0x4CC5D4BECB3E42B6
    if i == 77: return 0x597F299CFC657E2A
    if i == 78: return 0x5FCB6FAB3AD6FAEC
    return 0x6C44198C4A475817  # i == 79


# =============================================================================
# Helper Functions
# =============================================================================

fn _rotr64(x: UInt64, n: Int) -> UInt64:
    """Right rotate 64-bit."""
    return (x >> n) | (x << (64 - n))


fn _ch64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    """Choose function."""
    return (x & y) ^ (~x & z)


fn _maj64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    """Majority function."""
    return (x & y) ^ (x & z) ^ (y & z)


fn _sigma0_512(x: UInt64) -> UInt64:
    """Big sigma 0 for SHA-512."""
    return _rotr64(x, 28) ^ _rotr64(x, 34) ^ _rotr64(x, 39)


fn _sigma1_512(x: UInt64) -> UInt64:
    """Big sigma 1 for SHA-512."""
    return _rotr64(x, 14) ^ _rotr64(x, 18) ^ _rotr64(x, 41)


fn _gamma0_512(x: UInt64) -> UInt64:
    """Small sigma 0 for SHA-512 message schedule."""
    return _rotr64(x, 1) ^ _rotr64(x, 8) ^ (x >> 7)


fn _gamma1_512(x: UInt64) -> UInt64:
    """Small sigma 1 for SHA-512 message schedule."""
    return _rotr64(x, 19) ^ _rotr64(x, 61) ^ (x >> 6)


# =============================================================================
# SHA-512 Implementation
# =============================================================================

struct SHA512:
    """
    SHA-512 hash algorithm.

    Example:
        var hasher = SHA512()
        hasher.update(data)
        var digest = hasher.finalize()  # 64 bytes
    """
    var h0: UInt64
    var h1: UInt64
    var h2: UInt64
    var h3: UInt64
    var h4: UInt64
    var h5: UInt64
    var h6: UInt64
    var h7: UInt64
    var buffer: List[UInt8]
    var total_len: UInt64

    fn __init__(out self):
        """Initialize SHA-512 state."""
        self.h0 = H512_0
        self.h1 = H512_1
        self.h2 = H512_2
        self.h3 = H512_3
        self.h4 = H512_4
        self.h5 = H512_5
        self.h6 = H512_6
        self.h7 = H512_7
        self.buffer = List[UInt8]()
        self.total_len = 0

    fn update(inout self, data: List[UInt8]):
        """Add data to hash."""
        self.total_len += len(data)

        for i in range(len(data)):
            self.buffer.append(data[i])

        while len(self.buffer) >= BLOCK_SIZE_512:
            self._process_block()

    fn update_string(inout self, s: String):
        """Add string to hash."""
        var data = List[UInt8]()
        for i in range(len(s)):
            data.append(UInt8(ord(s[i])))
        self.update(data)

    fn _process_block(inout self):
        """Process a 128-byte block."""
        var w = List[UInt64]()
        for _ in range(80):
            w.append(0)

        # Copy block into first 16 words (big-endian)
        for i in range(16):
            var idx = i * 8
            w[i] = (UInt64(self.buffer[idx]) << 56) | \
                   (UInt64(self.buffer[idx + 1]) << 48) | \
                   (UInt64(self.buffer[idx + 2]) << 40) | \
                   (UInt64(self.buffer[idx + 3]) << 32) | \
                   (UInt64(self.buffer[idx + 4]) << 24) | \
                   (UInt64(self.buffer[idx + 5]) << 16) | \
                   (UInt64(self.buffer[idx + 6]) << 8) | \
                   UInt64(self.buffer[idx + 7])

        # Extend to 80 words
        for i in range(16, 80):
            w[i] = _gamma1_512(w[i - 2]) + w[i - 7] + _gamma0_512(w[i - 15]) + w[i - 16]

        var a = self.h0
        var b = self.h1
        var c = self.h2
        var d = self.h3
        var e = self.h4
        var f = self.h5
        var g = self.h6
        var h = self.h7

        # 80 rounds
        for i in range(80):
            var t1 = h + _sigma1_512(e) + _ch64(e, f, g) + _get_k512(i) + w[i]
            var t2 = _sigma0_512(a) + _maj64(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        self.h0 += a
        self.h1 += b
        self.h2 += c
        self.h3 += d
        self.h4 += e
        self.h5 += f
        self.h6 += g
        self.h7 += h

        var new_buffer = List[UInt8]()
        for i in range(BLOCK_SIZE_512, len(self.buffer)):
            new_buffer.append(self.buffer[i])
        self.buffer = new_buffer

    fn finalize(inout self) -> List[UInt8]:
        """Finalize and return 64-byte digest."""
        var msg_len_bits = self.total_len * 8

        self.buffer.append(0x80)

        # Pad to 112 mod 128 bytes
        while len(self.buffer) % 128 != 112:
            self.buffer.append(0x00)

        # Append original length in bits (big-endian, 128 bits - we use 64 bits as high part is 0)
        for _ in range(8):
            self.buffer.append(0x00)  # High 64 bits of length (assuming < 2^64 bits)
        for i in range(8):
            self.buffer.append(UInt8((msg_len_bits >> (56 - i * 8)) & 0xFF))

        while len(self.buffer) >= BLOCK_SIZE_512:
            self._process_block()

        var digest = List[UInt8]()
        for i in range(8):
            digest.append(UInt8((self.h0 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h1 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h2 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h3 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h4 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h5 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h6 >> (56 - i * 8)) & 0xFF))
        for i in range(8):
            digest.append(UInt8((self.h7 >> (56 - i * 8)) & 0xFF))

        return digest

    fn hexdigest(inout self) -> String:
        """Finalize and return hex string."""
        var digest = self.finalize()
        return _bytes_to_hex_512(digest)


# =============================================================================
# Convenience Functions
# =============================================================================

fn sha512(data: List[UInt8]) -> List[UInt8]:
    """Hash bytes and return 64-byte digest."""
    var hasher = SHA512()
    hasher.update(data)
    return hasher.finalize()


fn sha512_string(s: String) -> List[UInt8]:
    """Hash string and return 64-byte digest."""
    var hasher = SHA512()
    hasher.update_string(s)
    return hasher.finalize()


fn sha512_hex(s: String) -> String:
    """Hash string and return hex digest."""
    var hasher = SHA512()
    hasher.update_string(s)
    return hasher.hexdigest()


fn _bytes_to_hex_512(data: List[UInt8]) -> String:
    """Convert bytes to hex string."""
    alias HEX = "0123456789abcdef"
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        result += HEX[(b >> 4) & 0x0F]
        result += HEX[b & 0x0F]
    return result
