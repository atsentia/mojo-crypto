"""
SHA-256 Implementation

Pure Mojo SHA-256 hash function (FIPS 180-4).

PERF-001 Optimization Notes:
============================
SHA-256's compression function is inherently sequential - each round depends
on the output of the previous round (a,b,c,d,e,f,g,h chain). This means the
64 rounds CANNOT be parallelized via SIMD.

However, we CAN optimize:
1. Round constants (K) - Use compile-time alias tuple for O(1) lookup
   instead of 64-way if-else chain (O(n) worst case, O(log n) with optimization)
2. Hot functions - Mark with @always_inline to eliminate call overhead
3. Message schedule (W) expansion - First 16 words can be loaded with SIMD

For true SIMD parallelism, consider:
- Multi-buffer hashing (hash 4 messages simultaneously using SIMD lanes)
- Tree hashing modes (parallel leaf hashing in Merkle trees)
"""


# =============================================================================
# Constants
# =============================================================================

# Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
alias H0: UInt32 = 0x6A09E667
alias H1: UInt32 = 0xBB67AE85
alias H2: UInt32 = 0x3C6EF372
alias H3: UInt32 = 0xA54FF53A
alias H4: UInt32 = 0x510E527F
alias H5: UInt32 = 0x9B05688C
alias H6: UInt32 = 0x1F83D9AB
alias H7: UInt32 = 0x5BE0CD19

# SHA-256 block size in bytes
alias BLOCK_SIZE: Int = 64

# SHA-256 digest size in bytes
alias DIGEST_SIZE: Int = 32


# =============================================================================
# Round Constants (PERF-001: Compile-time constant array)
# =============================================================================
# First 32 bits of fractional parts of cube roots of first 64 primes.
# Using InlineArray enables O(1) indexed access vs O(n) if-else chain.
# The array is stack-allocated with fixed size known at compile time.

alias K_CONSTANTS = InlineArray[UInt32, 64](
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


@always_inline
fn _get_k(i: Int) -> UInt32:
    """Get round constant K[i].

    PERF-001: O(1) lookup via InlineArray index.
    The @always_inline decorator eliminates function call overhead in the hot loop.
    Previous implementation used 64-way if-else chain (O(n) worst case).
    """
    return K_CONSTANTS[i]


# =============================================================================
# Helper Functions (PERF-001: All marked @always_inline for hot loop performance)
# =============================================================================
# These functions are called 64 times per block in the compression loop.
# Inlining eliminates function call overhead (~5-10 cycles per call saved).

@always_inline
fn _rotr(x: UInt32, n: Int) -> UInt32:
    """Right rotate. PERF-001: Inlined, compiles to single ROR instruction."""
    return (x >> n) | (x << (32 - n))


@always_inline
fn _ch(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    """Choose function: if x then y else z (bitwise)."""
    return (x & y) ^ (~x & z)


@always_inline
fn _maj(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    """Majority function: majority vote of x, y, z bits."""
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
fn _sigma0(x: UInt32) -> UInt32:
    """Big sigma 0 (used in compression round for 'a' update)."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


@always_inline
fn _sigma1(x: UInt32) -> UInt32:
    """Big sigma 1 (used in compression round for 'e' update)."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


@always_inline
fn _gamma0(x: UInt32) -> UInt32:
    """Small sigma 0 (for message schedule expansion, rounds 16-63)."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


@always_inline
fn _gamma1(x: UInt32) -> UInt32:
    """Small sigma 1 (for message schedule expansion, rounds 16-63)."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


# =============================================================================
# SHA-256 Implementation
# =============================================================================

struct SHA256:
    """
    SHA-256 hash algorithm.

    Example:
        var hasher = SHA256()
        hasher.update(data)
        var digest = hasher.finalize()  # 32 bytes
    """
    var h0: UInt32
    var h1: UInt32
    var h2: UInt32
    var h3: UInt32
    var h4: UInt32
    var h5: UInt32
    var h6: UInt32
    var h7: UInt32
    var buffer: List[UInt8]
    var total_len: UInt64

    fn __init__(out self):
        """Initialize SHA-256 state."""
        self.h0 = H0
        self.h1 = H1
        self.h2 = H2
        self.h3 = H3
        self.h4 = H4
        self.h5 = H5
        self.h6 = H6
        self.h7 = H7
        self.buffer = List[UInt8]()
        self.total_len = 0

    fn update(inout self, data: List[UInt8]):
        """Add data to hash."""
        self.total_len += len(data)

        # Add to buffer
        for i in range(len(data)):
            self.buffer.append(data[i])

        # Process complete blocks
        while len(self.buffer) >= BLOCK_SIZE:
            self._process_block()

    fn update_string(inout self, s: String):
        """Add string to hash."""
        var data = List[UInt8]()
        for i in range(len(s)):
            data.append(UInt8(ord(s[i])))
        self.update(data)

    fn _process_block(inout self):
        """Process a 64-byte block.

        PERF-001 Note: The compression loop (64 rounds) is inherently sequential.
        Each round's output (a,b,c,d,e,f,g,h) depends on the previous round.
        SIMD cannot parallelize this - it's a fundamental SHA-256 design constraint.

        For SIMD benefits, consider multi-buffer hashing (hash N messages in parallel).
        """
        # Message schedule array
        # PERF-001: Using List for simplicity. Future optimization could use
        # InlineArray[UInt32, 64] to avoid heap allocation per block.
        var w = List[UInt32]()
        for _ in range(64):
            w.append(0)

        # Copy block into first 16 words (big-endian)
        # PERF-001: These 16 loads are independent - could use SIMD<4, UInt32>
        # to load 4 words at a time with byte-swap, but endianness handling
        # complicates this. Left as scalar for correctness.
        for i in range(16):
            var idx = i * 4
            w[i] = (UInt32(self.buffer[idx]) << 24) | \
                   (UInt32(self.buffer[idx + 1]) << 16) | \
                   (UInt32(self.buffer[idx + 2]) << 8) | \
                   UInt32(self.buffer[idx + 3])

        # Extend to 64 words (message schedule expansion)
        # PERF-001: Each w[i] depends on w[i-2], w[i-7], w[i-15], w[i-16].
        # Limited parallelism possible but dependencies make SIMD complex.
        for i in range(16, 64):
            w[i] = _gamma1(w[i - 2]) + w[i - 7] + _gamma0(w[i - 15]) + w[i - 16]

        # Initialize working variables
        var a = self.h0
        var b = self.h1
        var c = self.h2
        var d = self.h3
        var e = self.h4
        var f = self.h5
        var g = self.h6
        var h = self.h7

        # 64 rounds - PERF-001: Sequential dependency chain, cannot parallelize.
        # Optimizations applied: @always_inline on all helper functions,
        # O(1) constant lookup via InlineArray instead of if-else chain.
        for i in range(64):
            var t1 = h + _sigma1(e) + _ch(e, f, g) + _get_k(i) + w[i]
            var t2 = _sigma0(a) + _maj(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        # Update hash state
        self.h0 += a
        self.h1 += b
        self.h2 += c
        self.h3 += d
        self.h4 += e
        self.h5 += f
        self.h6 += g
        self.h7 += h

        # Remove processed block from buffer
        var new_buffer = List[UInt8]()
        for i in range(BLOCK_SIZE, len(self.buffer)):
            new_buffer.append(self.buffer[i])
        self.buffer = new_buffer

    fn finalize(inout self) -> List[UInt8]:
        """Finalize and return 32-byte digest."""
        # Padding
        var msg_len_bits = self.total_len * 8

        # Append bit '1' (0x80)
        self.buffer.append(0x80)

        # Pad to 56 mod 64 bytes
        while len(self.buffer) % 64 != 56:
            self.buffer.append(0x00)

        # Append original length in bits (big-endian, 64 bits)
        for i in range(8):
            self.buffer.append(UInt8((msg_len_bits >> (56 - i * 8)) & 0xFF))

        # Process final block(s)
        while len(self.buffer) >= BLOCK_SIZE:
            self._process_block()

        # Build digest
        var digest = List[UInt8]()
        for i in range(4):
            digest.append(UInt8((self.h0 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h1 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h2 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h3 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h4 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h5 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h6 >> (24 - i * 8)) & 0xFF))
        for i in range(4):
            digest.append(UInt8((self.h7 >> (24 - i * 8)) & 0xFF))

        return digest

    fn hexdigest(inout self) -> String:
        """Finalize and return hex string."""
        var digest = self.finalize()
        return _bytes_to_hex(digest)


# =============================================================================
# Convenience Functions
# =============================================================================

fn sha256(data: List[UInt8]) -> List[UInt8]:
    """Hash bytes and return 32-byte digest."""
    var hasher = SHA256()
    hasher.update(data)
    return hasher.finalize()


fn sha256_string(s: String) -> List[UInt8]:
    """Hash string and return 32-byte digest."""
    var hasher = SHA256()
    hasher.update_string(s)
    return hasher.finalize()


fn sha256_hex(s: String) -> String:
    """Hash string and return hex digest."""
    var hasher = SHA256()
    hasher.update_string(s)
    return hasher.hexdigest()


fn _bytes_to_hex(data: List[UInt8]) -> String:
    """Convert bytes to hex string."""
    alias HEX = "0123456789abcdef"
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        result += HEX[(b >> 4) & 0x0F]
        result += HEX[b & 0x0F]
    return result
