"""
rsa_core.py
===========
Two RSA implementations side-by-side:
  1. ScratchRSA  – built entirely from first principles (Miller-Rabin,
                   extended Euclidean, modular exponentiation).
  2. LibRSA      – thin wrapper around PyCryptodome (OpenSSL-backed).

Both expose the same public interface so the UI / CLI can swap them freely.
"""

import os
import math
import time
import random
from dataclasses import dataclass
from typing import Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Shared data structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RSAKeyPair:
    n:          int          # modulus
    e:          int          # public exponent
    d:          int          # private exponent
    p:          int          # prime 1
    q:          int          # prime 2
    bit_size:   int          # key size in bits
    source:     str          # "scratch" | "library"

@dataclass
class BenchResult:
    key_bits:       int
    keygen_ms:      float
    encrypt_ms:     float
    decrypt_ms:     float
    source:         str      # "scratch" | "library"


# ──────────────────────────────────────────────────────────────────────────────
# ① FROM-SCRATCH IMPLEMENTATION
# ──────────────────────────────────────────────────────────────────────────────

class ScratchRSA:
    """
    Textbook RSA implemented from first principles.

    Key decisions
    -------------
    - Prime generation  : random candidate → Miller-Rabin (40 rounds)
    - Key generation    : standard PKCS-style with e = 65537
    - Modular inverse   : extended Euclidean algorithm
    - Encrypt / Decrypt : Python's built-in pow(base, exp, mod)
                          (uses Barrett / Montgomery reduction internally)
    - Padding           : simple length-prefixed byte encoding so we can
                          handle arbitrary strings (NOT production-safe;
                          use OAEP for real use).  The UI clearly labels this.
    """

    # ── Miller-Rabin primality test ──────────────────────────────────────────
    @staticmethod
    def _miller_rabin(n: int, rounds: int = 40) -> bool:
        """
        Returns True if n is probably prime.
        Probability of false positive ≤ 4^(-rounds).
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(rounds):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False   # composite

        return True   # probably prime

    @staticmethod
    def _generate_prime(bit_size: int) -> int:
        """Generate a random prime of exactly `bit_size` bits."""
        while True:
            # Set MSB and LSB so the number has the right bit-length and is odd
            candidate = random.getrandbits(bit_size)
            candidate |= (1 << (bit_size - 1)) | 1    # set top & bottom bits
            if ScratchRSA._miller_rabin(candidate):
                return candidate

    # ── Extended Euclidean / modular inverse ─────────────────────────────────
    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)."""
        if a == 0:
            return b, 0, 1
        g, x1, y1 = ScratchRSA._extended_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1

    @staticmethod
    def _mod_inverse(e: int, phi: int) -> int:
        g, x, _ = ScratchRSA._extended_gcd(e % phi, phi)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    # ── Key generation ───────────────────────────────────────────────────────
    @staticmethod
    def generate_keypair(bit_size: int = 2048) -> RSAKeyPair:
        """
        Generate RSA key pair of `bit_size` total bits.
        Each prime p, q is bit_size//2 bits.
        """
        half = bit_size // 2
        e = 65537  # Fermat number F4; standard public exponent

        while True:
            p = ScratchRSA._generate_prime(half)
            q = ScratchRSA._generate_prime(half)
            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)

            if math.gcd(e, phi) != 1:
                continue   # rare; retry

            d = ScratchRSA._mod_inverse(e, phi)
            return RSAKeyPair(n=n, e=e, d=d, p=p, q=q,
                              bit_size=bit_size, source="scratch")

    # ── Encoding helpers (simple, NOT OAEP) ──────────────────────────────────
    @staticmethod
    def _str_to_int(text: str) -> int:
        encoded = text.encode("utf-8")
        return int.from_bytes(encoded, "big")

    @staticmethod
    def _int_to_str(n: int, length: int) -> str:
        return n.to_bytes(length, "big").decode("utf-8")

    # ── Encrypt / Decrypt ────────────────────────────────────────────────────
    @staticmethod
    def encrypt(plaintext: str, kp: RSAKeyPair) -> Tuple[int, int]:
        """
        Returns (ciphertext_int, original_byte_length).
        The byte length is needed to reconstruct the string on decryption.
        """
        raw = plaintext.encode("utf-8")
        m = int.from_bytes(raw, "big")
        max_m = (kp.n.bit_length() - 1) // 8
        if len(raw) > max_m:
            raise ValueError(
                f"Plaintext too long for key ({len(raw)} bytes > {max_m} bytes). "
                f"Use a larger key or shorter message."
            )
        c = pow(m, kp.e, kp.n)
        return c, len(raw)

    @staticmethod
    def decrypt(ciphertext: int, byte_len: int, kp: RSAKeyPair) -> str:
        m = pow(ciphertext, kp.d, kp.n)
        return m.to_bytes(byte_len, "big").decode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# ② LIBRARY-BASED IMPLEMENTATION (PyCryptodome)
# ──────────────────────────────────────────────────────────────────────────────

class LibRSA:
    """
    RSA via PyCryptodome (OpenSSL-backed C implementation).
    Uses PKCS#1 OAEP padding with SHA-256 — production-grade.
    """

    @staticmethod
    def generate_keypair(bit_size: int = 2048) -> RSAKeyPair:
        from Crypto.PublicKey import RSA as _RSA
        if bit_size < 1024:
            raise ValueError(
                f"LibRSA requires key_size >= 1024 bits (got {bit_size}). "
                "PyCryptodome enforces this as 512-bit RSA is cryptographically broken."
            )
        key = _RSA.generate(bit_size)
        return RSAKeyPair(
            n        = int(key.n),
            e        = int(key.e),
            d        = int(key.d),
            p        = int(key.p),
            q        = int(key.q),
            bit_size = bit_size,
            source   = "library"
        )

    @staticmethod
    def encrypt(plaintext: str, kp: RSAKeyPair) -> bytes:
        from Crypto.PublicKey import RSA as _RSA
        from Crypto.Cipher   import PKCS1_OAEP
        from Crypto.Hash     import SHA256
        # Reconstruct PyCryptodome key object from our dataclass
        key = _RSA.construct((kp.n, kp.e, kp.d, kp.p, kp.q))
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        return cipher.encrypt(plaintext.encode("utf-8"))

    @staticmethod
    def decrypt(ciphertext: bytes, kp: RSAKeyPair) -> str:
        from Crypto.PublicKey import RSA as _RSA
        from Crypto.Cipher   import PKCS1_OAEP
        from Crypto.Hash     import SHA256
        key = _RSA.construct((kp.n, kp.e, kp.d, kp.p, kp.q))
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        return cipher.decrypt(ciphertext).decode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# ③ BENCHMARKING ENGINE
# ──────────────────────────────────────────────────────────────────────────────

def _ms(start: float, end: float) -> float:
    return round((end - start) * 1000, 3)

def benchmark_scratch(key_bits: int, message: str = "Benchmark test payload") -> BenchResult:
    t0 = time.perf_counter()
    kp = ScratchRSA.generate_keypair(key_bits)
    t1 = time.perf_counter()

    ct, blen = ScratchRSA.encrypt(message, kp)
    t2 = time.perf_counter()

    ScratchRSA.decrypt(ct, blen, kp)
    t3 = time.perf_counter()

    return BenchResult(
        key_bits    = key_bits,
        keygen_ms   = _ms(t0, t1),
        encrypt_ms  = _ms(t1, t2),
        decrypt_ms  = _ms(t2, t3),
        source      = "scratch"
    )

def benchmark_library(key_bits: int, message: str = "Benchmark test payload") -> BenchResult:
    t0 = time.perf_counter()
    kp = LibRSA.generate_keypair(key_bits)
    t1 = time.perf_counter()

    ct = LibRSA.encrypt(message, kp)
    t2 = time.perf_counter()

    LibRSA.decrypt(ct, kp)
    t3 = time.perf_counter()

    return BenchResult(
        key_bits    = key_bits,
        keygen_ms   = _ms(t0, t1),
        encrypt_ms  = _ms(t1, t2),
        decrypt_ms  = _ms(t2, t3),
        source      = "library"
    )

def run_stress_test(
    key_sizes: list = None,
    message:   str  = "Benchmark test payload",
    runs:      int  = 1
) -> list:
    """
    Returns list[BenchResult] for all (key_size × implementation × run)
    combinations.
    """
    if key_sizes is None:
        key_sizes = [1024, 2048, 3072, 4096]

    results = []
    for bits in key_sizes:
        for _ in range(runs):
            results.append(benchmark_scratch(bits, message))
            results.append(benchmark_library(bits, message))
    return results
