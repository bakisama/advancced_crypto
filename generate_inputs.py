"""
================================================================================
CS6160: Advanced Topics in Cryptology -- IIT Hyderabad
Programming Assignment 1 -- Problem 4

generate_inputs.py
    Pure-Python input generator for the ZK polynomial-evaluation protocol.

Only imports: hashlib (SHA-256), secrets, random, json, sys, os.
Everything else -- primality testing, safe-prime search, subgroup generators
-- is hand-written.  No external cryptographic libraries are used.

--------------------------------------------------------------------------------
USAGE
    python generate_inputs.py --size small  --h-mode hash    --degree 3 --rounds 4
    python generate_inputs.py --size toy    --h-mode discard --degree 2 --rounds 3
    python generate_inputs.py --size full   --h-mode hash    --degree 3

FLAGS
    --size   {toy, small, full}   parameter regime (default: small)
        toy   = p=607,  q=101   (matches PDF numeric example, INSECURE)
        small = 128-bit q, 129-bit p  (<1 s to generate)
        full  = 256-bit q, 257-bit p  (~seconds)
    --h-mode {hash, discard}      method to pick independent generator h
        hash    = SHA-256 hash-to-subgroup  (no trapdoor)
        discard = h = g^s mod p, then discard s  (trapdoor in principle)
    --degree N    polynomial degree d (default 3)
    --rounds N    number of interactive rounds k (default 4)
    --z N         evaluation point (default: random in Z_q)
    --seed N      seed `random` module for reproducible non-crypto choices

OUTPUT
    public.json   = { p, q, g, h, d, k, commitments, z, y }
    private.json  = { coeffs, randomness }
================================================================================
"""

import hashlib
import json
import os
import random
import secrets
import sys


# ===============================================================
# 1. MILLER-RABIN PRIMALITY TEST  (hand-rolled)
# ===============================================================

# Deterministic MR witnesses that correctly classify all n < 3.3 * 10^24.
# Ref: Pomerance-Selfridge-Wagstaff; Jaeschke 1993; Sorenson-Webster 2017.
_DETERMINISTIC_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

# Small primes used for trial division before MR to cut cost.
_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
)


def _mr_is_witness(a: int, n: int, d: int, r: int) -> bool:
    """Return True iff base a is a Miller-Rabin witness proving n composite."""
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(r - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def is_prime(n: int) -> bool:
    """
    Primality test.

    Trial division by small primes, then Miller-Rabin.
    Deterministic for n < 3.3e24 via the fixed base set above.
    Falls back to 40 random bases for larger n (error <= 2^-80).
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n-1 = 2^r * d, d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Choose bases.
    if n < (1 << 82):
        bases = _DETERMINISTIC_BASES
    else:
        bases = [2 + secrets.randbelow(n - 3) for _ in range(40)]

    for a in bases:
        if a % n == 0:
            continue
        if _mr_is_witness(a, n, d, r):
            return False
    return True


# ===============================================================
# 2. SAFE-PRIME SEARCH
#    p = 2q + 1, with both p and q prime.
#    The order-q subgroup of Z_p* is then cyclic of prime order q,
#    and  QR_p = { x^2 mod p : x in Z_p* }  equals that subgroup.
# ===============================================================

def gen_safe_prime(bits: int, tries: int = 200_000) -> tuple:
    """
    Return (p, q) with q having exactly `bits` bits, q and p=2q+1 both prime.

    Cost: dominated by MR tests; empirically ~bits^2 per hit.
    """
    # Quick small-prime trial list for q and p=2q+1.
    sieve = _SMALL_PRIMES[1:]   # skip 2 (q is odd)
    for _ in range(tries):
        q = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        bad = False
        for sp in sieve:
            if q == sp:
                bad = False; break
            if q % sp == 0 or (2 * q + 1) % sp == 0:
                bad = True; break
        if bad:
            continue
        if not is_prime(q):
            continue
        p = 2 * q + 1
        if is_prime(p):
            return p, q
    raise RuntimeError(f"safe-prime search failed after {tries} attempts")


# ===============================================================
# 3. GENERATORS
# ===============================================================

def gen_generator_g(p: int, q: int) -> int:
    """
    Pick a random generator of the unique order-q subgroup of Z_p*.

    Standard trick: any non-trivial square mod p lies in that subgroup
    (since p = 2q+1 and (Z_p*)/{+-1} has order q).
    """
    while True:
        x = 2 + secrets.randbelow(p - 3)      # x in [2, p-2]
        g = pow(x, 2, p)
        if g == 1:
            continue
        if pow(g, q, p) == 1:
            return g


def _hash_to_int(label: bytes, counter: int, out_bytes: int) -> int:
    """
    Derive a deterministic integer of at least out_bytes bytes of entropy
    from `label || counter` using SHA-256 expansion (HKDF-like).
    """
    buf = b""
    i = 0
    while len(buf) < out_bytes:
        blk = hashlib.sha256(
            label + counter.to_bytes(8, "big") + i.to_bytes(4, "big")
        ).digest()
        buf += blk
        i += 1
    return int.from_bytes(buf[:out_bytes], "big")


def gen_h_hash(p: int, q: int, g: int,
               label: bytes = b"ZKP-POLY-H-v1") -> int:
    """
    Independent second generator h via hash-to-subgroup.

    Method: draw x = H(label || ctr) mod p, square into the QR subgroup,
    reject 0, 1, g; confirm order q.  Deterministic given the label and
    current (p, q, g).  No one knows log_g h since x is publicly derivable.
    """
    out_bytes = (p.bit_length() + 7) // 8 + 16      # extra 128 bits for safety
    counter = 0
    while True:
        x = _hash_to_int(label, counter, out_bytes) % p
        counter += 1
        if x < 2:
            continue
        h = pow(x, 2, p)
        if h in (0, 1, g):
            continue
        if pow(h, q, p) == 1:
            return h


def gen_h_discard(p: int, q: int, g: int) -> int:
    """
    Second generator h = g^s mod p, where s is drawn and then forgotten.

    Note: `del s` only removes the Python binding; true secret erasure
    is not guaranteed in a GC language.  Documented for comparison only.
    """
    s = 1 + secrets.randbelow(q - 1)      # s in [1, q-1]
    h = pow(g, s, p)
    del s
    return h


# ===============================================================
# 4. POLYNOMIAL + PEDERSEN
# ===============================================================

def poly_eval(coeffs, z: int, q: int) -> int:
    y = 0
    zp = 1
    for a in coeffs:
        y = (y + a * zp) % q
        zp = (zp * z) % q
    return y


def pedersen(a: int, r: int, g: int, h: int, p: int) -> int:
    return (pow(g, a, p) * pow(h, r, p)) % p


# ===============================================================
# 5. MAIN
# ===============================================================

def _parse(argv):
    a = {}
    i = 0
    while i < len(argv):
        t = argv[i]
        if t in ("-h", "--help"):
            a["help"] = True
            i += 1
        elif t.startswith("--") and i + 1 < len(argv):
            key = t[2:].replace("-", "_")
            a[key] = argv[i + 1]
            i += 2
        else:
            i += 1
    return a


def main():
    args = _parse(sys.argv[1:])
    if args.get("help"):
        print(__doc__)
        sys.exit(0)

    size    = args.get("size", "small").lower()
    h_mode  = args.get("h_mode", "hash").lower()
    degree  = int(args.get("degree", 3))
    rounds  = int(args.get("rounds", 4))
    z_cli   = args.get("z")
    seed    = args.get("seed")
    pub_out = args.get("out_public", "public.json")
    prv_out = args.get("out_private", "private.json")

    if seed is not None:
        random.seed(int(seed))

    # ---- group parameters ----
    if size == "toy":
        p, q, g = 607, 101, 7
    elif size == "small":
        p, q = gen_safe_prime(128)
        g = gen_generator_g(p, q)
    elif size == "full":
        p, q = gen_safe_prime(256)
        g = gen_generator_g(p, q)
    else:
        raise SystemExit(f"Unknown --size '{size}'. Use toy|small|full.")

    if h_mode == "hash":
        h = gen_h_hash(p, q, g)
    elif h_mode == "discard":
        h = gen_h_discard(p, q, g)
    else:
        raise SystemExit(f"Unknown --h-mode '{h_mode}'. Use hash|discard.")

    # ---- integrity asserts ----
    assert pow(g, q, p) == 1 and g != 1, "g not in order-q subgroup"
    assert pow(h, q, p) == 1 and h not in (0, 1), "h not in order-q subgroup"
    assert g != h, "g == h is a degenerate setup"

    # ---- polynomial ----
    coeffs      = [secrets.randbelow(q) for _ in range(degree + 1)]
    randomness  = [secrets.randbelow(q) for _ in range(degree + 1)]
    z           = (int(z_cli) % q) if z_cli is not None else secrets.randbelow(q)
    y           = poly_eval(coeffs, z, q)
    commitments = [pedersen(a, r, g, h, p) for a, r in zip(coeffs, randomness)]

    # ---- emit ----
    public = {
        "p": p, "q": q, "g": g, "h": h,
        "d": degree, "k": rounds,
        "commitments": commitments,
        "z": z, "y": y,
    }
    private = {"coeffs": coeffs, "randomness": randomness}

    with open(pub_out, "w") as f:
        json.dump(public, f, indent=2)
    with open(prv_out, "w") as f:
        json.dump(private, f, indent=2)

    print(f"[GEN] size   = {size}")
    print(f"[GEN] h-mode = {h_mode}")
    print(f"[GEN] q bits = {q.bit_length()}, p bits = {p.bit_length()}")
    print(f"[GEN] d = {degree}, k = {rounds}")
    print(f"[GEN] y = P({z}) = {y}  (mod q)")
    print(f"[GEN] wrote {pub_out} and {prv_out}")


if __name__ == "__main__":
    main()
