"""
================================================================================
CS6160: Advanced Topics in Cryptology -- IIT Hyderabad
Programming Assignment 1 -- Problem 4

Zero-Knowledge Proof of Knowledge and Correct Evaluation of a Secret Polynomial

Authors : Divyansh Sevta  (CS25MTECH14018)
          Nishanth D.      (CS25MTECH14020)

Protocol : Parallel per-coefficient Sigma protocol with shared challenge
           + scalar evaluation-consistency check.
Hash     : SHA-256  (Fiat-Shamir non-interactive; also used in hash-derived
           interactive variant).
Libs     : NONE -- only Python built-ins (hashlib, json, secrets, sys, os).

--------------------------------------------------------------------------------
MODES
    noninteractive
        Single-shot Fiat-Shamir NIZK.  Challenge c = H(all public + T_i + E).

    interactive-hash
        k-round interactive protocol.  In each round j the per-round challenge
        c_j = H("ZKP-POLY-INT-v1" || j || public || T_list_j || E_j)  mod q.
        Verifier independently recomputes c_j -- no trust in prover's draw.
        This is the single-program "simulated interactive" variant.

    (For the live two-program interactive variant see
     prover_interactive.py / verifier_interactive.py.)

USAGE
    python Problem4.py prover   --mode noninteractive
    python Problem4.py prover   --mode interactive-hash
    python Problem4.py prover   --mode noninteractive --tamper
    python Problem4.py verifier

INPUT / OUTPUT FILES
    public.json      public parameters + commitments + (z, y)   (read)
    private.json     prover's witness  (coeffs, randomness)     (read by prover)
    proof.json       proof transcript                           (written/read)
================================================================================
"""

import hashlib
import json
import secrets
import sys


# ============================================================================
# 1. GROUP ARITHMETIC
#    All exponents are reduced mod q (order of G_q).
#    All group elements live in Z_p^* with p = 2q + 1 (safe prime).
# ============================================================================

def g_exp(base: int, exp: int, p: int, q: int) -> int:
    return pow(base, exp % q, p)


def rand_scalar(q: int) -> int:
    return secrets.randbelow(q)


# ============================================================================
# 2. PEDERSEN COMMITMENT   C = g^v * h^r  mod p
# ============================================================================

def pedersen(v: int, r: int, g: int, h: int, p: int, q: int) -> int:
    return (g_exp(g, v, p, q) * g_exp(h, r, p, q)) % p


def compute_commitments(coeffs, randomness, g, h, p, q):
    assert len(coeffs) == len(randomness)
    return [pedersen(a, r, g, h, p, q) for a, r in zip(coeffs, randomness)]


# ============================================================================
# 3. POLYNOMIAL EVALUATION   y = sum_i a_i * z^i  mod q
# ============================================================================

def poly_eval(coeffs, z, q):
    y = 0
    zp = 1
    for a in coeffs:
        y = (y + a * zp) % q
        zp = (zp * z) % q
    return y


# ============================================================================
# 4. CANONICAL ENCODING + HASH CHALLENGES
#    Encoding: 4-byte big-endian length || big-endian bytes.
#    Domain-separated SHA-256 for each use-site.
# ============================================================================

def _enc_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative int not allowed in transcript")
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return len(raw).to_bytes(4, "big") + raw


def _hash_public_prefix(g, h, p, q, commitments, z, y) -> bytes:
    """Common prefix used by both NI and interactive-hash challenge hashes."""
    buf = b""
    for v in (g, h, p, q):
        buf += _enc_int(v)
    buf += _enc_int(len(commitments))
    for C in commitments:
        buf += _enc_int(C)
    buf += _enc_int(z)
    buf += _enc_int(y)
    return buf


def fs_challenge_ni(g, h, p, q, commitments, z, y, T_list, E) -> int:
    """Non-interactive (Fiat-Shamir) challenge."""
    H = hashlib.sha256()
    H.update(b"ZKP-POLY-FS-v1:")
    H.update(_hash_public_prefix(g, h, p, q, commitments, z, y))
    for T in T_list:
        H.update(_enc_int(T))
    H.update(_enc_int(E))
    return int.from_bytes(H.digest(), "big") % q


def fs_challenge_round(g, h, p, q, commitments, z, y,
                       round_index: int, T_list, E) -> int:
    """Hash-derived challenge for the j-th interactive round."""
    H = hashlib.sha256()
    H.update(b"ZKP-POLY-INT-v1:")
    H.update(_enc_int(round_index))
    H.update(_hash_public_prefix(g, h, p, q, commitments, z, y))
    for T in T_list:
        H.update(_enc_int(T))
    H.update(_enc_int(E))
    return int.from_bytes(H.digest(), "big") % q


# ============================================================================
# 5. SIGMA PROTOCOL CORE
# ============================================================================

def commit_phase(d, z, g, h, p, q):
    """
    Sample k_{i,a}, k_{i,r} fresh; compute T_i = g^{k_{i,a}} h^{k_{i,r}}
    and scalar E = sum_i k_{i,a} z^i  mod q.
    Returns (T_list, E, k_a, k_r).
    """
    k_a = [rand_scalar(q) for _ in range(d + 1)]
    k_r = [rand_scalar(q) for _ in range(d + 1)]
    T_list = [(g_exp(g, ka, p, q) * g_exp(h, kr, p, q)) % p
              for ka, kr in zip(k_a, k_r)]
    E = 0
    zp = 1
    for ka in k_a:
        E = (E + ka * zp) % q
        zp = (zp * z) % q
    return T_list, E, k_a, k_r


def response_phase(c, coeffs, randomness, k_a, k_r, q):
    u_a = [(ka + c * a) % q for ka, a in zip(k_a, coeffs)]
    u_r = [(kr + c * r) % q for kr, r in zip(k_r, randomness)]
    return u_a, u_r


def verify_checks(commitments, z, y, T_list, E, c, u_a, u_r, g, h, p, q) -> bool:
    # (V1)  g^{u_a} h^{u_r} == T_i * C_i^c   for every i
    for C, T, ua, ur in zip(commitments, T_list, u_a, u_r):
        lhs = (g_exp(g, ua, p, q) * g_exp(h, ur, p, q)) % p
        rhs = (T * g_exp(C, c, p, q)) % p
        if lhs != rhs:
            return False
    # (V_eval)  sum u_a z^i == E + c*y   mod q
    lhs_eval = 0
    zp = 1
    for ua in u_a:
        lhs_eval = (lhs_eval + ua * zp) % q
        zp = (zp * z) % q
    rhs_eval = (E + c * y) % q
    return lhs_eval == rhs_eval


# ============================================================================
# 6. SUBGROUP + RANGE VALIDATION  (verifier-side sanity checks)
# ============================================================================

def validate_public(pub: dict) -> None:
    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    # We require the order-q subgroup to exist inside Z_p^*, i.e. q | (p-1).
    # For the 'small'/'full' generators we produce p = 2q+1 (safe prime);
    # for 'toy' (PDF: p=607, q=101) we have p = 6q+1.  Either is fine.
    if p < 5 or q < 3 or (p - 1) % q != 0:
        raise ValueError("invalid (p, q): require q | (p-1)")
    if not (1 < g < p) or pow(g, q, p) != 1:
        raise ValueError("g is not an order-q element")
    if not (1 < h < p) or pow(h, q, p) != 1:
        raise ValueError("h is not an order-q element")
    if g == h:
        raise ValueError("g == h (degenerate)")
    for C in pub["commitments"]:
        if not (0 < C < p) or pow(C, q, p) != 1:
            raise ValueError(f"commitment {C} not in order-q subgroup")
    if not (0 <= pub["z"] < q):
        raise ValueError("z out of range")
    if not (0 <= pub["y"] < q):
        raise ValueError("y out of range")


# ============================================================================
# 7. PROTOCOL WRAPPERS
# ============================================================================

def ni_prover(pub, coeffs, randomness):
    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    d = pub["d"]
    z, y = pub["z"], pub["y"]
    C = pub["commitments"]

    T_list, E, k_a, k_r = commit_phase(d, z, g, h, p, q)
    c = fs_challenge_ni(g, h, p, q, C, z, y, T_list, E)
    u_a, u_r = response_phase(c, coeffs, randomness, k_a, k_r, q)
    return {"T_list": T_list, "E": E, "c": c, "u_a": u_a, "u_r": u_r}


def ni_verifier(pub, proof) -> bool:
    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    z, y = pub["z"], pub["y"]
    C = pub["commitments"]

    c_expected = fs_challenge_ni(g, h, p, q, C, z, y, proof["T_list"], proof["E"])
    if c_expected != proof["c"]:
        return False
    return verify_checks(
        C, z, y,
        proof["T_list"], proof["E"], proof["c"],
        proof["u_a"], proof["u_r"],
        g, h, p, q,
    )


def inthash_prover(pub, coeffs, randomness, k_rounds: int):
    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    d = pub["d"]
    z, y = pub["z"], pub["y"]
    C = pub["commitments"]

    rounds = []
    for j in range(k_rounds):
        T_list, E, k_a, k_r = commit_phase(d, z, g, h, p, q)
        c = fs_challenge_round(g, h, p, q, C, z, y, j, T_list, E)
        u_a, u_r = response_phase(c, coeffs, randomness, k_a, k_r, q)
        rounds.append({"T_list": T_list, "E": E, "c": c,
                       "u_a": u_a, "u_r": u_r})
    return rounds


def inthash_verifier(pub, rounds) -> bool:
    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    z, y = pub["z"], pub["y"]
    C = pub["commitments"]

    for j, rnd in enumerate(rounds):
        c_expected = fs_challenge_round(g, h, p, q, C, z, y, j,
                                        rnd["T_list"], rnd["E"])
        if c_expected != rnd["c"]:
            return False
        if not verify_checks(C, z, y, rnd["T_list"], rnd["E"], rnd["c"],
                             rnd["u_a"], rnd["u_r"], g, h, p, q):
            return False
    return True


# ============================================================================
# 8. TAMPERING  (for REJECT demo)
# ============================================================================

def tamper_proof(proof_obj, mode: str, q: int):
    """Flip the first response scalar by +1 mod q. Breaks V1 and V_eval."""
    def flip(resp):
        resp["u_a"][0] = (resp["u_a"][0] + 1) % q
    if mode == "noninteractive":
        flip(proof_obj["transcript"])
    else:
        flip(proof_obj["transcript"][0])
    proof_obj["tampered"] = True


# ============================================================================
# 9. PROVER / VERIFIER MAIN PROGRAMS
# ============================================================================

def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def run_prover(args):
    pub     = _load(args["public"])
    priv    = _load(args["private"])
    mode    = args["mode"]
    tamper  = args["tamper"]

    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    d, k       = pub["d"], pub.get("k", 1)
    coeffs     = priv["coeffs"]
    randomness = priv["randomness"]

    validate_public(pub)
    assert len(coeffs) == d + 1 == len(randomness)
    assert all(0 <= a < q for a in coeffs),     "coeff out of [0, q)"
    assert all(0 <= r < q for r in randomness), "randomness out of [0, q)"
    recomputed = compute_commitments(coeffs, randomness, g, h, p, q)
    assert recomputed == pub["commitments"], \
        "private witness does not open public commitments"
    assert poly_eval(coeffs, pub["z"], q) == pub["y"], \
        "P(z) != y -- prover cannot prove a false statement"

    if mode == "noninteractive":
        transcript = ni_prover(pub, coeffs, randomness)
    elif mode == "interactive-hash":
        transcript = inthash_prover(pub, coeffs, randomness, k)
    else:
        raise SystemExit(f"Unknown --mode '{mode}'")

    proof = {"mode": mode,
             "k": k if mode == "interactive-hash" else 1,
             "transcript": transcript,
             "tampered": False}

    if tamper:
        tamper_proof(proof, mode, q)

    _dump(args["proof"], proof)

    print(f"[PROVER] mode       = {mode}")
    print(f"[PROVER] tampered   = {proof['tampered']}")
    if mode == "interactive-hash":
        print(f"[PROVER] rounds     = {k}")
    print(f"[PROVER] wrote {args['proof']}")


def run_verifier(args):
    pub   = _load(args["public"])
    proof = _load(args["proof"])

    validate_public(pub)

    mode = proof["mode"]
    if mode == "noninteractive":
        ok = ni_verifier(pub, proof["transcript"])
    elif mode == "interactive-hash":
        ok = inthash_verifier(pub, proof["transcript"])
    else:
        print("REJECT")
        print(f"[VERIFIER] unknown proof mode '{mode}'")
        return "REJECT"

    verdict = "ACCEPT" if ok else "REJECT"
    print(verdict)
    print(f"[VERIFIER] mode     = {mode}")
    print(f"[VERIFIER] tampered-flag-in-proof = {proof.get('tampered', False)}")
    return verdict


# ============================================================================
# 10. CLI
# ============================================================================

def _parse(argv):
    a = {
        "mode":    "noninteractive",
        "public":  "public.json",
        "private": "private.json",
        "proof":   "proof.json",
        "tamper":  False,
    }
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == "--mode" and i + 1 < len(argv):
            a["mode"] = argv[i + 1]; i += 2
        elif t == "--public" and i + 1 < len(argv):
            a["public"] = argv[i + 1]; i += 2
        elif t == "--private" and i + 1 < len(argv):
            a["private"] = argv[i + 1]; i += 2
        elif t == "--proof" and i + 1 < len(argv):
            a["proof"] = argv[i + 1]; i += 2
        elif t == "--tamper":
            a["tamper"] = True; i += 1
        else:
            i += 1
    return a


_USAGE = """
USAGE
    python Problem4.py prover   [--mode noninteractive|interactive-hash]
                                [--public public.json]
                                [--private private.json]
                                [--proof proof.json]
                                [--tamper]

    python Problem4.py verifier [--public public.json]
                                [--proof proof.json]
"""

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(_USAGE); sys.exit(0)

    role = sys.argv[1].lower()
    args = _parse(sys.argv[2:])

    if role == "prover":
        run_prover(args)
    elif role == "verifier":
        res = run_verifier(args)
        sys.exit(0 if res == "ACCEPT" else 1)
    else:
        print(f"[ERROR] Unknown role '{role}'"); print(_USAGE); sys.exit(1)
