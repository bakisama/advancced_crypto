"""
================================================================================
CS6160: Advanced Topics in Cryptology — IIT Hyderabad
Programming Assignment 1 — Problem 4

Zero-Knowledge Proof of Knowledge and Correct Evaluation of a Secret Polynomial

Authors : Divyansh Sevta  (CS25MTECH14018)
          Nishanth D.      (CS25MTECH14020)

Protocol  : Parallel per-coefficient Sigma protocol + scalar evaluation check
Hash      : SHA-256 (Fiat-Shamir non-interactive version)
Libraries : NONE — only built-in Python (hashlib, json, secrets, sys)

--------------------------------------------------------------------------------
USAGE
    Prover   (interactive)     : python zkp_polynomial.py prover    --mode interactive
    Prover   (non-interactive) : python zkp_polynomial.py prover    --mode noninteractive
    Verifier                   : python zkp_polynomial.py verifier

INPUT FILES
    prover_input.json   — all prover private + public inputs
    proof.json          — written by prover; read by verifier

OUTPUT
    proof.json          — written by prover  (commitments, y, transcript)
    stdout              — verifier prints ACCEPT or REJECT

See README at the bottom of this file for full JSON schemas.
================================================================================
"""

import hashlib
import json
import secrets
import sys


# ═══════════════════════════════════════════════════════════════════════════════
# 1. GROUP ARITHMETIC
#    All group operations live in the cyclic subgroup G_q of Z*_p
#    where p is a safe prime (p = 2q+1) and q is the prime group order.
#    Exponent arithmetic is always mod q.
#    Group element arithmetic is always mod p.
# ═══════════════════════════════════════════════════════════════════════════════

def group_exp(base: int, exp: int, p: int, q: int) -> int:
    """base^exp mod p  (exponent reduced mod q first)."""
    return pow(base, exp % q, p)


def group_mul(a: int, b: int, p: int) -> int:
    """a * b mod p."""
    return (a * b) % p


def group_inv(a: int, p: int) -> int:
    """Modular inverse of a in Z*_p via Fermat's little theorem (p prime)."""
    return pow(a, p - 2, p)


def scalar_inv(a: int, q: int) -> int:
    """Modular inverse of a in Z_q (q prime)."""
    return pow(a, q - 2, q)


def rand_scalar(q: int) -> int:
    """
    Sample a uniformly random scalar from Z_q.
    Uses secrets.randbelow — a CSPRNG backed by OS entropy.
    Never use random.randint for cryptographic nonces.
    """
    return secrets.randbelow(q)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PEDERSEN COMMITMENT SCHEME
#    Com(v ; r) = g^v * h^r  mod p
#    Perfectly hiding (statistical), computationally binding under DL.
# ═══════════════════════════════════════════════════════════════════════════════

def pedersen_commit(v: int, r: int, g: int, h: int, p: int, q: int) -> int:
    """
    Compute Pedersen commitment C = g^v * h^r mod p.

    Args:
        v : secret value (polynomial coefficient a_i)
        r : blinding randomness r_i
        g : generator 1 (public)
        h : generator 2 (public, log_g(h) unknown — trapdoor)
        p : group modulus
        q : group order

    Returns:
        C = g^v * h^r mod p
    """
    gv = group_exp(g, v, p, q)
    hr = group_exp(h, r, p, q)
    return group_mul(gv, hr, p)


def compute_commitments(coeffs: list, randomness: list,
                        g: int, h: int, p: int, q: int) -> list:
    """
    Generate Pedersen commitments for all polynomial coefficients.

    Args:
        coeffs     : [a_0, a_1, ..., a_d]
        randomness : [r_0, r_1, ..., r_d]

    Returns:
        [C_0, C_1, ..., C_d]  where C_i = g^{a_i} * h^{r_i} mod p
    """
    assert len(coeffs) == len(randomness), \
        "coeffs and randomness must have the same length."
    return [
        pedersen_commit(a, r, g, h, p, q)
        for a, r in zip(coeffs, randomness)
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. POLYNOMIAL EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def poly_eval(coeffs: list, z: int, q: int) -> int:
    """
    Evaluate P(z) = sum_{i=0}^{d} a_i * z^i  mod q.

    Uses Horner's method:  P(z) = a_0 + z*(a_1 + z*(a_2 + ... ))
    but written in the forward direction for clarity.

    Args:
        coeffs : [a_0, a_1, ..., a_d]  (index matches degree)
        z      : evaluation point in Z_q
        q      : field modulus

    Returns:
        y = P(z) mod q
    """
    result = 0
    z_pow = 1
    for a in coeffs:
        result = (result + a * z_pow) % q
        z_pow = (z_pow * z) % q
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FIAT-SHAMIR CHALLENGE  (non-interactive version only)
#    c = H( g || h || p || q || C_0 || ... || C_d || z || y
#                             || T_0 || ... || T_d || E ) mod q
#
#    H is SHA-256; output is reduced mod q.
#    All integers use canonical big-endian, length-prefixed encoding.
#    Domain separator prevents cross-protocol attacks.
# ═══════════════════════════════════════════════════════════════════════════════

def _encode_int(n: int) -> bytes:
    """
    Canonical encoding: big-endian bytes of n, preceded by a 4-byte
    length field.  Ensures unambiguous parsing even for variable-length ints.
    """
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    return len(raw).to_bytes(4, 'big') + raw


def fiat_shamir_challenge(g: int, h: int, p: int, q: int,
                          commitments: list,
                          z: int, y: int,
                          T_list: list, E: int) -> int:
    """
    Derive the non-interactive Fiat-Shamir challenge via SHA-256.

    Returns c in Z_q.
    """
    h_obj = hashlib.sha256()
    h_obj.update(b"ZKP-POLY-FS-v1:")          # domain separator
    for val in [g, h, p, q]:
        h_obj.update(_encode_int(val))
    for C in commitments:
        h_obj.update(_encode_int(C))
    h_obj.update(_encode_int(z))
    h_obj.update(_encode_int(y))
    for T in T_list:
        h_obj.update(_encode_int(T))
    h_obj.update(_encode_int(E))
    return int.from_bytes(h_obj.digest(), 'big') % q


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SIGMA PROTOCOL — CORE STEPS  (shared by interactive and non-interactive)
# ═══════════════════════════════════════════════════════════════════════════════

def _commit_phase(coeffs: list, randomness: list,
                  z: int, g: int, h: int, p: int, q: int) -> dict:
    """
    PROVER — Commit phase (Move 1 of Sigma protocol).

    For each i in {0,...,d}:
        sample k_{i,a}, k_{i,r} <-$ Z_q
        compute T_i = g^{k_{i,a}} * h^{k_{i,r}}  mod p

    Compute scalar evaluation nonce:
        E = sum_{i=0}^{d} k_{i,a} * z^i  mod q

    Returns:
        T_list    : [T_0, ..., T_d]  — sent to verifier
        E         : int              — sent to verifier
        k_a_list  : secret nonces   — kept by prover, NOT sent
        k_r_list  : secret nonces   — kept by prover, NOT sent
    """
    d = len(coeffs) - 1
    k_a_list = [rand_scalar(q) for _ in range(d + 1)]
    k_r_list = [rand_scalar(q) for _ in range(d + 1)]

    T_list = [
        group_mul(group_exp(g, ka, p, q), group_exp(h, kr, p, q), p)
        for ka, kr in zip(k_a_list, k_r_list)
    ]

    E = 0
    z_pow = 1
    for ka in k_a_list:
        E = (E + ka * z_pow) % q
        z_pow = (z_pow * z) % q

    return {
        "T_list":  T_list,
        "E":       E,
        "k_a_list": k_a_list,
        "k_r_list": k_r_list,
    }


def _response_phase(c: int,
                    coeffs: list, randomness: list,
                    k_a_list: list, k_r_list: list,
                    q: int) -> dict:
    """
    PROVER — Response phase (Move 3 of Sigma protocol).

    For each i:
        u_{i,a} = k_{i,a} + c * a_i  mod q
        u_{i,r} = k_{i,r} + c * r_i  mod q

    Returns:
        u_a_list : [u_{0,a}, ..., u_{d,a}]
        u_r_list : [u_{0,r}, ..., u_{d,r}]
    """
    u_a_list = [(ka + c * a) % q for ka, a in zip(k_a_list, coeffs)]
    u_r_list = [(kr + c * r) % q for kr, r in zip(k_r_list, randomness)]
    return {"u_a_list": u_a_list, "u_r_list": u_r_list}


def _verify_checks(commitments: list, z: int, y: int,
                   T_list: list, E: int, c: int,
                   u_a_list: list, u_r_list: list,
                   g: int, h: int, p: int, q: int) -> bool:
    """
    VERIFIER — Two algebraic checks.

    Check (V1) for all i:
        g^{u_{i,a}} * h^{u_{i,r}}  ==  T_i * C_i^c   mod p

    Check (V_eval):
        sum_{i=0}^{d} u_{i,a} * z^i  ==  E + c * y   mod q

    Returns True iff both checks pass for all i.
    """
    # V1 — per-coefficient commitment opening check
    for i, (C, T, ua, ur) in enumerate(
            zip(commitments, T_list, u_a_list, u_r_list)):
        lhs = group_mul(group_exp(g, ua, p, q),
                        group_exp(h, ur, p, q), p)
        rhs = group_mul(T, group_exp(C, c, p, q), p)
        if lhs != rhs:
            return False

    # V_eval — scalar evaluation consistency check
    lhs_eval = 0
    z_pow = 1
    for ua in u_a_list:
        lhs_eval = (lhs_eval + ua * z_pow) % q
        z_pow = (z_pow * z) % q

    rhs_eval = (E + c * y) % q
    return lhs_eval == rhs_eval


# ═══════════════════════════════════════════════════════════════════════════════
# 6. INTERACTIVE PROTOCOL  (k rounds)
#    In a real deployment the verifier sends a fresh random c each round.
#    Here the verifier challenge is simulated by the prover using the CSPRNG
#    (rand_scalar) so the full transcript can be generated in one program and
#    verified in another via proof.json.
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_prover(coeffs: list, randomness: list,
                       commitments: list,
                       y: int, z: int, k: int,
                       g: int, h: int, p: int, q: int) -> list:
    """
    PROVER — Generate k-round interactive proof transcript.

    Each round is independent with fresh nonces.
    The verifier challenge c is sampled fresh each round.

    Returns:
        List of k dicts, each with keys: T_list, E, c, u_a_list, u_r_list
    """
    rounds = []
    for _ in range(k):
        commit_data = _commit_phase(coeffs, randomness, z, g, h, p, q)
        c = rand_scalar(q)                    # verifier challenge
        resp = _response_phase(
            c, coeffs, randomness,
            commit_data["k_a_list"], commit_data["k_r_list"], q
        )
        rounds.append({
            "T_list":   commit_data["T_list"],
            "E":        commit_data["E"],
            "c":        c,
            "u_a_list": resp["u_a_list"],
            "u_r_list": resp["u_r_list"],
        })
    return rounds


def interactive_verifier(commitments: list, z: int, y: int,
                         rounds: list,
                         g: int, h: int, p: int, q: int) -> str:
    """
    VERIFIER — Verify all k rounds of an interactive transcript.

    Returns "ACCEPT" only if every round passes; "REJECT" otherwise.
    """
    for rnd in rounds:
        if not _verify_checks(
            commitments, z, y,
            rnd["T_list"], rnd["E"], rnd["c"],
            rnd["u_a_list"], rnd["u_r_list"],
            g, h, p, q
        ):
            return "REJECT"
    return "ACCEPT"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. NON-INTERACTIVE PROTOCOL  (Fiat-Shamir transform, k=1)
# ═══════════════════════════════════════════════════════════════════════════════

def noninteractive_prover(coeffs: list, randomness: list,
                          commitments: list,
                          y: int, z: int,
                          g: int, h: int, p: int, q: int) -> dict:
    """
    PROVER — Generate a non-interactive proof via the Fiat-Shamir transform.

    Steps:
        1. Sample fresh nonces; compute first message (T_list, E)
        2. Derive challenge: c = H(g, h, p, q, C_i, z, y, T_i, E) mod q
        3. Compute responses (u_a_list, u_r_list)

    Returns proof pi = { T_list, E, c, u_a_list, u_r_list }
    """
    commit_data = _commit_phase(coeffs, randomness, z, g, h, p, q)

    c = fiat_shamir_challenge(
        g, h, p, q, commitments, z, y,
        commit_data["T_list"], commit_data["E"]
    )

    resp = _response_phase(
        c, coeffs, randomness,
        commit_data["k_a_list"], commit_data["k_r_list"], q
    )

    return {
        "T_list":   commit_data["T_list"],
        "E":        commit_data["E"],
        "c":        c,
        "u_a_list": resp["u_a_list"],
        "u_r_list": resp["u_r_list"],
    }


def noninteractive_verifier(commitments: list, z: int, y: int,
                             proof: dict,
                             g: int, h: int, p: int, q: int) -> str:
    """
    VERIFIER — Verify a non-interactive proof.

    Steps:
        1. Recompute c = H(...) and assert it matches proof["c"]
        2. Run standard V1 and V_eval checks

    Returns "ACCEPT" or "REJECT".
    """
    expected_c = fiat_shamir_challenge(
        g, h, p, q, commitments, z, y,
        proof["T_list"], proof["E"]
    )
    if expected_c != proof["c"]:
        return "REJECT"

    ok = _verify_checks(
        commitments, z, y,
        proof["T_list"], proof["E"], proof["c"],
        proof["u_a_list"], proof["u_r_list"],
        g, h, p, q
    )
    return "ACCEPT" if ok else "REJECT"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. PROVER MAIN PROGRAM
#    Input  : prover_input.json
#    Output : proof.json
# ═══════════════════════════════════════════════════════════════════════════════

def run_prover(input_path: str = "prover_input.json",
               output_path: str = "proof.json",
               mode: str = "noninteractive"):
    """
    Prover entry point.

    Reads prover_input.json, generates proof, writes proof.json.
    """
    with open(input_path, "r") as f:
        inp = json.load(f)

    p          = inp["p"]
    q          = inp["q"]
    g          = inp["g"]
    h          = inp["h"]
    d          = inp["d"]
    coeffs     = inp["coeffs"]
    randomness = inp["randomness"]
    z          = inp["z"]
    k          = inp.get("k", 1)

    assert len(coeffs) == d + 1,          "Need exactly d+1 coefficients."
    assert len(randomness) == d + 1,      "Need exactly d+1 randomness values."
    assert len(coeffs) == len(randomness)

    # Step 1 — Commitments
    commitments = compute_commitments(coeffs, randomness, g, h, p, q)

    # Step 2 — Claimed evaluation value
    y = poly_eval(coeffs, z, q)

    # Step 3 — Proof
    if mode == "interactive":
        transcript = interactive_prover(
            coeffs, randomness, commitments, y, z, k, g, h, p, q
        )
    else:
        transcript = noninteractive_prover(
            coeffs, randomness, commitments, y, z, g, h, p, q
        )

    # Step 4 — Write output
    output = {
        "mode":        mode,
        "p":           p,
        "q":           q,
        "g":           g,
        "h":           h,
        "commitments": commitments,
        "y":           y,
        "z":           z,
        "transcript":  transcript,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[PROVER] Commitments : {commitments}")
    print(f"[PROVER] y = P({z})  : {y}")
    print(f"[PROVER] Mode        : {mode}")
    print(f"[PROVER] Proof written to '{output_path}'")


# ═══════════════════════════════════════════════════════════════════════════════
# 9. VERIFIER MAIN PROGRAM
#    Input  : proof.json  (written by prover)
#    Output : ACCEPT or REJECT  (stdout)
# ═══════════════════════════════════════════════════════════════════════════════

def run_verifier(input_path: str = "proof.json"):
    """
    Verifier entry point.

    Reads proof.json, verifies, prints ACCEPT or REJECT.
    """
    with open(input_path, "r") as f:
        inp = json.load(f)

    mode        = inp["mode"]
    p           = inp["p"]
    q           = inp["q"]
    g           = inp["g"]
    h           = inp["h"]
    commitments = inp["commitments"]
    y           = inp["y"]
    z           = inp["z"]
    transcript  = inp["transcript"]

    if mode == "interactive":
        result = interactive_verifier(commitments, z, y, transcript, g, h, p, q)
    else:
        result = noninteractive_verifier(commitments, z, y, transcript, g, h, p, q)

    print(result)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 10. COMMAND-LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_args(argv):
    args = {"mode": "noninteractive", "input": None, "output": "proof.json"}
    i = 0
    while i < len(argv):
        if argv[i] == "--mode" and i + 1 < len(argv):
            args["mode"] = argv[i + 1]; i += 2
        elif argv[i] == "--input" and i + 1 < len(argv):
            args["input"] = argv[i + 1]; i += 2
        elif argv[i] == "--output" and i + 1 < len(argv):
            args["output"] = argv[i + 1]; i += 2
        else:
            i += 1
    return args


def _print_usage():
    print("""
USAGE
    python zkp_polynomial.py prover   [--mode interactive|noninteractive]
                                      [--input  prover_input.json]
                                      [--output proof.json]

    python zkp_polynomial.py verifier [--input proof.json]

DEFAULTS
    --mode   noninteractive
    --input  prover_input.json   (for prover)
             proof.json          (for verifier)
    --output proof.json
""")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _print_usage()
        sys.exit(0)

    role = sys.argv[1].lower()
    args = _parse_args(sys.argv[2:])

    if role == "prover":
        run_prover(
            input_path  = args["input"] or "prover_input.json",
            output_path = args["output"],
            mode        = args["mode"]
        )

    elif role == "verifier":
        run_verifier(input_path = args["input"] or "proof.json")

    else:
        print(f"[ERROR] Unknown role '{role}'. Expected: prover | verifier")
        _print_usage()
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# README — INPUT / OUTPUT SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════
#
# ── prover_input.json ──────────────────────────────────────────────────────────
# {
#   "p"          : <int>         safe prime  (group modulus, p = 2q+1)
#   "q"          : <int>         prime order of G_q
#   "g"          : <int>         generator g of G_q  (1 < g < p, order q)
#   "h"          : <int>         generator h of G_q  (1 < h < p, log_g(h) unknown)
#   "d"          : <int>         polynomial degree
#   "coeffs"     : [a0,...,ad]   polynomial coefficients  (length = d+1)
#   "randomness" : [r0,...,rd]   Pedersen blinding values (length = d+1)
#   "z"          : <int>         evaluation point in Z_q
#   "k"          : <int>         number of rounds (interactive mode only; ignored for NI)
# }
#
# ── proof.json  (prover output / verifier input) ───────────────────────────────
# {
#   "mode"        : "interactive" | "noninteractive"
#   "p"           : <int>
#   "q"           : <int>
#   "g"           : <int>
#   "h"           : <int>
#   "commitments" : [C0, C1, ..., Cd]
#   "y"           : <int>          claimed evaluation P(z) mod q
#   "z"           : <int>          evaluation point
#
#   — noninteractive —
#   "transcript"  : {
#       "T_list"   : [T0, ..., Td],
#       "E"        : <int>,
#       "c"        : <int>,
#       "u_a_list" : [u0a, ..., uda],
#       "u_r_list" : [u0r, ..., udr]
#   }
#
#   — interactive —
#   "transcript"  : [          <- list of k round objects
#       {
#           "T_list"   : [T0, ..., Td],
#           "E"        : <int>,
#           "c"        : <int>,
#           "u_a_list" : [u0a, ..., uda],
#           "u_r_list" : [u0r, ..., udr]
#       },
#       ...
#   ]
# }
# ═══════════════════════════════════════════════════════════════════════════════