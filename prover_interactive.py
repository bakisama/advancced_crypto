"""
================================================================================
prover_interactive.py  --  live two-program interactive prover (Variant B)

Runs the k-round multi-round interactive ZKP against a separately-running
verifier_interactive.py.  Messages are exchanged via files in a session
directory (default: ./session/), one file per message.

This matches the spec's "multi-round interactive zero-knowledge protocol":
the verifier samples a fresh challenge c_j in each round -- the prover
cannot influence it.

--------------------------------------------------------------------------------
USAGE (in two shells, or sequentially with a shared session dir)

    # shell A (starts first or second -- order does not matter, both poll)
    python verifier_interactive.py --session ./session

    # shell B
    python prover_interactive.py   --session ./session

Both sides read public.json; the prover additionally reads private.json.
Verifier prints ACCEPT / REJECT when done.
================================================================================
"""

import json
import os
import sys
import time

from Problem4 import (
    commit_phase, response_phase, compute_commitments, poly_eval,
    validate_public,
)


POLL_INTERVAL = 0.05   # seconds
POLL_TIMEOUT  = 60.0   # seconds per message


def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)   # atomic


def _wait(path):
    t0 = time.time()
    while not os.path.exists(path):
        if time.time() - t0 > POLL_TIMEOUT:
            raise TimeoutError(f"timeout waiting for {path}")
        time.sleep(POLL_INTERVAL)
    # small settle delay in case file is still being flushed
    time.sleep(0.02)
    return _load(path)


def run(session_dir: str, public_path: str, private_path: str):
    os.makedirs(session_dir, exist_ok=True)

    pub  = _load(public_path)
    priv = _load(private_path)
    validate_public(pub)

    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    d, k       = pub["d"], pub.get("k", 1)
    coeffs     = priv["coeffs"]
    randomness = priv["randomness"]
    z, y       = pub["z"], pub["y"]
    C          = pub["commitments"]

    # cross-check witness <-> public
    assert compute_commitments(coeffs, randomness, g, h, p, q) == C, \
        "private witness does not match public commitments"
    assert poly_eval(coeffs, z, q) == y, "P(z) != y"

    # announce session config (verifier may use this too)
    _dump(os.path.join(session_dir, "config.json"),
          {"k": k, "started_by": "prover"})

    print(f"[PROVER] session = {session_dir}")
    print(f"[PROVER] k = {k} rounds, d = {d}")

    for j in range(k):
        # --- Move 1: commit ---
        T_list, E, k_a, k_r = commit_phase(d, z, g, h, p, q)
        _dump(os.path.join(session_dir, f"round_{j}_A.json"),
              {"T_list": T_list, "E": E})
        print(f"[PROVER] round {j}: sent commit (T_list, E)")

        # --- Move 2: receive challenge ---
        chal_path = os.path.join(session_dir, f"round_{j}_B.json")
        challenge = _wait(chal_path)
        c = challenge["c"]
        print(f"[PROVER] round {j}: got challenge c = {c}")

        # --- Move 3: respond ---
        u_a, u_r = response_phase(c, coeffs, randomness, k_a, k_r, q)
        _dump(os.path.join(session_dir, f"round_{j}_C.json"),
              {"u_a": u_a, "u_r": u_r})
        print(f"[PROVER] round {j}: sent response (u_a, u_r)")

        # --- wait for verifier's per-round verdict ---
        verdict = _wait(os.path.join(session_dir, f"round_{j}_V.json"))
        print(f"[PROVER] round {j}: verifier says {verdict['result']}")
        if verdict["result"] != "ok":
            print("[PROVER] aborting -- verifier rejected a round")
            return 1

    print("[PROVER] all rounds sent.  Wait for verifier's final verdict.")
    return 0


def _parse(argv):
    a = {"session": "./session",
         "public":  "public.json",
         "private": "private.json"}
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == "--session" and i + 1 < len(argv):
            a["session"] = argv[i + 1]; i += 2
        elif t == "--public" and i + 1 < len(argv):
            a["public"] = argv[i + 1]; i += 2
        elif t == "--private" and i + 1 < len(argv):
            a["private"] = argv[i + 1]; i += 2
        else:
            i += 1
    return a


if __name__ == "__main__":
    args = _parse(sys.argv[1:])
    rc = run(args["session"], args["public"], args["private"])
    sys.exit(rc)
