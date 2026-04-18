"""
================================================================================
verifier_interactive.py  --  live two-program interactive verifier (Variant B)

Counterpart to prover_interactive.py.  Samples a fresh challenge c_j in each
round using secrets.randbelow(q) and checks both (V1) and (V_eval) after
receiving the prover's response.

See prover_interactive.py for the full exchange protocol.
================================================================================
"""

import json
import os
import secrets
import sys
import time

from Problem4 import verify_checks, validate_public


POLL_INTERVAL = 0.05
POLL_TIMEOUT  = 60.0


def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _wait(path):
    t0 = time.time()
    while not os.path.exists(path):
        if time.time() - t0 > POLL_TIMEOUT:
            raise TimeoutError(f"timeout waiting for {path}")
        time.sleep(POLL_INTERVAL)
    time.sleep(0.02)
    return _load(path)


def run(session_dir: str, public_path: str, transcript_path: str):
    os.makedirs(session_dir, exist_ok=True)

    pub = _load(public_path)
    validate_public(pub)

    p, q, g, h = pub["p"], pub["q"], pub["g"], pub["h"]
    z, y       = pub["z"], pub["y"]
    C          = pub["commitments"]
    k          = pub.get("k", 1)

    print(f"[VERIFIER] session = {session_dir}")
    print(f"[VERIFIER] k = {k} rounds")

    log = []
    all_ok = True

    for j in range(k):
        # --- receive commit ---
        commit_msg = _wait(os.path.join(session_dir, f"round_{j}_A.json"))
        T_list = commit_msg["T_list"]
        E      = commit_msg["E"]
        print(f"[VERIFIER] round {j}: got commit")

        # --- draw and send fresh challenge c_j ---
        c = secrets.randbelow(q)
        _dump(os.path.join(session_dir, f"round_{j}_B.json"), {"c": c})
        print(f"[VERIFIER] round {j}: sent challenge c = {c}")

        # --- receive response ---
        resp = _wait(os.path.join(session_dir, f"round_{j}_C.json"))
        u_a, u_r = resp["u_a"], resp["u_r"]

        # --- verify this round ---
        ok = verify_checks(C, z, y, T_list, E, c, u_a, u_r, g, h, p, q)
        verdict = {"result": "ok" if ok else "fail"}
        _dump(os.path.join(session_dir, f"round_{j}_V.json"), verdict)
        print(f"[VERIFIER] round {j}: check = {verdict['result']}")

        log.append({
            "round":   j,
            "T_list":  T_list, "E": E, "c": c,
            "u_a":     u_a, "u_r": u_r,
            "result":  verdict["result"],
        })

        if not ok:
            all_ok = False
            break   # soundness: one bad round is enough to reject

    # persist a transcript file for audit / report use
    _dump(transcript_path, {
        "mode":      "interactive-live",
        "k":         k,
        "transcript": log,
        "verdict":    "ACCEPT" if all_ok else "REJECT",
    })

    verdict = "ACCEPT" if all_ok else "REJECT"
    print(verdict)
    print(f"[VERIFIER] transcript written to {transcript_path}")
    return 0 if all_ok else 1


def _parse(argv):
    a = {"session":    "./session",
         "public":     "public.json",
         "transcript": "transcript_interactive.json"}
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == "--session" and i + 1 < len(argv):
            a["session"] = argv[i + 1]; i += 2
        elif t == "--public" and i + 1 < len(argv):
            a["public"] = argv[i + 1]; i += 2
        elif t == "--transcript" and i + 1 < len(argv):
            a["transcript"] = argv[i + 1]; i += 2
        else:
            i += 1
    return a


if __name__ == "__main__":
    args = _parse(sys.argv[1:])
    rc = run(args["session"], args["public"], args["transcript"])
    sys.exit(rc)
