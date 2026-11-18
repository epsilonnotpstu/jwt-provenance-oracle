"""
G3 corpus — extended grammar, compact only, HONEST ONLY (PREREG_g3.md §2)
=========================================================================
Reuses the frozen g2 generator (grammar, emitter, issuer, self-check) and adds the G3 dimensions: NumericDate
forms, exotic member names, number edges, string edges, size/nesting limits, extra typ values, registered-claim
type violations (issuer-signed conformance probes) and an unknown critical header. Every token is signed by the
issuer AFTER generation+mutation; truth is honestly_issued=True for all.

usage: python gen_corpus_g3.py [--seed N] [--out DIR] [--per-depth N]
"""
import argparse, hashlib, hmac, json, random, sys
from collections import Counter
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "corpus_g2"))
import gen_corpus_g2 as G  # noqa: E402  (frozen at 4577f91)
from gen_corpus_g2 import S, N, member, walk  # noqa: E402

KEYNAMES = ["x_名前", "x_é", "", "x_" + "k" * 256, "x_sp ace", "x_ "]
NUM_EDGE = ["-0", "0e0", "1E+2", "-0.0", "1e308", "5e-324", "2.2250738585072014e-308",
            "123456789012345678901234567890", "1e400"]
STR_EDGE = ["line sep", "zw﻿nbsp", "\ud800"]            # "\ud800" is emitted escaped (lone surrogate)
NONCONF = [("iss", N(1)), ("sub", N(42)), ("jti", N(5)), ("aud", N(7)),
           ("exp", S(str(G.g.EXP))), ("iat", S(str(G.g.IAT))), ("nbf", S(str(G.g.IAT)))]
TYP3 = [None, "JWT", "jwt", "at+jwt", "JOSE", "application/jwt"]
DMAX = 1.7976931348623157e308


def edge_str(s):
    return ["str", s, "lower" if any(0xD800 <= ord(c) <= 0xDFFF for c in s) else None]


def set_member(obj, name, val):
    m = member(obj, name)
    if m: m[1] = val
    else: obj[1].append([S(name), val])


def nested(depth):
    v = N(1)
    for i in range(depth): v = ["arr", [v]] if i % 2 else ["obj", [[S("x_n"), v]]]
    return v


# ───────── new mutation operators ─────────
def m_numdate(D, rng):
    c = rng.choice([k for k in ("iat", "exp", "nbf") if member(D["pl"], k)])
    m = member(D["pl"], c)
    if m[1][0] != "num": return False
    base = G.g.EXP if c == "exp" else G.g.IAT
    m[1] = N(f"{base}{rng.choice(['.5', '.25', '.125'])}"); return True


def m_keyname(D, rng):
    used = {m[0][1] for m in D["pl"][1]}
    free = [k for k in KEYNAMES if k not in used]
    if not free: return False
    D["pl"][1].append([S(rng.choice(free)), G.gen_value(rng, 2)]); return True


def m_numedge(D, rng): G.add_member(D["pl"], N(rng.choice(NUM_EDGE)), rng); return True
def m_stredge(D, rng): G.add_member(D["pl"], edge_str(rng.choice(STR_EDGE)), rng); return True


OPS3 = [f for f in G.OPS if f.__name__ != "m_ser"] + [m_numdate, m_keyname, m_numedge, m_stredge]


# ───────── generation (d = 0) ─────────
def generate3(rng):
    D = G.generate(rng)
    D["ser"], D["xtags"] = "compact", set()
    if rng.random() < 0.10:                                          # extended typ values
        D["hdr"][1] = [m for m in D["hdr"][1] if m[0][1] != "typ"]
        t = rng.choice(["JOSE", "application/jwt"]); D["hdr"][1].append([S("typ"), S(t)])
    if rng.random() < 0.25: m_numdate(D, rng)
    if rng.random() < 0.15: m_keyname(D, rng)
    if rng.random() < 0.20: m_numedge(D, rng)
    if rng.random() < 0.15: m_stredge(D, rng)
    if rng.random() < 0.05:
        kind = rng.choice(["nest20", "nest64", "arr1000", "str16k"])
        val = {"nest20": lambda: nested(20), "nest64": lambda: nested(64),
               "arr1000": lambda: ["arr", [N(i) for i in range(1000)]], "str16k": lambda: S("y" * 16384)}[kind]()
        G.add_member(D["pl"], val, rng); D["xtags"].add("limits")
    if rng.random() < 0.06:
        name, val = rng.choice(NONCONF)
        set_member(D["pl"], name, val); D["xtags"] |= {"nonconformant", f"nonconf_{name}"}
    if rng.random() < 0.04:
        D["hdr"][1] += [[S("crit"), ["arr", [S("x_must")]]], [S("x_must"), ["lit", "true"]]]
        D["xtags"].add("must_reject")
    return D


def mutate3(D, rng, d):
    while len(D["ops"]) < d:
        f = rng.choice(OPS3)
        a = member(D["pl"], "aud")
        if f is G.m_aud and a and a[1][0] not in ("str", "arr"): continue   # keep the nonconformant aud probe intact
        if f is G.m_typ:                                              # typ choices extended for G3
            cur = member(D["hdr"], "typ")
            ch = rng.choice([c for c in TYP3 if c != (cur[1][1] if cur else None)])
            D["hdr"][1] = [m for m in D["hdr"][1] if m[0][1] != "typ"]
            if ch: D["hdr"][1].append([S("typ"), S(ch)])
            D["ops"].append("m_typ"); continue
        if f(D, rng): D["ops"].append(f.__name__)


def tags3(D):
    t = set(G.tags_of(D)) | D["xtags"]
    t.discard("json_ser")
    for k in ("iat", "exp", "nbf"):
        m = member(D["pl"], k)
        if m and m[1][0] == "num" and Decimal(m[1][1]) != Decimal(m[1][1]).to_integral_value(): t.add("numdate_frac")
    for n in walk(D["pl"]):
        if n[0] == "obj":
            for k, _ in n[1]:
                s = k[1]
                if s == "" or len(s) > 64 or " " in s or any(ord(c) > 0x7F for c in s): t.add("keyname")
        elif n[0] == "num":
            if n[1] in NUM_EDGE: t.add("numedge")
            if abs(Decimal(n[1])) > Decimal(DMAX): t.add("non_ijson")
        elif n[0] == "str":
            if any(c in n[1] for c in " ﻿") or any(0xD800 <= ord(c) <= 0xDFFF for c in n[1]): t.add("stredge")
            if any(0xD800 <= ord(c) <= 0xDFFF for c in n[1]): t.add("parse_ambiguous")
    return sorted(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261001)
    ap.add_argument("--out", default=str(HERE))
    ap.add_argument("--per-depth", type=int, default=1200)
    a = ap.parse_args()
    out = Path(a.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    K = G.make_keys(a.seed)
    cases, truth, signed = [], {}, {}
    for d in G.DEPTHS:
        rng = random.Random(hmac.new(str(a.seed).encode(), f"d{d}".encode(), hashlib.sha256).digest())
        for k in range(a.per_depth):
            D = generate3(rng)
            mutate3(D, rng, d)
            alg, tok, pb = G.issue(D, K)
            G.self_check(tok, alg, K, pb, D)
            cid = f"G3/d{d}/{k:04d}"
            cases.append(dict(id=cid, token=tok, allowed_algs=[alg], key=K[alg]["key"],
                              meta=dict(alg=alg, variant=K[alg]["variant"], family="G3", seed=a.seed, depth=d,
                                        ser="compact", op_chain=D["ops"], tags=tags3(D))))
            truth[cid] = dict(honestly_issued=True, legit_role="user", attack_role="")
            signed[cid] = pb.decode("utf-8")
    files = {"cases.json": {"version": "g3", "cases": cases}, "truth.json": truth, "signed.json": signed,
             "issuer_keys.json": G.dump_keys(K)}
    for f, obj in files.items():
        (out / f).write_text(json.dumps(obj, indent=0, ensure_ascii=False))
    EXCL = {"nonconformant", "must_reject", "parse_ambiguous", "non_ijson"}
    cnt = lambda key: dict(sorted(Counter(key(c) for c in cases).items()))
    man = {"n_cases": len(cases), "seed": a.seed, "self_check": "passed (all)",
           "by_depth": cnt(lambda c: c["meta"]["depth"]), "by_alg": cnt(lambda c: c["meta"]["alg"]),
           "by_tag": dict(sorted(Counter(t for c in cases for t in c["meta"]["tags"]).items())),
           "primary_stratum": sum(not EXCL & set(c["meta"]["tags"]) for c in cases),
           "sha256": {f: hashlib.sha256((out / f).read_bytes()).hexdigest() for f in files}}
    (out / "corpus_manifest.json").write_text(json.dumps(man, indent=1))
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
