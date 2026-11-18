"""
G2 corpus — grammar generation + issuer-side mutation, HONEST ONLY (PREREG_g2.md §2)
====================================================================================
Every token is signed by the issuer with the issuer's key AFTER mutation. Mutation operators change only
how the issuer writes its own token (member order, whitespace, escaping, number spelling, extra claims,
header members, serialization, alg). No token is forged or attacker-constructed; truth is
honestly_issued=True, legit_role="user" for all.

A JSON value is kept as a small AST so the byte-level choices are exactly what gets signed:
  ["obj", [[key_str_node, value], ...]]   ["arr", [values]]   ["str", s, esc]   ["num", text]
  ["lit", "true"|"false"|"null"]          esc ∈ {None, "lower", "upper"}  (write every char as \\uXXXX)

Writes to OUT (default: this directory):
  cases.json   adapter input        truth.json   id -> TokenTruth (adapters never read it)
  signed.json  id -> signed payload bytes (UTF-8)   issuer_keys.json  test issuer keys (PEM / hex)
  corpus_manifest.json  counts + sha256

usage: python gen_corpus_g2.py [--seed N] [--out DIR] [--per-depth N]
Regenerating with the same seed reproduces every derivation and payload byte; RSA/EC/Ed25519 keys and ECDSA
signatures are fresh each time, so the emitted files (hashed in the manifest) are the reproducibility artefact.
"""
import argparse, copy, hashlib, hmac, json, random, sys
from collections import Counter
from decimal import Decimal
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "corpus"))
sys.path.insert(0, str(HERE.parents[1]))
import gen_corpus as g  # noqa: E402  (claims, signer, key_hmac, key_pub, IAT, EXP)
import operators as op   # noqa: E402

KID = "issuer-key-1"
ALGS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512", "EdDSA"]
DEPTHS = range(5)
HC = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
INT_POOL = [0, 1, -1, 42, 2 ** 31 - 1, 2 ** 31, 2 ** 32, 2 ** 53 - 1, -(2 ** 53 - 1)]
INT_PREC = [2 ** 53 + 1, 2 ** 63 - 1, 2 ** 64, -(2 ** 63)]                 # tag precision
FLT_EXACT = ["0.5", "-2.75", "1.25e3", "3.0", "1e2", "6.103515625e-05"]
FLT_INEXACT = ["0.1", "3.14159", "1e-7", "2.5E-8"]                        # tag decimal_inexact
STR_POOL = ["abc", "a/b/c", 'q"uote', "back\\slash", "tab\tnl\n", "café", "straße", "অআই",
            "\U0001f642 ok", "é", "x" * 300, "", " lead space"]
NAMES = ["a", "b", "ctx", "lvl", "tenant", "n", "v", "flag", "list", "data", "meta", "q"]


# ───────── issuer keys ─────────
def make_keys(seed):
    hs = {a: hmac.new(str(seed).encode(), a.encode(), hashlib.sha512).digest()[:int(a[2:]) // 8]
          for a in ("HS256", "HS384", "HS512")}
    rs, ps = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    ecs = {"ES256": ec.generate_private_key(ec.SECP256R1()), "ES384": ec.generate_private_key(ec.SECP384R1()),
           "ES512": ec.generate_private_key(ec.SECP521R1())}
    ed = ed25519.Ed25519PrivateKey.generate()
    K = {}
    for a in ALGS:
        if a in hs: priv, pub, var, kd = hs[a], None, "min", g.key_hmac(hs[a])
        elif a[:2] in ("RS", "PS"):
            priv = rs if a[:2] == "RS" else ps
            pub, var = priv.public_key(), "2048"; kd = g.key_pub(pub)
        elif a in ecs:
            priv = ecs[a]; pub = priv.public_key(); kd = g.key_pub(pub)
            var = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[a]
        else: priv, pub, var, kd = ed, ed.public_key(), "Ed25519", g.key_pub(ed.public_key())
        K[a] = dict(priv=priv, pub=pub, variant=var, key={**kd, "jwk": {**kd["jwk"], "kid": KID}})
    return K


def dump_keys(K):
    out = {}
    for a, k in K.items():
        p = k["priv"]
        out[a] = p.hex() if isinstance(p, bytes) else p.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return out


# ───────── AST helpers ─────────
def S(s): return ["str", s, None]
def N(text): return ["num", str(text)]
def member(obj, name):
    return next((m for m in obj[1] if m[0][1] == name), None)


def gen_value(rng, depth):
    kinds = ["int", "flt", "str", "bool", "null"] + (["arr", "obj"] if depth < 3 else [])
    k = rng.choices(kinds, weights=[25, 10, 30, 10, 5, 10, 10][:len(kinds)])[0]
    if k == "int": return N(rng.choice(INT_PREC if rng.random() < 0.08 else INT_POOL))
    if k == "flt": return N(rng.choice(FLT_INEXACT if rng.random() < 0.3 else FLT_EXACT))
    if k == "str": return S("a\u0000b" if rng.random() < 0.05 else rng.choice(STR_POOL))
    if k == "bool": return ["lit", rng.choice(["true", "false"])]
    if k == "null": return ["lit", "null"]
    if k == "arr": return ["arr", [gen_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]]
    o = ["obj", []]
    for _ in range(rng.randint(0, 3)): add_member(o, gen_value(rng, depth + 1), rng)
    return o


def add_member(obj, val, rng):
    used = {m[0][1] for m in obj[1]}
    while True:
        name = "x_" + rng.choice(NAMES) + (str(rng.randint(0, 99)) if rng.random() < 0.5 else "")
        if name not in used: break
    obj[1].append([S(name), val])


def walk(node):
    yield node
    if node[0] == "obj":
        for k, v in node[1]:
            yield k; yield from walk(v)
    elif node[0] == "arr":
        for v in node[1]: yield from walk(v)


def objects(node): return [n for n in walk(node) if n[0] == "obj"]


# ───────── emitter (bytes the issuer signs) ─────────
SHORT = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\t": "\\t", "\r": "\\r", "\b": "\\b", "\f": "\\f"}


def emit_str(node, solidus):
    s, esc = node[1], node[2]
    out = []
    for ch in s:
        if esc:
            cps = [ord(ch)] if ord(ch) < 0x10000 else [0xD800 + ((ord(ch) - 0x10000) >> 10),
                                                      0xDC00 + ((ord(ch) - 0x10000) & 0x3FF)]
            f = "\\u%04x" if esc == "lower" else "\\u%04X"
            out += [f % c for c in cps]
        elif ch in SHORT: out.append(SHORT[ch])
        elif ch == "/" and solidus: out.append("\\/")
        elif ord(ch) < 0x20: out.append("\\u%04x" % ord(ch))
        else: out.append(ch)
    return '"' + "".join(out) + '"'


def emit(node, ws, solidus, ind=0):
    t = node[0]
    if t == "str": return emit_str(node, solidus)
    if t in ("num", "lit"): return node[1]
    sep, colon = {"none": (",", ":"), "spaced": (", ", " : "), "pretty": (",", ": ")}[ws]
    nl = lambda i: ("\n" + "  " * i) if ws == "pretty" else ""
    if t == "arr":
        if not node[1]: return "[]"
        return "[" + sep.join(nl(ind + 1) + emit(v, ws, solidus, ind + 1) for v in node[1]) + nl(ind) + "]"
    if not node[1]: return "{}"
    return "{" + sep.join(nl(ind + 1) + emit_str(k, solidus) + colon + emit(v, ws, solidus, ind + 1)
                          for k, v in node[1]) + nl(ind) + "}"


def to_py(node):
    """reference meaning of the AST (numbers as exact Decimal/int)."""
    t = node[0]
    if t == "str": return node[1]
    if t == "num": return int(node[1]) if node[1].lstrip("-").isdigit() else Decimal(node[1])
    if t == "lit": return {"true": True, "false": False, "null": None}[node[1]]
    if t == "arr": return [to_py(v) for v in node[1]]
    return {k[1]: to_py(v) for k, v in node[1]}


# ───────── generation grammar (d = 0) ─────────
def generate(rng):
    alg = rng.choice(ALGS)
    hdr = ["obj", [[S("alg"), S(alg)]]]
    r = rng.random()
    if r < 0.6: hdr[1].append([S("typ"), S("JWT" if r < 0.4 else rng.choice(["jwt", "at+jwt"]))])
    if rng.random() < 0.3: hdr[1].append([S("kid"), S(KID)])
    if rng.random() < 0.2: add_member(hdr, gen_value(rng, 2), rng)
    pl = ["obj", [[S("sub"), S("alice")], [S("role"), S("user")], [S("iss"), S("real-issuer")],
                  [S("iat"), N(g.IAT)], [S("exp"), N(g.EXP)]]]
    if rng.random() < 0.3: pl[1].append([S("nbf"), N(g.IAT)])
    if rng.random() < 0.3: pl[1].append([S("jti"), S("id-%d" % rng.randint(0, 10 ** 6))])
    if rng.random() < 0.3:
        pl[1].append([S("aud"), S("api") if rng.random() < 0.5 else ["arr", [S("api"), S("web")]]])
    for _ in range(rng.randint(0, 4)): add_member(pl, gen_value(rng, 1), rng)
    return dict(hdr=hdr, pl=pl, ser=rng.choices(["compact", "json_flat", "json_general"], [70, 15, 15])[0],
                ws=rng.choices(["none", "spaced", "pretty"], [80, 10, 10])[0], solidus=False, ops=[])


# ───────── issuer-side mutation operators (return False if not applicable) ─────────
def m_order(D, rng):
    objs = [o for o in objects(D["hdr"]) + objects(D["pl"]) if len(o[1]) >= 2]
    if not objs: return False
    o = rng.choice(objs); before = [m[0][1] for m in o[1]]
    for _ in range(5):
        rng.shuffle(o[1])
        if [m[0][1] for m in o[1]] != before: break
    return True


def m_ws(D, rng):
    D["ws"] = rng.choice([w for w in ("none", "spaced", "pretty") if w != D["ws"]]); return True


def m_uesc(D, rng):
    strs = [n for n in list(walk(D["hdr"])) + list(walk(D["pl"])) if n[0] == "str" and n[1] and not n[2]]
    role = member(D["pl"], "role")[1]
    if role in strs and rng.random() < 0.3: n = role          # the authority value itself, written escaped
    elif strs: n = rng.choice(strs)
    else: return False
    n[2] = rng.choice(["lower", "upper"]); return True


def m_solidus(D, rng):
    if D["solidus"] or not any(n[0] == "str" and "/" in n[1] for n in walk(D["pl"])): return False
    D["solidus"] = True; return True


def m_numspell(D, rng):
    nums = [n for n in list(walk(D["hdr"])) + list(walk(D["pl"])) if n[0] == "num" and n[1].lstrip("-").isdigit()]
    if not nums: return False
    n = rng.choice(nums); n[1] = n[1] + rng.choice([".0", "e0", "E0", ".00"]); return True


def m_addclaim(D, rng): add_member(D["pl"], gen_value(rng, 1), rng); return True
def m_addhdr(D, rng): add_member(D["hdr"], gen_value(rng, 2), rng); return True


def m_deepen(D, rng):
    xs = [m for o in objects(D["pl"]) for m in o[1] if m[0][1].startswith("x_")]
    if not xs: return False
    m = rng.choice(xs)
    m[1] = ["arr", [m[1]]] if rng.random() < 0.5 else ["obj", [[S("x_w"), m[1]]]]; return True


def m_aud(D, rng):
    a = member(D["pl"], "aud")
    if a is None: D["pl"][1].append([S("aud"), S("api")])
    elif a[1][0] == "str": a[1] = ["arr", [a[1]]]
    elif len(a[1][1]) == 1: a[1] = a[1][1][0]
    else: a[1][1].reverse()
    return True


def m_typ(D, rng):
    cur = member(D["hdr"], "typ")
    choice = rng.choice([c for c in (None, "JWT", "jwt", "at+jwt") if c != (cur[1][1] if cur else None)])
    D["hdr"][1] = [m for m in D["hdr"][1] if m[0][1] != "typ"]
    if choice: D["hdr"][1].append([S("typ"), S(choice)])
    return True


def m_kid(D, rng):
    if member(D["hdr"], "kid"): D["hdr"][1] = [m for m in D["hdr"][1] if m[0][1] != "kid"]
    else: D["hdr"][1].append([S("kid"), S(KID)])
    return True


def m_ser(D, rng):
    D["ser"] = rng.choice([s for s in ("compact", "json_flat", "json_general") if s != D["ser"]]); return True


def m_alg(D, rng):
    a = member(D["hdr"], "alg")
    a[1] = S(rng.choice([x for x in ALGS if x != a[1][1]])); return True


OPS = [m_order, m_ws, m_uesc, m_solidus, m_numspell, m_addclaim, m_addhdr, m_deepen, m_aud, m_typ, m_kid,
       m_ser, m_alg]
OP_TAG = {"m_uesc": "uesc", "m_numspell": "num_respelled", "m_ser": "json_ser", "m_aud": "aud",
          "m_typ": "typ", "m_kid": "kid", "m_addhdr": "xhdr", "m_solidus": "solidus"}


def mutate(D, rng, d):
    while len(D["ops"]) < d:
        f = rng.choice(OPS)
        if f(D, rng): D["ops"].append(f.__name__)


# ───────── issue (sign) + independent self-check ─────────
def issue(D, K):
    alg = member(D["hdr"], "alg")[1][1]
    hb = emit(D["hdr"], D["ws"], D["solidus"]).encode()
    pb = emit(D["pl"], D["ws"], D["solidus"]).encode()
    h, p = op.b64url(hb), op.b64url(pb)
    s = op.b64url(g.signer(alg, K[alg]["priv"])(f"{h}.{p}".encode()))
    tok = {"compact": f"{h}.{p}.{s}",
           "json_flat": json.dumps({"protected": h, "payload": p, "signature": s}),
           "json_general": json.dumps({"payload": p, "signatures": [{"protected": h, "signature": s}]})}[D["ser"]]
    return alg, tok, pb


def _nodup(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)): raise ValueError("duplicate member")
    return dict(pairs)


def self_check(tok, alg, K, pb, D):
    if tok.startswith("{"):
        j = json.loads(tok)
        p = j["payload"]; sig = j["signatures"][0] if "signatures" in j else j
        h, s = sig["protected"], sig["signature"]
    else:
        h, p, s = tok.split(".")
    ld = lambda b: json.loads(op.b64url_decode(b), object_pairs_hook=_nodup, parse_float=Decimal)
    assert op.b64url_decode(p) == pb, "payload bytes"
    assert ld(h)["alg"] == alg, "alg"
    pl = ld(p)
    assert pl["role"] == "user" and pl == to_py(D["pl"]), "payload meaning"
    si, sg, k = f"{h}.{p}".encode(), op.b64url_decode(s), K[alg]
    bits = alg[2:5]
    if alg.startswith("HS"): assert hmac.compare_digest(sg, g.signer(alg, k["priv"])(si)), "hmac"
    elif alg.startswith("RS"): k["pub"].verify(sg, si, padding.PKCS1v15(), HC[bits])
    elif alg.startswith("PS"):
        k["pub"].verify(sg, si, padding.PSS(mgf=padding.MGF1(HC[bits]), salt_length=int(bits) // 8), HC[bits])
    elif alg.startswith("ES"):
        n = len(sg) // 2
        k["pub"].verify(encode_dss_signature(int.from_bytes(sg[:n], "big"), int.from_bytes(sg[n:], "big")),
                        si, ec.ECDSA(HC[bits]))
    else: k["pub"].verify(sg, si)


def tags_of(D):
    t = {OP_TAG[o] for o in D["ops"] if o in OP_TAG}
    if D["ser"] != "compact": t.add("json_ser")
    for n in list(walk(D["hdr"])) + list(walk(D["pl"])):
        if n[0] == "num":
            v = to_py(n)
            if isinstance(v, int) or v == v.to_integral_value():
                if abs(int(v)) > 2 ** 53 - 1: t.add("precision")
            elif Decimal(float(v)) != v: t.add("decimal_inexact")
            if not n[1].lstrip("-").isdigit() and v == v.to_integral_value(): t.add("num_respelled")
        elif n[0] == "str":
            if "\u0000" in n[1]: t.add("nul")
            if any(ord(c) > 0xFFFF or 0x300 <= ord(c) <= 0x36F for c in n[1]): t.add("unicode")
            if n[2]: t.add("uesc")
    if member(D["pl"], "aud"): t.add("aud")
    if member(D["hdr"], "typ"): t.add("typ")
    if member(D["hdr"], "kid"): t.add("kid")
    if any(m[0][1].startswith("x_") for m in D["hdr"][1]): t.add("xhdr")
    return sorted(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20260925)
    ap.add_argument("--out", default=str(HERE))
    ap.add_argument("--per-depth", type=int, default=320)
    a = ap.parse_args()
    out = Path(a.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    K = make_keys(a.seed)
    cases, truth, signed = [], {}, {}
    for d in DEPTHS:
        rng = random.Random(hmac.new(str(a.seed).encode(), f"d{d}".encode(), hashlib.sha256).digest())
        for k in range(a.per_depth):
            D = generate(rng)
            mutate(D, rng, d)
            alg, tok, pb = issue(D, K)
            self_check(tok, alg, K, pb, D)
            cid = f"G2/d{d}/{k:03d}"
            cases.append(dict(id=cid, token=tok, allowed_algs=[alg], key=K[alg]["key"],
                              meta=dict(alg=alg, variant=K[alg]["variant"], family="G2", seed=a.seed, depth=d,
                                        ser=D["ser"], op_chain=D["ops"], tags=tags_of(D))))
            truth[cid] = dict(honestly_issued=True, legit_role="user", attack_role="")
            signed[cid] = pb.decode("utf-8")
    files = {"cases.json": {"version": "g2", "cases": cases}, "truth.json": truth, "signed.json": signed,
             "issuer_keys.json": dump_keys(K)}
    for f, obj in files.items():
        (out / f).write_text(json.dumps(obj, indent=0, ensure_ascii=False))
    cnt = lambda key: dict(sorted(Counter(key(c) for c in cases).items()))
    man = {"n_cases": len(cases), "seed": a.seed, "self_check": "passed (all)",
           "by_depth": cnt(lambda c: c["meta"]["depth"]), "by_alg": cnt(lambda c: c["meta"]["alg"]),
           "by_ser": cnt(lambda c: c["meta"]["ser"]),
           "by_tag": dict(sorted(Counter(t for c in cases for t in c["meta"]["tags"]).items())),
           "primary_stratum": sum(not {"precision", "decimal_inexact"} & set(c["meta"]["tags"]) for c in cases),
           "sha256": {f: hashlib.sha256((out / f).read_bytes()).hexdigest() for f in files}}
    (out / "corpus_manifest.json").write_text(json.dumps(man, indent=1))
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
