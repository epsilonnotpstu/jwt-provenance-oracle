"""Gate cases (PREREG §3) — cases.json থেকে বের করা, আলাদা ফাইলে (corpus hash অপরিবর্তিত)।
G1 = বৈধ HS256-min / RS256-2048 / ES256 (seed 1) → ACCEPT, role=user
G2 = একই টোকেন, signature-এর প্রথম byte-এর lowest bit উল্টানো → REJECT
G4 = F1/alg_none_0/s1 (allow-list-এ none নেই) → REJECT
G3 (claims.role=="user") judge-এ G1-এর ফল থেকে দেখা হয়।"""
import base64, json
from pathlib import Path
D = Path(__file__).resolve().parent
cases = {c["id"]: c for c in json.loads((D / "cases.json").read_text())["cases"]}

def flip(tok):
    h, p, s = tok.split(".")
    raw = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))); raw[0] ^= 1
    return f"{h}.{p}.{base64.urlsafe_b64encode(bytes(raw)).decode().rstrip('=')}"

out = []
for g1 in ("V1/HS256/min/s1", "V1/RS256/2048/s1", "V1/ES256/P-256/s1"):
    c = cases[g1]
    out.append({**c, "id": "G1/" + g1, "expect": "accept"})
    out.append({**c, "id": "G2/" + g1, "token": flip(c["token"]), "expect": "reject"})
out.append({**cases["F1/alg_none_0/s1"], "id": "G4/alg_none", "expect": "reject"})
(D / "gate.json").write_text(json.dumps({"version": "gate-v1", "cases": out}, indent=0))
print(len(out), "gate cases")
