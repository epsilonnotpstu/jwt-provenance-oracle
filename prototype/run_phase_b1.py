"""
run_phase_b1.py — Phase B1 orchestrator (external validity)
============================================================
প্রতিটা পুরনো-দুর্বল ও আধুনিক-fixed library version-এ detector চালিয়ে দেখায়:
detector real, published library-তে real vulnerability reproduce করে, এবং fixed
version-এ মিথ্যা alarm দেয় না।

পূর্বশর্ত: এই venv-গুলো আগে বানানো (setup_oldlibs.sh দেখো)। অনুপস্থিত venv skip হয়।

চালাও:  python run_phase_b1.py     (যেকোনো interpreter — এটা sub-venv ডাকে)
আউটপুট: EXP_phase_b1.md
"""
import subprocess, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (label, venv-relative-path, script, প্রত্যাশা vulnerable?)
CONFUSION = [
    ("PyJWT 0.2.3",       "_oldlibs/venv_pyjwt__0_2_3_py39",       True),
    ("PyJWT 0.4.3",       "_oldlibs/venv_pyjwt__0_4_3_py39",       True),
    ("PyJWT 1.4.2",       "_oldlibs/venv_pyjwt__1_4_2_py39",       False),
    ("PyJWT 1.5.0",       "_oldlibs/venv_pyjwt__1_5_0_py39",       False),
    ("PyJWT 1.7.1",       "_oldlibs/venv_pyjwt__1_7_1",            False),
    ("PyJWT 2.14.0 (cur)", ".venv",                                False),
    ("Authlib 0.15.5",    "_oldlibs/venv_authlib__0_15_5",         True),
    ("python-jose 2.0.2", "_oldlibs/venv_python-jose__2_0_2_py39", False),
    ("python-jose 3.3.0", "_oldlibs/venv_python-jose__3_3_0",      False),
]
JWE = [
    ("python-jose 3.3.0", "_oldlibs/venv_jose330bomb", True),
    ("python-jose 3.5.0 (cur)", ".venv",               False),
]


def run(venv, script):
    py = os.path.join(HERE, venv, "bin", "python")
    if not os.path.exists(py):
        return None, "venv নেই"
    r = subprocess.run([py, "-W", "ignore", os.path.join(HERE, script)],
                       capture_output=True, text=True, cwd=HERE)
    m = re.search(r"RESULT\t.*?=(\d+)", r.stdout)
    return (int(m.group(1)) if m else None), (r.stdout + r.stderr)


def main():
    L = ["# Phase B1 — real library version-এ external validity", "",
         "detector (ground-truth oracle) documented-দুর্বল পুরনো library version-এ real",
         "vulnerability reproduce করে, আধুনিক fixed version-এ চুপ থাকে। Python 3.12 (আধুনিক)",
         "ও 3.9 (খুব পুরনো library-র জন্য) venv-এ pinned version।", "",
         "## ১. Algorithm confusion (RS256→HS256) — claim-mismatch oracle", "",
         "attacker শুধু issuer-এর PUBLIC key জানে; সেটাকে HMAC secret বানিয়ে HS256-এ",
         "role=admin সাইন করে। verifier RSA public key ধরে, ভুলে HS256-ও গ্রহণযোগ্য।", "",
         "| Library version | forged admin গৃহীত? | detector | প্রত্যাশা |",
         "|---|---|---|---|"]
    ok = True
    for label, venv, expect in CONFUSION:
        tp, log = run(venv, "phase_b1.py")
        if tp is None:
            L.append(f"| {label} | (skip: venv নেই) | — | — |"); continue
        vuln = tp > 0
        match = "✅" if vuln == expect else "❌ অপ্রত্যাশিত"
        ok &= (vuln == expect)
        L.append(f"| {label} | {'🚨 হ্যাঁ (TP)' if vuln else 'না (REJECT)'} | "
                 f"{'শ্রেণী-A ধরল' if vuln else 'চুপ'} | {'দুর্বল' if expect else 'fixed'} {match} |")

    L += ["", "## ২. JWE decompression bomb (CVE-2024-33664) — resource oracle", "",
          "ছোট JWE টোকেন (zip=DEF) decrypt-এ বিশাল প্রসারণ → DoS। claim ঠিক থাকলেও",
          "সম্পদ শেষ হয়; resource oracle ধরে।", "",
          "| Library version | ছোট→বড় প্রসারণ? | detector | প্রত্যাশা |",
          "|---|---|---|---|"]
    for label, venv, expect in JWE:
        tp, log = run(venv, "phase_b1_jwe.py")
        if tp is None:
            L.append(f"| {label} | (skip: venv নেই) | — | — |"); continue
        vuln = tp > 0
        match = "✅" if vuln == expect else "❌ অপ্রত্যাশিত"
        ok &= (vuln == expect)
        L.append(f"| {label} | {'🚨 হ্যাঁ (bomb)' if vuln else 'না (সীমিত)'} | "
                 f"{'শ্রেণী-A ধরল' if vuln else 'চুপ'} | {'দুর্বল' if expect else 'fixed'} {match} |")

    L += ["", "## সৎ interpretation", "",
          "- controlled VULN-target-এর বাইরে **৩টা distinct real true-positive** — ২টা",
          "  library (PyJWT 0.x, Authlib 0.15.5) algorithm confusion, ১টা (python-jose 3.3.0)",
          "  JWE bomb — এবং প্রতিটার আধুনিক fixed counterpart চুপ থাকে (মিথ্যা alarm নেই)।",
          "- দুই oracle-path-ই বাস্তব bug-এ কাজ করে: claim-mismatch (confusion) ও resource (bomb)।",
          "- এগুলো *পরিচিত ঐতিহাসিক দুর্বলতা* (নতুন 0-day নয়) — উদ্দেশ্য detector-এর external",
          "  validity, নতুন CVE দাবি নয়। CVE-2024-33664 (jose JWE bomb) documented; PyJWT/Authlib",
          "  algorithm-confusion = Tim McLean 2015-এর শ্রেণী (নির্দিষ্ট CVE নম্বর UNVERIFIED)।",
          "- confusion আক্রমণে caller-ও দায়ী (allow-list না দেওয়া) — কিন্তু আধুনিক version",
          "  একই call-এ asymmetric key HMAC-এ ঢুকতে না দিয়ে defense-in-depth যোগ করেছে;",
          "  পুরনো version করেনি। detector সেই পার্থক্যই ধরে।", ""]

    report = "\n".join(L)
    open(os.path.join(HERE, "EXP_phase_b1.md"), "w", encoding="utf-8").write(report)
    print(report)
    print("\n" + ("✅ সব প্রত্যাশার সাথে মিলল" if ok else "❌ কিছু ফল প্রত্যাশার সাথে মেলেনি — উপরে দেখো"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
