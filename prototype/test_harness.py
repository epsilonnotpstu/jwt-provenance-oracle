"""Harness পরীক্ষা — বৈধ টোকেন ও alg:none টোকেন সব library-তে চালানো।"""
import jwt as pyjwt
from harness import verify_all

SECRET = "my-secret-key-32-bytes-long!!aaaa"   # ৩২ বাইট — RFC 7518 HS256 ন্যূনতম
ALGS = ["HS256"]

def show(title, results):
    print(f"\n=== {title} ===")
    for r in results:
        verdict = "ACCEPT" if r.accepted else "REJECT"
        detail = str(r.claims) if r.accepted else r.error[:55]
        print(f"  {r.library:12} {verdict:7} {detail}")
    accepts = sum(1 for r in results if r.accepted)
    print(f"  → {accepts}/{len(results)} ACCEPT" +
          ("   ⚠️ অমিল! সম্ভাব্য signal" if 0 < accepts < len(results) else "   (সবাই একমত)"))

# ১. বৈধ HS256 টোকেন — সবার ACCEPT করা উচিত
good = pyjwt.encode({"role": "user", "iss": "real"}, SECRET, algorithm="HS256")
show("বৈধ HS256 টোকেন (সবার ACCEPT আশা করি)", verify_all(good, SECRET, ALGS))

# ২. alg:none টোকেন — সবার REJECT করা উচিত (নইলে বিপদ)
none_tok = pyjwt.encode({"role": "admin"}, key="", algorithm="none")
show("alg:none টোকেন (সবার REJECT আশা করি)", verify_all(none_tok, SECRET, ALGS))
