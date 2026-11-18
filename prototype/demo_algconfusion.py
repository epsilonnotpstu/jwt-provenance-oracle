"""
Algorithm Confusion — operator জোড়া দিয়ে বানানো, ৪ library-তে চালানো।

দৃশ্য (classic RS256→HS256 confusion):
  - Issuer RSA দিয়ে সাইন করে (role=user)। Verifier public key দিয়ে যাচাই করে।
  - Attacker public key পায় (প্রকাশ্য), সেটাকে HMAC secret বানিয়ে
    HS256 দিয়ে একটা role=admin টোকেন সাইন করে।
  - Verifier যদি ভুলবশত HS256-ও মেনে নেয় একই key দিয়ে → আক্রমণ সফল।
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from operators import (
    fn_header, fn_payload, fn_signing_input, fn_compact,
    fn_hmac_sign, fn_pubkey_pem, fn_alg_hs256, fn_role_admin,
)
from harness import verify_all

# ── Issuer-এর RSA keypair ──
issuer_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_pem = fn_pubkey_pem(issuer_priv)          # প্রকাশ্য — attacker এটা পায়

# ── আক্রমণ টোকেন: operator জোড়া দিয়ে বানানো ──
#   fn_hmac_sign(signing_input, key = fn_pubkey_pem(...))
#   ↑ ঠিক এই জোড়াটাই Algorithm Confusion — public key কে HMAC secret বানানো
header  = fn_header(fn_alg_hs256())                 # alg=HS256
payload = fn_payload(fn_role_admin())              # role=admin
si      = fn_signing_input(header, payload)
sig     = fn_hmac_sign(si, key=pub_pem)            # ⚠️ public key = HMAC secret
forged  = fn_compact(header, payload, sig)

print("আক্রমণ টোকেন (শুরু):", forged[:50], "...\n")

# ── Verifier public key PEM ধরে আছে, আর ভুলবশত HS256 allow করে ──
#   (এটাই সেই misconfiguration যা আক্রমণ সম্ভব করে)
results = verify_all(forged, key=pub_pem.decode(), algorithms=["HS256", "RS256"])

print(f"{'Library':13} {'ফল':8} বিস্তারিত")
print("-" * 60)
for r in results:
    verdict = "ACCEPT" if r.accepted else "REJECT"
    detail = str(r.claims) if r.accepted else r.error[:45]
    flag = "  🚨 আক্রমণ সফল!" if (r.accepted and r.claims.get("role") == "admin") else ""
    print(f"{r.library:13} {verdict:8} {detail}{flag}")

n = sum(1 for r in results if r.accepted and r.claims.get("role") == "admin")
print(f"\n→ {n}/{len(results)} library আক্রমণে দুর্বল")
