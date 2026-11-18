"""
Oracle — একটা ফলাফল কি আক্রমণ, নাকি নিছক পার্থক্য?  (v3 — ground-truth-চালিত)
==============================================================================
কেন v3 (২২ সেপ্টে): v2 REJECT-কে error-বার্তার keyword (_CAPABILITY_HINTS)
দেখে C বলত। কিন্তু probe_algsupport.py-তে পাওয়া ৯টা *বাস্তব* capability-difference-এর
একটাও ওই keyword-এ পড়ে না (jwcrypto short-HMAC, python-jose PS*/EdDSA — সব "?"
হয়ে যাচ্ছিল)। মানে keyword-heuristic ভঙ্গুর ও circular — corpus হাতে বানানো
কেসেই শুধু কাজ করত।

v3-এর নীতি (keyword নয়, provenance):
  প্রতিটা টোকেনের সাথে একটা ground-truth থাকে — issuer কি এটা বৈধভাবে সাইন করেছিল?
  শ্রেণীকরণ শুধু সেই সত্য + verifier কী believe করল, তার উপর:

  A = Security violation:  issuer সাইন করেনি (বা escalated authority দেয়নি) এমন
      টোকেন verifier ACCEPT করল, এবং attacker-এর চাওয়া claim গৃহীত হলো।
  C = Capability/strictness difference:  issuer *বৈধভাবে* সাইন করেছিল এমন টোকেন
      এই library REJECT করল (অন্য কেউ ACCEPT করে থাকতে পারে বা নাও পারে)। বৈধ
      টোকেন প্রত্যাখ্যান কখনো নিরাপত্তা-দুর্বলতা নয় — সংজ্ঞা অনুযায়ী।
  OK = সঠিক আচরণ:  বৈধ টোকেন ACCEPT, অথবা জাল টোকেন REJECT।

এই নিয়ম general — নির্দিষ্ট alg/library-র নাম জানে না, error-string পড়ে না।
তাই probe-এ পাওয়া ৯টা কেসেও কাজ করে, যদিও oracle সেগুলোর কথা "জানে না" → circularity ভাঙে।
"""
from dataclasses import dataclass


@dataclass
class TokenTruth:
    """একটা টোকেন সম্পর্কে issuer-এর দিক থেকে সত্য (corpus-এর সাথে বহন করা হয়)।"""
    honestly_issued: bool    # issuer কি নিজের বৈধ key দিয়ে এই টোকেন সাইন করেছিল?
    legit_role: str          # issuer বৈধভাবে যে role সাইন করেছিল (honest হলে)
    attack_role: str = ""    # attacker যে escalated role চায় (জাল টোকেনে)


# পুরনো নাম রেখে দেওয়া (fuzz.py compatibility) — legit/attack role ধরে রাখে
@dataclass
class GroundTruth:
    legit_role: str
    attack_role: str


@dataclass
class Judgment:
    library: str
    verdict: str             # ACCEPT / REJECT / SLOW
    klass: str = "OK"        # A / C / OK
    note: str = ""


def judge_truth(result, truth: TokenTruth, baseline_seconds: float, dos_factor: float = 20.0) -> Judgment:
    """ground-truth provenance দিয়ে একটা library-র ফল শ্রেণীভুক্ত করা।"""
    # ── Resource oracle (claim-নিরপেক্ষ) ──
    if baseline_seconds > 0 and result.seconds > baseline_seconds * dos_factor:
        return Judgment(result.library, "SLOW", "A",
                        f"DoS সন্দেহ: {result.seconds:.3f}s vs baseline {baseline_seconds:.4f}s")

    if result.accepted:
        if truth.honestly_issued:
            return Judgment(result.library, "ACCEPT", "OK", "বৈধ টোকেন গৃহীত (স্বাভাবিক)")
        # জাল/crafted টোকেন গৃহীত — verifier আসলে কোন role বিশ্বাস করল?
        got = result.claims.get("role")
        if truth.attack_role and got == truth.attack_role and truth.attack_role != truth.legit_role:
            return Judgment(result.library, "ACCEPT", "A",
                            f"issuer সাইন করেনি এমন role='{got}' গৃহীত")
        # verifier crafted টোকেন গ্রহণ করলেও শুধু issuer-এর বৈধ-সাইন-করা মানই বিশ্বাস করল
        # (যেমন Format-safe: unsigned বাড়তি field উপেক্ষা করে signed payload পড়ল) → নিরাপদ
        if got == truth.legit_role:
            return Judgment(result.library, "ACCEPT", "OK",
                            "শুধু signed মান বিশ্বাস করল (unsigned অংশ উপেক্ষা)")
        # অন্য যেকোনো unsigned/জাল মান বিশ্বাস করা = নিরাপত্তা লঙ্ঘন
        return Judgment(result.library, "ACCEPT", "A", f"issuer সাইন করেনি এমন claim গৃহীত: role='{got}'")

    # ── REJECT ──
    if truth.honestly_issued:
        # বৈধ টোকেন প্রত্যাখ্যান = capability/strictness difference, নিরাপত্তা নয়
        return Judgment(result.library, "REJECT", "C", f"বৈধ টোকেন প্রত্যাখ্যাত: {result.error[:60]}")
    return Judgment(result.library, "REJECT", "OK", f"জাল টোকেন সঠিকভাবে বাতিল: {result.error[:50]}")


def naive_differential(results: list) -> list:
    """Baseline detector: library-দের মধ্যে verdict-অমিল হলেই "bug" (JWTeemo-র
    আগে-করা naive differential)। ground-truth ব্যবহার করে না — তাই capability
    difference-কে false-positive হিসেবে flag করে। এটাই আমরা beat করতে চাই।"""
    verdicts = {("ACCEPT" if r.accepted else "REJECT") for r in results}
    flagged = len(verdicts) > 1
    return [Judgment(r.library, "ACCEPT" if r.accepted else "REJECT",
                     "BUG?" if flagged else "OK",
                     "library-অমিল → সন্দেহভাজন" if flagged else "সবাই একমত")
            for r in results]


# ─────────────────────────────────────────────────────────────
# পুরনো API (fuzz.py / fuzz_with_targets.py compatibility)
# ─────────────────────────────────────────────────────────────
def judge(result, gt: GroundTruth, baseline_seconds: float, dos_factor: float = 20.0) -> Judgment:
    """পুরনো call-সাইটের জন্য shim — GroundTruth(legit,attack) থেকে TokenTruth বানায়।
    এখানে honestly_issued আন্দাজ করা যায় না, তাই accept-oracle-ই মূল: attack_role
    গৃহীত হলে A; নইলে ACCEPT=OK, REJECT=OK ধরা হয় (differential summarize()-এ C ঠিক হয়)।"""
    if baseline_seconds > 0 and result.seconds > baseline_seconds * dos_factor:
        return Judgment(result.library, "SLOW", "A",
                        f"DoS সন্দেহ: {result.seconds:.3f}s vs {baseline_seconds:.4f}s")
    if result.accepted:
        got = result.claims.get("role")
        if got == gt.attack_role and gt.attack_role != gt.legit_role:
            return Judgment(result.library, "ACCEPT", "A", f"issuer সাইন করেনি এমন role='{got}' গৃহীত")
        return Judgment(result.library, "ACCEPT", "OK", "বৈধ টোকেন গৃহীত (স্বাভাবিক)")
    return Judgment(result.library, "REJECT", "OK", result.error[:50])


def summarize(judgments: list) -> str:
    A = [j for j in judgments if j.klass == "A"]
    if A:
        return "🚨 শ্রেণী-A (সত্যিকারের আক্রমণ): " + ", ".join(j.library for j in A)
    accepts = [j for j in judgments if j.verdict == "ACCEPT"]
    rejects = [j for j in judgments if j.verdict == "REJECT"]
    if accepts and rejects:
        for j in rejects:
            j.klass = "C"
        return "⚠️ lead: library-দের মধ্যে অমিল — C=capability difference (নিরাপত্তা নয়)"
    if not accepts:
        return "✓ সবাই সঠিকভাবে বাতিল করল (সঠিক প্রতিরক্ষা, C নয়)"
    return "✓ সবাই বৈধ টোকেন গ্রহণ করল (স্বাভাবিক)"
