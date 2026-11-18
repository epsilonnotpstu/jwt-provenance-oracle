"""
ঘর #৬ — Harness (অর্ধেক ভরা ফর্ম)
====================================
লক্ষ্য: প্রতিটা JWT library-কে একটা অভিন্ন সুইচবোর্ডে নামানো।
       টোকেন (একটা string) দাও → অভিন্ন উত্তর ফেরত নাও।

নিয়ম: সব library একই আকারের উত্তর দেবে, যাতে fuzzer তুলনা করতে পারে।

"← তুমি" জায়গাগুলো ভরবে।
"""

from dataclasses import dataclass
import jwt as pyjwt          # PyJWT


# ─────────────────────────────────────────────────────────────
# অংশ ক — অভিন্ন উত্তরের আকার (আমি ভরে দিলাম)
# ─────────────────────────────────────────────────────────────
# প্রতিটা library এই একই আকারে উত্তর দেবে। এটাই "অনুবাদের গন্তব্য"।

@dataclass
class VerifyResult:
    accepted: bool          # library টোকেন মেনে নিল?  True/False
    claims: dict            # ACCEPT হলে যে payload পেল (নইলে {})
    error: str              # REJECT হলে কেন (নইলে "")

    # কেন claims দরকার? — ঘর #৫ (Violation check) মেলাবে
    #   "verifier কী believe করল" vs "issuer কী সাইন করেছিল"।
    #   সেই "verifier কী believe করল" = এই claims. না রাখলে #৫ চলবেই না।


# ─────────────────────────────────────────────────────────────
# অংশ খ — PyJWT-র harness (অর্ধেক ভরা)
# ─────────────────────────────────────────────────────────────

def verify_pyjwt(token: str, key: str, algorithms: list) -> VerifyResult:
    """একটা টোকেন PyJWT-কে দিয়ে verify করাও, অভিন্ন উত্তর ফেরত দাও।"""
    try:
        # PyJWT ভালো টোকেনে decoded payload (dict) ফেরত দেয়
        claims = pyjwt.decode(token, key, algorithms=algorithms)

        # ── এখানে পৌঁছানো মানে library টোকেন মেনে নিয়েছে ──
        return VerifyResult(
            accepted=True,
            claims=claims,
            error="",
        )

    except pyjwt.ExceptionType as e:      # ← তুমি: PyJWT কোন exception ছোঁড়ে?
        #                                      (ইঙ্গিত: pyjwt.InvalidTokenError
        #                                       হলো সব JWT error-এর parent।
        #                                       একটা ধরলেই সব ধরা পড়ে।)

        # ── এখানে পৌঁছানো মানে library টোকেন বাতিল করেছে ──
        return VerifyResult(
            accepted=______,     # ← তুমি: True না False?
            claims=______,       # ← তুমি: REJECT হলে claims কী?
            error=str(e),        # কেন বাতিল করল — exception-এর বার্তা
        )


# ─────────────────────────────────────────────────────────────
# অংশ গ — একটা ফাঁদ নিয়ে ভাবো (এখনই ভরতে হবে না, শুধু ভাবো)
# ─────────────────────────────────────────────────────────────
#
# প্রশ্ন: DoS আক্রমণে (Billion Hashes) library কোনো exception ছোঁড়ে না,
#         REJECT-ও করে না — সে শুধু আটকে থাকে (হয়তো ১০ মিনিট CPU খায়)।
#
#         এই VerifyResult আকারে সেটা কীভাবে ধরা পড়বে?
#         (ইঙ্গিত: হয়তো একটা বাড়তি field লাগবে — time_taken?
#          অথবা এটা harness-এর কাজ নয়, আলাদা oracle-এর কাজ?
#          মনে করো ঘর #৫-এর "দুই রকম oracle" আলোচনা।)
#
# ← তোমার ভাবনা এখানে:
