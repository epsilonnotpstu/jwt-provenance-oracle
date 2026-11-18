"""
ঘর #১ — Message Struct (সম্পূর্ণ)
==================================
একটা JWT-কে code-এ ধরে রাখার বাক্স। শুধু তথ্য রাখে, কোনো কাজ করে না।

সিদ্ধান্ত: পথ B — এক class + format flag। (কারণ নিচে ব্যাখ্যা করা)
"""

from dataclasses import dataclass, field


@dataclass
class Jwt:
    """একটা JWT-র সব রূপ (compact ও JSON) ধরে রাখার একক বাক্স।"""

    header: dict                    # {"alg": "HS256", "typ": "JWT"}
    payload: dict                   # {"role": "user", "iss": "real-issuer"}
    signature: bytes = b""          # signature bytes; খালি b"" = alg:none

    # format: "compact" বা "json"
    #   কেন default "compact"? — স্বাভাবিক, নিরাপদ JWT সবসময় compact।
    #   fuzzer এটাকে "json"-এ বদলালেই Format Confusion-এর দরজা খোলে।
    fmt: str = "compact"

    # extra_fields: শুধু JSON রূপে অর্থবহ। fakeiss-এর মতো বাড়তি field এখানে।
    #   কেন dict? — "যেকোনো নাম → যেকোনো মান" ধরে রাখে (fakeiss, fake, যা খুশি)।
    #   কেন field(default_factory=dict)? — এটাই সেই "ফাঁদ": dataclass-এ
    #   সরাসরি `= {}` দিলে সব object একই dict শেয়ার করে (Python-এর mutable
    #   default bug)। default_factory প্রতিবার নতুন খালি dict বানায়।
    extra_fields: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# কেন পথ B (এক class), পথ A নয় — সততার সাথে trade-off
# ─────────────────────────────────────────────────────────────
#
# Format Confusion mutation = "compact JWT নাও → JSON বানাও → fakeiss ঢোকাও"
#
#   পথ A (দুই class): mutation-কে CompactJwt object মুছে নতুন JsonJwt
#                     object বানাতে হবে — বেশি code, বেশি ভুলের সুযোগ।
#
#   পথ B (এক class):  mutation শুধু দুটো লাইন বদলায় —
#                        jwt.fmt = "json"
#                        jwt.extra_fields["fakeiss"] = <জাল>
#                     সহজ, এবং DY-mutation-এর "term-এর ছোট অংশ বদলানো"
#                     দর্শনের সাথে মেলে।
#
# Trade-off: এক class-এ compact অবস্থায় extra_fields ফাঁকা পড়ে থাকে
#            (সামান্য অপচয়)। কিন্তু সরলতা সেই অপচয়ের চেয়ে বেশি মূল্যবান।
