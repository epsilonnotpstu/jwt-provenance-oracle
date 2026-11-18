"""ঘর #১ পরীক্ষা — বাক্সে তিন রকম JWT ধরা যায় কিনা।"""
from jwt_message import Jwt

# ১. স্বাভাবিক compact JWT
normal = Jwt(
    header={"alg": "HS256", "typ": "JWT"},
    payload={"role": "user", "iss": "real-issuer"},
    signature=b"VALID_SIG",
)
print("১. Compact:", normal.fmt, "| sig খালি?", normal.signature == b"")

# ২. alg:none — signature খালি
none_jwt = Jwt(
    header={"alg": "none"},
    payload={"role": "admin"},
    signature=b"",          # খালি = signature নেই
)
print("২. alg:none:", none_jwt.header["alg"], "| sig খালি?", none_jwt.signature == b"")

# ৩. Format Confusion — JSON রূপ + fakeiss
fc = Jwt(
    header={"alg": "RS256"},
    payload={"role": "user", "iss": "real-issuer"},   # আসল, signature এটার উপর
    signature=b"VALID_SIG",
    fmt="json",
)
fc.extra_fields["fakeiss"] = {"iss": "ADMIN-issuer"}   # জাল, পাশে বসানো
print("৩. Format Confusion:", fc.fmt, "| extra:", fc.extra_fields)

# ফাঁদ পরীক্ষা: দুটো আলাদা Jwt কি ভুল করে একই extra_fields শেয়ার করে?
a = Jwt(header={}, payload={})
b = Jwt(header={}, payload={})
a.extra_fields["x"] = 1
print("ফাঁদ পরীক্ষা — b.extra_fields খালি থাকা উচিত:", b.extra_fields, "→", "✅ ঠিক" if b.extra_fields == {} else "❌ bug!")
