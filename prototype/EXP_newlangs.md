# PREREG-L — নতুন ecosystem-এ held-out replication: ফলাফল (২৫ সেপ্ট ২০২৬)

> Pre-registration: `scale30/PREREG_newlangs.md` (61d9211)। প্রতিটা adapter gate-পাসের পরে, **main corpus-এ চালানোর আগে**
> commit (freeze) করা: Dart b477bac, C 057afd2, BEAM 84edf97, Swift 6b677d4, runner 28271e7।
> রান: `scale30/run_newlangs.sh corpus/cases.json results_l/main` (network ছাড়া, `unshare -rn`), বিচার:
> `judge.py --newset results_l`। মূল ৩২-এর কোনো সংখ্যা বদলায়নি।

## ১. Implementation (নির্বাচন-নিয়ম PREREG §2/§3)

| impl | version | অবস্থা |
|---|---|---|
| c/libjwt | 3.6.1 | **primary** |
| erlang/erlang-jose | 1.11.12 (Elixir 1.20.4 / OTP 29) | **primary** |
| dart/dart_jsonwebtoken | 3.4.1 | **primary** |
| c/cjose | 0.8.1 (cisco/cjose) | বাদ — keyload 9.4% > 5% (RSA-1024 ×15: `cjose_jwk_import` প্রত্যাখ্যান) |
| swift/jwt-kit | 5.7.1 | বাদ — keyload 11.3% > 5% (RSA < 2048 container-এই throw ×15, Ed448 ×3) |
| dart/jose | 0.3.5+2 | বাদ — keyload 5.7% > 5% (secp256k1 ×3, OKP ×6); সীমানায়, নিয়ম অনুযায়ী বাদ |
| swift/swift-jwt | 4.0.2 | বাদ — build হয় না (BlueRSA-র OpenSSL 1.x macro, OpenSSL 3.x-এ Swift import করে না) |

নির্বাচনের সিদ্ধান্ত (সব কোনো corpus রানের আগে; বিস্তারিত `scale30/ADAPTERS.md`): আগে ক্লোন করা C source release ছিল না →
release tag-এ বদলানো; cjose-এর মূল ধারা (cisco) নেওয়া, OpenIDC fork নিয়ম ২-এ বাদ। reserve নেই, তাই primary set = ৩।

**সীমাবদ্ধতা:** তিনটা primary impl-এর set ছোট; ছয়টার তিনটা keyload নিয়মে বাদ, যা আংশিকভাবে API ডিজাইনের উপর নির্ভরশীল
(ADAPTERS.md-র সাধারণ নীতি)।

## ২. Hypothesis-এর রায়

| | pre-registered শর্ত | ফল | রায় |
|---|---|---|---|
| **L1** | নতুন কোনো impl ২০৪৫টা জাল টোকেনের একটাও গ্রহণ করে না | c/libjwt ৩৯৬টা গ্রহণ করে (সবই F2 `format_confusion`); অন্য কোনো জাল টোকেন কেউ গ্রহণ করেনি | **ভুল প্রমাণিত** (যেমন লেখা) |
| **L2** | নতুন set-এর B2 held-out FP ≥ ৫% এবং CI-নিম্নসীমা > ০ | ৯.৭% (১২/১২৪), 95% CI [৪.৮%, ১৫.৩%] | **সমর্থিত** |
| **L3** | PROV_claim বৈধ-টোকেন FP = ০ | ০/১৫৯ | **সমর্থিত** (soundness থেকে প্রত্যাশিত; sanity check) |

**L1 — হাতে যাচাই (PREREG অনুযায়ী; তালিকা `scale30/sealed/`-এ):** গৃহীত ৩৯৬টার প্রতিটায় libjwt-এর belief =
issuer-signed `role=user`; unsigned `admin` overlay কোথাও belief-এ আসেনি → oracle-এ সব **OK**, শ্রেণী-A ০টা।
একটা টোকেন (`F2/format_confusion/0011`) স্বতন্ত্রভাবে যাচাই: flattened JSON serialization, issuer-এর HS256 signature
signed payload-এর উপর বৈধ, আর unsigned top-level member `fakeiss={role:admin}`। RFC 7515 §7.2.1 অনুযায়ী অজানা অতিরিক্ত
member "MUST be ignored" — libjwt ঠিক তাই করে। তাই এটা **নিরাপত্তা লঙ্ঘন নয়, disclosure লাগবে না।** মূল ৩২টা এই ৩৯৬টার
একটাও গ্রহণ করেনি: তাদের adapter-এ ব্যবহৃত JWT API টোকেনটা malformed বা compact-নয় বলে reject করে (যেমন "Expected
compact serialized token")। এটা ব্যবহৃত API-র বৈশিষ্ট্য; library-গুলো অন্য API-তে JSON serialization সমর্থন করে কি না,
তা এখানে মাপা হয়নি।

L1-এর শর্ত acceptance-ভিত্তিক ছিল, belief-ভিত্তিক নয় — তাই যেমন লেখা তেমনই "ভুল প্রমাণিত" রিপোর্ট হচ্ছে। এটা পরে
বদলানো হচ্ছে না।
পর্যবেক্ষণ (post-hoc, দাবি নয়): এটা বাস্তব library-তে "গ্রহণ ≠ লঙ্ঘন" পার্থক্যের প্রথম উদাহরণ; আগে শুধু synthetic
FMT-SAFE target-এ দেখা গিয়েছিল। acceptance-ভিত্তিক detector এখানে ৩৯৬টা alarm দিত, belief-ভিত্তিক oracle দেয় ০।

## ৩. বর্ণনামূলক (নতুন set, ৩ impl, বৈধ টোকেন n=১৫৯)

- **Honest FP:** B0 = ৩৯, B1 = ৩, B2 = ১২, PROV = ২৮, PROV_claim = ০।
- **PROV-এর ২৮টার উৎস:** সবই resource v1 (alg-নিরপেক্ষ ২০× single-shot baseline)। এটা scale30-এ অস্থির বলে জানা ছিল,
  আর v2 (`PREREG_resource.md`) এখানে pre-register করা হয়নি। তাই এই সংখ্যা resource v1-এর অস্থিরতার আরেকটা replication,
  PROV-এর দাবি নয়।
- **B2-এর ১২টা FP:** সবই V2 (typ-নেই, typ=at+jwt; RS256 ও HS256 base; ৩ seed) আর সবই dart_jsonwebtoken-এর কারণে।
  এর default `checkHeaderType` `typ=="JWT"` দাবি করে। (alg, key)-profile header-নির্ভর capability দেখতে পায় না, তাই
  scale30 H3-এর একই কারণ এখানেও।
- **honest-reject (বাদ-পড়াসহ):** libjwt ২৪, erlang-jose ৩, dart_jsonwebtoken ১৫, cjose ১৫ (keyload), jwt-kit ৩ (+১৮ keyload),
  dart/jose ৩০ (+৯ keyload)।
- **Adapter bug যা gate/fidelity-তে ধরা পড়ে (corpus রানের আগে ঠিক করা):** erlang — OTP `json`-এর `:null` string "null"
  হিসেবে লেখা হচ্ছিল।
