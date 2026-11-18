# Coverage-guided vs uniform-random fuzzing

Grammar-coverage proxy over a reachable behaviour space of 136 signatures (alg-family x serialization x key-kind x kid x crit x provenance), median over 10 seeds.

| target coverage | uniform (median iters) | guided (median iters) |
|---|---|---|
| 50% | 97 | 69 |
| 90% | 311 | 143 |
| 100% | None | 194 |

At a 50-iteration budget the guided driver reaches 37% of the space versus 31% for uniform random; the coupon-collector tail makes uniform random slow to close the last few behaviours, which the novelty-search frontier targets directly. This is a grammar-coverage result, not code coverage, consistent with the DY-fuzzing observation that code coverage is a poor signal for logical JOSE bugs.
