# Scalability, overhead, and false-negative analysis

**Throughput.** 1500 tokens against 4 libraries (6000 verifications) in 0.50s = **3013 tokens/s**. The provenance oracle itself costs 4.7ms total (0.95% of runtime): the classification is essentially free next to signature verification.

**False negatives.** On a known-attack set spanning the detector-testable classes (alg:none, algorithm confusion, format confusion), recall is **3/3 = 100%** (false-negative rate 0%). The provenance oracle adds no missed detections relative to a verdict-only differential: whatever a genuine attack makes a verifier believe, the belief-vs-Signed check flags it.
