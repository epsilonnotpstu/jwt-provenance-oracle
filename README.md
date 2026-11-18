# Issuer-Provenance Oracles for JOSE/JWT Library Testing — Artifact

Artifact for the paper:

> M. A. A. Pranto, N. H. Khokon, and G. M. M. Bashir, "Whose Token Is It? Issuer-Provenance Oracles for
> Low-False-Positive Testing of JOSE/JWT Libraries," in *Proc. 29th Int. Conf. on Computer and Information
> Technology (IEEE ICCIT 2026)*, Cox's Bazar, Bangladesh, 2026.

The artifact holds the prototype (operators, mutation driver, harness and provenance oracle) and the
pre-registrations. It also holds the corpora and raw verifier outputs that the paper's tables are computed from.
Some working notes are in Bangla; all code and data are language-neutral.

## Layout

| Path | Contents | Paper |
|---|---|---|
| `prototype/operators.py`, `mutations.py`, `jwt_message.py`, `random_fuzz.py` | composable token operators, DY-limited mutation driver | Sec. IV-A |
| `prototype/oracle.py`, `ORACLE_FORMAL_v2.md` | issuer-provenance oracle (Eq. 1) and its formal notes | Sec. IV-B |
| `prototype/harness.py`, `controlled_targets.py` | four-library Python harness, VULN/SAFE controlled targets | Sec. IV-C, RQ1 |
| `prototype/run_all.py` | RQ1 pipeline: unit tests → true positives → capability probe → naive vs. provenance → coverage → seeded campaign | RQ1, Sec. V-E |
| `prototype/crosslang/`, `prototype/multilang/`, `prototype/setup_oldlibs.sh` | historical-vulnerability reproduction and survey scripts. Vulnerable package versions are fetched by the setup scripts and not vendored. | RQ3 |
| `prototype/PREREG_METHODOLOGY.md`, `prototype/methodology/` | study-level pre-registration | Sec. V |
| `scale30/PREREG*.md` | pre-registrations for the 32-implementation study, B2+, resource v2, held-out ecosystems and G2–G4 | RQ2 |
| `scale30/adapters/<lang>/` | one adapter per implementation, covering 8 primary languages + C, Erlang/Elixir, Swift and Dart. The record format is uniform. See `ADAPTERS.md`. | Sec. IV-C |
| `scale30/corpus/`, `scale30/results/` | scale corpus (2,204 tokens, 159 validly issued) and per-implementation outputs; `results/judged.csv` | Table I |
| `scale30/corpus_b/`, `results_b/` | fresh corpus for the 190-rule blacklist B2+ | Table I (‡) |
| `scale30/corpus_r/`, `results_r/`, `resource_v2.py` | fresh corpus and resource-oracle v2 | Table I (†) |
| `scale30/results_l/` | held-out ecosystems (C, Erlang/Elixir, Swift, Dart) | Sec. V-B |
| `scale30/corpus_g*/` | honest-only G2–G4 corpora (1,600 / 6,000 / 24,000 tokens): generators, seeds, manifests, cases | Sec. V-B, VI |
| `scale30/analysis.py`, `judge.py`, `b2plus.py`, `analyze_g*.py` | analysis scripts that produce the reported rates | Tables I, IV |

## Running

**RQ1 prototype (Python 3.12):**

```sh
cd prototype
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python run_all.py
```

**Scale study (all languages).** Toolchain versions are listed in `scale30/env.sh`: Node 22, Go 1.27, Java 21 + Maven,
PHP 8.5 + Composer, Rust/Cargo, Ruby 3.3 and .NET 8. Install each adapter's dependencies as described in
`scale30/ADAPTER_GUIDE.md`. Then run:

```sh
scale30/run_all.sh scale30/corpus/cases.json /tmp/out   # runs all adapters on one corpus
python scale30/check_gate.py ...                          # admission gate (see PREREG.md §3)
python scale30/analysis.py ...                            # FP / silencing metrics (Table I)
```

Library versions are pinned in each adapter's lock file and were current on 2026-09-25. Runs were
network-isolated.

**Keys.** Every key in `issuer_keys.json` and in the corpora was generated for this test only and protects nothing.

## What is not included, and why

- **RQ4 defect reproducers** are not included. These cover the empty JWS JSON `signatures` list and the ignored `crit`
  extensions. The paper's disclosure policy publishes the library, the behaviour, the root cause and the impact, but
  no exploit inputs. All eight defects were reported privately and confirmed by the maintainers.
- **Per-implementation raw outputs for G2–G4** are not included while one related maintainer report is pending. The
  generators, seeds and inputs are included, so these outputs can be regenerated with the adapters above.
- Vendored third-party packages, build outputs and virtual environments are not included; they are fetched by the
  setup scripts or lock files.

## Hardware note

Throughput and resource-oracle timings in the paper were measured on one laptop. They are not a cross-platform
benchmark (paper Sec. VI).
