# Adapter guide — language-agnostic verifier adapters

> This guide does not change the contract in `PREREG.md` §3. It spells that contract out so a new adapter
> can be written and validated the same way in any language. The per-library cards stay in `ADAPTERS.md`.

## 1. Contract

**Invocation:** `adapter <cases.json> <outdir> [impl …]`

**Input:** `cases.json` only. The adapter must never open `truth.json`, and the runner should not even make
it reachable (§5).

**Output:** `<outdir>/<impl>.jsonl`, one JSON object per case, in file order, flushed after each line.

| field | type | meaning |
|---|---|---|
| `impl` | string | `<lang>/<name>`, stable identifier |
| `version` | string | read from package metadata at runtime, never hard-coded |
| `lang`, `backend` | string | language; crypto backend the library uses |
| `case` | string | case id |
| `accepted` | bool | the library's high-level verify returned success **and** its documented claim validation passed |
| `claims` | object \| null | what the library exposes on success (§2); `null` on reject |
| `error` | string | `"<ErrorType>: <message>"`, truncated to 200 chars; `""` on accept |
| `stage` | `keyload` \| `verify` \| `claims` | where it failed (on accept: `verify`) |
| `ns` | int | monotonic-clock nanoseconds around the verify call only, key loading excluded |

The requested minimal shape (`accepted, claims, error, time`) is a subset of this. **Keep `stage`.** The
keyload > 5% exclusion rule depends on it, and without it, key-format artefacts would be counted as
capability differences.

## 2. Claim normalization: the adapter reports, the judge normalizes

- Emit the library's exposed claims converted to native JSON, and **nothing else**. Do not merge headers,
  add defaults, or drop members.
- **Do not "repair" values.** If the library turns a large integer into a float, emit the float, because that
  *is* the verifier's belief. Normalization (`ν` in `ORACLE_FORMAL_v2.md`) happens in one place, the judge,
  so it is identical for every language.
- Exceptions are only type conversions forced by the language, and each must be documented in the card.
  For example, a date object is converted to integer seconds (and must be exact), and a map with
  non-string keys is converted to a string-keyed object.
- Keep `absent` and `null` distinct.
- Emit UTF-8. Escaping style does not matter once the output is parsed.

## 3. Configuration policy

- Use the documented safe usage from the library's own README or docs, with the algorithm allow-list pinned
  to `allowed_algs`. If the API takes a single algorithm, pin `allowed_algs[0]` and mark the card "pin[0]".
- Do not configure issuer or audience checks, and do not install optional plug-ins. The default install is
  what gets measured.
- If the library has no API for an algorithm: reject at `verify` with `"no algorithm for <alg>"`.
- If the library cannot import the key container: `stage = keyload`.

## 4. Timeouts

In-process timeouts cannot reliably interrupt a hung native call in most runtimes. Enforce them in the
**runner**, not the adapter:

1. The adapter writes and flushes one line per case.
2. The runner watches the output. If no new line appears within `T` seconds (suggested 10 s), it kills the
   process, writes the missing line itself (`accepted: false, stage: "timeout", ns: T·10⁹`), and restarts
   the adapter from the next case.
3. Apply an address-space limit (for example `ulimit -v`) so a memory blow-up becomes a crash, not a host hang.

**Note:** `stage = timeout` / `crash` is an extension to the `PREREG.md` §3 contract. Add it to `judge.py`
and record it as a deviation in whichever pre-registration first uses it.

## 5. Sandboxing

- **No network.** The corpus contains header-driven key-URL cases, and an adapter must never fetch anything.
  `unshare -rn <cmd>` works on this machine without sudo (checked). Run every adapter through it.
- **Truth isolation.** Run from a scratch directory that contains only a copy of `cases.json`, never the
  corpus directory itself.
- **Hermetic environment:** `TZ=UTC`, `LC_ALL=C`, a temporary `HOME`, and write access only to `outdir`.
- **Resource limits:** `ulimit -v`, `ulimit -t` as a backstop to §4.

## 6. Generic template (pseudocode)

```
IMPLS = { name → (package_id, backend, load_fn, verify_fn) }        # one entry per library

main(cases_path, outdir, selected):
    cases = read_json(cases_path).cases
    for name in selected or IMPLS:
        (pkg, backend, load, verify) = IMPLS[name]
        out = open(outdir/lang/name.jsonl, "w")
        warm_up(load, verify, cases[0])                              # per the fixed warm-up policy
        for c in cases:
            rec = {impl, version: pkg_version(pkg), lang, backend, case: c.id,
                   accepted: false, claims: null, error: "", stage: "keyload", ns: 0}
            try:
                k = load(c.key)                                     # key-container conversion only
                rec.stage = "verify"
                t0 = monotonic_ns()
                claims = verify(c.token, k, c.allowed_algs)         # high-level API + documented claim validation
                rec.ns = monotonic_ns() - t0
                rec.accepted = true; rec.claims = to_json(claims)
            except any e:
                rec.ns = rec.ns or (monotonic_ns() - t0 if t0 set else 0)
                rec.error = truncate(type_name(e) + ": " + message(e), 200)
            write_line(out, rec); flush(out)
```

Rules the template encodes:

- **Exceptions:** catch everything, including panics and runtime errors, so one case can never abort the run.
- **Where policy checks land:** `load` does container conversion only. The library's own policy checks
  normally happen inside `verify`.
- **What goes to `claims`:** `verify` returns the library's claim object as-is.

## 7. Per-adapter validation checklist

Record the result of every item in the `ADAPTERS.md` card.

**Build**
- [ ] Lockfile committed; the version in the output equals the lockfile version.
- [ ] Build or install is reproducible from a clean checkout plus `env.sh`, with no sudo.

**Gate**
- [ ] G1–G4 pass on `corpus/gate.json` (`check_gate.py`). If not, fix only adapter bugs, and log each fix in
  "Gate-caught adapter bugs".
- [ ] Keyload failures ≤ 5% of honest cases.

**Output**
- [ ] One output line per case; case ids match exactly.
- [ ] Belief fidelity: claims on honest V3 cases (Unicode, 2^60, audience forms) compared against issuer
  claims, with differences documented, not patched.
- [ ] Every reject has a non-empty `error`.

**Stability and isolation**
- [ ] Determinism: two runs give identical `accepted` and `claims`, and `ns` differs only in noise.
- [ ] A network-off run (`unshare -rn`) gives identical output.
- [ ] Truth isolation: the adapter source never mentions `truth`, and it runs from a directory without it.
- [ ] Timeout path tested with a deliberately slow dummy verifier. The runner records `timeout` and resumes.

**Freeze**
- [ ] Adapter committed (frozen) **before** its first run on any evaluation corpus. After that, any change is a deviation.

## 8. Plan for the remaining ecosystems

Python, Node, Go, Java, PHP, Rust, Ruby and .NET are done (`ADAPTERS.md`). Still open, per the
already-committed `PREREG_newlangs.md`: **C, Erlang/Elixir, Swift, Dart.** The library selection is fixed
there, so this plan does not change it.

| step | action | exit criterion |
|---|---|---|
| 0 | Toolchain check, no sudo. Checked today: `dart` ✓, `gcc`/`cmake` ✓, jansson 2.15 ✓, OpenSSL 3.6 ✓; `swift`, `erl`, `elixir` ✗ | Installs user-locally (e.g. vendor tarball, or conda-forge via micromamba), or the ecosystem is excluded with the reason recorded (`PREREG_newlangs.md` §2) |
| 1 | Pin versions, commit lockfiles / source commit hashes | Card row started |
| 2 | Write the adapter from §6 | Compiles |
| 3 | Gate (§7) | All gate items ticked |
| 4 | Remaining checklist items | All ticked |
| 5 | Freeze commit | Hash recorded in the card |
| 6 | Run on `corpus/` with a **separate** runner script (keeps `run_all.sh` and the 32-implementation numbers unchanged) | One `.jsonl` per implementation |
| 7 | Judge the new set separately (L1–L3) | Report, including negatives |

Suggested order, from fewest to most blockers:

1. **Dart** — toolchain present.
2. **C** — sources are already in `adapters/c/src`; build them against the system jansson and OpenSSL.
3. **Erlang/Elixir** — toolchain install needed.
4. **Swift** — toolchain install needed; the largest install.

**Known gaps to close first:**
- `judge.py --corpus` builds its implementation set from the primary 32 (`analysis.json`). The new set
  therefore needs its own implementation-set option before L1–L3 can be judged.
- `adapters/c/src/` holds complete third-party source trees. Do not commit them. Commit a fetch script
  pinned to a commit hash, and ignore `src/`.
