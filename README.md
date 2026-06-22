# quic-fingerprint-conformance

Conformance contract and differential-testing harness for the three independent
QUIC/TLS fingerprinters, ensuring they never silently diverge:

| Implementation | Language | Repo |
|---|---|---|
| pyquicfp | Python | [refraction-networking/pyquicfp](https://github.com/refraction-networking/pyquicfp) |
| clienthellod | Go | [refraction-networking/clienthellod](https://github.com/refraction-networking/clienthellod) |
| retina-quic-fp | Rust | [refraction-networking/retina-quic-fp](https://github.com/refraction-networking/retina-quic-fp) |

All three must produce **byte-identical** fingerprints (the four hashes —
`quic_header_fp`, `tls_fp`, `qtp_fp`, `super_fp` — plus the parsed feature fields)
for the same input.

## The contract: `corpus/`

Each case is an input pcap plus its **golden** (the expected canonical-record
output), committed to git:

```
corpus/<case>/
  input.pcap      minimized to the QUIC Initial(s) — a few KB
  expected.json   the golden: canonical records the impls must reproduce
  meta.json       provenance: source, reference impl, grease mode
```

The golden encodes the **consensus**: a case is promoted only after all impls
agree on it (`harness.run`). To change the algorithm you must regenerate the
goldens (`harness.gen_golden --refresh`), review the diff, and bump the contract
— so divergence is always a deliberate, reviewed event, never an accident.

## Two test layers

1. **Per-repo self-test (every PR, fast).** Each implementation's CI runs
   `harness.check --impl <impl>` against the pinned corpus. No cross-language
   toolchain needed; catches that repo drifting from the contract.
2. **Differential run (periodic, DPDK host).** `harness.run` executes all
   available impls over the corpus and verifies they agree with each other —
   catching anything a frozen golden might miss, and flagging real captures the
   impls disagree on.

`known_issues.py` registers *understood* divergences (e.g. retina keys
connections by 5-tuple, py/go by DCID) so those stay green while anything new
stands out.

## Usage

```bash
pip install -r requirements.txt        # installs the reference impl (pyquicfp)

python -m harness.check                # pyquicfp self-consistency (default impl)
python -m harness.check --impl go      # clienthellod vs the goldens
python -m harness.run                  # full differential, all available impls
python -m harness.gen_golden foo.pcap  # add/refresh a corpus case (review the diff!)
```

Discovering the other impls:
- **clienthellod**: set `QUICFP_CLIENTHELLOD=/path/to/clienthellod`, or place a
  checkout beside this repo / in `$HOME`. The Go runner wires it via a generated
  `go.work` (the committed go.mod is left alone).
- **retina-quic-fp**: needs DPDK. Build the binary on a DPDK host (or the
  `docker/` image) and set `QUICFP_RETINA_BIN` / `QUICFP_RETINA_CONFIG`. Absent,
  the retina runner reports unavailable and is skipped.

## Consuming the corpus from a fingerprinter repo

Pin this repo as a submodule and self-test in CI:

```bash
git submodule update --init testdata/conformance   # pulls the corpus contract
python -m harness.check --impl <impl>
```

The submodule commit you pin *is* the contract version your repo conforms to;
bumping it is an explicit, reviewed change.

## Versioning

The contract is released as git tags **`vMAJOR.MINOR`** (pre-1.0 while it
stabilizes). Each tag is a deliberate, reviewed snapshot of the corpus, goldens,
and comparison semantics that consumers test against; the GitHub Release for each
tag records what changed and whether consumers must re-verify.

- **MAJOR** — the fingerprint algorithm or goldens changed; every consumer must
  update and re-run its self-test (breaking).
- **MINOR** — corpus cases added, or a known-issue added/removed (additive
  coverage; a consumer may newly diverge — which is the point).
- Harness-internal, docker, or docs-only changes that can't affect pass/fail
  don't get a tag.

A consumer pins the tag's commit as its submodule (the recorded SHA is the exact
contract version). To adopt a new contract, check out the tag and commit the bump:

```bash
git -C testdata/conformance fetch --tags
git -C testdata/conformance checkout v0.1.0
git add testdata/conformance
git commit -m "Bump conformance contract to v0.1.0"
```
