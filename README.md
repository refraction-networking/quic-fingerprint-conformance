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

## `samples/` — the growing archive (Git LFS)

`samples/` accumulates captures over time, **Git LFS**-backed and deduplicated by
fingerprint, so the repo and its submodule consumers stay lean. See
[`samples/README.md`](samples/README.md). New distinct fingerprints get minimized
and promoted into `corpus/`.

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
- **retina-quic-fp**: needs DPDK. Build the binary on a DPDK host (or the planned
  `docker/` image) and set `QUICFP_RETINA_BIN` / `QUICFP_RETINA_CONFIG`. Absent,
  the retina runner reports unavailable and is skipped.

## Consuming the corpus from a fingerprinter repo

Pin this repo as a submodule and self-test in CI, skipping the LFS archive:

```bash
GIT_LFS_SKIP_SMUDGE=1 git submodule update --init   # pulls corpus, not sample blobs
python -m harness.check --impl <impl>
```

The submodule commit you pin *is* the contract version your repo conforms to;
bumping it is an explicit, reviewed change. (Alternatively, consume a
corpus-only release artifact — see the design notes.)
