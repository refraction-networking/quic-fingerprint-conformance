# samples/ — the growing pcap archive (Git LFS)

This tier accumulates QUIC captures over time. Unlike `corpus/` (the small,
curated contract that gates CI), `samples/` is comprehensive and **Git LFS**-backed,
so cloning the repo and the fingerprinter submodules stays lean — consumers get
LFS *pointers*, not the multi-MB blobs (and CI sets `GIT_LFS_SKIP_SMUDGE=1`).

## Layout

One shallow grouping level by **implementation family**, then files named by
version + fingerprint. No deep category taxonomy — family-first avoids the
"browser vs library vs proxy" edge cases, and richer grouping is a *generated
view* over `meta.json`, not the directory tree.

```
samples/
  chrome/
    chrome_148_0_7274_55__<super_fp>.pcap
    chrome_148_0_7274_55__<super_fp>.meta.json
  firefox/
  quiche/
  aioquic/
```

## Conventions

- **Dedup by fingerprint.** Keep ~one minimized capture per distinct `super_fp`
  (the filename carries the fingerprint so duplicates are obvious). The archive
  grows with the *diversity of QUIC clients seen*, not traffic volume.
- **Minimize.** Trim each capture to just the relevant QUIC Initial(s)
  (`editcap`/`tshark`) so samples stay small.
- **`meta.json` is the source of truth for labels**: `{impl, family, version,
  source, captured_at, quic_header_fp, tls_fp, qtp_fp, super_fp}`.
- **Privacy.** Real tap/decoy captures may carry IPs/SNIs — scrub on ingest or
  keep lab/synthetic captures here; raw real traffic goes to a private tier.

## Promotion

`capture → samples/ → minimize + dedup → promote distinct ones into corpus/`
(with a golden via `harness.gen_golden`). The differential run flags any sample
where the three implementations disagree.
