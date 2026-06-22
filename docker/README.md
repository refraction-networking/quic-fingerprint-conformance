# docker/ — DPDK container for the retina runner

retina-quic-fp links DPDK, so it can't build or run in vanilla CI. This image
provides the environment (Ubuntu 24.04 + DPDK 23.11 + libclang + rustup stable +
python3) so the conformance harness can exercise `--impl retina` without a
dedicated DPDK tap host. It builds retina at run time, so you always test the
current code.

> Status: **validated on Linux** (quicfp, aarch64) and **green in GitHub Actions**
> — the image builds retina against apt DPDK 23.11 and runs `--impl retina` →
> 6 ok / 2 known-issue / 0 failed. Build/run on a real Linux host or in CI; macOS
> Docker Desktop isn't part of the tested path (see the IOVA note under "What we
> learned").

## Build

```bash
docker build -t quicfp-conformance-dpdk docker/
```

## Run locally (real Linux host)

DPDK EAL needs a **mounted hugetlbfs for every reserved hugepage size** or
mempool creation fails. `run-conformance.sh` self-bootstraps this: if no
hugetlbfs is mounted it allocates 2 MB pages and mounts them, so a fresh host
only needs `--privileged`. If the host already mounts hugetlbfs (e.g. quicfp
mounts `/mnt/huge_1G` + `/mnt/huge_2M`), bind those in so DPDK finds a mount for
each reserved size.

```bash
# check out retina-quic-fp beside this repo, then:
docker run --rm --privileged \
  -v "$PWD/..":/work \
  -e RETINA_DIR=/work/retina-quic-fp \
  -e CONFORMANCE_DIR=/work/quic-fingerprint-conformance \
  quicfp-conformance-dpdk run-conformance.sh

# host that pre-mounts hugetlbfs (e.g. quicfp): add
#   -v /mnt/huge_1G:/mnt/huge_1G -v /mnt/huge_2M:/mnt/huge_2M
```

`run-conformance.sh` ensures hugepages, builds retina (`cargo build --release`),
and runs `python -m harness.check --impl retina` against the corpus.

## GitHub Actions

```yaml
jobs:
  retina-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { path: quic-fingerprint-conformance, submodules: false }
      - uses: actions/checkout@v4
        with: { repository: refraction-networking/retina-quic-fp, path: retina-quic-fp }
      - name: Build DPDK image
        run: docker build -t quicfp-conformance-dpdk quic-fingerprint-conformance/docker
      - name: Build retina + run conformance
        run: |
          docker run --rm --privileged \
            -v "$PWD":/work \
            -e RETINA_DIR=/work/retina-quic-fp \
            -e CONFORMANCE_DIR=/work/quic-fingerprint-conformance \
            quicfp-conformance-dpdk run-conformance.sh
```

`--privileged` lets `run-conformance.sh` allocate 2 MB hugepages and mount a
hugetlbfs inside the runner (no host pre-step needed).

Cache `~/.cargo` and `retina-quic-fp/target` between runs to avoid rebuilding the
DPDK+retina tree every time.

## What we learned (validated on quicfp, aarch64 Linux)

- **bindgen emits the RSS constants** in a clean image — `RTE_ETH_RSS_IP/TCP/UDP`
  (from the function-like `RTE_BIT64()` macro) generate fine with `libclang-dev`.
  The decoy-tap failure was host-state drift, not reproducible here.
- **apt DPDK needs `PKG_CONFIG_ALLOW_SYSTEM_LIBS=1`** (baked into the image):
  apt installs libdpdk in a standard dir, so `pkg-config --libs libdpdk` omits
  the `-L` that retina-core's `build.rs` unwraps (`library_location.unwrap()`).
- **"Mempool mempool_0 creation failed" has two distinct causes** — both bit us:
  (1) a *reserved* hugepage size with no matching hugetlbfs mount (quicfp reserves
  1 GB pages, so DPDK needs `/mnt/huge_1G` mounted too, not just 2 MB); and (2) the
  requested pool exceeds the available hugepage memory — a CI runner has only ~2 GB
  (1024 × 2 MB pages), but offline.toml's default mempool (capacity 262_144 at MTU
  9702 ≈ jumbo mbufs) needs ~2.6 GB. `run-conformance.sh` shrinks the pool for the
  corpus; capacity does not affect the fingerprint. The error string is identical,
  so check the failure *stage*: a missing mount aborts during EAL init, whereas an
  oversized pool fails at `rte_mempool_create` *after* EAL is fully up.
- **IOVA mode.** Offline retina forces `--iova-mode=va` + `--no-pci` in its EAL
  args (the `get_eal_params` offline branch), so it no longer depends on IOVA `PA`
  / real physical addresses — this is what unblocked the cloud CI runner (and the
  reason the `--tmpfs` PCI-hiding stopgap is gone). macOS Docker Desktop
  historically failed on IOVA `PA`; that specific blocker is removed, but the Mac
  path isn't tested — use real Linux / CI.

## Notes

- DPDK comes from apt (`dpdk-dev` = 23.11); `build.rs` accepts it and the
  fingerprint output is DPDK-version-independent, so this need not match the
  production 24.11 exactly. The entrypoint derives `DPDK_VERSION` from
  `pkg-config` and sets `LD_LIBRARY_PATH`/`PKG_CONFIG_PATH` per architecture.
- The build pulls retina-core/-filtergen/-datatypes from the `sampling` fork and
  `tls-parser` from its fork (per retina-quic-fp's `Cargo.toml`), over git.
