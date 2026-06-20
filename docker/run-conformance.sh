#!/usr/bin/env bash
# Build retina-quic-fp and run the conformance corpus check against it, inside the
# DPDK container. Mount both repos and point these at them (defaults assume they
# are checked out side by side under /work):
#
#   RETINA_DIR        (default /work/retina-quic-fp)
#   CONFORMANCE_DIR   (default /work/quic-fingerprint-conformance)
#
# Extra args are forwarded to `harness.check` (e.g. -v).
set -euo pipefail

RETINA_DIR="${RETINA_DIR:-/work/retina-quic-fp}"
CONFORMANCE_DIR="${CONFORMANCE_DIR:-/work/quic-fingerprint-conformance}"

# DPDK EAL needs a mounted hugetlbfs for every reserved hugepage size, or the
# mempool creation fails. On a fresh CI runner (no hugepages), allocate 2 MB
# pages and mount them. On a host that already mounts hugetlbfs (e.g. /mnt/huge_*
# bind-mounted in), this is a no-op. Requires --privileged.
ensure_hugepages() {
    if grep -q hugetlbfs /proc/mounts; then
        echo "==> hugetlbfs already mounted: $(awk '$3=="hugetlbfs"{print $2}' /proc/mounts | tr '\n' ' ')"
        return
    fi
    echo "==> no hugetlbfs mount found; allocating 2 MB hugepages + mounting (needs --privileged)"
    sysctl -w vm.nr_hugepages=1024 >/dev/null 2>&1 || echo "  WARN: could not set vm.nr_hugepages"
    mkdir -p /dev/hugepages
    mount -t hugetlbfs none /dev/hugepages 2>/dev/null || echo "  WARN: could not mount hugetlbfs"
}
ensure_hugepages
grep -iE "HugePages_Total|HugePages_Free" /proc/meminfo || true

echo "==> DPDK $(pkg-config --modversion libdpdk 2>/dev/null || echo '?')  (DPDK_VERSION=${DPDK_VERSION:-unset})"
echo "==> cargo $(cargo --version)"

echo "==> building retina-quic-fp (release)"
( cd "$RETINA_DIR" && cargo build --release )

# Honor CARGO_TARGET_DIR (CI caches the target in a volume outside the source).
TARGET_DIR="${CARGO_TARGET_DIR:-$RETINA_DIR/target}"
BIN="$TARGET_DIR/release/quic_fingerprint"
[ -x "$BIN" ] || { echo "build did not produce $BIN" >&2; exit 1; }

# Diagnostic: run retina on one pcap with DPDK logging ON (suppress_dpdk_output=
# false) so a failure shows the real EAL reason — IOVA mode, hugepage status,
# mempool error. The harness truncates retina's stderr, so this prints it raw.
echo "==> DPDK diagnostic (one pcap, verbose EAL)"
{ echo "suppress_dpdk_output = false"; cat "$RETINA_DIR/configs/offline.toml"; } > /tmp/offline-verbose.toml
diag_pcap="$(ls "$CONFORMANCE_DIR"/corpus/*/input.pcap* 2>/dev/null | head -1)"
"$BIN" --config /tmp/offline-verbose.toml --pcap "$diag_pcap" --stdout 2>&1 | head -50 || true
echo "==> end diagnostic"

echo "==> conformance: retina vs corpus goldens"
cd "$CONFORMANCE_DIR"
exec env \
    QUICFP_RETINA_BIN="$BIN" \
    QUICFP_RETINA_CONFIG="$RETINA_DIR/configs/offline.toml" \
    python3 -m harness.check --impl retina "$@"
