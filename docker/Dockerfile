# Build + run environment for retina-quic-fp (the Rust/DPDK fingerprinter) so the
# conformance harness can exercise `--impl retina` in CI without a dedicated DPDK
# tap host.
#
# Mirrors the production hosts: Ubuntu 24.04, DPDK 23.11 from apt (retina-core's
# build.rs accepts 20.11/21.08/23.11/24.11 and the fingerprint output is
# DPDK-version-independent), libclang for bindgen, rustup stable.
#
# This image is the ENVIRONMENT; retina-quic-fp is built at run time so you test
# the current code (see README.md / run-conformance.sh). NOTE: *running* retina
# offline still initializes DPDK EAL, which needs hugepages — so the container
# must run privileged with /dev/hugepages mounted (see README.md).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git pkg-config build-essential \
        dpdk dpdk-dev libnuma-dev \
        clang libclang-dev \
        python3 \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Rust (stable) via rustup. If retina-quic-fp pins a toolchain via
# rust-toolchain.toml, rustup honours it automatically.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal \
        --default-toolchain stable

# DPDK build env consumed by retina-core's build.rs:
#   - DPDK_VERSION must be one of {20.11, 21.08, 23.11, 24.11}.
#   - build.rs locates DPDK via "$LD_LIBRARY_PATH/pkgconfig", treating
#     LD_LIBRARY_PATH as a SINGLE directory — so it must be exactly the DPDK lib
#     dir (the multiarch dir where apt installs libdpdk + its .pc).
# These statics target x86_64 (GitHub Actions runners), where `container:` usage
# bypasses the entrypoint. The entrypoint recomputes them for other arches when
# the image is used via `docker run`.
ENV DPDK_VERSION=23.11 \
    LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu \
    PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

# apt installs DPDK libs in a standard dir, so `pkg-config --libs libdpdk` omits
# the -L flag by default — but retina-core's build.rs unwraps that -L
# (library_location). These make pkg-config emit -L/-I for system paths so the
# build works against apt DPDK (the prod /opt/dpdk-24.11 is non-standard, so it
# emits -L there without this).
ENV PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
    PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

COPY entrypoint.sh run-conformance.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/run-conformance.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
