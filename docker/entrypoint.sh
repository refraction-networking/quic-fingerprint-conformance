#!/usr/bin/env bash
# Set the DPDK build/run env retina-core expects, recomputed for the running
# architecture, then exec the command. (Under GitHub Actions `container:` the
# static ENV in the Dockerfile applies instead, since Actions bypasses the
# entrypoint — those statics target x86_64 runners.)
set -e

arch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
if [ -n "$arch" ] && [ -d "/usr/lib/$arch/pkgconfig" ]; then
    # Must be a SINGLE directory: build.rs does PathBuf(LD_LIBRARY_PATH)/pkgconfig.
    export LD_LIBRARY_PATH="/usr/lib/$arch"
    export PKG_CONFIG_PATH="/usr/lib/$arch/pkgconfig"
fi

# retina-core's build.rs unwraps the -L from `pkg-config --libs libdpdk`; apt
# DPDK lives in a standard dir, which pkg-config omits -L for unless told to.
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

# DPDK_VERSION must be major.minor in {20.11, 21.08, 23.11, 24.11}.
if v="$(pkg-config --modversion libdpdk 2>/dev/null)"; then
    export DPDK_VERSION="${v%.*}"
fi

exec "$@"
