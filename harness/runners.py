"""Per-implementation runner adapters.

Each runner takes a pcap path and returns a list of canonical record dicts. The
harness can select any subset via ``--impl(s)``; an unavailable implementation
(e.g. retina on a non-DPDK host, or a missing clienthellod checkout) reports why
and is skipped rather than failing the run.

Because the three implementations now live in separate repos, the runners
discover them per host:
  - pyquicfp    : imported as an installed package (``pip install`` from git).
  - clienthellod: a sibling/`$HOME` checkout, wired in via a generated go.work
                  (env ``QUICFP_CLIENTHELLOD`` overrides discovery).
  - retina      : a prebuilt binary (env ``QUICFP_RETINA_BIN`` /
                  ``QUICFP_RETINA_CONFIG`` / ``QUICFP_DPDK_LIB``), since it needs
                  DPDK to build.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .schema import load_jsonl, retina_record_to_canonical

REPO_ROOT = Path(__file__).resolve().parent.parent
GO_RUNNER_DIR = REPO_ROOT / "go_runner"

CLIENTHELLOD_MODULE = "github.com/refraction-networking/clienthellod"


class Runner:
    name = "base"

    def available(self) -> tuple[bool, str]:
        raise NotImplementedError

    def run(self, pcap_path: str) -> list[dict]:
        raise NotImplementedError


class PythonRunner(Runner):
    name = "python"

    def __init__(self, grease_tp_mode: str = "normalized"):
        self.grease_tp_mode = grease_tp_mode

    def available(self) -> tuple[bool, str]:
        try:
            from pyquicfp import fingerprint_pcap  # noqa: F401
            return True, ""
        except Exception as e:  # pragma: no cover
            return False, f"cannot import pyquicfp (pip install from git): {e}"

    def run(self, pcap_path: str) -> list[dict]:
        from pyquicfp import fingerprint_pcap

        records = fingerprint_pcap(pcap_path, grease_tp_mode=self.grease_tp_mode)
        return [r.to_dict() for r in records]


class GoRunner(Runner):
    name = "go"

    def __init__(self, go_runner_dir: Path = GO_RUNNER_DIR, clienthellod_dir=None):
        self.dir = Path(go_runner_dir)
        self.binary = self.dir / "go_runner"
        self.clienthellod_dir = clienthellod_dir
        self._built = False
        self._build_error = ""

    def _find_clienthellod(self) -> Path | None:
        candidates = []
        if self.clienthellod_dir:
            candidates.append(Path(self.clienthellod_dir))
        env = os.environ.get("QUICFP_CLIENTHELLOD")
        if env:
            candidates.append(Path(env))
        home = Path.home()
        candidates += [
            REPO_ROOT.parent / "clienthellod",
            REPO_ROOT.parent / "fingerprint-web" / "clienthellod",
            home / "clienthellod",
            home / "fingerprint-web" / "clienthellod",
        ]
        for c in candidates:
            if (c / "go.mod").exists():
                return c.resolve()
        return None

    def _ensure_built(self) -> bool:
        if self._built:
            return True
        if self._build_error:
            return False
        if not _which("go"):
            self._build_error = "go toolchain not found on PATH"
            return False
        chd = self._find_clienthellod()
        if chd is None:
            self._build_error = (
                "clienthellod repo not found (set QUICFP_CLIENTHELLOD, or place a "
                "refraction-networking/clienthellod checkout beside this repo / in $HOME)"
            )
            return False
        try:
            # Point the build at this host's clienthellod via a go.work file
            # (gitignored) so the committed go.mod is left alone.
            workfile = self.dir / "go.work"
            workfile.write_text(
                f"go 1.22\n\nuse .\n\nreplace {CLIENTHELLOD_MODULE} => {chd}\n"
            )
            subprocess.run(
                ["go", "build", "-o", str(self.binary), "."],
                cwd=str(self.dir),
                check=True,
                capture_output=True,
                text=True,
            )
            self._built = True
            return True
        except subprocess.CalledProcessError as e:  # pragma: no cover
            self._build_error = (e.stderr or e.stdout or str(e)).strip()
            return False

    def available(self) -> tuple[bool, str]:
        if self._ensure_built():
            return True, ""
        return False, self._build_error

    def run(self, pcap_path: str) -> list[dict]:
        if not self._ensure_built():
            raise RuntimeError(f"go runner unavailable: {self._build_error}")
        proc = subprocess.run(
            [str(self.binary), pcap_path], capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise RuntimeError(f"go runner failed: {proc.stderr.strip()}")
        return load_jsonl(proc.stdout)


class RetinaRunner(Runner):
    """Drives retina-quic-fp's offline mode (Linux/DPDK only).

    On a host without a built, runnable retina binary this runner reports as
    unavailable and is skipped. Build the binary on a DPDK host (or in the
    docker/retina image) and point QUICFP_RETINA_BIN at it.
    """

    name = "retina"

    def __init__(self, binary=None, config_template=None, dpdk_lib=None):
        self.binary = binary or os.environ.get("QUICFP_RETINA_BIN") or self._default_binary()
        self.config_template = (
            config_template
            or os.environ.get("QUICFP_RETINA_CONFIG")
            or self._default_config()
        )
        self.dpdk_lib = dpdk_lib or os.environ.get("QUICFP_DPDK_LIB") or self._detect_dpdk_lib()

    @staticmethod
    def _candidate_retina_dirs() -> list[Path]:
        return [
            REPO_ROOT.parent / "retina-quic-fp",
            Path.home() / "retina-quic-fp",
        ]

    def _default_binary(self) -> str:
        for base in self._candidate_retina_dirs():
            rel = base / "target" / "release"
            for name in ("quic_fingerprint", "quic-fingerprint"):
                if (rel / name).exists():
                    return str(rel / name)
        return str(self._candidate_retina_dirs()[0] / "target" / "release" / "quic_fingerprint")

    def _default_config(self) -> str:
        for base in self._candidate_retina_dirs():
            cfg = base / "configs" / "offline.toml"
            if cfg.exists():
                return str(cfg)
        return str(self._candidate_retina_dirs()[0] / "configs" / "offline.toml")

    @staticmethod
    def _detect_dpdk_lib():
        import glob

        for pattern in ("/opt/dpdk-*/lib/*", "/usr/local/lib/*", "/usr/local/lib"):
            for d in glob.glob(pattern):
                if glob.glob(os.path.join(d, "librte_eal.so*")):
                    return d
        return None

    def _env(self) -> dict:
        env = os.environ.copy()
        if self.dpdk_lib:
            existing = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"{self.dpdk_lib}:{existing}" if existing else self.dpdk_lib
        return env

    def available(self) -> tuple[bool, str]:
        if not os.path.exists(self.binary):
            return False, f"retina binary not found at {self.binary} (build on a DPDK host / docker image, or set QUICFP_RETINA_BIN)"
        if not os.access(self.binary, os.X_OK):
            return False, f"retina binary not executable: {self.binary}"
        return True, ""

    def run(self, pcap_path: str) -> list[dict]:
        ok, why = self.available()
        if not ok:
            raise RuntimeError(why)
        proc = subprocess.run(
            [self.binary, "--config", str(self.config_template), "--pcap", pcap_path, "--stdout"],
            capture_output=True,
            text=True,
            env=self._env(),
        )
        if proc.returncode != 0:
            raise RuntimeError(f"retina failed: {proc.stderr.strip()[:500]}")
        records: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue  # skip retina status lines
            obj = json.loads(line)
            if "quic_header" not in obj:
                continue  # skip TCP/TLS-only records, not QUIC
            records.append(retina_record_to_canonical(obj))
        return records


def _which(prog: str):
    from shutil import which

    return which(prog)


def make_runner(name: str, grease_tp_mode: str = "normalized") -> Runner:
    if name == "python":
        return PythonRunner(grease_tp_mode=grease_tp_mode)
    if name == "go":
        return GoRunner()
    if name == "retina":
        return RetinaRunner()
    raise ValueError(f"unknown implementation: {name}")
