"""Generate / refresh corpus goldens from a reference implementation.

The golden for a case is the canonical-record list the reference implementation
(default: pyquicfp) produces for that pcap. Goldens encode the *consensus*: only
promote a new case after the full differential run (``harness.run``) confirms all
implementations agree on it. Review the diff before committing.

Usage:
    # add/update cases from pcap files (case name = pcap basename without extension)
    python -m harness.gen_golden path/to/foo.pcapng path/to/bar.pcap
    python -m harness.gen_golden path/to/pcap_dir/

    # regenerate expected.json for every existing corpus case from its input pcap
    python -m harness.gen_golden --refresh

Options:
    --ref python            reference implementation (default: python)
    --grease-tp normalized  GREASE transport-parameter handling (default)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .corpus import CORPUS_DIR, dump_expected, find_input_pcap, load_corpus
from .runners import make_runner


def _discover_pcaps(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            out += sorted(
                q for q in path.iterdir() if q.suffix in (".pcap", ".pcapng")
            )
        elif path.suffix in (".pcap", ".pcapng"):
            out.append(path)
        else:
            print(f"  skip (not a pcap): {p}", file=sys.stderr)
    return out


def _write_case(case_dir: Path, src_pcap: Path, records: list[dict], ref: str, grease: str) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    # Normalise the input filename so cases are uniform.
    dst_pcap = case_dir / f"input{src_pcap.suffix}"
    for stale in case_dir.glob("input.pcap*"):
        if stale != dst_pcap:
            stale.unlink()
    if src_pcap.resolve() != dst_pcap.resolve():
        shutil.copy(src_pcap, dst_pcap)
    (case_dir / "expected.json").write_text(dump_expected(records))
    (case_dir / "meta.json").write_text(
        json.dumps(
            {"source": src_pcap.name, "reference": ref, "grease_tp_mode": grease},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gen_golden")
    ap.add_argument("pcaps", nargs="*", help="pcap files or directories to add/update")
    ap.add_argument("--refresh", action="store_true", help="regenerate goldens for existing cases")
    ap.add_argument("--ref", default="python", help="reference implementation (default: python)")
    ap.add_argument("--grease-tp", default="normalized", choices=("normalized", "raw"))
    args = ap.parse_args(argv)

    if not args.pcaps and not args.refresh:
        ap.error("provide pcap paths or --refresh")

    runner = make_runner(args.ref, grease_tp_mode=args.grease_tp)
    ok, why = runner.available()
    if not ok:
        print(f"reference impl '{args.ref}' unavailable: {why}", file=sys.stderr)
        return 2

    jobs: list[tuple[str, Path]] = []  # (case_name, src_pcap)
    if args.refresh:
        for case in load_corpus():
            jobs.append((case.name, case.input_pcap))
    for pcap in _discover_pcaps(args.pcaps):
        jobs.append((pcap.stem, pcap))

    if not jobs:
        print("nothing to do (no pcaps found / corpus empty)")
        return 0

    n = 0
    for name, src in jobs:
        try:
            records = runner.run(str(src))
        except Exception as e:
            print(f"  ERROR {name}: {e}", file=sys.stderr)
            continue
        _write_case(CORPUS_DIR / name, src, records, args.ref, args.grease_tp)
        print(f"  wrote corpus/{name}/  ({len(records)} record(s))")
        n += 1
    print(f"done: {n} case(s) written to {CORPUS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
