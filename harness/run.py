"""Full differential run: execute selected implementations over the corpus (or
ad-hoc pcaps) and verify they agree with *each other*.

This is the periodic, DPDK-host job (it can run all three impls). It complements
``check`` (per-repo, golden-based, runs in normal CI): ``check`` catches a single
impl drifting from the contract; ``run`` catches a divergence a frozen golden
might miss, and surfaces real captures the impls disagree on.

Usage:
    python -m harness.run                    # all available impls, over the corpus
    python -m harness.run --impls python,go
    python -m harness.run --pcaps a.pcap b/  # ad-hoc inputs instead of the corpus
    python -m harness.run -v                 # show every field diff
Exits non-zero on any undocumented divergence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .compare import compare_records, format_comparison
from .corpus import load_corpus
from .known_issues import known_divergence
from .runners import make_runner


def _inputs(args) -> list[tuple[str, str]]:
    """Return [(case_name, pcap_path)]: the corpus by default, else --pcaps."""
    if args.pcaps:
        out = []
        for p in args.pcaps:
            path = Path(p)
            if path.is_dir():
                out += [(q.stem, str(q)) for q in sorted(path.glob("*.pcap*"))]
            else:
                out.append((path.stem, str(path)))
        return out
    return [(c.name, str(c.input_pcap)) for c in load_corpus()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run")
    ap.add_argument("--impls", default="python,go,retina", help="comma list (default: all)")
    ap.add_argument("--pcaps", nargs="*", help="ad-hoc pcap files/dirs (default: the corpus)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    wanted = [s.strip() for s in args.impls.split(",") if s.strip()]
    runners = []
    for name in wanted:
        r = make_runner(name)
        ok, why = r.available()
        if ok:
            runners.append(r)
        else:
            print(f"skip {name}: {why}")
    if len(runners) < 2:
        print("need at least two available implementations to compare", file=sys.stderr)
        return 2

    inputs = _inputs(args)
    if not inputs:
        print("no inputs (empty corpus / no --pcaps)", file=sys.stderr)
        return 2

    ref = runners[0]
    n_fail = 0
    for name, pcap in inputs:
        try:
            recs = {r.name: r.run(pcap) for r in runners}
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
            n_fail += 1
            continue
        for other in runners[1:]:
            cmp = compare_records(name, ref.name, recs[ref.name], other.name, recs[other.name])
            if cmp.ok:
                if args.verbose:
                    print(format_comparison(cmp))
                continue
            reason = known_divergence(cmp)
            if reason:
                print(f"[KNOWN] {name}: {ref.name} vs {other.name}: {reason.splitlines()[0]}")
            else:
                n_fail += 1
                print(f"[DIVERGENCE] {format_comparison(cmp, verbose=True)}")

    print(f"\n{len(inputs)} input(s), impls={[r.name for r in runners]}: "
          f"{'all agree' if not n_fail else str(n_fail) + ' undocumented divergence(s)'}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
