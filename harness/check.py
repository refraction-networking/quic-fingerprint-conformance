"""Check one implementation against the corpus goldens — the per-repo self-test.

For every corpus case: run the implementation on the input pcap and compare its
canonical records to the golden. A divergence fails the run unless it is a
documented known issue (see ``known_issues``). Exits non-zero on any undocumented
divergence, so it drops straight into a repo's CI.

Usage:
    python -m harness.check                 # default impl: python (self-consistency)
    python -m harness.check --impl go
    python -m harness.check --impl retina -v
"""

from __future__ import annotations

import argparse
import sys

from .compare import compare_records, format_comparison
from .corpus import load_corpus
from .known_issues import known_divergence
from .runners import make_runner

# The golden is produced by the reference impl (pyquicfp), so compare it under
# the name "python" — that lets the known-issue registry's {python, X} entries
# also cover golden-vs-X.
GOLDEN_NAME = "python"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check")
    ap.add_argument("--impl", default="python", choices=("python", "go", "retina"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    cases = load_corpus()
    if not cases:
        print("no corpus cases found (run gen_golden first)", file=sys.stderr)
        return 2

    runner = make_runner(args.impl)
    ok, why = runner.available()
    if not ok:
        print(f"SKIP: implementation '{args.impl}' unavailable: {why}")
        return 0  # unavailable is a skip, not a failure (e.g. retina without DPDK)

    n_pass = n_known = n_fail = 0
    for case in cases:
        try:
            records = runner.run(str(case.input_pcap))
        except Exception as e:
            print(f"[ERROR] {case.name}: {args.impl} runner raised: {e}")
            n_fail += 1
            continue

        cmp = compare_records(case.name, GOLDEN_NAME, case.expected, args.impl, records)
        cmp.impl_a = "golden"  # display only; known-issue matching used GOLDEN_NAME above
        if cmp.ok:
            n_pass += 1
            if args.verbose:
                print(f"[OK] {case.name}")
            continue

        # Re-evaluate known-issue under the reference name, not the display name.
        probe = compare_records(case.name, GOLDEN_NAME, case.expected, args.impl, records)
        reason = known_divergence(probe)
        if reason:
            n_known += 1
            print(f"[KNOWN] {case.name}: {reason.splitlines()[0] if reason else ''}")
            if args.verbose:
                print(format_comparison(cmp, verbose=True))
        else:
            n_fail += 1
            print(f"[FAIL] {case.name}: {args.impl} diverges from golden")
            print(format_comparison(cmp, verbose=True))

    print(
        f"\n{args.impl} vs golden: {n_pass} ok, {n_known} known-issue, {n_fail} FAILED "
        f"({len(cases)} cases)"
    )
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
