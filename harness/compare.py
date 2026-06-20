"""Align and compare canonical records from two implementations.

Records are aligned by ``conn_key`` (the DCID hex emitted by pyquicfp and the Go
runner). When one side lacks conn_keys (retina's offline output), alignment falls
back to ``super_fp``. Each shared connection is then diffed field-by-field so a
mismatch points at the exact diverging field, not just "something differs".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schema import deep_diff


@dataclass
class ConnDiff:
    key: str
    diffs: list[tuple[str, object, object]]  # (path, value_a, value_b)


@dataclass
class PcapComparison:
    pcap: str
    impl_a: str
    impl_b: str
    only_a: list[str] = field(default_factory=list)
    only_b: list[str] = field(default_factory=list)
    mismatches: list[ConnDiff] = field(default_factory=list)
    matched: int = 0

    @property
    def ok(self) -> bool:
        return not self.only_a and not self.only_b and not self.mismatches


def _choose_key(records: list[dict]) -> str:
    """Pick the join field: conn_key if every record has a distinct one, else
    super_fp."""
    keys = [r.get("conn_key", "") for r in records]
    if all(keys) and len(set(keys)) == len(keys):
        return "conn_key"
    return "super_fp"


def _index(records: list[dict], key_field: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in records:
        out[r.get(key_field, "")] = r
    return out


def compare_records(
    pcap: str,
    impl_a: str,
    records_a: list[dict],
    impl_b: str,
    records_b: list[dict],
) -> PcapComparison:
    # Prefer conn_key, but only if BOTH sides supply usable conn_keys.
    field_a = _choose_key(records_a)
    field_b = _choose_key(records_b)
    key_field = "conn_key" if field_a == "conn_key" and field_b == "conn_key" else "super_fp"

    idx_a = _index(records_a, key_field)
    idx_b = _index(records_b, key_field)

    cmp = PcapComparison(pcap=pcap, impl_a=impl_a, impl_b=impl_b)
    cmp.only_a = sorted(set(idx_a) - set(idx_b))
    cmp.only_b = sorted(set(idx_b) - set(idx_a))

    for key in sorted(set(idx_a) & set(idx_b)):
        diffs = deep_diff(idx_a[key], idx_b[key])
        if diffs:
            cmp.mismatches.append(ConnDiff(key=key, diffs=diffs))
        else:
            cmp.matched += 1
    return cmp


def format_comparison(cmp: PcapComparison, verbose: bool = False) -> str:
    lines = []
    status = "OK" if cmp.ok else "MISMATCH"
    lines.append(
        f"[{status}] {cmp.pcap}: {cmp.impl_a} vs {cmp.impl_b} "
        f"(matched={cmp.matched}, only_{cmp.impl_a}={len(cmp.only_a)}, "
        f"only_{cmp.impl_b}={len(cmp.only_b)}, mismatched={len(cmp.mismatches)})"
    )
    if cmp.ok and not verbose:
        return lines[0]
    for k in cmp.only_a:
        lines.append(f"    only in {cmp.impl_a}: {k}")
    for k in cmp.only_b:
        lines.append(f"    only in {cmp.impl_b}: {k}")
    for md in cmp.mismatches:
        lines.append(f"    conn {md.key}:")
        for path, va, vb in md.diffs:
            lines.append(f"        {path}: {cmp.impl_a}={va!r}  {cmp.impl_b}={vb!r}")
    return "\n".join(lines)
