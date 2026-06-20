"""Load conformance corpus cases — the versioned contract.

A case is a directory under ``corpus/``::

    corpus/<name>/
        input.pcap      (or input.pcapng)   the fixed input
        expected.json   the golden: a JSON array of canonical records
        meta.json       (optional) provenance: source, reference impl, grease mode

Inputs are pcaps because all three runners consume pcaps; the L2-L4 framing does
not affect the QUIC/TLS fingerprint. The golden is the canonical-record list the
reference implementation produces (see ``gen_golden``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


@dataclass
class Case:
    name: str
    input_pcap: Path
    expected: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def find_input_pcap(case_dir: Path) -> Path:
    for name in ("input.pcap", "input.pcapng"):
        p = case_dir / name
        if p.exists():
            return p
    pcaps = sorted(p for p in case_dir.glob("*.pcap*"))
    if pcaps:
        return pcaps[0]
    raise FileNotFoundError(f"no input pcap in {case_dir}")


def load_case(case_dir: Path, name: str | None = None) -> Case:
    expected_path = case_dir / "expected.json"
    expected = json.loads(expected_path.read_text()) if expected_path.exists() else []
    meta_path = case_dir / "meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    return Case(
        name=name or case_dir.name,
        input_pcap=find_input_pcap(case_dir),
        expected=expected,
        meta=meta,
    )


def load_corpus(corpus_dir: Path = CORPUS_DIR) -> list[Case]:
    """Discover cases by walking for ``expected.json`` markers, so the corpus
    can be flat or nested without the harness caring. The case name is the path
    relative to ``corpus/`` (e.g. ``chrome_148`` or ``chrome/chrome_148``)."""
    if not corpus_dir.is_dir():
        return []
    cases = []
    for expected in sorted(corpus_dir.rglob("expected.json")):
        d = expected.parent
        cases.append(load_case(d, name=str(d.relative_to(corpus_dir))))
    return cases


def dump_expected(records: list[dict]) -> str:
    """Serialize golden records stably: sorted by conn_key then super_fp, with
    sorted keys and 2-space indent, so git diffs are minimal and reviewable."""
    ordered = sorted(records, key=lambda r: (r.get("conn_key", ""), r.get("super_fp", "")))
    return json.dumps(ordered, indent=2, sort_keys=True) + "\n"
