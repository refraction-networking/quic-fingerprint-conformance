"""Canonical record schema helpers shared by the conformance harness.

Every implementation is normalised to the same canonical record (see
pyquicfp.fingerprint.CanonicalRecord.to_dict). This module provides JSONL
loading, a structural diff, and a converter from retina's native offline output
to the canonical schema.
"""

from __future__ import annotations

import json
from typing import Any

# Top-level fingerprint hashes present in every canonical record.
HASH_KEYS = ("quic_header_fp", "tls_fp", "qtp_fp", "super_fp")


def load_jsonl(text: str) -> list[dict]:
    """Parse newline-delimited JSON into a list of records."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def key_by_conn(records: list[dict]) -> dict[str, dict]:
    """Index records by conn_key (falling back to super_fp when absent)."""
    out: dict[str, dict] = {}
    for rec in records:
        key = rec.get("conn_key") or rec.get("super_fp", "")
        out[key] = rec
    return out


def deep_diff(a: Any, b: Any, path: str = "") -> list[tuple[str, Any, Any]]:
    """Return ``(path, a_value, b_value)`` for every leaf where ``a`` and ``b``
    differ. ``conn_key`` is ignored (it is the join key, not a fingerprint field).
    """
    diffs: list[tuple[str, Any, Any]] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k == "conn_key" and path == "":
                continue
            sub = f"{path}.{k}" if path else k
            diffs.extend(deep_diff(a.get(k, _MISSING), b.get(k, _MISSING), sub))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append((path, a, b))
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                diffs.extend(deep_diff(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            diffs.append((path, a, b))
    return diffs


class _Missing:
    def __repr__(self):
        return "<missing>"


_MISSING = _Missing()


# ── retina offline output → canonical ─────────────────────────────────────────


def _hex8(byte_list: list[int]) -> str:
    return bytes(byte_list[:8]).hex()


def _decode_compress_certificate(raw: list[int]) -> list[int]:
    # retina stores the raw ext-27 body: [byte-length][u16 algos...].
    if not raw:
        return []
    algos = raw[1:]
    return [
        (algos[i] << 8) | algos[i + 1] for i in range(0, len(algos) - 1, 2)
    ]


def retina_record_to_canonical(obj: dict) -> dict:
    """Convert one retina FileData JSON object to a canonical record.

    retina's offline output has no per-connection key, so conn_key is left empty;
    the comparator aligns retina records by super_fp.
    """
    qh = obj["quic_header"]
    tls = obj["tls"]
    qtp = obj["qtp"]
    return {
        "conn_key": "",
        "quic_header_fp": _hex8(obj["quic_header_fp"]),
        "tls_fp": _hex8(obj["tls_fp"]),
        "qtp_fp": _hex8(obj["qtp_fp"]),
        "super_fp": _hex8(obj["super_fp"]),
        "quic_header": {
            "version": qh["version"],
            "dcid_len": qh["dcid_len"],
            "scid_len": qh["scid_len"],
            "packet_number_length": qh["packet_number_length"],
            "sorted_unique_frames": qh["sorted_unique_frames"],
            "token_presence": qh["token_presence"],
        },
        "tls": {
            "version": tls["version"],
            "cipher_suites": tls["cipher_suites"],
            "compression_methods": tls["compression_algs"],
            "extensions_sorted": tls["extension_list"],
            "named_groups": tls["named_groups"],
            "ec_point_formats": tls["ec_point_formats"],
            "signature_algorithms": tls["signature_algs"],
            "alpn": tls["alpn_protocols"],
            "key_share": tls["key_share"],
            "psk_key_exchange_modes": tls["psk_exchange_modes"],
            "supported_versions": tls["supported_versions"],
            "cert_compression_algs": _decode_compress_certificate(
                tls.get("compress_certificate", [])
            ),
            "record_size_limit": tls.get("record_size_limit"),
        },
        "qtp": {
            "parameter_ids": qtp["parameter_ids"],
            "max_idle_timeout": qtp["max_idle_timeout"],
            "max_udp_payload_size": qtp["max_udp_payload_size"],
            "initial_max_data": qtp["initial_max_data"],
            "initial_max_stream_data_bidi_local": qtp[
                "initial_max_stream_data_bidi_local"
            ],
            "initial_max_stream_data_bidi_remote": qtp[
                "initial_max_stream_data_bidi_remote"
            ],
            "initial_max_stream_data_uni": qtp["initial_max_stream_data_uni"],
            "initial_max_streams_bidi": qtp["initial_max_streams_bidi"],
            "initial_max_streams_uni": qtp["initial_max_streams_uni"],
            "ack_delay_exponent": qtp["ack_delay_exponent"],
            "max_ack_delay": qtp["max_ack_delay"],
            "active_connection_id_limit": qtp["active_connection_id_limit"],
        },
    }
