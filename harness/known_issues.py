"""Documented cross-implementation discrepancies discovered by this harness.

These are *real*, understood divergences between the implementations, not harness
bugs. They are registered here so the conformance run/tests stay green on
already-understood issues while any NEW divergence still stands out as a failure.

Note: in ``check`` (golden-vs-implementation), the golden is produced by the
reference implementation (pyquicfp), so it is compared under the name "python";
an entry whose ``impls`` includes {"python", X} therefore also covers
golden-vs-X.
"""

from __future__ import annotations

# Per-pcap discrepancies. `impls` is the set of implementations the issue
# involves; a comparison matches if both of its implementations are in `impls`.
# `pcaps` matches the corpus case name (the pcap basename without extension) OR
# the raw pcap filename, so the same entry works for the differential run and the
# corpus check.
KNOWN_DISCREPANCIES = [
    {
        "pcaps": {"cloudflare_quiche_0_24_4", "cloudflare_quiche_0_24_4.pcapng"},
        "impls": {"python", "go"},
        "summary": "clienthellod ingests GREASE-version Initials",
        "reason": (
            "quiche sends a GREASE-version probe Initial (version 0xbabababa) "
            "reusing the real connection's DCID. clienthellod's "
            "DecodeQUICHeaderAndFrames does not validate the QUIC version and "
            "decrypts it with v1 keys; its CRYPTO then collides with the real "
            "v1 Initial under the same DCID, so reconstruction fails and "
            "clienthellod produces no fingerprint. pyquicfp rejects unknown "
            "versions (RFC-correct) and fingerprints the real Initial. "
            "Fix: add a version check to clienthellod before deriving v1 keys."
        ),
    },
    {
        "pcaps": {"multi_firefox_149", "multi_firefox_149.pcapng"},
        "impls": {"python", "go", "retina"},
        "summary": "retina fingerprints the pre-Retry Initial of a QUIC Retry flow",
        "reason": (
            "multi_firefox_149 contains a QUIC Retry. The client sends a pre-Retry "
            "Initial (DCID A, no token) and, after the server's Retry, a post-Retry "
            "Initial (DCID B, with token). retina keys by 5-tuple and fingerprints "
            "the pre-Retry Initial; pyquicfp/clienthellod key by DCID and "
            "fingerprint the post-Retry group. The TLS and transport-parameter "
            "fingerprints are identical on both sides; only the QUIC-header "
            "fingerprint differs (dcid_len / token / packet_number_length). A "
            "connection-identification difference (same class as the 5-tuple-vs-"
            "DCID granularity), not a fingerprint disagreement."
        ),
    },
]

# Structural divergence: retina identifies connections by transport 5-tuple
# (FiveTuple), while pyquicfp and clienthellod key by the QUIC DCID. When a
# source reuses a 5-tuple across several QUIC connections (scanners, sequential
# connections from one ephemeral port), retina fingerprints only the first
# handshake per flow and therefore emits a *subset* of the connections — with
# identical fingerprint values. Verified: per-pcap, retina's distinct-fingerprint
# count equals python's "first connection per 5-tuple" count exactly.
RETINA_FLOW_SUBSET_REASON = (
    "retina keys connections by 5-tuple flow while python/go key by QUIC DCID; "
    "retina emits the first handshake per flow (a subset) with identical values. "
    "Connection-granularity difference, not a fingerprint disagreement."
)


def known_divergence(cmp) -> str | None:
    """Return a documented reason if this comparison is a known divergence,
    else None. ``cmp`` is a compare.PcapComparison."""
    pair = {cmp.impl_a, cmp.impl_b}

    # Per-pcap registry.
    for entry in KNOWN_DISCREPANCIES:
        if "pcaps" in entry and cmp.pcap not in entry["pcaps"]:
            continue
        if not pair.issubset(entry["impls"]):
            continue
        return entry["reason"]

    # Structural retina flow-vs-DCID subset: no value conflicts, and retina does
    # not emit anything the DCID-keyed side lacks.
    if "retina" in pair and not cmp.mismatches:
        retina_only = cmp.only_b if cmp.impl_b == "retina" else cmp.only_a
        if not retina_only:
            return RETINA_FLOW_SUBSET_REASON

    return None
