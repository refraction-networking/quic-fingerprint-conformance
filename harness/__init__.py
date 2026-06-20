"""Conformance harness for the QUIC/TLS fingerprinters.

Three independent implementations must produce byte-identical fingerprints:
  - pyquicfp        (Python)  github.com/refraction-networking/pyquicfp
  - clienthellod    (Go)      github.com/refraction-networking/clienthellod
  - retina-quic-fp  (Rust)    github.com/refraction-networking/retina-quic-fp

The ``corpus/`` directory is the versioned contract: each case is an input pcap
plus its golden canonical-record output. ``gen_golden`` writes goldens from a
reference implementation; ``check`` verifies one implementation against them
(the per-repo self-test); ``run`` does a full differential comparison of all
selected implementations against each other.
"""
