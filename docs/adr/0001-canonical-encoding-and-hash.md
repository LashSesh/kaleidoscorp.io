# ADR 0001: Canonical Encoding and Hash Default

## Decision
Use canonical CBOR (`ciborium`) for persisted canonical encoding and BLAKE3 as default content hash. Provide `HashAlg::Sha256` mapping as compatibility option.

## Rationale
Canonical CBOR gives deterministic binary form for replay and content-addressed IDs. BLAKE3 is fast and suitable for frequent runtime hashing.

## Consequences
IDs and hash-chains are deterministic and efficient by default. Cross-system SHA-256 compatibility remains available.
