# Interoperability Specification (v1.0.0)

## Scope
This spec defines wire-level and negotiation behavior for SSK runtime interoperability.

## Wire Format (Canonical CBOR Profile)
- Transport payloads MUST use canonical CBOR encoding.
- Decoder default mode is strict; non-canonical encodings are rejected.
- Ambiguous encodings are forbidden:
  - non-minimal integer representations,
  - duplicate map keys,
  - trailing bytes after one canonical payload,
  - out-of-order map key encodings.
- Implementations MUST re-encode decoded payloads and compare bytes in strict mode.

## Version Negotiation
- Protocol version format: SemVer `major.minor.patch`.
- Current protocol: `1.0.0`.
- Minimum compatible: `1.0.0`.
- Compatibility rules:
  1. `major` MUST match.
  2. Peer protocol MUST be `>= min_supported`.
  3. Local current protocol MUST be `>= peer.min_compatible`.

## Capability Negotiation
- Capabilities are lowercase machine strings (`[a-z0-9_-]+`) with no duplicates.
- Required baseline capabilities:
  - `gate-vector-12`
  - `replay-v1`
- Negotiated set is capability intersection after validation.

## Error Codes
- `VersionIncompatible`
- `CapabilityMismatch`
- `StrictModeRequired`
- `ClockOutOfRange`
- `NonCanonicalEncoding`
- `DecodeRejected`

All errors MUST be machine-readable and accompanied by human diagnostics and next-step guidance.

## Determinism Rules
- Handshake includes deterministic seed and clock epoch.
- Strict mode is mandatory for production negotiation.
- Determinism-sensitive fields (`run_id`, `replay_id`, `seeded`, `epoch`) MUST be logged in structured events.

## Reference Implementation
- Crate: `/crates/ssk-interop`
- API:
  - `HandshakeRequest` / `HandshakeResponse`
  - `CompatibilityPolicy::evaluate`
  - `encode_canonical`, `decode_strict`, `decode_with_mode`
