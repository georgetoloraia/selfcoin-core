# Adversarial Runtime Hardening

## Threat Model

The active SelfCoin runtime is exposed to:

- malformed or oversized P2P frames and payloads
- repeated invalid proposals, votes, blocks, and transactions
- peer-driven CPU amplification through repeated parse and signature work
- memory growth through duplicate junk and per-round object churn
- asymmetric lightserver requests that ask for very large historical ranges

This hardening pass preserves the fixed deterministic runtime:

- deterministic proposer selection
- deterministic committee selection
- committee-membership voting
- quorum from committee size
- current validator/bond validation semantics

## Implemented Protections

- Bounded P2P message decoding for software version strings, proposal payloads, block payloads, transaction payloads, vote proofs, and address batches.
- Explicit rejection of unknown P2P message types.
- Recent invalid-payload suppression in the node so repeated malformed or previously rejected payloads do not re-trigger the same expensive path.
- Recent accepted TX/PROPOSE/BLOCK payload suppression to avoid repeated full processing of identical objects.
- Negative vote-signature cache so repeated bad votes do not keep re-running Ed25519 verification.
- Additional per-peer rate limits for `GET_BLOCK`, `GET_FINALIZED_TIP`, `GETADDR`, and `ADDR`.
- Lightserver HTTP header/body caps.
- Lightserver batch caps for `get_headers` and `get_header_range`.

## Preserved Runtime Semantics

None of the hardening changes alter:

- proposer legality
- committee membership
- vote eligibility
- quorum rules
- validator/bond validation rules
- lightserver RPC meaning for valid bounded requests

## Remaining Gaps

- The lightserver still does full DB-backed work for some valid single-object queries; this pass only bounds request size and obvious batch asymmetry.
- P2P processing still happens inline on the node thread; caches and budgets reduce amplification, but a fuller staged work scheduler would be a larger change.
- State-commitment proof paths remain intentionally unchanged because they affect externally visible proof/root behavior.

## Test And Runtime Stability Note

- A recurring late-run full-suite crash was traced to local-bus teardown in test/runtime plumbing, where queued vote delivery could outlive node shutdown and reach DB-backed code after close.
- The conservative fix aligned local-bus vote delivery with the same shutdown guard used for peer-originated traffic and tightened teardown ordering.
- This was a stability/lifetime issue, not a change in deterministic consensus behavior.

## Future Work

- global per-tick validation budgets across peers
- explicit invalid proposal/block ID caches keyed after cheap structural parsing
- inbound connection churn budgets by source subnet
- lightserver hot-response caching for repeated committee/root/header queries
