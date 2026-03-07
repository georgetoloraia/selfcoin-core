## Runtime Consensus

The active SelfCoin runtime follows one fixed consensus path.

- Proposer path: deterministic leader selection from finalized chain state.
- Committee path: deterministic committee selection from finalized chain state.
- Vote rule: only committee members vote; votes are tracked per `(height, round, block_id)`.
- Quorum rule: `quorum_threshold(committee.size())`.
- Validation semantics: transaction and block validation use the current validator/bond rules, including variable validator bond bounds.
- Finality artifact: finalized blocks still embed `Block.finality_proof`, and the runtime now also persists a separate raw-signature `FinalityCertificate` for the same finalized quorum result.
- Execution scope: no VM, no general-purpose smart contracts, and no application-layer execution in the base layer.
- Base-layer script scope: P2PKH plus the existing validator register, validator unbond, and slash-burn settlement forms.

Research helpers such as VRF utilities and `sortition_v2` experiments are not part of the active runtime path.
This document describes the shipped runtime behavior, not older development-era consensus experiments.

## Finality Certificates

The current runtime exposes finality in two compatible forms:

- embedded `Block.finality_proof` inside finalized block data
- separate persisted `FinalityCertificate` objects built from the same finalized quorum signatures

The current certificate implementation is conservative:

- raw committee member list, not a separate committee hash commitment
- raw signatures, not aggregated signatures
- persisted and exposed through lightserver for finalized blocks

The following are intentionally deferred:

- header commitment of certificate bytes
- aggregated-signature cryptography
- standalone P2P certificate distribution

## Snapshot Tooling

Snapshot export/import exists as implementation-first operational tooling, not as a new consensus or sync mode.

Current properties:

- deterministic export/import of finalized-state DB content
- empty-DB-only import
- export expected from a stopped or otherwise quiescent DB

Current non-properties:

- not trust-minimized fast sync
- not protocol-grade checkpoint verification
- not incremental synchronization
- not a live-export guarantee
