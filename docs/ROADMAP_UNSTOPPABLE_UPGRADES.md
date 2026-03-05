# SelfCoin Upgrade Roadmap (Mainnet-Only)

This repository now runs a single network mode: `mainnet`.
All future protocol evolution must be activation-gated on mainnet.

## Rules
- Keep chain identity, genesis marker checks, serialization, txid, and block_id stable.
- No privileged admin keys/endpoints.
- New rules are introduced only behind activation windows and explicit versioning.

## Activation Foundation
- Activation framework lives in `src/consensus/activation.hpp` and `src/consensus/activation.cpp`.
- Node wiring is in `src/node/node.cpp` (`apply_activation_signal`, persisted activation state).
- Mainnet defaults are conservative:
  - `activation_enabled = false`
  - `initial_consensus_version = 1`
  - `max_consensus_version = 4`

## Upgrade Path
1. Enable activation parameters in a planned release (window/threshold/delay).
2. Introduce new consensus/data features behind version gates.
3. Activate only after finalized-window signaling meets threshold.
4. Keep backward-unsafe behavior rejected pre-activation.

## PR2 Status: Random Public Sortition (v2, Activation-Gated)
- Implemented in consensus helpers:
  - `compute_finality_entropy_v2`
  - `make_sortition_seed_v2`
  - `committee_size_v2` (adaptive for small validator sets)
  - `select_committee_v2`
  - `select_leader_v2`
- Node integration is gated by activation version:
  - v1 path remains default when activation is disabled or `cv < 2`
  - v2 path is used only when activation is explicitly enabled and `cv >= 2`
- Round fallback in v2 is deterministic:
  - committee size expands by round on stalls (doubling until active set cap),
    so offline committee members are tolerated without non-determinism.
- Mainnet remains safe by default:
  - activation is disabled unless operator passes override flags.

## PR3 Status: Proof-Carrying Light Clients (v3, Activation-Gated)
- Added deterministic state commitments:
  - UTXO commitment root
  - Validator registry commitment root
- Roots are committed in v3 blocks via coinbase marker `:r3=<utxo_root><validators_root>`
  and validated during propose/finalize handling.
- Added Sparse Merkle proof serving in lightserver:
  - `get_header_range`
  - `get_roots`
  - `get_utxo_proof`
  - `get_validator_proof`
- Added SDK proof verifier utilities:
  - SMT proof verification
  - finality proof quorum/signature verification helper
- Default mainnet behavior remains unchanged while activation is disabled.

## PR4 Status: Admission + Liveness Hardening (v4, Activation-Gated)
- Added v4-gated validator admission controls:
  - minimum bond
  - re-join cooldown for exiting validators
  - deterministic join-rate window limits
- Added deterministic liveness accounting:
  - counts only committee eligibility and finality-proof participation
  - applies suspend/exit ladder on window rollover
  - no downtime slashing (equivocation slashing remains separate)
- Added participation-aware reward signer filtering for v4 proposal assembly.
- Mainnet default remains unchanged while activation is disabled (`cv=1`).

## PR4.1 Status: Consensus Edge Hardening
- Locked v4 liveness to a single epoch boundary model:
  - count finalized block participation first, then evaluate/reset exactly at epoch boundary.
- Added finalized-only join window helper usage in node and replay-focused tests.
- Hardened liveness participation derivation with a shared helper:
  - signature order independent
  - duplicate signer pubkeys deduplicated
  - only committee members count.
- Fixed validator commitment encoding gap with consensus-version gating:
  - v3 commitment bytes ignore v4-only fields
  - v4 commitment bytes include v4 liveness/suspension fields.

## PR5 Status: Private Sortition (v5, Activation-Gated)
- Added signature-based VRF-like primitive and v5 sortition helpers.
- Added role-separated proposer/voter seeds derived from finalized entropy.
- Extended `PROPOSE` and `VOTE` payloads with v5 proof/output fields (legacy decoding preserved).
- Added v5 proposer/voter eligibility verification path in node handling.
- Added v5 quorum target (`k_eff`) with round-based expansion for liveness.
- Mainnet defaults remain unchanged because activation is disabled by default.

## Candidate Upgrades
- Unpredictable committee sortition (VRF-based).
- Proof-carrying light client verification.
- Incentive/liveness hardening.
- Batch-settlement primitives.
- Wallet safety improvements.

## Operational Guidance
- Treat activation changes like consensus changes: staged rollout, audits, and long lead time.
- Prefer test harness validation before enabling any mainnet activation switch.
