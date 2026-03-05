# Private Sortition V5 (Activation-Gated)

This document describes the v5 consensus-gated private sortition path implemented in `selfcoin-core`.

## Scope
- Applies only when activation is enabled and `consensus_version >= 5`.
- Default mainnet behavior is unchanged (`activation_enabled=false`).
- Uses a signature-based VRF-like primitive for private eligibility reveal.

## Seed Derivation
- `prev_entropy = compute_finality_entropy_v2(prev_block_id, prev_finality_proof)`
- `seed = sha256d("SC-VRF-SEED-V5" || prev_entropy || u64_le(height) || u32_le(round))`
- Role-separated seeds:
  - proposer: `sha256d("SC-VRF-ROLE-PROPOSER" || seed)`
  - voter: `sha256d("SC-VRF-ROLE-VOTER" || seed)`

Implementation: `src/consensus/sortition_v5.cpp`.

## VRF-like Primitive
- `proof = ed25519_sign(sk, role_seed)`
- `output = sha256d("SC-VRF-OUT-V0" || proof)`
- Verifier checks signature + output derivation.

Implementation: `src/crypto/vrf.cpp`.

## Eligibility Rules
- Proposer eligibility:
  - probability target from `v5_proposer_expected_num / (v5_proposer_expected_den * active_count)`
- Voter eligibility:
  - `k_target = voter_target_k_v5(active_count, round, params)`
  - probability target from `k_target / active_count`
- Round expansion increases voter target deterministically for liveness.

Implementation: `src/consensus/sortition_v5.cpp`, `src/node/node.cpp`.

## Wire Fields (v5 path)
- `PROPOSE` carries `vrf_proof` and `vrf_output`.
- `VOTE` carries `vrf_proof` and `vrf_output`.
- Legacy codec remains valid pre-v5.

Implementation: `src/p2p/messages.hpp`, `src/p2p/messages.cpp`.

## Anti-Spam / Validation
- Reject proposer/voter if not ACTIVE.
- Reject missing/invalid proof.
- Reject eligibility mismatch against deterministic seed/threshold.
- Deduplicate proposer claims per `(height, round, proposer_pubkey)`.
- Vote dedup remains one vote per validator per `(height, round)` in `VoteTracker`.

## Finality Rule in v5
- `k_eff = max(2, min(active_count, voter_target_k_v5(active_count, round, params)))`
- `quorum = floor(2*k_eff/3)+1`
- Count only valid signatures (distinct pubkeys, valid signatures).

Implementation: `src/node/node.cpp::finalize_if_quorum`.

## Liveness Accounting Note
- v4 liveness logic is kept, but in v5 the accounting uses revealed finality participants
  (Option A style) so it remains deterministic without requiring non-participant eligibility reveals.
