# Weighted Private Sortition V6 (Activation-Gated)

PR6 adds stake/bond-weighted private sortition on top of v5 transcript-bound VRF-like proofs.

## Scope
- Active only when activation is enabled and `consensus_version >= 6`.
- Default mainnet behavior is unchanged (`activation_enabled=false`).

## Weight Derivation
- Weight source: validator bonded amount in registry state.
- Units:
  - `units = floor(bonded_amount / v6_bond_unit)`
  - clamped to `v6_units_max`
  - zero units => never eligible
- Active-only: only ACTIVE non-suspended validators are counted in total weight.

Implementation:
- `src/consensus/validators.cpp::validator_weight_units_v6`
- `src/consensus/validators.cpp::total_active_weight_units_v6`

## Eligibility Rule (Option 2 threshold scaling)
- Keep v5 private proof flow and transcript binding.
- For role-specific expected target `(expected_num / expected_den)`:
  - `p_i = (expected_num * validator_weight) / (expected_den * total_weight)`
- A validator is eligible if VRF output falls below this probability threshold.

Implementation:
- `src/consensus/sortition_v6.cpp::threshold_weighted_v6`
- `src/consensus/sortition_v6.cpp::eligible_weighted_v6`

## Round Expansion
- Voter target expands by round using deterministic doubling:
  - `k(round) = min(active_count, k0 * factor^min(round, cap))`
- Quorum remains count-based (`floor(2k/3)+1`) in v6.

Implementation:
- `src/consensus/sortition_v6.cpp::voter_target_k_v6`
- `src/node/node.cpp::finalize_if_quorum`

## Notes
- No new cryptography in PR6; VRF-like primitive remains signature-based from v5.1.
- This approximates stake-weighted lottery behavior while keeping wire format unchanged.
