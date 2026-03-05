# Validator Liveness v4 (Activation-Gated)

This document describes the v4 validator hardening rules implemented in `selfcoin-core`.

## Scope
- Applies only when activation is enabled and `consensus_version >= 4`.
- Default mainnet behavior is unchanged because activation is disabled by default.

## Admission Rules
- Minimum bond: SCVALREG outputs must meet `validator_min_bond`.
- Cooldown: EXITING validators cannot re-register until `validator_cooldown_blocks` passes.
- Join-rate limit: new registrations per window are capped by:
  - `validator_join_limit_window_blocks`
  - `validator_join_limit_max_new`

## Liveness Accounting
Per finalized block `(height, round)`:
- Determine deterministic committee for that height/round.
- Increment `eligible_count_window` for committee validators.
- Increment `participated_count_window` only for committee members whose signatures are included in the finalized proof.

Only committee eligibility is counted; non-committee validators are not penalized for misses.

## Penalty Ladder
At deterministic window rollover (`height % liveness_window_blocks == 0`):
- Compute `miss_rate = (eligible - participated) / eligible`.
- If miss rate exceeds exit threshold, mark validator `EXITING`.
- Else if miss rate exceeds suspend threshold, mark validator `SUSPENDED` until `height + suspend_duration_blocks`.
- No downtime slashing is applied.

Equivocation slashing remains unchanged and separate.

## Committee/Rewards Interaction
- `SUSPENDED` validators are excluded from active committee selection.
- v4 proposal assembly uses participation-aware reward signer filtering derived from finalized-chain counters.

## Persistence
The validator record persists liveness/suspension counters in DB, so restarts preserve deterministic state progression.
