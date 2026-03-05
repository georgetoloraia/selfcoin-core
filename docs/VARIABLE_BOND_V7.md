# Variable Bond V7 (Activation-Gated)

PR7 introduces variable validator bond amounts and effective weight capping for weighted private sortition.

## Scope
- Active only when activation is enabled and `consensus_version >= 7`.
- Default mainnet behavior is unchanged when activation is disabled.

## Registration Rules
For `cv >= 7`, SCVALREG output value must satisfy:
- `v7_min_bond_amount <= bond_amount <= v7_max_bond_amount`

For `cv < 7`, legacy fixed-bond rule remains:
- `bond_amount == BOND_AMOUNT`

## Weight Derivation
- Raw units (from PR6):
  - `raw_units = floor(bond_amount / v6_bond_unit)` clamped by `v6_units_max`
- V7 effective cap:
  - `effective_units = min(raw_units, v7_effective_units_cap)`

The effective units are used for `cv >= 7` sortition threshold calculations.

## Deterministic Timing
- Bond amount is set at SCVALREG apply in finalized block processing.
- Weight becomes relevant once validator is ACTIVE (after warmup).
- Non-ACTIVE validators contribute zero effective weight.

## Replay Safety
- Bonded amount is persisted in validator DB records.
- Legacy records without explicit bonded amount default deterministically to `BOND_AMOUNT`.
