# selfcoin-core Execution Plan

This document turns the current `selfcoin-core` codebase into a concrete product direction:

- narrow deterministic L1 settlement
- explicit validator onboarding
- stronger decentralization
- privacy outside consensus
- anti-abuse in mempool policy

It is written against the current repo layout and runtime:

- UTXO transactions and blocks in `src/utxo/tx.hpp`
- tx validation in `src/utxo/validate.cpp`
- mempool policy in `src/mempool/mempool.cpp`
- validator lifecycle and finalized chain behavior in `src/node/node.cpp`
- validator registry in `src/consensus/validators.hpp` and `src/consensus/validators.cpp`
- state commitments in `src/consensus/state_commitment.cpp`
- keying and signatures in `src/crypto/ed25519.hpp`

This is the recommended path if the goal is to make `selfcoin-core` a serious deterministic settlement layer rather than a protocol experiment.

---

## 1. Protocol boundaries

### Keep inside consensus

- UTXO validity
- block validity
- finalized tip progression
- validator registry state transitions
- slashing evidence
- warmup, active, cooldown, banned, suspended states
- state commitment roots
- proposer eligibility rules

### Keep outside consensus

- Chaumian mint issuance and spend logic
- blind signatures
- wallet coordination for privacy
- relay reputation systems
- Hashcash market logic
- payment batching/aggregation services

### Keep in mempool policy only

- Hashcash stamps
- low-fee spam gating
- source-based tx throttling
- tx scoring that combines fee and work

### Strong recommendation

Do not turn the current chain into a "hash-only" ledger.

The current repo already has the right narrow base:

- UTXO set
- deterministic block/finality flow
- validator registry
- state commitment infrastructure

That should remain the settlement core.

---

## 2. Current repo assessment

### What is already correct

- UTXO model is present and should remain the L1 ledger model.
- Active state is naturally prunable because spent outputs disappear.
- Validator registry lifecycle already exists.
- Deterministic finality already exists.
- State commitment support already exists for UTXO and validator state.
- Ed25519 is already deeply integrated and should remain for now.

### What is currently unsafe or incomplete

- Bootstrap validator onboarding still relies on automatic sponsor behavior in `src/node/node.cpp`.
- Sponsorship/readiness is too trust-heavy and too automatic.
- Join intent is not represented as an explicit on-chain request object.
- Current decentralization model still uses predictable proposer/committee behavior.
- Privacy is not architected yet and must not be forced into L1 consensus naively.
- Anti-abuse policy is still mostly fee-only.

---

## 3. Target architecture

### L1: deterministic settlement core

L1 should do only these jobs:

- validate UTXO spends
- maintain finalized chain state
- maintain validator registry
- enforce slashing/withdrawal rules
- expose cheap verification for full nodes and light clients
- settle deposits and redemptions for external privacy/payment layers

### Privacy subsystem

Recommended model:

- separate Chaumian mint or mint federation
- L1 used only for deposit and redemption settlement
- no private transfer proof system inside L1 consensus in the first production version

### Anti-abuse subsystem

Recommended model:

- Hashcash-style tx stamp
- optional at serialization level
- enforced only by mempool policy

### Validator decentralization subsystem

Recommended model:

- explicit join request and approval
- proof-of-possession for validator key
- persisted join state
- VRF proposer selection first
- keep finality voting simpler initially

---

## 4. Validator onboarding redesign

This is the first production-critical change.

### Current behavior to remove

Legacy/bootstrap logic in `src/node/node.cpp` to remove or constrain:

- ad-hoc peer-driven bootstrap sponsorship
- `bootstrap_joiner_ready_locked(...)`
- any automatic approval submission from node runtime

The unsafe legacy model let the leader automatically approve a connected peer that:

- advertises a validator key
- reaches tip equality
- stays established

That is not production-safe.

### New target flow

1. Joiner creates `SCVALJOINREQ` transaction.
2. `SCVALJOINREQ` includes:
   - validator pubkey
   - proof-of-possession signature by validator private key
   - requested bond amount
   - optional payout/withdraw address
3. Chain records request state.
4. Sponsor or governance actor creates `SCVALAPPROVE` transaction.
5. Approval finalizes on-chain.
6. Warmup begins.
7. Validator becomes active after warmup.

### Required new transaction/script tags

Add new script recognizers in the existing style used by:

- `is_validator_register_script(...)`
- `is_validator_unbond_script(...)`

New tags:

- `SCVALJOINREQ`
- `SCVALAPPROVE`

### Suggested new structs

In `src/utxo/tx.hpp` or a new validator-specific header:

```cpp
struct ValidatorJoinRequestPayload {
  PubKey32 validator_pubkey;
  PubKey32 payout_pubkey;
  std::uint64_t requested_bond{0};
  Sig64 proof_of_possession;
};

struct ValidatorApprovalPayload {
  Hash32 join_request_txid{};
  PubKey32 approver_pubkey;
  Sig64 approval_signature;
};
```

### Required new state

Add persistent join-request state.

Suggested file:

- `src/validator/join_requests.hpp`
- `src/validator/join_requests.cpp`

Suggested states:

- `REQUESTED`
- `APPROVED`
- `PENDING_WARMUP`
- `ACTIVE`
- `EXITING`
- `BANNED`

### Required DB persistence

Persist join request objects and approval state in RocksDB.

This should not remain in-memory only.

### Required CLI support

Add commands in `apps/selfcoin-cli/main.cpp`:

- `create_validator_join_request_tx`
- `create_validator_approval_tx`
- `show_validator_join_requests`

### Required validation changes

Update `src/utxo/validate.cpp` to:

- parse join request script/payload
- verify proof-of-possession
- verify sponsor approval references a real request
- reject duplicate or conflicting approvals

### Required registry changes

Update `src/consensus/validators.cpp` and `src/consensus/validators.hpp` to:

- persist and expose join request metadata
- move validator from requested to approved to pending to active

### Explicit policy

No blind auto-sponsorship of arbitrary peers.

The bootstrap node may still act as sponsor, but only through:

- explicit operator approval
- or an explicit allowlist-based sponsor policy

---

## 5. Decentralization upgrade

### Current weakness

Fully predictable proposer selection makes the next block producer easy to target.

### Recommended smallest upgrade

Adopt VRF proposer selection only.

Keep committee/finality logic mostly as-is during the first decentralization phase.

### Why this is the right upgrade

- biggest security gain for lowest complexity
- preserves deterministic finality flow
- avoids pushing too much new cryptography into the protocol at once

### Current repo starting point

There is already a VRF helper:

- `src/crypto/vrf.hpp`
- `src/crypto/vrf.cpp`

It is currently a research-only Ed25519-signature-based helper and not the active consensus path.

### Target proposer flow

For each slot `(height, round)`:

1. derive transcript from:
   - prior epoch randomness
   - height
   - round
2. proposer computes VRF proof/output
3. block header carries:
   - `vrf_output`
   - `vrf_proof`
4. full nodes verify:
   - proof validity
   - proposer eligibility
   - proposer matches slot selection rule

### Suggested header additions

Extend `BlockHeader` in `src/utxo/tx.hpp`:

```cpp
Hash32 vrf_output{};
Bytes vrf_proof;
```

### Randomness source

Use finalized-chain-derived randomness:

```text
epoch_rand[n+1] = H(epoch_rand[n] || finalized_block_hash || proposer_vrf_output)
```

### New modules

- `src/consensus/randomness.hpp`
- `src/consensus/randomness.cpp`

### Slashing

Implement first:

- double-propose equivocation
- double-vote equivocation

Delay:

- nuanced liveness slashing

### Withdrawal delay

Keep cooldown and delayed withdrawal.

This is already aligned with the current validator lifecycle direction.

---

## 6. Privacy design

### Recommended model

Do not add full private transfers to L1 first.

Use:

- separate Chaumian mint or mint federation
- L1 as settlement for deposits and redemptions only

### Why this fits selfcoin-core

- keeps full node verification cheap
- avoids zk-heavy consensus
- preserves small-node determinism
- gives real user privacy value without bloating L1

### What L1 needs

Minimal chain support only.

Two acceptable options:

1. plain ordinary mint-owned deposit UTXOs
2. lightly tagged deposit outputs

Recommended if you want explicit protocol support:

- add a dedicated deposit tag like `SCMINTDEP`

### What must not go into consensus

- blind-signature issuance
- note redemption logic
- off-chain note spends
- mint double-spend database

### Suggested core modules

- `src/privacy/mint_scripts.hpp`
- `src/privacy/mint_scripts.cpp`

Responsibilities:

- parse/format mint deposit outputs
- wallet helpers for building mint deposits

### What belongs in a separate repo/service

- mint server
- blind signature logic
- reserve accounting
- redemption batching
- federation logic if used

---

## 7. Hashcash anti-abuse plan

### Recommended model

Hashcash is mempool policy only.

Do not make it consensus-critical.

### Where it belongs

- tx serialization: optional extension field
- mempool acceptance policy
- block assembly scoring

### Where it must not belong initially

- block validity
- finalized-state transitions

### Use cases

Require stamps for:

- low-fee transactions
- untrusted peers
- public relay endpoints under pressure

Exempt:

- high-fee transactions
- local wallet submissions
- validator lifecycle txs if desired

### Suggested serialization addition

In `src/utxo/tx.hpp`:

```cpp
struct TxHashcashStamp {
  std::uint32_t version{1};
  std::uint64_t epoch_bucket{0};
  std::uint32_t bits{0};
  std::uint64_t nonce{0};
};
```

Add optional field to `Tx`:

```cpp
std::optional<TxHashcashStamp> hashcash;
```

### Suggested policy module

- `src/policy/hashcash.hpp`
- `src/policy/hashcash.cpp`

### Suggested mempool changes

Update `src/mempool/mempool.cpp`:

- if fee below threshold, verify stamp
- compute required bits from:
  - mempool load
  - tx size
  - peer trust
  - fee credit

### Verification goal

Verification must remain cheap:

- recompute preimage hash
- count leading zero bits

---

## 8. Keep Ed25519 for now

Do not switch to `secp256k1` right now.

Why:

- Ed25519 is already used throughout the repo
- validator keys, votes, tx signatures, slash evidence, and keystore all depend on it
- changing curves now would touch almost every consensus-critical path

Possible future reason to revisit:

- ecosystem wallet interoperability
- Bitcoin-style tooling alignment

But it should not block protocol work.

---

## 9. Concrete file-level plan

### Files to change first

- `src/utxo/tx.hpp`
- `src/utxo/validate.cpp`
- `src/utxo/signing.cpp`
- `src/consensus/validators.hpp`
- `src/consensus/validators.cpp`
- `src/node/node.cpp`
- `src/mempool/mempool.cpp`
- `apps/selfcoin-cli/main.cpp`

### New files to add

- `src/validator/join_requests.hpp`
- `src/validator/join_requests.cpp`
- `src/policy/hashcash.hpp`
- `src/policy/hashcash.cpp`
- `src/consensus/randomness.hpp`
- `src/consensus/randomness.cpp`
- `src/privacy/mint_scripts.hpp`
- `src/privacy/mint_scripts.cpp`

### Responsibilities

`src/validator/join_requests.*`
- join request parsing
- approval tracking
- persistence helpers

`src/policy/hashcash.*`
- stamp parsing
- difficulty calculation
- verification helpers

`src/consensus/randomness.*`
- epoch randomness accumulation
- proposer transcript derivation

`src/privacy/mint_scripts.*`
- minimal mint settlement output support

---

## 10. Rollout order

### Phase 1: safety and operational correctness

Implement first:

- explicit validator join request
- sponsor approval tx
- proof-of-possession
- persistent join request state
- remove automatic sponsorship path

This is the most important production safety improvement.

### Phase 2: anti-abuse

Implement:

- optional Hashcash stamp
- mempool-only enforcement
- fee + work scoring

This protects nodes without changing consensus.

### Phase 3: decentralization

Implement:

- VRF proposer selection
- epoch randomness accumulator
- block header VRF fields
- proposer verification

Delay VRF committees until proposer VRF is stable.

### Phase 4: privacy integration

Implement:

- mint deposit scripts
- wallet deposit helpers
- separate mint service
- redemption support

Keep private transfers outside L1 consensus.

### Phase 5: later hardening

Implement:

- equivocation slashing improvements
- explicit withdrawal delay enforcement review
- archival/pruned/light client UX improvements
- optional allowlist/governance tooling

---

## 11. Direct recommendation

If this repo is going to become a real protocol, implement these three things first:

1. Replace bootstrap auto-sponsorship with explicit join-request + approval + proof-of-possession.
2. Add mempool-only Hashcash.
3. Add VRF proposer selection.

That sequence gives the highest return in:

- security
- decentralization
- operational realism

without turning `selfcoin-core` into a bloated research protocol.
