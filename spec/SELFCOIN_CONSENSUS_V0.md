# SelfCoin Consensus v0 (PoCT-BFT)
Version: 0.1
Status: Draft (implementation-targeted)
Last updated: 2026-03-01

## 0. Purpose

SelfCoin v0 defines a permissionless blockchain with:
- UTXO transactions (Bitcoin-like model, simplified)
- Validator quorum finality (BFT-style finality)
- Fixed validator bond (Sybil resistance) without stake-weighted power
- Deterministic leader selection per height/round based on finalized chain state
- Slashing for provable equivocation (double-sign)

Core philosophy:
Security rewards time spent in transparent confirmation (online, correct signing), not hash-burning or capital dominance.

---

## 1. Cryptography

### 1.1 Hash function
- `H(x)` = SHA-256(SHA-256(x)) (double SHA-256)
- Output: 32 bytes

### 1.2 Signatures
- Scheme: Ed25519
- Public key: 32 bytes
- Signature: 64 bytes
- Message signed: `block_id` (32 bytes), as defined in §4.2

Rationale: deterministic, fast, widely supported, small keys.

### 1.3 Merkle tree
- Leaves: `H(tx_bytes)` for each tx in block order.
- Parent: `H(left || right)`
- If odd number of nodes at a level: duplicate the last node (Bitcoin rule).
- Merkle root of empty tx list is invalid (blocks MUST contain at least 1 tx, the coinbase).

---

## 2. Serialization & Encoding (Critical)

All multi-byte integers are **little-endian** unless explicitly noted.

### 2.1 Primitive types
- `u8`  : 1 byte
- `u16` : 2 bytes LE
- `u32` : 4 bytes LE
- `u64` : 8 bytes LE
- `bytes[N]`: exactly N bytes
- `varbytes`: `varint length` followed by that many bytes
- `varint`: unsigned LEB128 (u64 range)

#### 2.1.1 varint (ULEB128)
- Encode u64 using base-128 continuation bytes:
  - lower 7 bits per byte
  - MSB=1 indicates continuation
  - MSB=0 last byte
- Must be minimally encoded (no leading zero groups).

### 2.2 Canonical encoding rules
- No alternative encodings are valid.
- No trailing bytes allowed after parsing a structure.
- All hashes and IDs are raw bytes; when displayed, use lowercase hex (not part of consensus).

---

## 3. Transactions (UTXO)

### 3.1 Transaction format
`Tx` serialized as:

- `u32 version` (currently 1)
- `varint input_count`
- inputs...
- `varint output_count`
- outputs...
- `u32 lock_time` (currently 0; reserved)

#### 3.1.1 TxIn
- `bytes[32] prev_txid` (little-endian tx hash bytes as stored; do not reverse)
- `u32 prev_index`
- `varbytes script_sig`
- `u32 sequence` (set to 0xFFFFFFFF for v0)

#### 3.1.2 TxOut
- `u64 value` (smallest unit: "satoshi-like" base unit)
- `varbytes script_pubkey`

### 3.2 Script system (v0 minimal)
SelfCoin v0 supports ONLY one output type for spendable outputs:

#### 3.2.1 P2PKH-like (Pay to PubKey Hash)
- `pubkey_hash = H160(pubkey)` where:
  - `H160(x) = RIPEMD160(SHA256(x))`
- Note: H160 is used only for address encoding and script hashing; signature uses Ed25519.

**script_pubkey (P2PKH) format (exact bytes):**
- `OP_DUP`        = 0x76
- `OP_HASH160`    = 0xA9
- `PUSH_20`       = 0x14
- `bytes[20] pubkey_hash`
- `OP_EQUALVERIFY`= 0x88
- `OP_CHECKSIG`   = 0xAC

So: `76 A9 14 <20B> 88 AC`

**script_sig format (exact bytes):**
- `PUSH_64` = 0x40
- `bytes[64] signature`
- `PUSH_32` = 0x20
- `bytes[32] pubkey`

So: `40 <64B sig> 20 <32B pubkey>`

Notes:
- Pubkey is Ed25519 32-byte pubkey.
- No DER. No variable signature sizes. Fixed-size only.
- Any deviation is invalid.

### 3.3 Signature digest (what is signed)
For each input i, compute `sighash_msg`:

`signing_tx = Tx with:`
- All inputs same as original EXCEPT:
  - For input i: script_sig set to empty varbytes (length=0)
  - For all other inputs: script_sig set to empty varbytes
- Outputs unchanged
- lock_time unchanged

Then:
`msg = H( "SC-SIG-V0" || u32_le(i) || H(signing_tx_bytes) )`

Where:
- `"SC-SIG-V0"` is ASCII bytes: 9 bytes
- `i` is input index
- `signing_tx_bytes` is canonical Tx serialization

Validator must verify signature over `msg` using the pubkey provided in script_sig.

### 3.4 TxID
`txid = H(tx_bytes)`

---

## 4. Blocks

### 4.1 Block format
A `Block` is serialized as:
- `BlockHeader header`
- `varint tx_count`
- `Tx[tx_count] transactions`
- `FinalityProof finality_proof` (may be empty for non-finalized propagation; see §6)

Blocks MUST have `tx_count >= 1` and first tx MUST be coinbase.

### 4.2 Block header
`BlockHeader` serialized as:
- `bytes[32] prev_finalized_hash`
- `u64 height`
- `u64 timestamp` (unix seconds)
- `bytes[32] merkle_root`
- `bytes[32] leader_pubkey`
- `u32 round`

### 4.3 Block ID
`block_id = H( "SC-BLOCK-V0" || header_bytes )`
Where:
- `"SC-BLOCK-V0"` is ASCII bytes: 11 bytes
- `header_bytes` is canonical BlockHeader serialization

Note: merkle_root is already in header.

### 4.4 Coinbase transaction (issuance)
Coinbase tx rules:
- Has `input_count = 1`
- Its single input must have:
  - `prev_txid = 32 bytes of 0x00`
  - `prev_index = 0xFFFFFFFF`
  - `script_sig = varbytes arbitrary <= 100 bytes` (for entropy / memo)
  - `sequence = 0xFFFFFFFF`
- Outputs define reward distribution.

Coinbase value:
- `block_reward(height)` + total_fees
- v0 block_reward schedule:
  - Fixed reward: `R = 50 * 10^8` base units (placeholder)
  - Halving schedule is out of scope for v0; can be constant in v0 testnet.

Reward split suggestion (not consensus-critical if coinbase outputs satisfy total):
- 40% to leader payout address
- 60% split equally among signers included in finality proof (or to a single "signer pool" address in v0)

NOTE: The exact split SHOULD be consensus-defined eventually. For v0, only enforce:
`sum(coinbase_outputs.value) == block_reward(height) + fees`

---

## 5. Validator Set & Bond

### 5.1 Validator identity
A validator is identified by:
- `validator_pubkey` (Ed25519 pubkey, 32 bytes)

### 5.2 Fixed bond (Sybil resistance)
To become ACTIVE, a validator must create a bond UTXO:
- value = `BOND_AMOUNT` (protocol constant)
- output script is a special bond script (v0)

#### 5.2.1 Bond script (v0 placeholder)
To avoid designing full covenant scripts in v0, implement bond registration as:
- A special `REGISTER_VALIDATOR` transaction type recognized by consensus:
  - defined by a dedicated `script_pubkey` prefix.

**REGISTER output script_pubkey format:**
- Prefix bytes: ASCII `"SCVALREG"` (8 bytes)
- Followed by `bytes[32] validator_pubkey`

So script_pubkey = `53 43 56 41 4C 52 45 47 <32B pubkey>`
(That's ASCII bytes for SCVALREG)

Rules:
- A tx output with this script_pubkey is a validator bond output.
- The output value must equal `BOND_AMOUNT`.
- The validator becomes PENDING at inclusion, ACTIVE after warmup.

This is not a general smart contract; it is a consensus-recognized special output.

### 5.3 Validator lifecycle
- `PENDING`: registered but not eligible to sign (warmup)
- `ACTIVE`: eligible in leader selection and quorum
- `BANNED`: removed due to equivocation; cannot rejoin until re-register with new key

Protocol constants:
- `WARMUP_BLOCKS` (e.g., 100)
- `BOND_AMOUNT` (e.g., 1000 * 10^8 units on testnet; tune later)

---

## 6. Consensus: Proposal, Voting, Finality

### 6.1 Definitions
- `finalized_tip`: the highest finalized block (height, hash)
- Nodes only extend from finalized_tip.

### 6.2 Leader selection
Let `V` be the ACTIVE validator set at the start of height `h`, sorted ascending by `validator_pubkey` bytes.

Leader index:
`leader_index = (u64_from_le_bytes(H(prev_finalized_hash || u64_le(h) || u32_le(round))[0..8])) % |V|`

Leader pubkey:
`leader_pubkey = V[leader_index].pubkey`

Round starts at 0 for each height.

### 6.3 Messages (p2p logical types)
All messages are length-prefixed frames:
- `u32 magic` = 0x53434F49 ("SCOI" ASCII) LE
- `u16 version` = 1
- `u16 msg_type`
- `varbytes payload`
- `bytes[32] checksum` = H(payload) (full 32 bytes)

msg_type:
- 1 = VERSION
- 2 = VERACK
- 3 = GET_FINALIZED_TIP
- 4 = FINALIZED_TIP
- 5 = PROPOSE
- 6 = VOTE
- 7 = GET_BLOCK
- 8 = BLOCK

### 6.4 PROPOSE message
Payload:
- `u64 height`
- `u32 round`
- `bytes[32] prev_finalized_hash`
- `varbytes block_bytes` (full Block serialization without requiring finality_proof)

Rules:
- A valid proposal must match leader selection for `(height, round)`.

### 6.5 VOTE message
Payload:
- `u64 height`
- `u32 round`
- `bytes[32] block_id`
- `bytes[32] validator_pubkey`
- `bytes[64] signature` (Ed25519 over block_id)

Signature is verified using validator_pubkey.

### 6.6 FinalityProof
When propagating finalized blocks, include:

`FinalityProof` serialized as:
- `varint sig_count`
- For each signature:
  - `bytes[32] validator_pubkey`
  - `bytes[64] signature`

Signatures are over `block_id`.

Constraints:
- Must be unique pubkeys (no duplicates).
- Each pubkey must be ACTIVE at height start (or as of prev finalized state).

### 6.7 Quorum threshold
Let `N = |ACTIVE validators|` for height `h` (derived from finalized state at `h-1`).
`QUORUM = floor(2*N/3) + 1`

A block is FINAL when:
- It is valid
- It references `prev_finalized_hash` equal to finalized tip hash
- It has a FinalityProof with at least QUORUM valid signatures from distinct ACTIVE validators for that height.

### 6.8 Liveness / timeouts (implementation guidance)
- Each node maintains a local timer `ROUND_TIMEOUT_MS` (e.g., 5000ms)
- If no block is finalized for `(height, round)` by timeout, advance to `round+1`.
- Nodes may accept late finality if it meets rules.

Consensus validity does not depend on local clocks; only timestamps in header must be within bounds:
- `timestamp >= median(last 11 finalized timestamps)`
- `timestamp <= local_time + MAX_FUTURE_DRIFT` (e.g., 120 seconds) (policy; may differ for testnet)

---

## 7. Slashing / Misbehavior Evidence

### 7.1 Equivocation (double-sign) definition
A validator equivocates if it produces two VOTE messages with:
- same `height`
- and (option A) same `round`
- but different `block_id`

v0 uses option A (same height & round) to keep it tight.

### 7.2 Evidence format
`EquivocationEvidence`:
- `VOTE vote_a`
- `VOTE vote_b`

Must verify:
- same validator_pubkey
- same height and round
- block_id differs
- both signatures valid

### 7.3 Penalty (v0)
Upon acceptance of valid evidence:
- Validator status set to `BANNED` in consensus state.
- Banned validators are excluded from ACTIVE set immediately for subsequent heights.

Bond burning is deferred to v1 (requires spend-path enforcement). v0 focuses on removing influence.

---

## 8. Node State Machine (high level)

At finalized tip (height h):
- Determine ACTIVE validator set for h+1.
- For next height:
  - Start round=0
  - Compute leader
  - If node is leader: assemble candidate block, broadcast PROPOSE
  - On receiving PROPOSE: validate block, if valid then broadcast VOTE
  - Collect VOTEs; when quorum reached, finalize block and broadcast BLOCK(with FinalityProof)

Nodes reject:
- proposals not from correct leader
- votes by non-ACTIVE validator
- blocks extending non-finalized tip
- blocks finalized with insufficient quorum or invalid signatures

---

## 9. Constants (v0 testnet defaults)
- `MAGIC = 0x53434F49` ("SCOI" LE)
- `PROTOCOL_VERSION = 1`
- `BOND_AMOUNT = 1000 * 10^8` (tune)
- `WARMUP_BLOCKS = 100`
- `ROUND_TIMEOUT_MS = 5000`
- `MAX_FUTURE_DRIFT_SECONDS = 120`

These constants must be identical across all nodes on a network.

---

## 10. Light Client Notes
Light clients follow only finalized headers:
- Download finalized block headers + finality proof
- Verify quorum signatures for each finalized header
- (Optional) request merkle proofs for tx inclusion (future light server)

---

## 11. Security Notes (v0 scope)
- v0 aims for clarity and implementability, not maximum adversarial resilience.
- v1 should implement:
  - bond slashing with enforceable spend paths
  - committee sampling for scalability
  - better timestamp handling
  - fork-choice rules under network partitions
  - DoS protection, peer scoring

---

## 12. Implementation Checklist
- Deterministic byte encoding everywhere
- Strict canonical parsing
- Ed25519 verification with constant-time libs
- RocksDB schema for:
  - blocks by hash
  - finalized tip
  - UTXO set
  - validator registry state
  - vote cache for current height/round
- Simulation tests with 4 validators:
  - finalize 100 blocks
  - induce leader failure and ensure round increment finalizes
  - inject equivocation evidence and ensure banning occurs
## SPEC CLARIFICATION: Monetary Policy (Deterministic Height Schedule)

This clarification defines the monetary schedule and deterministic payout split in integer base units.

- Base unit: `1 SelfCoin = 100,000,000` units.
- `TOTAL_SUPPLY_COINS = 7,000,000`.
- `TOTAL_SUPPLY_UNITS = 700,000,000,000,000`.
- Target block interval is informational only: `180` seconds (3 minutes).
- Deterministic schedule uses fixed block counts:
  - `BLOCKS_PER_YEAR_365 = 175,200`
  - `EMISSION_BLOCKS = 3,504,000` (20 years)

Per-height block reward:

- Let:
  - `q = TOTAL_SUPPLY_UNITS / EMISSION_BLOCKS = 199,771,689`
  - `r = TOTAL_SUPPLY_UNITS % EMISSION_BLOCKS = 1,744,000`
- For height `h`:
  - if `0 <= h < EMISSION_BLOCKS`:
    - `reward_units(h) = q + (h < r ? 1 : 0)`
  - if `h >= EMISSION_BLOCKS`:
    - `reward_units(h) = 0`

This yields exact total issuance:

- `sum_{h=0..EMISSION_BLOCKS-1} reward_units(h) == TOTAL_SUPPLY_UNITS`.

Deterministic payout split for a finalized block:

- Let:
  - `R = reward_units(height)`
  - `F = total_fees_units_in_block` (sum non-coinbase fees)
  - `T = R + F`
  - `S = number of distinct signers used for payout split`
- Compute:
  - `leader_units = floor(T * 20 / 100)`
  - `pool = T - leader_units`
  - `base_signer_units = pool / S`
  - `rem = pool % S`
- Signer remainder rule:
  - sort signer pubkeys ascending by raw bytes
  - first `rem` signers in sorted order receive `+1` unit
  - each signer receives `base_signer_units` (+1 if selected by remainder rule)

Coinbase conservation:

- `sum(coinbase_outputs) == T` exactly.
- After `h >= EMISSION_BLOCKS`, `R = 0`, so `sum(coinbase_outputs) == F`.
