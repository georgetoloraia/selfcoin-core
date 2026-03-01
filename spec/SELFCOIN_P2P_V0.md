# SelfCoin P2P v0
Version: 0.1
Status: Draft (implementation-targeted)
Last updated: 2026-03-01

This document specifies the SelfCoin v0 peer-to-peer networking layer: framing, handshake, message types, and peer behavior.

It is designed for correctness and simplicity, not maximum feature coverage.

---

## 1. Transport

- Transport: TCP
- Default port (testnet): 18444
- Default port (mainnet placeholder): 8444
- One connection = one TCP stream
- Peers may open outbound connections; inbound acceptance is permissionless.

---

## 2. Framing (Wire Format)

All messages are framed as:

- `u32 magic`          = 0x53434F49 ("SCOI" LE)
- `u16 proto_version`  = 1
- `u16 msg_type`
- `u32 payload_len`    (LE)
- `bytes[payload_len] payload`
- `bytes[32] checksum` = H(payload)  (double SHA-256 from consensus spec)

Notes:
- `payload_len` MUST be <= `MAX_PAYLOAD_LEN` (default 8 MiB).
- Nodes MUST drop connections sending oversized frames or invalid checksums.
- Message parsing MUST be strict: read exact sizes, no trailing bytes.

Constants:
- `MAX_PAYLOAD_LEN = 8 * 1024 * 1024`

---

## 3. Handshake

Handshake is required before any consensus-relevant messages are accepted.

### 3.1 VERSION (msg_type = 1)
Payload:

- `u16 proto_version` (must be 1 for v0)
- `u64 services` (bitfield; v0 use 0)
- `u64 timestamp` (unix seconds)
- `u32 nonce` (random)
- `varbytes user_agent` (ASCII, e.g. "selfcoin-core/0.1")
- `u64 start_height` (node's finalized tip height)
- `bytes[32] start_hash` (node's finalized tip hash)

Rules:
- On receiving VERSION:
  - If proto_version != 1: disconnect.
  - Store peer's user_agent, start_height/hash.
  - Reply with VERACK.

### 3.2 VERACK (msg_type = 2)
Payload: empty

Rules:
- After both sides exchanged VERSION and VERACK, connection is "established".

### 3.3 Anti-self-connection
- If peer_nonce equals our outbound nonce (rare collision) is not enough.
- Better: if received VERSION nonce equals a nonce we recently sent to ourselves (optional).
- v0: ignore unless you implement address manager; can be added later.

---

## 4. Inventory and Data Exchange (Simplified v0)

v0 keeps it minimal and deterministic.

### 4.1 GET_FINALIZED_TIP (msg_type = 3)
Payload: empty

Response: FINALIZED_TIP

### 4.2 FINALIZED_TIP (msg_type = 4)
Payload:
- `u64 height`
- `bytes[32] hash`

### 4.3 GET_BLOCK (msg_type = 7)
Payload:
- `bytes[32] block_hash`

Response: BLOCK (msg_type = 8) if known; otherwise ignore.

### 4.4 BLOCK (msg_type = 8)
Payload:
- `varbytes block_bytes` (full Block serialization; should include FinalityProof if block is finalized)

Rules:
- Nodes MUST validate and store blocks they accept.
- Nodes SHOULD relay finalized blocks to peers (see relay policy).

---

## 5. Consensus Messages

These correspond to the consensus spec.

### 5.1 PROPOSE (msg_type = 5)
Payload:
- `u64 height`
- `u32 round`
- `bytes[32] prev_finalized_hash`
- `varbytes block_bytes` (Block serialization WITHOUT requiring finality proof)

Rules:
- Accept only if:
  - handshake complete
  - height == local_finalized_height + 1
  - prev_finalized_hash matches local finalized tip hash
  - leader_pubkey in header matches computed leader for (height, round)
  - block validates structurally and transactionally (except finality proof)
- If valid, node SHOULD broadcast VOTE.

### 5.2 VOTE (msg_type = 6)
Payload:
- `u64 height`
- `u32 round`
- `bytes[32] block_id`
- `bytes[32] validator_pubkey`
- `bytes[64] signature`

Rules:
- Accept only if:
  - handshake complete
  - validator_pubkey is ACTIVE for that height
  - signature verifies over block_id
  - vote not duplicate
- On receiving votes, node accumulates. When quorum achieved, it finalizes the block locally and broadcasts BLOCK with FinalityProof.

---

## 6. Peer Behavior

### 6.1 Connection limits (suggested)
- max_inbound = 64
- max_outbound = 16

### 6.2 Relay policy (v0)
- Relay FINALIZED blocks immediately.
- Relay PROPOSE if it is for next height and passes basic checks.
- Relay VOTE messages for current height/round only.

### 6.3 Rate limiting (minimum)
- Per-peer max messages/sec: 100 (soft)
- Drop peers that exceed limits persistently.

### 6.4 Timeouts (suggested)
- handshake timeout: 10s
- idle timeout: 120s (send ping later in v1; v0 can just close)

### 6.5 Misbehavior
Disconnect peer if:
- invalid frame checksum
- invalid payload length
- wrong magic or version
- sends consensus messages pre-handshake
- sends repeated invalid proposals/votes

---

## 7. Future Extensions (v1+)
- Addr manager: ADDR/GETADDR
- INV/GETDATA for tx propagation
- Compact blocks
- Peer scoring and ban list persistence
- Encrypted transport (Noise) (optional)