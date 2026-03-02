# Figure Descriptions (Text-Only)

## Figure 1: System Architecture (Node / Lightserver / Wallet)
Show three layers:
- Core P2P layer: multiple `selfcoin-node` instances exchanging VERSION/VERACK/PROPOSE/VOTE/BLOCK/TX.
- Data/API layer: `selfcoin-lightserver` connected to node DB (finalized-only reads) and node relay socket for `broadcast_tx`.
- Client layer: TS wallet SDK and external apps calling lightserver JSON-RPC.
Annotate trust boundaries: wallet keys stay client-side; lightserver is non-custodial and stateless.

## Figure 2: Consensus Sequence (Propose -> Vote -> Finalize)
Sequence diagram for one height:
1. Nodes derive ACTIVE set, leader, committee from finalized `h-1`.
2. Leader proposes block.
3. Committee members validate block and emit votes.
4. Vote tracker dedupes/conflict-checks.
5. On quorum signatures (`floor(2N/3)+1`), node finalizes block, persists indexes, and broadcasts finalized block.
Include timeout branch where round increments and next leader is used.

## Figure 3: Validator Lifecycle State Machine
States: `PENDING`, `ACTIVE`, `EXITING`, `BANNED`.
Transitions:
- bond registration (`SCVALREG`) -> `PENDING`.
- warmup reached -> `ACTIVE`.
- unbond request (`SCVALUNB` path) -> `EXITING`.
- equivocation ban/slash -> `BANNED`.
Include note that ACTIVE set excludes EXITING/BANNED and committee derivation uses finalized state.

## Figure 4: Wallet Transaction Flow
Flow:
1. Wallet derives address -> scriptPubKey -> scripthash.
2. Wallet queries `get_utxos`.
3. Deterministic coin selection and tx build/sign locally.
4. Wallet calls `broadcast_tx`.
5. Node mempool accepts and leader includes tx.
6. Finalization occurs; wallet polls `get_tx`/`get_headers` until finalized.
7. Wallet observes updated recipient UTXO.

## Figure 5: Genesis Reproducibility Pipeline
Pipeline diagram:
`mainnet/genesis.json` -> canonical binary encoder -> `mainnet/genesis.bin` -> `genesis_hash` (`sha256d`) and deterministic `genesis_block_id`.
Include verify loop using CLI (`genesis_build`, `genesis_hash`, `genesis_verify`) and node startup marker checks (`G:`, `GB:`).

## Figure 6: P2P Hardening Controls
Layered defense diagram:
- frame parser limits/checksum,
- per-connection timeouts,
- per-peer outbound queue caps,
- token bucket rate limits,
- peer scoring/soft mute/ban,
- bounded vote/proposal caches.
Show that these are policy/availability controls, while consensus correctness is enforced independently by validation rules.
