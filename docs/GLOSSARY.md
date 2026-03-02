# SelfCoin Glossary

- ACTIVE validator: Validator currently eligible for committee selection and consensus participation.
- BANNED validator: Validator excluded due to equivocation/misbehavior handling.
- Bond (`SCVALREG`): Special output locking validator stake for participation.
- Committee: Deterministically selected subset of ACTIVE validators for a given height.
- Finality proof: Signature set attached to finalized block proving quorum approval.
- Finalized-chain-first: Operational rule that nodes only build from finalized tip, not speculative branches.
- Lightserver: Finalized-only JSON-RPC service used by wallets.
- P2PKH: Script template `76 A9 14 <20B> 88 AC` with matching signature script format.
- Quorum: `floor(2N/3)+1` threshold over committee size `N`.
- Round: Consensus retry index at same height, incremented on timeout.
- Scripthash: `sha256(script_pubkey)` single SHA-256 used for wallet UTXO lookup.
- Slashing (`SCSLASH`): Bond-consuming transaction path using equivocation evidence.
- TxID: `sha256d(serialized_tx)`.
- UTXO: Unspent transaction output entry used as spendable input reference.
- Warmup: Delay from bond registration to ACTIVE eligibility.
