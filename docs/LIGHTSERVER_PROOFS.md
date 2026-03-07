# Lightserver Proof Format (v3)

Proof RPCs:
- `get_utxo_proof`
- `get_validator_proof`

Related root RPC:
- `get_roots`

Both return:
- `proof_format`: `"smt_v0"`
- `height`: finalized height used for proof
- `key_hex`: 32-byte derived SMT key
- `root_hex`: committed SMT root (same as `utxo_root` / `validators_root`)
- `value_hex`: canonical value bytes hex, or `null` for non-membership
- `siblings_hex`: array of 256 sibling hashes (leaf->root), each 32-byte hex

Compatibility aliases are still present:
- `utxo_root` / `validators_root`
- `siblings`

Current runtime limits:
- proof requests are supported for the current finalized tip
- historical proof requests are rejected in the current fixed runtime
- `get_roots` may report unavailable if the requested finalized height does not have persisted root records

Cryptographic semantics are unchanged from PR3.
