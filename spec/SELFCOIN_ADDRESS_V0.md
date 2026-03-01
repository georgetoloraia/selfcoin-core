# SelfCoin Address v0
Version: 0.1
Status: Draft (implementation-targeted)
Last updated: 2026-03-01

Defines human-readable addresses for SelfCoin P2PKH outputs.

---

## 1. Overview

SelfCoin uses:
- Ed25519 pubkeys (32 bytes)
- P2PKH-like outputs (20-byte pubkey hash = H160(pubkey))

Address is an encoding of:
- network prefix (hrp)
- address type
- pubkey hash
- checksum

---

## 2. Hashes

- `H(x)` = SHA256(SHA256(x))
- `H160(x)` = RIPEMD160(SHA256(x))

pubkey_hash = H160(pubkey) where pubkey is 32 bytes Ed25519 pubkey.

---

## 3. Address Payload

Payload bytes:

- `u8 addr_type`
- `bytes[20] pubkey_hash`

v0 supports:
- `addr_type = 0x00`  (P2PKH)

So payload length = 21 bytes.

---

## 4. Human-Readable Format

Format:
`<hrp>1<base32(payload || checksum)>`

Where:
- `<hrp>` is:
  - `sc` for mainnet
  - `tsc` for testnet
- Separator is literal `'1'`
- `base32` is RFC 4648 base32 alphabet LOWERCASE without padding:
  - alphabet: `abcdefghijklmnopqrstuvwxyz234567`
  - output is lowercase
  - no '=' padding

### 4.1 Checksum
Checksum is 4 bytes:

`checksum = H( ascii(hrp) || 0x00 || payload )[0..4]`

Notes:
- Include hrp to prevent cross-network address reuse.
- `0x00` delimiter avoids ambiguity.

Total encoded data bytes = payload (21) + checksum (4) = 25 bytes.

---

## 5. Encoding steps (P2PKH)

Given pubkey (32 bytes):
1) pubkey_hash = H160(pubkey) (20 bytes)
2) payload = addr_type(0x00) || pubkey_hash  (21 bytes)
3) checksum = H( ascii(hrp) || 0x00 || payload )[0..4]
4) data = payload || checksum (25 bytes)
5) addr = hrp || "1" || base32_lower_no_pad(data)

Example (structure only):
`tsc1m5...` (exact string depends on keys)

---

## 6. Decoding & Validation

Given address string:
1) Split at the first '1':
   - hrp = left
   - b32 = right
2) Validate hrp in {sc, tsc}
3) base32 decode b32 (lowercase only, no padding allowed)
4) Validate length == 25 bytes
5) payload = first 21 bytes
   checksum = last 4 bytes
6) Recompute checksum' = H(ascii(hrp) || 0x00 || payload)[0..4]
7) checksum must match checksum'
8) addr_type must be 0x00 (v0)
9) Extract pubkey_hash (20 bytes)

---

## 7. ScriptPubKey from Address (P2PKH)

Given pubkey_hash (20 bytes), script_pubkey bytes are:
`76 A9 14 <20 bytes> 88 AC`

---

## 8. Notes
- This is intentionally not full bech32; it is "bech32-like" with simple base32 + checksum.
- v1 could adopt bech32m for wider tooling compatibility.