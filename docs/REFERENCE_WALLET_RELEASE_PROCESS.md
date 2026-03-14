# SelfCoin Wallet Release Process

## 1. Generate or load release keys

Generate a keypair once:

```bash
./scripts/generate_wallet_release_key.sh /secure/path/wallet-release-key
```

Keep:
- `release-private.pem` private
- `release-public.pem` publishable

## 2. Build a signed release

```bash
RELEASE_SIGNING_KEY=/secure/path/wallet-release-key/release-private.pem \
RELEASE_SIGNING_PUBKEY=/secure/path/wallet-release-key/release-public.pem \
./scripts/package_reference_wallet.sh
```

## 3. Review artifacts

Expected files in `build/release/`:
- wallet archives
- `SHA256SUMS.txt`
- `manifest.txt`
- optional `SHA256SUMS.txt.sig`
- optional `manifest.txt.sig`
- optional copied public key

## 4. Verify locally

```bash
./scripts/verify_wallet_release.sh build/release /secure/path/wallet-release-key/release-public.pem
```

## 5. Publish

Publish:
- archives
- `SHA256SUMS.txt`
- `manifest.txt`
- signatures if present
- public verification key
- release notes based on `docs/REFERENCE_WALLET_RELEASE_NOTES_TEMPLATE.md`
