# SelfCoin Wallet Release Notes

## Release
- Version: `0.1.0`
- Date:
- Commit:

## Summary
- Reference wallet packaging release.

## Included artifacts
- `selfcoin-wallet-0.1.0-Linux.tar.gz`
- `selfcoin-wallet-0.1.0-Linux.zip`
- `SHA256SUMS.txt`
- `manifest.txt`

## Key changes
- Wallet UX / packaging / install updates:

## Operator notes
- Runtime requires Qt5 Widgets and OpenSSL on the target host.
- Verify `SHA256SUMS.txt` before distribution.
- If signed metadata is included, verify `manifest.txt.sig` and `SHA256SUMS.txt.sig`.

## Verification
```bash
./scripts/verify_wallet_release.sh build/release /path/to/release-public.pem
```
