# SelfCoin Reference Wallet Install

## Goal
Make the Qt reference wallet easy to stage, install, and package on a Linux desktop without inventing a custom deployment stack.

## Build

```bash
cmake -S . -B build
cmake --build build --target selfcoin-wallet -j1
```

## Stage Install

To install into a local staging directory:

```bash
cmake --install build --prefix /tmp/selfcoin-wallet-stage
```

That produces:
- `bin/selfcoin-wallet`
- `share/applications/selfcoin-wallet.desktop`
- `share/icons/hicolor/scalable/apps/selfcoin-wallet.svg`
- `share/doc/selfcoin-wallet/*`

## Package Artifacts

If `cpack` is available, package archives can be built directly from the configured tree:

```bash
cd build
cpack -G TGZ
cpack -G ZIP
```

The generated package contains the staged wallet binary, desktop entry, and wallet docs.

## One-Step Release Build

To build, stage, package, and generate release checksums/manifests in one step:

```bash
./scripts/package_reference_wallet.sh
```

That produces:
- staged install under `/tmp/selfcoin-wallet-stage` by default
- package archives under `build/release/`
- `build/release/SHA256SUMS.txt`
- `build/release/manifest.txt`
- `build/release/RELEASE_NOTES.md`

For signed release metadata:

```bash
RELEASE_SIGNING_KEY=/path/to/release-private.pem \
RELEASE_SIGNING_PUBKEY=/path/to/release-public.pem \
./scripts/package_reference_wallet.sh
```

That additionally produces:
- `build/release/SHA256SUMS.txt.sig`
- `build/release/manifest.txt.sig`
- copied public key, if provided

To verify a built release:

```bash
./scripts/verify_wallet_release.sh build/release /path/to/release-public.pem
```

## Desktop Launch

After install, the wallet can be started by:

```bash
selfcoin-wallet
```

Or via the installed desktop entry:
- `SelfCoin Wallet`

## Runtime Requirements

This packaging path does not bundle Qt or OpenSSL itself.
The target machine still needs the runtime libraries that the built wallet links against.

For a typical Linux desktop build host, that means:
- Qt5 Widgets runtime
- OpenSSL runtime

## Recommended Local Test

```bash
cmake --build build --target selfcoin-wallet -j1
cmake --install build --prefix /tmp/selfcoin-wallet-stage
timeout 2s /tmp/selfcoin-wallet-stage/bin/selfcoin-wallet -platform offscreen
```
