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
- `share/doc/selfcoin-wallet/*`

## Package Artifacts

If `cpack` is available, package archives can be built directly from the configured tree:

```bash
cd build
cpack -G TGZ
cpack -G ZIP
```

The generated package contains the staged wallet binary, desktop entry, and wallet docs.

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
