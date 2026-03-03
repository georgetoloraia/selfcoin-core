# Mainnet Seeds

Initial placeholders:
- `212.58.103.170:19440` (temporary raw IP seed)
- `seed1.mainnet.selfcoin.example:19440`
- `seed2.mainnet.selfcoin.example:19440`

Operator expectations:
- at least 2 independent organizations
- static DNS + health monitoring
- public uptime targets and incident contact

Operator run example:
```bash
./build/selfcoin-node --mainnet --public
```

Default data dir:
- `~/.selfcoin/mainnet`

Port sanity:
- Seeds must be P2P endpoints (`19440`), not lightserver HTTP (`19444`).
- Do not place TLS/HTTP reverse proxies in front of the P2P port.
