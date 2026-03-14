# Mainnet Seeds

Initial placeholders:
- `212.58.103.170:19440` (temporary raw IP seed)
- `seed1.gotdns.ch:19440` (active dynamic DNS seed)
- `138.197.113.69:19440` (public VPS seed)
- `seed1.mainnet.selfcoin.example:19440`
- `seed2.mainnet.selfcoin.example:19440`
- format to publish: `seedX.domain:19440`

Operator expectations:
- at least 2 independent organizations
- static DNS + health monitoring
- public uptime targets and incident contact

Operator run example:
```bash
./build/selfcoin-node --public
```

Default data dir:
- `~/.selfcoin/mainnet`

Port sanity:
- Seeds must be P2P endpoints (`19440`), not lightserver HTTP (`19444`).
- Publish lightservers separately as RPC URLs (`http://host:19444/rpc`).
- Do not place TLS/HTTP reverse proxies in front of the P2P port.
