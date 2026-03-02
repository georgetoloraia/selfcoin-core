# Mainnet Parameters

Network profile (`--mainnet`):
- `network_name`: `mainnet`
- `magic`: `0x53434D4E` (`1396919630`)
- `network_id`: `sha256("selfcoin:mainnet")[:16]`
- `network_id_hex`: `192d26a3e3decbc1919afbbe9d849149`
- `protocol_version`: `1`
- `feature_flags`: `1` (strict version/network handshake)
- `p2p_default_port`: `19440`
- `lightserver_default_port`: `19444`

Consensus/limits (unchanged rules):
- `MAX_COMMITTEE`: `128`
- `ROUND_TIMEOUT_MS`: `5000`
- `MAX_PAYLOAD_LEN`: `8 MiB`
- `BOND_AMOUNT`: `5,000,000,000` units
- `WARMUP_BLOCKS`: `100`
- `UNBOND_DELAY_BLOCKS`: `100`
- hardened networking defaults remain identical to current node defaults.
