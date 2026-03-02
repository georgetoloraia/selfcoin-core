import { describe, expect, it } from 'vitest';

import { LightServerClient, SelfCoinWallet } from '../src/index.js';

const RUN = process.env.SELFCOIN_SDK_IT === '1';
const BASE_URL = process.env.SELFCOIN_LIGHTSERVER_URL ?? 'http://127.0.0.1:19444';
const FUNDING_PRIV = process.env.SELFCOIN_FUNDING_PRIVKEY;
const DEST_ADDRESS = process.env.SELFCOIN_IT_DEST_ADDRESS;

describe('integration devnet', () => {
  it.skipIf(!RUN)('builds, broadcasts, and observes finality via lightserver', async () => {
    if (!FUNDING_PRIV || !DEST_ADDRESS) {
      throw new Error('missing SELFCOIN_FUNDING_PRIVKEY or SELFCOIN_IT_DEST_ADDRESS');
    }

    const client = new LightServerClient(BASE_URL, { timeoutMs: 6000 });
    const wallet = new SelfCoinWallet(client);

    const sender = SelfCoinWallet.importPrivkeyHex(FUNDING_PRIV);
    const fromAddress = SelfCoinWallet.deriveAddress(sender.pubkeyHex, 'tsc');
    const before = await wallet.getBalance(fromAddress);
    expect(before > 0n).toBe(true);

    const sent = await wallet.sendTransaction({
      fromPrivkeyHex: FUNDING_PRIV,
      toAddress: DEST_ADDRESS,
      amountUnits: 1_000n,
      feeUnits: 1_000n,
      hrp: 'tsc',
    });

    const finalized = await wallet.waitForFinality(sent.txid, { timeoutMs: 180000, pollIntervalMs: 2000 });
    expect(finalized.height > 0n).toBe(true);

    const destUtxos = await wallet.listUtxos(DEST_ADDRESS);
    expect(destUtxos.some((u) => u.txid === sent.txid)).toBe(true);
  });
});
