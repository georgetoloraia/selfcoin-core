import { LightServerClient, SelfCoinWallet } from '../src/index.js';

async function main() {
  const url = process.env.SELFCOIN_LIGHTSERVER_URL ?? 'http://127.0.0.1:19444';
  const client = new LightServerClient([url], { quorumMode: 'off', timeoutMs: 5000 });
  const wallet = new SelfCoinWallet(client);

  const keypair = SelfCoinWallet.generateKeypair();
  const address = SelfCoinWallet.deriveAddress(keypair.pubkeyHex, 'tsc');
  console.log('generated address:', address);

  const balance = await wallet.getBalance(address);
  console.log('balance units:', balance.toString());

  const toAddress = process.env.SELFCOIN_TO_ADDRESS;
  if (!toAddress) {
    console.log('set SELFCOIN_TO_ADDRESS to send a tx');
    return;
  }

  const sent = await wallet.sendTransaction({
    fromPrivkeyHex: keypair.privkeyHex,
    toAddress,
    amountUnits: BigInt(process.env.SELFCOIN_AMOUNT_UNITS ?? '1000'),
    feeUnits: BigInt(process.env.SELFCOIN_FEE_UNITS ?? '1000'),
    hrp: 'tsc',
  });
  console.log('broadcast txid:', sent.txid);

  const finalized = await wallet.waitForFinality(sent.txid, { timeoutMs: 120000, pollIntervalMs: 2000 });
  console.log('finalized at height:', finalized.height.toString());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
