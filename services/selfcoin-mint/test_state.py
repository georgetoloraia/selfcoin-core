from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_server_module():
    server_path = Path(__file__).with_name("server.py")
    spec = importlib.util.spec_from_file_location("selfcoin_mint_server", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load server module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server = load_server_module()


class MintStateTests(unittest.TestCase):
    def test_register_deposit_persists_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            deposit = {
                "chain": "mainnet",
                "deposit_txid": "11" * 32,
                "deposit_vout": 1,
                "mint_id": "22" * 32,
                "recipient_pubkey_hash": "33" * 20,
                "amount": 1000,
                "mint_deposit_ref": "ref-1",
            }
            state.register_deposit(deposit)

            reloaded = server.MintState(state_path)
            got = reloaded.get_deposit("ref-1")
            self.assertIsNotNone(got)
            self.assertEqual(got["amount"], 1000)
            self.assertEqual(got["recipient_pubkey_hash"], "33" * 20)

    def test_redemption_marks_notes_spent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            redemption = {
                "redemption_batch_id": "batch-1",
                "notes": ["note-a", "note-b"],
                "redeem_address": "sc1example",
                "state": "pending",
                "l1_txid": "",
            }
            state.create_redemption(redemption)
            self.assertTrue(state.note_already_spent("note-a"))
            self.assertTrue(state.note_already_spent("note-b"))
            self.assertFalse(state.note_already_spent("note-c"))

    def test_blind_signer_signs_and_verifies(self) -> None:
        signer = server.BlindSigner.from_seed("seed-x", bits=256)
        message = 123456789
        signature = int(signer.sign_blinded_hex(format(message, "x")), 16)
        self.assertEqual(pow(signature, signer.e, signer.n), message)

    def test_blind_signer_is_deterministic_for_seed(self) -> None:
        a = server.BlindSigner.from_seed("seed-a", bits=256)
        b = server.BlindSigner.from_seed("seed-a", bits=256)
        self.assertEqual(a.n, b.n)
        self.assertEqual(a.e, b.e)
        self.assertEqual(a.d, b.d)


if __name__ == "__main__":
    unittest.main()
