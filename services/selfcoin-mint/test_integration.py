from __future__ import annotations

import json
import math
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "services" / "selfcoin-mint" / "server.py"
CLI = REPO_ROOT / "build" / "selfcoin-cli"


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


class MintIntegrationTests(unittest.TestCase):
    def test_cli_roundtrip_against_live_service(self) -> None:
        port = free_port()
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "mint-state.json"
            proc = subprocess.Popen(
                [
                    "python3",
                    str(SERVER),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--state-file",
                    str(state_path),
                    "--mint-id",
                    "22" * 32,
                    "--signing-seed",
                    "integration-seed",
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(50):
                    try:
                        health = http_get_json(f"http://127.0.0.1:{port}/healthz")
                        if health.get("ok"):
                            break
                    except Exception:
                        time.sleep(0.1)
                else:
                    self.fail("mint service did not become ready")

                deposit_cmd = [
                    str(CLI),
                    "mint_deposit_register",
                    "--url",
                    f"http://127.0.0.1:{port}/deposits/register",
                    "--deposit-txid",
                    "11" * 32,
                    "--deposit-vout",
                    "0",
                    "--mint-id",
                    "22" * 32,
                    "--recipient-address",
                    "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy",
                    "--amount",
                    "100000",
                ]
                dep = subprocess.run(deposit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                lines = dict(line.split("=", 1) for line in dep.stdout.strip().splitlines())
                mint_deposit_ref = lines["mint_deposit_ref"]

                pubkey = http_get_json(f"http://127.0.0.1:{port}/mint/key")
                n = int(pubkey["modulus_hex"], 16)
                e = int(pubkey["public_exponent"])
                message = 123456789
                r = 5
                while math.gcd(r, n) != 1:
                    r += 2
                blinded = (message * pow(r, e, n)) % n

                blind_cmd = [
                    str(CLI),
                    "mint_issue_blinds",
                    "--url",
                    f"http://127.0.0.1:{port}/issuance/blind",
                    "--mint-deposit-ref",
                    mint_deposit_ref,
                    "--blind",
                    format(blinded, "x"),
                ]
                blind = subprocess.run(blind_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                signed_line = next(line for line in blind.stdout.splitlines() if line.startswith("signed_blind[0]="))
                signed_blind = int(signed_line.split("=", 1)[1], 16)
                unblinded = (signed_blind * pow(r, -1, n)) % n
                self.assertEqual(pow(unblinded, e, n), message)

                redeem_cmd = [
                    str(CLI),
                    "mint_redeem_create",
                    "--url",
                    f"http://127.0.0.1:{port}/redemptions/create",
                    "--redeem-address",
                    "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy",
                    "--note",
                    "note-1",
                    "--note",
                    "note-2",
                ]
                redeem = subprocess.run(redeem_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                redeem_lines = dict(line.split("=", 1) for line in redeem.stdout.strip().splitlines())
                batch_id = redeem_lines["redemption_batch_id"]

                status_cmd = [
                    str(CLI),
                    "mint_redeem_status",
                    "--url",
                    f"http://127.0.0.1:{port}/redemptions/status",
                    "--batch-id",
                    batch_id,
                ]
                status = subprocess.run(status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                status_lines = dict(line.split("=", 1) for line in status.stdout.strip().splitlines())
                self.assertEqual(status_lines["state"], "pending")
                self.assertEqual(status_lines["l1_txid"], "")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
