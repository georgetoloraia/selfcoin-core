from __future__ import annotations

import json
import math
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def http_get_json(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_server_module():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("selfcoin_mint_server_integration", SERVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load server module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server_module = load_server_module()


class FakeLightserver:
    def __init__(self, port: int) -> None:
        self.port = port
        self.tip_height = 0
        self.tx_heights: dict[str, int] = {}
        self.utxos_by_scripthash: dict[str, list[dict]] = {}
        self.broadcast_spend_queue: list[list[tuple[str, int]]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._make_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                body = json.loads(raw.decode("utf-8"))
                method = body.get("method")
                req_id = body.get("id")
                if method == "get_status":
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"height": outer.tip_height},
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "get_tx":
                    txid = body.get("txid", "")
                    if txid not in outer.tx_heights:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32001, "message": "not found"},
                        }
                    else:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {"height": outer.tx_heights[txid], "tx_hex": ""},
                        }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "get_utxos":
                    sh = body.get("scripthash_hex", "")
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": outer.utxos_by_scripthash.get(sh, []),
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "broadcast_tx":
                    tx_hex = body.get("tx_hex", "")
                    if outer.broadcast_spend_queue:
                        spent = set(outer.broadcast_spend_queue.pop(0))
                        updated: dict[str, list[dict]] = {}
                        for scripthash, utxos in outer.utxos_by_scripthash.items():
                            updated[scripthash] = [
                                item
                                for item in utxos
                                if (str(item.get("txid", "")), int(item.get("vout", -1))) not in spent
                            ]
                        outer.utxos_by_scripthash = updated
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"accepted": True, "txid": tx_hex[:64] if isinstance(tx_hex, str) else ""},
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                self._write_json(
                    HTTPStatus.OK,
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "method not found"}},
                )

            def _write_json(self, status: HTTPStatus, payload: dict) -> None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class MintIntegrationTests(unittest.TestCase):
    def test_cli_roundtrip_against_live_service(self) -> None:
        port = free_port()
        lightserver_port = free_port()
        lightserver = FakeLightserver(lightserver_port)
        lightserver.start()
        operator_key_id = "integration-operator"
        operator_secret_hex = "11" * 32
        try:
            with tempfile.TemporaryDirectory() as td:
                state_path = Path(td) / "mint-state.json"
                reserve_wallet = Path(td) / "reserve-wallet.json"
                reserve_privkey = "55" * 32
                wallet_cmd = [
                    str(CLI),
                    "wallet_import",
                    "--out",
                    str(reserve_wallet),
                    "--privkey",
                    reserve_privkey,
                ]
                wallet = subprocess.run(wallet_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                wallet_lines = dict(line.split("=", 1) for line in wallet.stdout.strip().splitlines())
                reserve_address = wallet_lines["address"]

                address_cmd = [
                    str(CLI),
                    "wallet_export",
                    "--file",
                    str(reserve_wallet),
                ]
                exported = subprocess.run(address_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                exported_lines = dict(line.split("=", 1) for line in exported.stdout.strip().splitlines())
                reserve_pubkey = exported_lines["pubkey_hex"]
                reserve_pkh_cmd = [
                    str(CLI),
                    "address_from_pubkey",
                    "--pubkey",
                    reserve_pubkey,
                ]
                reserve_addr_check = subprocess.run(reserve_pkh_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                self.assertEqual(reserve_addr_check.stdout.strip(), reserve_address)
                reserve_scripthash = "0000000000000000000000000000000000000000000000000000000000000000"
                utxo_txid_a = "66" * 32
                utxo_txid_b = "77" * 32
                # P2PKH script hash: sha256(76a914 || pkh || 88ac)
                reserve_pkh = server_module.decode_selfcoin_address(reserve_address)
                self.assertIsNotNone(reserve_pkh)
                reserve_scripthash = __import__("hashlib").sha256(server_module.p2pkh_script_pubkey(reserve_pkh)).hexdigest()
                lightserver.utxos_by_scripthash[reserve_scripthash] = [
                    {
                        "txid": utxo_txid_a,
                        "vout": 0,
                        "value": 60000,
                        "height": 1,
                        "script_pubkey_hex": "",
                    },
                    {
                        "txid": utxo_txid_b,
                        "vout": 1,
                        "value": 50000,
                        "height": 1,
                        "script_pubkey_hex": "",
                    }
                ]
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
                        "--operator-key",
                        f"{operator_key_id}:{operator_secret_hex}",
                        "--lightserver-url",
                        f"http://127.0.0.1:{lightserver_port}/rpc",
                        "--reserve-privkey",
                        reserve_privkey,
                        "--reserve-address",
                        reserve_address,
                        "--cli-path",
                        str(CLI),
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
                        "--note-amount",
                        "100000",
                    ]
                    blind = subprocess.run(blind_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    blind_lines = blind.stdout.splitlines()
                    signed_line = next(line for line in blind_lines if line.startswith("signed_blind[0]="))
                    note_ref_line = next(line for line in blind_lines if line.startswith("note_ref[0]="))
                    signed_blind = int(signed_line.split("=", 1)[1], 16)
                    note_ref = note_ref_line.split("=", 1)[1]
                    unblinded = (signed_blind * pow(r, -1, n)) % n
                    self.assertEqual(pow(unblinded, e, n), message)

                    accounting = http_get_json(f"http://127.0.0.1:{port}/accounting/summary")
                    self.assertEqual(accounting["total_deposited"], 100000)
                    self.assertEqual(accounting["issued_blind_count"], 1)
                    self.assertEqual(accounting["issued_amount"], 100000)

                    redeem_cmd = [
                        str(CLI),
                        "mint_redeem_create",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/create",
                        "--redeem-address",
                        "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy",
                        "--amount",
                        "100000",
                        "--note",
                        note_ref,
                    ]
                    redeem = subprocess.run(redeem_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    redeem_lines = dict(line.split("=", 1) for line in redeem.stdout.strip().splitlines())
                    batch_id = redeem_lines["redemption_batch_id"]

                    pending_status_cmd = [
                        str(CLI),
                        "mint_redeem_status",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/status",
                        "--batch-id",
                        batch_id,
                    ]
                    pending_status = subprocess.run(pending_status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    pending_lines = dict(line.split("=", 1) for line in pending_status.stdout.strip().splitlines())
                    self.assertEqual(pending_lines["state"], "pending")
                    self.assertEqual(pending_lines["l1_txid"], "")

                    lightserver.broadcast_spend_queue.append(
                        [
                            (utxo_txid_a, 0),
                            (utxo_txid_b, 1),
                        ]
                    )

                    approve_cmd = [
                        str(CLI),
                        "mint_redeem_approve_broadcast",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/approve_broadcast",
                        "--batch-id",
                        batch_id,
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    approve = subprocess.run(approve_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    approve_json = json.loads(approve.stdout)
                    self.assertTrue(approve_json["accepted"])
                    self.assertEqual(approve_json["state"], "broadcast")
                    self.assertTrue(approve_json["l1_txid"])

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
                    self.assertEqual(status_lines["state"], "broadcast")
                    self.assertTrue(status_lines["l1_txid"])
                    self.assertEqual(status_lines["amount"], "100000")

                    reserves = http_get_json(f"http://127.0.0.1:{port}/reserves")
                    self.assertEqual(reserves["available_reserve"], 0)
                    self.assertEqual(reserves["pending_spend_commitment_count"], 1)
                    self.assertEqual(reserves["pending_spend_input_count"], 2)
                    self.assertEqual(reserves["wallet_utxo_count"], 0)
                    self.assertEqual(reserves["wallet_utxo_value"], 0)
                    self.assertEqual(reserves["wallet_locked_utxo_count"], 0)
                    self.assertEqual(reserves["wallet_locked_utxo_value"], 0)
                    self.assertEqual(reserves["coin_selection_max_inputs"], 8)
                    self.assertFalse(reserves["recommend_consolidation"])
                    self.assertFalse(reserves["alert_fragmentation_threshold_breach"])
                    self.assertTrue(reserves["alert_reserve_exhaustion_risk"])
                    l1_txid = status_lines["l1_txid"]
                    lightserver.tip_height = 20
                    lightserver.tx_heights[l1_txid] = 20

                    finalized = subprocess.run(status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    finalized_lines = dict(line.split("=", 1) for line in finalized.stdout.strip().splitlines())
                    self.assertEqual(finalized_lines["state"], "finalized")
                    self.assertEqual(finalized_lines["l1_txid"], l1_txid)
                    self.assertEqual(finalized_lines["amount"], "100000")

                    audit_cmd = [
                        str(CLI),
                        "mint_audit_export",
                        "--url",
                        f"http://127.0.0.1:{port}/audit/export",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    audit = subprocess.run(audit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    audit_json = json.loads(audit.stdout)
                    self.assertEqual(len(audit_json["payload"]["issuances"]), 1)
                    self.assertEqual(audit_json["payload"]["reserves"]["pending_spend_commitment_count"], 0)
                    self.assertEqual(audit_json["payload"]["reserves"]["finalized_redemption_amount"], 100000)
                    self.assertEqual(audit_json["payload"]["reserves"]["coin_selection_max_inputs"], 8)
                    self.assertTrue(audit_json["payload"]["reserves"]["alert_reserve_exhaustion_risk"])
                    self.assertEqual(audit_json["payload"]["redemptions"][0]["coin_selection_policy"], "smallest-sufficient-non-dust-change")
                    self.assertEqual(audit_json["payload"]["redemptions"][0]["change_value"], 9000)
                    self.assertEqual(len(audit_json["payload"]["redemptions"][0]["selected_utxos"]), 2)
                    self.assertTrue(audit_json["signature_hex"])

                    attest_cmd = [
                        str(CLI),
                        "mint_attest_reserves",
                        "--url",
                        f"http://127.0.0.1:{port}/attestations/reserves",
                    ]
                    attestation = subprocess.run(attest_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    attest_json = json.loads(attestation.stdout)
                    self.assertEqual(attest_json["payload"]["reserve_balance"], 0)
                    self.assertEqual(attest_json["payload"]["wallet_locked_utxo_count"], 0)
                    self.assertEqual(attest_json["payload"]["finalized_redemption_amount"], 100000)
                    self.assertTrue(attest_json["payload"]["alert_reserve_exhaustion_risk"])
                    self.assertTrue(attest_json["signature_hex"])

                    lightserver.utxos_by_scripthash[reserve_scripthash] = [
                        {
                            "txid": "88" * 32,
                            "vout": 0,
                            "value": 500,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                        {
                            "txid": "99" * 32,
                            "vout": 1,
                            "value": 700,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                        {
                            "txid": "aa" * 32,
                            "vout": 2,
                            "value": 3000,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                    ]
                    lightserver.broadcast_spend_queue.append(
                        [
                            ("88" * 32, 0),
                            ("99" * 32, 1),
                            ("aa" * 32, 2),
                        ]
                    )
                    consolidate_cmd = [
                        str(CLI),
                        "mint_reserve_consolidate",
                        "--url",
                        f"http://127.0.0.1:{port}/reserves/consolidate",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    consolidate = subprocess.run(consolidate_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    consolidate_json = json.loads(consolidate.stdout)
                    self.assertTrue(consolidate_json["accepted"])
                    self.assertEqual(consolidate_json["input_count"], 3)
                    self.assertEqual(consolidate_json["total_input_value"], 4200)
                    self.assertEqual(consolidate_json["output_value"], 3200)

                    reserves_after_consolidation = http_get_json(f"http://127.0.0.1:{port}/reserves")
                    self.assertEqual(reserves_after_consolidation["wallet_utxo_count"], 0)
                    self.assertTrue(reserves_after_consolidation["alert_reserve_exhaustion_risk"])

                    consolidation_txid = consolidate_json["l1_txid"]
                    lightserver.tip_height = 25
                    lightserver.tx_heights[consolidation_txid] = 25

                    final_audit = subprocess.run(audit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    final_audit_json = json.loads(final_audit.stdout)
                    self.assertEqual(len(final_audit_json["payload"]["consolidations"]), 1)
                    self.assertEqual(final_audit_json["payload"]["consolidations"][0]["state"], "finalized")
                    self.assertEqual(final_audit_json["payload"]["consolidations"][0]["coin_selection_policy"], "smallest-first-consolidation")

                    operator_pub = http_get_json(f"http://127.0.0.1:{port}/operator/key")
                    self.assertEqual(operator_pub["operator_key_id"], operator_key_id)
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
        finally:
            lightserver.stop()


if __name__ == "__main__":
    unittest.main()
