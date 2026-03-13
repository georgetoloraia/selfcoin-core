#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def sha256_hex(parts: list[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    length = handler.headers.get("Content-Length")
    if not length:
        return None
    try:
        raw = handler.rfile.read(int(length))
        body = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict):
            return None
        return body
    except Exception:
        return None


def write_json(handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def is_hex_of_size(value: Any, size_bytes: int) -> bool:
    return isinstance(value, str) and len(value) == size_bytes * 2 and all(c in "0123456789abcdefABCDEF" for c in value)


@dataclass
class MintConfig:
    state_file: Path
    confirmations_required: int
    signing_seed: str
    mint_id: str


class MintState:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data = {
            "deposits": {},
            "redemptions": {},
            "spent_notes": {},
        }
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._data.update(data)
        except Exception:
            pass

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True)
        os.replace(tmp, self._path)

    def register_deposit(self, deposit: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._data["deposits"][deposit["mint_deposit_ref"]] = deposit
            self._flush()
            return dict(deposit)

    def get_deposit(self, mint_deposit_ref: str) -> dict[str, Any] | None:
        with self._lock:
            dep = self._data["deposits"].get(mint_deposit_ref)
            return dict(dep) if isinstance(dep, dict) else None

    def create_redemption(self, redemption: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._data["redemptions"][redemption["redemption_batch_id"]] = redemption
            for note in redemption["notes"]:
                self._data["spent_notes"][note] = redemption["redemption_batch_id"]
            self._flush()
            return dict(redemption)

    def get_redemption(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._data["redemptions"].get(batch_id)
            return dict(item) if isinstance(item, dict) else None

    def note_already_spent(self, note: str) -> bool:
        with self._lock:
            return note in self._data["spent_notes"]


def make_handler(config: MintConfig, state: MintState):
    class MintHandler(BaseHTTPRequestHandler):
        server_version = "selfcoin-mint/0.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/healthz":
                write_json(self, HTTPStatus.OK, {"ok": True, "mint_id": config.mint_id})
                return
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            body = read_json_body(self)
            if body is None:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid json body"})
                return

            if self.path == "/deposits/register":
                self._handle_deposit_register(body)
                return
            if self.path == "/issuance/blind":
                self._handle_blind_issue(body)
                return
            if self.path == "/redemptions/create":
                self._handle_redemption_create(body)
                return
            if self.path == "/redemptions/status":
                self._handle_redemption_status(body)
                return

            write_json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _handle_deposit_register(self, body: dict[str, Any]) -> None:
            required = ["chain", "deposit_txid", "deposit_vout", "mint_id", "recipient_pubkey_hash", "amount"]
            if any(k not in body for k in required):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "missing fields"})
                return
            if not is_hex_of_size(body["deposit_txid"], 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid deposit_txid"})
                return
            if not is_hex_of_size(body["mint_id"], 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid mint_id"})
                return
            if not is_hex_of_size(body["recipient_pubkey_hash"], 20):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid recipient_pubkey_hash"})
                return
            if config.mint_id and body["mint_id"].lower() != config.mint_id.lower():
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "mint_id mismatch"})
                return

            mint_deposit_ref = sha256_hex([
                str(body["chain"]),
                body["deposit_txid"],
                str(body["deposit_vout"]),
                body["mint_id"],
            ])
            deposit = {
                "chain": body["chain"],
                "deposit_txid": body["deposit_txid"],
                "deposit_vout": int(body["deposit_vout"]),
                "mint_id": body["mint_id"],
                "recipient_pubkey_hash": body["recipient_pubkey_hash"],
                "amount": int(body["amount"]),
                "mint_deposit_ref": mint_deposit_ref,
            }
            state.register_deposit(deposit)
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "confirmations_required": config.confirmations_required,
                    "mint_deposit_ref": mint_deposit_ref,
                },
            )

        def _handle_blind_issue(self, body: dict[str, Any]) -> None:
            mint_deposit_ref = body.get("mint_deposit_ref")
            blinded_messages = body.get("blinded_messages")
            if not isinstance(mint_deposit_ref, str) or not isinstance(blinded_messages, list):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            deposit = state.get_deposit(mint_deposit_ref)
            if deposit is None:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown mint_deposit_ref"})
                return

            signed_blinds = [
                sha256_hex([config.signing_seed, mint_deposit_ref, str(idx), str(msg)])
                for idx, msg in enumerate(blinded_messages)
            ]
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "signed_blinds": signed_blinds,
                    "mint_epoch": 0,
                },
            )

        def _handle_redemption_create(self, body: dict[str, Any]) -> None:
            notes = body.get("notes")
            redeem_address = body.get("redeem_address")
            if not isinstance(notes, list) or not isinstance(redeem_address, str) or not notes:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            for note in notes:
                if not isinstance(note, str):
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "notes must be strings"})
                    return
                if state.note_already_spent(note):
                    write_json(self, HTTPStatus.CONFLICT, {"error": "note already spent"})
                    return

            batch_id = sha256_hex([redeem_address, *notes])
            redemption = {
                "redemption_batch_id": batch_id,
                "notes": list(notes),
                "redeem_address": redeem_address,
                "state": "pending",
                "l1_txid": "",
            }
            state.create_redemption(redemption)
            write_json(self, HTTPStatus.OK, {"accepted": True, "redemption_batch_id": batch_id})

        def _handle_redemption_status(self, body: dict[str, Any]) -> None:
            batch_id = body.get("redemption_batch_id")
            if not isinstance(batch_id, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid redemption_batch_id"})
                return
            redemption = state.get_redemption(batch_id)
            if redemption is None:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown redemption_batch_id"})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "state": redemption["state"],
                    "l1_txid": redemption["l1_txid"],
                },
            )

    return MintHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal selfcoin-mint boundary service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="/tmp/selfcoin-mint-state.json")
    parser.add_argument("--confirmations-required", type=int, default=1)
    parser.add_argument(
        "--signing-seed",
        default="selfcoin-mint-dev-seed",
        help="Deterministic placeholder seed for blind issuance responses.",
    )
    parser.add_argument(
        "--mint-id",
        default="",
        help="Optional 32-byte hex mint id to enforce on /deposits/register.",
    )
    args = parser.parse_args()

    config = MintConfig(
        state_file=Path(args.state_file),
        confirmations_required=args.confirmations_required,
        signing_seed=args.signing_seed,
        mint_id=args.mint_id,
    )
    state = MintState(config.state_file)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(config, state))
    print(f"selfcoin-mint listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
