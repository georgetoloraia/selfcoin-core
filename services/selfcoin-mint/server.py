#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import threading
import time
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


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        witness = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                witness = False
                break
        if witness:
            return False
    return True


def _next_prime(rng: random.Random, bits: int) -> int:
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if _is_probable_prime(candidate):
            return candidate


@dataclass
class BlindSigner:
    n: int
    e: int
    d: int

    @classmethod
    def from_seed(cls, seed: str, bits: int = 512) -> "BlindSigner":
        rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16))
        e = 65537
        while True:
            p = _next_prime(rng, bits)
            q = _next_prime(rng, bits)
            if p == q:
                continue
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) == 1:
                n = p * q
                d = pow(e, -1, phi)
                return cls(n=n, e=e, d=d)

    def sign_blinded_hex(self, blinded_hex: str) -> str:
        blinded = int(blinded_hex, 16)
        if blinded <= 0 or blinded >= self.n:
            raise ValueError("blinded message out of range")
        signed = pow(blinded, self.d, self.n)
        return format(signed, "x")


class MintState:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data = {
            "deposits": {},
            "issuances": {},
            "redemptions": {},
            "note_records": {},
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
                if "spent_notes" in self._data and "note_records" not in self._data:
                    self._data["note_records"] = {
                        note: {
                            "state": "legacy-spent",
                            "redemption_batch_id": batch_id,
                            "redeem_address": "",
                            "amount": 0,
                            "updated_at": 0,
                        }
                        for note, batch_id in self._data["spent_notes"].items()
                    }
                self._data.pop("spent_notes", None)
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
            deposit = dict(deposit)
            deposit.setdefault("issued_blind_count", 0)
            deposit.setdefault("issuance_ids", [])
            self._data["deposits"][deposit["mint_deposit_ref"]] = deposit
            self._flush()
            return dict(deposit)

    def get_deposit(self, mint_deposit_ref: str) -> dict[str, Any] | None:
        with self._lock:
            dep = self._data["deposits"].get(mint_deposit_ref)
            return dict(dep) if isinstance(dep, dict) else None

    def record_issuance(self, mint_deposit_ref: str, blinded_messages: list[str], signed_blinds: list[str]) -> dict[str, Any]:
        blinded_hashes = [hashlib.sha256(msg.encode("utf-8")).hexdigest() for msg in blinded_messages]
        issued_at = int(time.time())
        with self._lock:
            deposit = self._data["deposits"].get(mint_deposit_ref)
            if not isinstance(deposit, dict):
                raise KeyError("unknown mint_deposit_ref")
            existing = set()
            for issuance_id in deposit.get("issuance_ids", []):
                issuance = self._data["issuances"].get(issuance_id)
                if isinstance(issuance, dict):
                    existing.update(issuance.get("blinded_hashes", []))
            overlap = existing.intersection(blinded_hashes)
            if overlap:
                raise ValueError("duplicate blinded message")
            issuance_id = sha256_hex([mint_deposit_ref, *blinded_hashes])
            issuance = {
                "issuance_id": issuance_id,
                "mint_deposit_ref": mint_deposit_ref,
                "blinded_hashes": blinded_hashes,
                "signed_blinds": list(signed_blinds),
                "created_at": issued_at,
                "note_count": len(blinded_messages),
            }
            self._data["issuances"][issuance_id] = issuance
            deposit["issuance_ids"] = list(deposit.get("issuance_ids", [])) + [issuance_id]
            deposit["issued_blind_count"] = int(deposit.get("issued_blind_count", 0)) + len(blinded_messages)
            self._data["deposits"][mint_deposit_ref] = deposit
            self._flush()
            return dict(issuance)

    def create_redemption(self, redemption: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            outstanding = self._total_deposited_locked() - self._total_reserved_locked()
            if int(redemption["amount"]) > outstanding:
                raise ValueError("insufficient reserve")
            now = int(time.time())
            redemption = dict(redemption)
            redemption.setdefault("created_at", now)
            redemption["updated_at"] = now
            self._data["redemptions"][redemption["redemption_batch_id"]] = redemption
            for note in redemption["notes"]:
                self._data["note_records"][note] = {
                    "state": redemption["state"],
                    "redemption_batch_id": redemption["redemption_batch_id"],
                    "redeem_address": redemption["redeem_address"],
                    "amount": int(redemption["amount"]),
                    "updated_at": now,
                }
            self._flush()
            return dict(redemption)

    def get_redemption(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._data["redemptions"].get(batch_id)
            return dict(item) if isinstance(item, dict) else None

    def note_already_spent(self, note: str) -> bool:
        with self._lock:
            return note in self._data["note_records"]

    def update_redemption(self, batch_id: str, new_state: str, l1_txid: str = "") -> dict[str, Any]:
        allowed = {
            "pending": {"broadcast", "finalized", "rejected"},
            "broadcast": {"finalized", "rejected"},
        }
        with self._lock:
            redemption = self._data["redemptions"].get(batch_id)
            if not isinstance(redemption, dict):
                raise KeyError("unknown redemption_batch_id")
            current = str(redemption.get("state", "pending"))
            if current == new_state:
                return dict(redemption)
            if current not in allowed or new_state not in allowed[current]:
                raise ValueError("invalid redemption state transition")
            now = int(time.time())
            redemption["state"] = new_state
            redemption["updated_at"] = now
            if l1_txid:
                redemption["l1_txid"] = l1_txid
            if new_state == "rejected":
                for note in redemption["notes"]:
                    self._data["note_records"].pop(note, None)
            else:
                for note in redemption["notes"]:
                    self._data["note_records"][note] = {
                        "state": new_state,
                        "redemption_batch_id": batch_id,
                        "redeem_address": redemption["redeem_address"],
                        "amount": int(redemption["amount"]),
                        "updated_at": now,
                    }
            self._data["redemptions"][batch_id] = redemption
            self._flush()
            return dict(redemption)

    def accounting_summary(self) -> dict[str, Any]:
        with self._lock:
            total_deposited = self._total_deposited_locked()
            pending = sum(int(item.get("amount", 0)) for item in self._data["redemptions"].values()
                          if isinstance(item, dict) and item.get("state") == "pending")
            broadcast = sum(int(item.get("amount", 0)) for item in self._data["redemptions"].values()
                            if isinstance(item, dict) and item.get("state") == "broadcast")
            finalized = sum(int(item.get("amount", 0)) for item in self._data["redemptions"].values()
                            if isinstance(item, dict) and item.get("state") == "finalized")
            rejected = sum(int(item.get("amount", 0)) for item in self._data["redemptions"].values()
                           if isinstance(item, dict) and item.get("state") == "rejected")
            issuance_count = len(self._data["issuances"])
            blind_count = sum(int(item.get("note_count", 0)) for item in self._data["issuances"].values()
                              if isinstance(item, dict))
            return {
                "mint_id": None,
                "deposit_count": len(self._data["deposits"]),
                "issuance_count": issuance_count,
                "issued_blind_count": blind_count,
                "redemption_count": len(self._data["redemptions"]),
                "active_note_locks": len(self._data["note_records"]),
                "total_deposited": total_deposited,
                "pending_redemption_amount": pending,
                "broadcast_redemption_amount": broadcast,
                "finalized_redemption_amount": finalized,
                "rejected_redemption_amount": rejected,
                "reserve_balance": total_deposited - finalized,
                "available_reserve": total_deposited - pending - broadcast - finalized,
            }

    def reserve_summary(self) -> dict[str, Any]:
        with self._lock:
            total_deposited = self._total_deposited_locked()
            finalized = sum(int(item.get("amount", 0)) for item in self._data["redemptions"].values()
                            if isinstance(item, dict) and item.get("state") == "finalized")
            reserved = self._total_reserved_locked()
            return {
                "total_deposited": total_deposited,
                "reserved_redemption_amount": reserved,
                "finalized_redemption_amount": finalized,
                "reserve_balance": total_deposited - finalized,
                "available_reserve": total_deposited - reserved,
            }

    def _total_deposited_locked(self) -> int:
        return sum(int(item.get("amount", 0)) for item in self._data["deposits"].values() if isinstance(item, dict))

    def _total_reserved_locked(self) -> int:
        return sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") in {"pending", "broadcast", "finalized"}
        )


def make_handler(config: MintConfig, state: MintState, signer: BlindSigner):
    class MintHandler(BaseHTTPRequestHandler):
        server_version = "selfcoin-mint/0.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/healthz":
                write_json(self, HTTPStatus.OK, {"ok": True, "mint_id": config.mint_id})
                return
            if self.path == "/mint/key":
                write_json(
                    self,
                    HTTPStatus.OK,
                    {
                        "algorithm": "rsa-chaum-blind",
                        "modulus_hex": format(signer.n, "x"),
                        "public_exponent": signer.e,
                    },
                )
                return
            if self.path == "/reserves":
                summary = state.reserve_summary()
                summary["mint_id"] = config.mint_id
                write_json(self, HTTPStatus.OK, summary)
                return
            if self.path == "/accounting/summary":
                summary = state.accounting_summary()
                summary["mint_id"] = config.mint_id
                write_json(self, HTTPStatus.OK, summary)
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
            if self.path == "/redemptions/update":
                self._handle_redemption_update(body)
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

            signed_blinds = []
            try:
                for msg in blinded_messages:
                    if not isinstance(msg, str) or not msg:
                        raise ValueError("blinded message must be a non-empty hex string")
                    signed_blinds.append(signer.sign_blinded_hex(msg))
                issuance = state.record_issuance(mint_deposit_ref, blinded_messages, signed_blinds)
            except ValueError as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown mint_deposit_ref"})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "signed_blinds": signed_blinds,
                    "mint_epoch": 0,
                    "issuance_id": issuance["issuance_id"],
                },
            )

        def _handle_redemption_create(self, body: dict[str, Any]) -> None:
            notes = body.get("notes")
            redeem_address = body.get("redeem_address")
            amount = body.get("amount")
            if not isinstance(notes, list) or not isinstance(redeem_address, str) or not notes or not isinstance(amount, int):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            if amount <= 0:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "amount must be positive"})
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
                "amount": amount,
                "state": "pending",
                "l1_txid": "",
            }
            try:
                state.create_redemption(redemption)
            except ValueError as exc:
                write_json(self, HTTPStatus.CONFLICT, {"error": str(exc)})
                return
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
                    "amount": redemption["amount"],
                },
            )

        def _handle_redemption_update(self, body: dict[str, Any]) -> None:
            batch_id = body.get("redemption_batch_id")
            new_state = body.get("state")
            l1_txid = body.get("l1_txid", "")
            if not isinstance(batch_id, str) or not isinstance(new_state, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            if l1_txid and not is_hex_of_size(l1_txid, 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid l1_txid"})
                return
            try:
                updated = state.update_redemption(batch_id, new_state, l1_txid)
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown redemption_batch_id"})
                return
            except ValueError as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "state": updated["state"],
                    "l1_txid": updated["l1_txid"],
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
    signer = BlindSigner.from_seed(config.signing_seed)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(config, state, signer))
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
