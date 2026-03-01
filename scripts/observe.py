#!/usr/bin/env python3
import argparse
import json
import sys
import time
import urllib.request


def rpc(url: str, method: str, params: dict) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        obj = json.loads(resp.read().decode("utf-8"))
    if "error" in obj:
        raise RuntimeError(str(obj["error"]))
    return obj["result"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Observe multiple SelfCoin lightservers and detect divergence.")
    ap.add_argument("urls", nargs="+", help="JSON-RPC endpoint URLs, e.g. http://host:19444/rpc")
    ap.add_argument("--interval", type=float, default=2.0, help="Polling interval seconds")
    ap.add_argument("--max-intervals", type=int, default=0, help="Stop after N intervals (0 = forever)")
    ap.add_argument("--mismatch-threshold", type=int, default=3, help="Exit non-zero after this many bad intervals")
    args = ap.parse_args()

    mismatch_streak = 0
    interval_count = 0

    while True:
        rows = []
        tips = []
        for url in args.urls:
            try:
                tip = rpc(url, "get_tip", {})
                h = int(tip["height"])
                hs = str(tip["hash"])
                rows.append((url, h, hs, "ok"))
                tips.append((h, hs))
            except Exception as exc:
                rows.append((url, -1, "error", f"err:{exc}"))
                tips.append((-1, "error"))

        best_h = max(h for h, _ in tips)
        canonical = max(tips, key=lambda t: (t[0], t[1]))
        mismatch = False

        print("server\theight\thash\tlag\tstatus")
        for url, h, hs, st in rows:
            lag = max(0, best_h - h) if h >= 0 else -1
            row_status = st
            if h >= 0 and (h, hs) != canonical:
                row_status = "mismatch"
                mismatch = True
            print(f"{url}\t{h}\t{hs[:16]}...\t{lag}\t{row_status}")
        print("")

        if mismatch:
            mismatch_streak += 1
        else:
            mismatch_streak = 0

        if mismatch_streak >= args.mismatch_threshold:
            print(f"mismatch persisted for {mismatch_streak} intervals", file=sys.stderr)
            return 2

        interval_count += 1
        if args.max_intervals > 0 and interval_count >= args.max_intervals:
            return 0

        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

