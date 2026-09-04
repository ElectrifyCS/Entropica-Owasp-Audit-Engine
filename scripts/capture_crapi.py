#!/usr/bin/env python3
"""
crAPI real-traffic capture scaffold (Priority 4).

Same provenance discipline as capture_vampi.py:
  * organic  = data already present / created by the target itself
  * injected = data we deliberately create (always labelled)

crAPI is valuable because it supplies:
  - numeric object IDs (good exercise for keyspace + sequential signals)
  - a known SSRF ground-truth for a future differential rule

This scaffold is intentionally minimal.  Expand the endpoint list once
you have a running crAPI instance and have confirmed the real routes.

Usage
-----
  python scripts/capture_crapi.py --base-url http://localhost:8888 --out calibration_output/crapi_organic.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx", file=sys.stderr)
    sys.exit(1)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(scheme: str, values: List[Any], *, source: str, label: str = "unknown", extra: Optional[Dict] = None) -> Dict:
    rec = {
        "scheme": scheme,
        "label": label,
        "source": source,
        "captured_at": _now_iso(),
        "n": len(values),
        "sample_preview": [str(v) for v in values[:12]],
        "values": [str(v) for v in values],
    }
    if extra:
        rec.update(extra)
    return rec


def capture(base_url: str, timeout: float = 10.0) -> List[Dict]:
    base = base_url.rstrip("/")
    records: List[Dict] = []

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # --- Example: vehicle / identity IDs (adjust paths to your crAPI version) ---
        # Common community crAPI routes vary; try a few and surface errors clearly.
        candidates = [
            ("/identity/api/v2/vehicle/vehicles", "crapi_vehicle_id"),
            ("/workshop/api/shop/orders", "crapi_order_id"),
            ("/identity/api/v2/user/dashboard", "crapi_user_surface"),
        ]
        for path, scheme in candidates:
            url = f"{base}{path}"
            try:
                r = client.get(url)
            except httpx.HTTPError as exc:
                print(f"[skip] {url}: {exc}", file=sys.stderr)
                continue
            if r.status_code != 200:
                print(f"[skip] {url}: HTTP {r.status_code} body={r.text[:200]}", file=sys.stderr)
                continue
            data = r.json()
            # Best-effort extraction — real shapes differ; refine once live data arrives
            values: List[Any] = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for key in ("id", "vehicleId", "orderId", "uuid", "vin"):
                            if key in item:
                                values.append(item[key])
                                break
                    else:
                        values.append(item)
            elif isinstance(data, dict):
                for key in ("vehicles", "orders", "data", "items"):
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, dict):
                                for k in ("id", "vehicleId", "orderId", "uuid"):
                                    if k in item:
                                        values.append(item[k])
                                        break
            if values:
                records.append(
                    _record(scheme, values, source="organic", extra={"id_type": "mixed", "path": path})
                )
                print(f"[ok] {scheme}: {len(values)} values from {path}")
            else:
                print(f"[empty] {path} returned 200 but no extractable IDs", file=sys.stderr)

    return records


def main() -> None:
    p = argparse.ArgumentParser(description="crAPI organic capture scaffold for ENTROPICA")
    p.add_argument("--base-url", default="http://localhost:8888")
    p.add_argument("--out", default="calibration_output/crapi_organic.jsonl")
    args = p.parse_args()

    records = capture(args.base_url)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Wrote {len(records)} record(s) → {out}")


if __name__ == "__main__":
    main()
