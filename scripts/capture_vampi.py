#!/usr/bin/env python3
"""
VAmPI real-traffic capture for ENTROPICA calibration (project notes §1).

Design goals (Priority 2 — capture methodology hygiene)
-------------------------------------------------------
Previous captures mixed organic VAmPI seed data with script-injected high-
entropy usernames (register_extra_users). That made the "real" username
sample 93 % self-generated and therefore useless as evidence about VAmPI's
own scheme.

This script is explicit about provenance:

  * organic  = data that already exists in a fresh / minimally-seeded VAmPI
               instance (or that the target creates through its normal UI
               flows without our padding generators).
  * injected = data we deliberately create to pad sample size.  These
               records are labelled `source="injected"` so the harness and
               any downstream analysis can filter them out.

Default mode is **organic-only**.  Pass --allow-inject only when you
consciously want padding, and the resulting JSONL will still carry the
source label so contamination is never silent.

Also surfaces real HTTP error bodies for book-creation failures instead of
failing quietly (the add_books silent-failure issue noted in the notes).

Usage
-----
  # Organic-only (recommended for credibility)
  python scripts/capture_vampi.py --base-url http://localhost:5000 --out calibration_output/vampi_organic.jsonl

  # Allow limited injection for sample-size experiments (still labelled)
  python scripts/capture_vampi.py --base-url http://localhost:5000 --allow-inject --inject-users 10

Requires a running VAmPI instance (Docker).  Network access is mandatory;
this script is deliberately *not* part of the offline unit-test suite.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rand_suffix(n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _record(
    scheme: str,
    values: List[Any],
    *,
    source: str,
    label: str = "unknown",
    extra: Optional[Dict] = None,
) -> Dict[str, Any]:
    """One calibration-style record with explicit provenance."""
    rec = {
        "scheme": scheme,
        "label": label,
        "source": source,  # "organic" | "injected"
        "captured_at": _now_iso(),
        "n": len(values),
        "sample_preview": [str(v) for v in values[:12]],
        "values": [str(v) for v in values],
    }
    if extra:
        rec.update(extra)
    return rec


# ---------------------------------------------------------------------------
# Capture functions
# ---------------------------------------------------------------------------
def fetch_users(client: httpx.Client, base: str) -> List[str]:
    """Return usernames already present (organic)."""
    r = client.get(f"{base}/users/v1")
    r.raise_for_status()
    data = r.json()
    # VAmPI shape is typically a list of user objects or a dict with users
    if isinstance(data, list):
        return [u.get("username") or u.get("user") or str(u) for u in data if u]
    if isinstance(data, dict):
        users = data.get("users") or data.get("data") or []
        return [u.get("username") or u.get("user") or str(u) for u in users if u]
    return []


def register_user(client: httpx.Client, base: str, username: str, password: str = "calibpass1") -> bool:
    """Register one user. Returns True on success; prints body on failure."""
    payload = {
        "username": username,
        "password": password,
        "email": f"{username}@example.local",
    }
    r = client.post(f"{base}/users/v1/register", json=payload)
    if r.status_code in (200, 201):
        return True
    # Surface the real error body (fixes the previous silent-failure pattern)
    print(f"[register] FAILED {username}: HTTP {r.status_code} body={r.text[:300]}", file=sys.stderr)
    return False


def fetch_books(client: httpx.Client, base: str) -> List[str]:
    """Return book titles already present (organic)."""
    r = client.get(f"{base}/books/v1")
    if r.status_code != 200:
        print(f"[books] list failed: HTTP {r.status_code} body={r.text[:300]}", file=sys.stderr)
        return []
    data = r.json()
    if isinstance(data, list):
        return [b.get("book_title") or b.get("title") or str(b) for b in data if b]
    if isinstance(data, dict):
        books = data.get("books") or data.get("data") or []
        return [b.get("book_title") or b.get("title") or str(b) for b in books if b]
    return []


def add_book(client: httpx.Client, base: str, title: str, secret: str = "s3cret") -> bool:
    """
    Add one book. Surfaces the real response body on failure instead of
    failing silently (the exact issue called out in the project notes).
    """
    payload = {"book_title": title, "secret": secret}
    r = client.post(f"{base}/books/v1", json=payload)
    if r.status_code in (200, 201):
        return True
    print(f"[add_book] FAILED '{title}': HTTP {r.status_code} body={r.text[:400]}", file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# Main capture flow
# ---------------------------------------------------------------------------
def capture(
    base_url: str,
    *,
    allow_inject: bool = False,
    inject_users: int = 0,
    inject_books: int = 0,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    base = base_url.rstrip("/")
    records: List[Dict[str, Any]] = []

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # --- Users (organic first) ---
        organic_users = fetch_users(client, base)
        print(f"[users] organic count = {len(organic_users)}")
        if organic_users:
            records.append(
                _record(
                    "vampi_username",
                    organic_users,
                    source="organic",
                    label="unknown",  # calibration harness can re-label later
                    extra={"id_type": "non-numeric"},
                )
            )

        injected_users: List[str] = []
        if allow_inject and inject_users > 0:
            for _ in range(inject_users):
                uname = f"calib{_rand_suffix(8)}"
                if register_user(client, base, uname):
                    injected_users.append(uname)
            print(f"[users] injected count = {len(injected_users)}")
            if injected_users:
                records.append(
                    _record(
                        "vampi_username",
                        injected_users,
                        source="injected",
                        label="safe",  # high-entropy by construction
                        extra={"id_type": "non-numeric", "generator": "calib_random"},
                    )
                )

        # --- Books (organic first) ---
        organic_books = fetch_books(client, base)
        print(f"[books] organic count = {len(organic_books)}")
        if organic_books:
            records.append(
                _record(
                    "vampi_book_title",
                    organic_books,
                    source="organic",
                    label="unknown",
                    extra={"id_type": "non-numeric"},
                )
            )

        injected_books: List[str] = []
        if allow_inject and inject_books > 0:
            for i in range(inject_books):
                title = f"calibBook{_rand_suffix(6)}"
                if add_book(client, base, title):
                    injected_books.append(title)
            print(f"[books] injected count = {len(injected_books)}")
            if injected_books:
                records.append(
                    _record(
                        "vampi_book_title",
                        injected_books,
                        source="injected",
                        label="safe",
                        extra={"id_type": "non-numeric", "generator": "calib_random"},
                    )
                )

    return records


def main() -> None:
    p = argparse.ArgumentParser(description="VAmPI organic-first capture for ENTROPICA calibration")
    p.add_argument("--base-url", default="http://localhost:5000", help="VAmPI base URL")
    p.add_argument("--out", default="calibration_output/vampi_organic.jsonl", help="Output JSONL path")
    p.add_argument("--allow-inject", action="store_true", help="Permit padding with injected samples (still labelled)")
    p.add_argument("--inject-users", type=int, default=0, help="How many synthetic users to register")
    p.add_argument("--inject-books", type=int, default=0, help="How many synthetic books to create")
    args = p.parse_args()

    if not args.allow_inject and (args.inject_users or args.inject_books):
        print("Refusing to inject without --allow-inject (keeps organic captures clean).", file=sys.stderr)
        sys.exit(2)

    records = capture(
        args.base_url,
        allow_inject=args.allow_inject,
        inject_users=args.inject_users,
        inject_books=args.inject_books,
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    organic_n = sum(1 for r in records if r["source"] == "organic")
    injected_n = sum(1 for r in records if r["source"] == "injected")
    print(f"Wrote {len(records)} record(s) → {out}  (organic={organic_n}, injected={injected_n})")


if __name__ == "__main__":
    main()
