"""
Capture real resource-ID samples from a locally running VAmPI instance
and fold them into the calibration harness's JSONL record store.

This is the "real/realistic API traffic" half of project notes section 1
that the synthetic generators can't provide on their own — everything
downstream (records_from_samples, the sweep, the report) already works
on any (samples, label) pair, synthetic or real; this script is just the
missing glue that gets real samples into that shape.

IMPORTANT — the read-endpoint shapes below (GET /users/v1, GET /books/v1)
are now confirmed against a real running VAmPI instance, not guessed:
  - GET /users/v1 -> {"users": [{"username": ..., "email": ...}, ...]}
  - GET /books/v1 -> {"Books": [{"book_title": ..., "user": ...}, ...]}
    (note the capital "Books" and the "book_title" field name - both
    differ from what a consistent API would suggest, and both were wrong
    in the first draft of this script until checked against real output.)

Still unverified: the exact field names POST /users/v1/register and
POST /books/v1 expect for *writing* new data (register_extra_users and
add_books below are still best-effort guesses). If register_extra_users
creates 0 users, check the response body it gets back - VAmPI's Swagger
UI at /ui/ has the authoritative request schema if the guessed field
names are wrong.

Prerequisites
-------------
    docker run -d --name vampi -e vulnerable=1 -e tokentimetolive=18000 -p 5000:5000 erev0s/vampi:latest
    curl http://localhost:5000/createdb

Usage
-----
    python -m entropica_audit_engine.calibration.capture_vampi

Ground truth: captured records are stored with label="unknown" (not
"safe" or "vulnerable") — we don't have an authoritative answer on how
predictable VAmPI's dummy usernames/titles are *by design*, and the
harness's own docstring says exactly this case belongs under
"unknown" rather than a guessed label. Sweeps and confusion counts
correctly skip "unknown" rows, but scheme_summary and the raw JSONL
still capture their metrics — that's the useful part: comparing real
metric *distributions* against the synthetic safe/vulnerable ones,
even without a hard label on this particular capture.
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path
from typing import Any, List, Optional

import httpx

from entropica_audit_engine.calibration.harness import (
    load_jsonl,
    save_jsonl,
    render_markdown,
    records_from_samples,
)

VAMPI_BASE = "http://localhost:5000"
OUTPUT_DIR = Path("calibration_output")
JSONL_PATH = OUTPUT_DIR / "calibration_records.jsonl"
MD_PATH = OUTPUT_DIR / "calibration_report.md"

REGISTER_COUNT = 40  # VAmPI's seeded dummy data alone is too small an n to be useful
BOOK_COUNT = 40


def _random_suffix(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _extract_list(payload: Any, wrapper_key: str) -> List[dict]:
    """
    VAmPI's docs don't pin down whether list endpoints return a bare
    JSON array or {"<wrapper_key>": [...]}. Handle both; if this
    returns [] where you expected data, that's the mismatch to fix.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and wrapper_key in payload:
        return payload[wrapper_key]
    return []


def seed_database(client: httpx.Client) -> None:
    resp = client.get("/createdb")
    resp.raise_for_status()


def register_extra_users(client: httpx.Client, count: int) -> List[str]:
    created = []
    printed_error = False
    for _ in range(count):
        username = f"calib{_random_suffix()}"
        payload = {
            "username": username,
            "password": "CalibrationPass123!",
            "email": f"{username}@example.com",
        }
        try:
            resp = client.post("/users/v1/register", json=payload)
            if resp.status_code in (200, 201):
                created.append(username)
            elif not printed_error:
                # First failure only - print the real error body, so a
                # wrong field-name guess is visible immediately instead
                # of just "0 users created" with no clue why.
                print(f"  register failed ({resp.status_code}): {resp.text[:300]}", file=sys.stderr)
                printed_error = True
        except httpx.HTTPError:
            continue
    return created


def login(client: httpx.Client, username: str, password: str) -> Optional[str]:
    try:
        resp = client.post("/users/v1/login", json={"username": username, "password": password})
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    return data.get("auth_token") or data.get("token")


def add_books(client: httpx.Client, token: str, count: int) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(count):
        title = f"book{_random_suffix()}"
        try:
            client.post("/books/v1", json={"title": title, "secret": "calibration"}, headers=headers)
        except httpx.HTTPError:
            continue


def capture_usernames(client: httpx.Client) -> List[str]:
    resp = client.get("/users/v1")
    resp.raise_for_status()
    users = _extract_list(resp.json(), "users")
    return [u["username"] for u in users if isinstance(u, dict) and "username" in u]


def capture_book_titles(client: httpx.Client) -> List[str]:
    resp = client.get("/books/v1")
    resp.raise_for_status()
    # Confirmed against a real VAmPI instance: the wrapper key is "Books"
    # (capital B, unlike "users" for the users endpoint - inconsistent,
    # but that's VAmPI's actual API, not a guess), and the field holding
    # the title is "book_title", not "title".
    books = _extract_list(resp.json(), "Books")
    return [b["book_title"] for b in books if isinstance(b, dict) and "book_title" in b]


def main() -> None:
    print("Sanity check first, if this is your first run:")
    print("  curl http://localhost:5000/users/v1")
    print("  curl http://localhost:5000/books/v1")
    print("...and confirm the JSON shape matches what _extract_list() expects.\n")

    with httpx.Client(base_url=VAMPI_BASE, timeout=10.0) as client:
        print("Seeding database via /createdb ...")
        seed_database(client)

        print(f"Registering {REGISTER_COUNT} extra users for a usable sample size ...")
        created_usernames = register_extra_users(client, REGISTER_COUNT)
        if not created_usernames:
            print(
                "WARNING: registered 0 users — check the container is running and "
                "that /users/v1/register's expected field names match register_extra_users().",
                file=sys.stderr,
            )

        print("Capturing usernames from /users/v1 ...")
        usernames = capture_usernames(client)
        print(f"  -> {len(usernames)} usernames")

        token = None
        if created_usernames:
            token = login(client, created_usernames[0], "CalibrationPass123!")
        titles: List[str] = []
        if token:
            print(f"Adding {BOOK_COUNT} books for a usable title sample ...")
            add_books(client, token, BOOK_COUNT)
            print("Capturing book titles from /books/v1 ...")
            titles = capture_book_titles(client)
            print(f"  -> {len(titles)} book titles")
        else:
            print("Skipping book capture — could not log in as a newly created user.", file=sys.stderr)

    new_records = []
    if usernames:
        new_records.append(
            records_from_samples("vampi_username_live", usernames, label="unknown", seed=1)
        )
    if titles:
        new_records.append(
            records_from_samples("vampi_book_title_live", titles, label="unknown", seed=1)
        )

    if not new_records:
        print("Nothing captured — nothing written. See the WARNINGs above.", file=sys.stderr)
        sys.exit(1)

    existing = load_jsonl(str(JSONL_PATH)) if JSONL_PATH.exists() else []
    combined = existing + new_records
    save_jsonl(combined, str(JSONL_PATH))
    MD_PATH.parent.mkdir(parents=True, exist_ok=True)
    MD_PATH.write_text(render_markdown(combined))

    print(f"\nWrote {len(new_records)} real-traffic record(s) into {JSONL_PATH}")
    print(f"Report regenerated at {MD_PATH} (now includes {len(combined)} total records)")


if __name__ == "__main__":
    main()
