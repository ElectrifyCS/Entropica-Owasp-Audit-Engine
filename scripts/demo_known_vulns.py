#!/usr/bin/env python3
"""
Demonstrate that ENTROPICA catches *known* vulnerabilities, not just
calibrates thresholds against ID samples.

Priority 3 from the research notes:
  "Catch an actual known vulnerability, not just calibrate against ID
   samples — VAmPI has a real BOLA (read another user's data by swapping
   the username in a request), crAPI has a real SSRF."

This script is deliberately offline-friendly for the parts that only need
the rule math, and documents the live steps required when Docker/network
are available.

What it proves today (no network required)
------------------------------------------
1. PredictableResourceIDRule + templated-ID signal fires on the exact
   VAmPI book-title pattern that previously scored "safe".
2. A synthetic "username-swap BOLA" evidence set produces a Finding with
   clear metrics (the shape of evidence a live capture would hand the rule).

What still needs a live VAmPI / crAPI instance
----------------------------------------------
3. Actually perform the username-swap request against a running VAmPI and
   confirm the response contains another user's data → then feed the
   observed IDs / fields into the same rule path.
4. crAPI SSRF differential check (skeleton only; full differential rule
   is future work).

Usage
-----
  python scripts/demo_known_vulns.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Ensure package is importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entropica_audit_engine.rules.bola import PredictableResourceIDRule
from entropica_audit_engine.explain import explain


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


async def demo_templated_book_titles() -> None:
    """Reproduces the real-data finding that motivated the structural signal."""
    section("1. Templated book titles (the pattern whole-string entropy missed)")
    rule = PredictableResourceIDRule(entropy_threshold=3.0)
    # Exact organic-style titles observed in the partial live capture
    ids = ["bookTitle7", "bookTitle38", "bookTitle17", "bookTitle42"]
    finding = await rule.execute(
        "http://vampi.local/books/v1/{id}",
        sample_ids=ids,
    )
    assert finding is not None, "Expected a Finding for templated book titles"
    print("triggered_by :", finding.metrics["triggered_by"])
    print("common_prefix:", finding.metrics.get("common_prefix"))
    print("suffix_entropy:", finding.metrics.get("avg_suffix_entropy_bits"))
    print("whole-string entropy:", finding.metrics.get("avg_entropy_bits"))
    print("\nExplain output:")
    print(explain(finding))
    assert "templated_id" in finding.metrics["triggered_by"]
    print("\n✓ Structural signal correctly flags the known templated pattern.")


async def demo_username_swap_bola_shape() -> None:
    """
    Shows the *shape* of evidence a live VAmPI BOLA (username swap) would
    produce.  Live step (when Docker is up):

      1. Register / login as user A.
      2. Request /users/v1/{username_of_B} (or equivalent object endpoint).
      3. Observe that the response contains B's data → authorization failure.
      4. Collect the set of usernames / object IDs observed across such
         probes and feed them here as sample_ids / field samples.

    Until that live step is run, we demonstrate with a realistic sample
    that includes both organic short names and the kind of sequential /
    low-entropy identifiers that make object-level access trivial.
    """
    section("2. Username / object-ID surface consistent with VAmPI BOLA")
    rule = PredictableResourceIDRule()
    # Mixed sample: a few organic-style short names + sequential-looking IDs
    # that an attacker would iterate after discovering the pattern.
    sample = ["name1", "name2", "admin", "user3", "user4", "user5"]
    finding = await rule.execute(
        "http://vampi.local/users/v1/{username}",
        sample_ids=sample,
    )
    if finding is None:
        print("No Finding raised on this particular sample (thresholds not crossed).")
        print("Live demonstration still required: perform the actual username-swap")
        print("request against a running VAmPI and feed the observed response fields.")
    else:
        print("triggered_by :", finding.metrics["triggered_by"])
        print("\nExplain output:")
        print(explain(finding))
        print("\n✓ Rule produced a Finding on a VAmPI-shaped username surface.")
    print(
        "\nLive checklist (when VAmPI is running):\n"
        "  [ ] Login as user A\n"
        "  [ ] Request another user's resource by swapping the username/id\n"
        "  [ ] Confirm response contains data belonging to user B\n"
        "  [ ] Capture the set of identifiers observed and re-run this demo\n"
        "  [ ] Confirm Finding is raised and explain() text is actionable"
    )


async def demo_crapi_ssrf_skeleton() -> None:
    section("3. crAPI SSRF — skeleton only (Priority 4 / future differential rule)")
    print(
        "crAPI ships a known SSRF.  A full differential / side-channel rule is\n"
        "not yet implemented.  When it is, the demonstration path will be:\n"
        "  1. Baseline latency / response shape for a safe internal URL\n"
        "  2. Probe a known-vulnerable parameter with an attacker-controlled URL\n"
        "  3. Compare (Welford z-score + EWMA + optional content differential)\n"
        "  4. Emit a Finding with the observed metrics\n\n"
        "Until then this section only records the intended ground-truth target."
    )
    print("Status: skeleton documented — implementation still open.")


async def main() -> None:
    print("ENTROPICA — known-vulnerability demonstration (Priority 3)")
    await demo_templated_book_titles()
    await demo_username_swap_bola_shape()
    await demo_crapi_ssrf_skeleton()
    section("Summary")
    print(
        "• Templated-ID structural signal: proven against the real pattern that\n"
        "  previously escaped whole-string entropy.\n"
        "• Username-swap BOLA: rule path ready; live request still required for\n"
        "  full end-to-end proof.\n"
        "• crAPI SSRF: documented as next differential-rule target.\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
