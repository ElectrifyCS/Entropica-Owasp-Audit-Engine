"""
Calibration harness for the ENTROPICA Audit Engine (project notes, section 1).

Two pieces:
  generators.py — synthetic-but-realistic ID sample generators, labeled
                   safe / vulnerable / mixed.
  harness.py     — runs MathCore directly against samples (real or
                    synthetic), stores raw metrics per sample, and lets
                    you sweep rule thresholds against stored data without
                    re-generating anything.
"""
