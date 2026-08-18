# ENTROPICA Audit Engine

**A personal deep-dive into the mathematical foundations of API security.**

This project is the result of several months of focused research, late nights, and a lot of trial and error. I set out to understand *why* certain API vulnerabilities keep appearing, not just how to detect them with off-the-shelf tools. What started as curiosity about Shannon entropy and online algorithms slowly turned into a working engine that treats security findings as measurable mathematical signals.

I built this the hard way — reading papers, implementing the formulas from scratch, watching floating-point errors appear, fixing them, and slowly learning how pure math can sit underneath real security checks. Every module here represents something I had to wrestle with until it clicked.

---

## The Math & The Reasoning

### 1. Shannon Entropy — Predictable Resource IDs (ENTROPICA API1:2023)

**The problem**  
Broken Object Level Authorization (BOLA) often starts with IDs that an attacker can guess. Sequential integers (`1001`, `1002`, `1003`…) or short repeated tokens give away the structure of the backend. Most scanners only look for the presence of an ID parameter; they rarely ask *how random* that ID actually is.

**The mathematics**

$$
H(X) = -\sum_{i=1}^{N} P(x_i) \log_2 P(x_i)
$$

- $H(X) \to 0$ when the same symbols dominate (highly predictable).
- $H(X) \to \log_2 |\text{alphabet}|$ when every symbol is equally likely (maximum uncertainty).

I also compute a **normalized entropy** in $[0,1]$ so that short and long IDs can be compared fairly, and a **sequential score** that measures how often consecutive numeric IDs differ by a small constant step. Entropy alone can be misleading on very short strings; the sequential score catches the classic auto-increment pattern that pure entropy sometimes under-penalizes.

**Why it matters**  
A finding is raised when average entropy falls below a threshold *or* the sequential score is high. Both signals are returned in the metrics so the result is explainable, not just a boolean.

---

### 2. Streaming Welford Algorithm — Latency & Side-Channel Anomalies

**The problem**  
Timing side-channels and unhandled database locking often appear as sudden spikes in response latency. Calculating mean and variance with the classic two-pass formula is both memory-heavy and numerically unstable on long streams.

**The mathematics** (Welford’s online algorithm)

$$
M_k = M_{k-1} + \frac{x_k - M_{k-1}}{k}
$$

$$
S_k = S_{k-1} + (x_k - M_{k-1})(x_k - M_k)
$$

Sample standard deviation and z-score follow directly:

$$
s_k = \sqrt{\frac{S_k}{k-1}}, \qquad Z = \frac{x_k - M_k}{s_k}
$$

**Why Welford**  
I first implemented the naïve sum-of-squares approach and watched catastrophic cancellation destroy the variance on real traffic. Welford keeps a running mean and a compensated sum of squared differences, giving stable results in $O(1)$ memory. An anomaly is flagged when $|Z| > 3$ (a conventional three-sigma rule). The tracker returns the full snapshot (count, mean, std, latest z) so every alert stays transparent.

---

### 3. Differential Queue Dynamics — Unrestricted Resource Consumption (ENTROPICA API4)

**The problem**  
Rate-limiting and resource exhaustion attacks are usually detected with simple sliding-window counters. Those counters lose the *dynamics* of the attack — how fast the queue is growing and whether the arrival rate itself is accelerating.

**The continuous model**

$$
\frac{dQ}{dt} = \lambda(t) - \mu
$$

where $\lambda(t)$ is the observed arrival rate and $\mu$ is the estimated service (drain) rate of the endpoint.

**Discrete recurrence used in code**

$$
Q_{k+1} = \max\bigl(0,\; Q_k + (\lambda_k - \mu)\Delta t\bigr)
$$

**Acceleration (second derivative)**  
To distinguish organic spikes from automated tools I also track the first and second derivatives of the request rate:

$$
R'(t) \approx \text{velocity}, \qquad R''(t) \approx \text{acceleration}
$$

Sustained high positive acceleration is a strong indicator of scripted / brute-force traffic.

**Why this formulation**  
Treating the endpoint as a simple queue makes the overload condition intuitive: when arrivals consistently exceed the drain rate the queue grows without bound. The acceleration term adds a second signal that pure rate counters miss. Both $Q(t)$ and $R''(t)$ are exposed in the metrics.

---

## Project layout

```
ENTROPICA_audit_engine/
├── core/                 # Pure math — zero I/O, fully unit-testable
│   ├── math_core.py      # Shannon entropy + sequential score
│   ├── welford.py        # Online mean / variance / z-score
│   └── queue_dynamics.py # Queue model + acceleration tracker
├── rules/                # Strategy-pattern audit rules
│   ├── base.py           # Finding schema + Severity enum
│   ├── bola.py           # Predictable Resource ID rule (API1)
│   └── registry.py       # Simple plugin registry
├── tests/                # Unit tests for the mathematical core
├── demo.py               # Runnable end-to-end showcase
├── api/                  # FastAPI control plane (next)
└── worker/               # Async HTTP probes + Celery (next)
```

---

## Quick start

```bash
# Run the interactive demo
python -m ENTROPICA_audit_engine.demo

# Run the unit tests
python -m pytest ENTROPICA_audit_engine/tests/ -v
```

---

## Current status & roadmap

| Component                              | Status    |
|----------------------------------------|-----------|
| Math core (Entropy + Sequential score) | Done      |
| Math core (Welford)                    | Done      |
| Math core (Queue + Acceleration)       | Done      |
| BOLA rule (API1)                       | Done      |
| Finding schema + Rule registry         | Done      |
| Async HTTP probing workers             | Next      |
| FastAPI control plane                  | Planned   |
| Additional rules (Mass Assignment …)   | Planned   |

The mathematical foundations are solid and covered by tests. The next phase turns the pure functions into live probes and a usable control plane.

---

## Design principles I learned the hard way

1. **Pure math first** — every statistical primitive lives in `core/` with zero side effects.
2. **Explainable findings** — every alert carries the actual metrics (entropy bits, z-score, queue length, acceleration), not just a true/false.
3. **Streaming by default** — Welford and the queue tracker work on unbounded live traffic.
4. **Strategy / plugin pattern** — new checks are just new subclasses of `BaseAuditRule`.
5. **Numerical honesty** — prefer algorithms that remain stable under real data rather than the simplest textbook formula.

---

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

You are free to use, copy, modify, merge, publish, distribute, and sell copies of the software, provided the copyright notice and permission notice are included.

---

## Looking ahead

This repository will keep evolving. I plan to add real HTTP workers, more ENTROPICA API rules, and eventually a small FastAPI control plane. Every improvement will stay grounded in the same mathematical approach.

If you find this useful, or if you spot places where the math or the engineering can be stronger, I’d love to hear about it. This project has already taught me more than I expected — and there’s still a lot left to learn.

---

*Built as a personal research and portfolio project. Months of reading, coding, breaking things, and rebuilding them.*
