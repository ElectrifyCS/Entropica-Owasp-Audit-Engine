# Entropica Audit Engine

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

### 4. Miller–Madow Bias Correction — Small-Sample Entropy

**The problem**  
The plug-in entropy estimator (section 1) is negatively biased on small samples — exactly the regime a live API probe operates in, since you rarely get thousands of observations of the same field before deciding whether it looks risky. Underestimating entropy makes a genuinely random field look more predictable than it is.

**The mathematics**

$$
\mathbb{E}[\hat{H}_{\text{plugin}}] = H - \frac{K-1}{2n\ln 2} + O\!\left(\frac{1}{n^2}\right)
$$

where $K$ is the number of distinct symbols observed and $n$ is the sample size (Miller, 1955). Adding back the leading-order bias term gives the corrected estimator:

$$
\hat{H}_{\text{MM}} = \hat{H}_{\text{plugin}} + \frac{K-1}{2n\ln 2}
$$

**Why it matters**  
I checked this against a brute-force Monte Carlo simulation (sampling from a known uniform distribution and comparing the average plug-in entropy to the true entropy) — the predicted bias matched the empirical bias closely, confirming the formula holds as advertised. For large $n$ the correction vanishes and it reduces to ordinary Shannon entropy; for the small samples typical of early probing it materially reduces the systematic under-estimate.

---

### 5. Order-Statistics Keyspace Estimator — How Big Is the ID Space?

**The problem**  
Entropy tells you how random the *values you saw* are, but not how large the *underlying keyspace* is. A handful of numeric IDs clustered in a tiny range is just as much a BOLA risk as sequential IDs, even if the samples themselves aren't literally consecutive.

**The mathematics (German-tank problem)**  
Assuming IDs are drawn uniformly from an unknown integer range of length $R$, the order statistics $X_{(1)} < \dots < X_{(n)}$ of a sample of size $n$ satisfy

$$
\mathbb{E}[X_{(n)} - X_{(1)}] = R \cdot \frac{n-1}{n+1}
$$

Solving for $R$ gives the unbiased point estimator $\hat{R} = (X_{(n)}-X_{(1)}) \cdot \frac{n+1}{n-1}$, and the keyspace size in bits is $\log_2 \hat{R}$.

**The confidence interval — and a bug I caught and fixed**  
My first draft of the CI treated $\operatorname{Var}(\ln \hat{R})$ as $\approx 2/n$, reasoning from a central-limit / Gumbel-tail argument. I tested that assumption with a Monte Carlo simulation and it was wrong — off by roughly a factor of $n$. The scaled range $(X_{(n)}-X_{(1)})/R$ is actually a *known* $\text{Beta}(n-1, 2)$ random variable, so there's no need for an asymptotic approximation at all:

$$
\operatorname{Var}\!\left[\frac{W}{R}\right] = \frac{2(n-1)}{(n+1)^2(n+2)} \;\sim\; \frac{2}{n^2}, \quad \text{not } \frac{2}{n}
$$

Propagating this exact variance through the delta method gives $\sigma_{\text{bits}} = \sqrt{\operatorname{Var}(\ln\hat R)}/\ln 2$, which tightens roughly as $1/n$ instead of $1/\sqrt{n}$. The corrected version is both more accurate *and* simpler to justify, since it uses exact moments rather than an asymptotic limit — a good reminder that "asymptotically justified" isn't the same as "checked against the actual distribution."

---

### 6. EWMA Sequential Test — Sustained vs. One-Off Latency Spikes

**The problem**  
A single $|Z| > 3$ from the Welford tracker (section 2) can just be a cache miss or a GC pause. A genuine timing side-channel or scripted attack shows up as a *sustained* elevation, and a raw three-sigma rule can't tell the two apart.

**The mathematics**

$$
S_t = \lambda|Z_t| + (1-\lambda)S_{t-1}, \qquad S_0 = 0,\ \lambda \in (0,1]
$$

An alarm fires when $S_t$ exceeds a threshold $\tau$ after a minimum number of observations. The weight of an observation $k$ steps back decays as $(1-\lambda)^k$, so old anomalies stop mattering exponentially fast, using only $O(1)$ state on top of the existing Welford stream.

**Why EWMA**  
It's the natural next layer once you already have a z-score stream: single spikes stay below threshold, sustained elevation accumulates and trips the alarm. (Page's CUSUM is the formally optimal test for a sustained mean shift; EWMA is a simpler, easier-to-tune relative built on the same streaming infrastructure — CUSUM could be added later if needed.)

---

### 7. Excessive Data Exposure (API3:2023) — Same Triad, New Target

The BOLA rule (section 1) applies the entropy/sequential/keyspace triad to *resource IDs in the URL*. The new `ExcessiveDataExposureRule` applies the exact same mathematical signals to *response field values* — catching over-exposed internal IDs or predictable tokens leaking through response bodies rather than just the endpoint path. No new math here, just a second consumer of the same primitives, which is what "pure math first" (see design principles below) was supposed to buy in the first place.

---

### 8. Queue Dynamics as a Rule — Unrestricted Resource Consumption (ENTROPICA API4:2023)

The queue and acceleration model (section 3) existed as pure, tested functions before it existed as something that could produce a `Finding`. `UnrestrictedResourceConsumptionRule` is the missing plumbing: it feeds a time series of `(timestamp, arrival_rate)` observations through `QueueDynamicsTracker` and `AccelerationTracker` and raises a finding when either the modelled queue length crosses a threshold, or acceleration stays elevated for several consecutive windows in a row (see section 3 for why a single spike isn't enough evidence on its own). No new math — just closing the gap between "the model works" and "the model produces a finding."

---

### 9. Mass Assignment (ENTROPICA API6:2023) — A Structural Signal, Not a Statistical One

**The problem**  
Every rule so far measures the *randomness* of a value. Mass assignment is a different shape of vulnerability entirely: it's not about how predictable a field's value is, it's about whether a field should be settable by a client at all — e.g. a write endpoint silently accepting a `role` field that never even appears in any read response for that resource.

**The mathematics (set theory, not information theory)**  
Let $R$ be the set of field names observed in read responses for a resource, and $W$ be the set of field names accepted (not rejected) by write requests for the same resource. Two signals fall out of comparing them:

$$
\text{extra} = W \setminus R \qquad \text{(fields writable but never readable — the highest-risk set)}
$$

$$
J(R, W) = \frac{|R \cap W|}{|R \cup W|} \qquad \text{(Jaccard index — standard set-similarity measure, } 1.0 = \text{identical, } 0.0 = \text{disjoint)}
$$

A finding fires when `extra` is non-empty past a small threshold, or when $J(R,W)$ drops below a cutoff — i.e. the writable and readable surfaces have structurally drifted apart, independent of what any individual field is *named*.

**Why set theory here, and not string matching**  
The existing `ExcessiveDataExposureRule` docstring already commits to "pure mathematical signals only — no string pattern matching for 'password', 'ssn', etc." Mass assignment is the case that tests whether that principle actually holds up: you can flag the *shape* of a mass-assignment surface (a write-only field with no read counterpart) without ever needing to know or care what the field is called. Set difference and Jaccard similarity turn out to be exactly the right tool — a different branch of math (combinatorics/set theory rather than information theory) applied to a genuinely different question than every rule before it.

---

## Async probing (`worker/`) and the control plane (`api/`)

Two more pieces exist now beyond the rule math itself:

- **`worker/prober.py`** — an async HTTP prober (`httpx` + `asyncio`) that collects real evidence (resource IDs, response field samples, response latencies) and hands it to the rules above in the shapes they already expect. The one design choice worth calling out: the prober's own request concurrency is governed by the *same* `QueueDynamicsTracker` used to detect overload in section 8 — instead of a fixed requests-per-second ceiling, it tracks its own modelled queue against the target and backs off exactly when that queue would start growing. The tool uses its own detection math to avoid becoming the thing it's built to find.
- **`api/app.py`** — a small FastAPI control plane exposing the rule registry (`GET /rules`), per-rule evaluation endpoints (`POST /findings/{rule}`) for handing in evidence directly, a `POST /scans` endpoint that runs the prober against a list of URLs and auto-evaluates whatever evidence comes back, and `GET /findings` to list everything collected. Findings persist in an in-memory store for the process lifetime — SQLite is the obvious next step and the store module is already isolated so that swap won't touch the routes.

---

## Project layout


```
entropica_audit_engine/
├── core/                      # Pure math — zero I/O, fully unit-testable
│   ├── math_core.py           # Shannon/Miller–Madow entropy, sequential score, keyspace + CI
│   ├── welford.py             # Online mean/variance/z-score + EWMA sequential anomaly test
│   └── queue_dynamics.py      # Queue model + acceleration tracker
├── rules/                     # Strategy-pattern audit rules
│   ├── base.py                 # Finding schema + Severity enum
│   ├── bola.py                 # Predictable Resource ID rule (API1)
│   ├── excessive_data.py       # Excessive Data Exposure rule (API3)
│   ├── resource_consumption.py # Unrestricted Resource Consumption rule (API4)
│   ├── mass_assignment.py      # Mass Assignment rule (API6)
│   └── registry.py             # Simple plugin registry
├── worker/                    # Async HTTP probing (self-governed via queue model)
│   └── prober.py
├── api/                        # FastAPI control plane
│   ├── app.py                  # Routes
│   ├── models.py                # Pydantic request/response schemas
│   └── store.py                 # In-memory findings store
├── tests/                      # Unit tests for every module above
└── demo.py                     # Runnable end-to-end showcase
```

---

## Quick start

```bash
# Run the interactive demo
python -m entropica_audit_engine.demo

# Run the unit tests
python -m pytest entropica_audit_engine/tests/ -v

# Run the control plane locally
uvicorn entropica_audit_engine.api.app:app --reload
```

---

## Current status & roadmap

| Component                              | Status    |
|----------------------------------------|-----------|
| Math core (Entropy + Sequential score) | Done      |
| Math core (Miller–Madow + keyspace CI) | Done      |
| Math core (Welford + EWMA)             | Done      |
| Math core (Queue + Acceleration)       | Done      |
| BOLA rule (API1)                       | Done      |
| Excessive Data Exposure rule (API3)    | Done      |
| Unrestricted Resource Consumption (API4) | Done    |
| Mass Assignment rule (API6)            | Done      |
| Finding schema + Rule registry         | Done      |
| Async HTTP probing worker              | Done      |
| FastAPI control plane                  | Done      |
| Persistent storage (SQLite)            | Planned   |
| Distributed workers (Celery)           | Planned   |
| Auth on the control plane              | Planned   |

The mathematical foundations, the active probing layer, and a usable control plane are all in place now. The next phase is persistence and making the probing layer safe to point at more than a single process's worth of targets.

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

This repository will keep evolving. Persistent storage (SQLite), distributed workers (Celery), and auth on the control plane are next. Every improvement will stay grounded in the same mathematical approach — and, per section 5's confidence-interval bug, in checking that approach against reality rather than trusting that it sounds rigorous.

If you find this useful, or if you spot places where the math or the engineering can be stronger, I’d love to hear about it. This project has already taught me more than I expected — and there’s still a lot left to learn.

---

*Built as a personal research and portfolio project. Months of reading, coding, breaking things, and rebuilding them.*
