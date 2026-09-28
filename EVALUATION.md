# Evaluation results

How the system was evaluated, the numbers it produced, and — just as
importantly — what those numbers do and do not prove.

---

## Method

Two precautions make this evaluation honest rather than circular:

1. **Held-out data.** The detectors' thresholds were tuned against one
   synthetic dataset (seed 42). Evaluation was run on a *separate* dataset
   generated with a different random seed (2026): same categories of threat,
   different specific events. Testing on unseen data shows the system
   generalises rather than having been fitted to the test set. This directly
   addresses the simulation-validity concern raised in Risk R2.

2. **Ground-truth labels.** Every row in the synthetic data carries a label
   (normal, or the specific threat type). Each generated alert is matched back
   to its source row's label, so true positives and false positives are
   counted objectively rather than by inspection.

Metrics follow the definitions in Section 1.4:
- Detection rate = threats detected / threats injected   (target > 80%)
- False positive rate = false positives / normal events  (target < 20%)

---

## Results (held-out dataset)

| Metric | Result | Target | Outcome |
|--------|--------|--------|---------|
| Normal events | 484 | — | — |
| Injected threats | 15 | — | — |
| True positives | 15 | — | — |
| False positives | 0 | — | — |
| Detection rate | 100% | > 80% | PASS |
| False positive rate | 0% | < 20% | PASS |

Both success criteria are met on data the system was not tuned against.

---

## Interpretation — what the numbers mean (and don't)

A perfect score must be read carefully. It does **not** mean the system would
achieve 100% in a real organisation. It means the synthetic threats are clear
examples of exactly the behaviours the four rules target — a 03:00 login
against a 09:00–17:00 baseline, a tight burst of failed logins. On clean,
unambiguous cases the detectors fire reliably, which is the correct and
expected outcome.

The honest limitation is **false negatives on subtle threats.** A separate
test injected two deliberately subtle events:

- a login at 18:30 (just past the active-hours tolerance) — *detected*
- a slow brute-force: 5 failed logins spread over 30 minutes, instead of a
  burst within 10 minutes — *not detected*

The slow brute-force evades the count rule because it falls outside the
configured window. This is not a defect; it is the defining property of
rule-based detection, acknowledged in Section 2.2: such systems detect only
the patterns they are configured to recognise, and novel behaviour can fall
outside the rules entirely. It is precisely why the false negative rate is
treated as a real concern rather than assumed away, and why a production
system would tune thresholds against observed attacker behaviour over time.

---

## Reproducibility (NFR-09)

The evaluation is deterministic. Re-running `python src/evaluate.py` produces
identical numbers every time, because both the data generation (fixed seed)
and the scoring (no randomness) are deterministic. The 33-test unit suite
includes an explicit determinism test for the scorer.

---

## How to reproduce

```bash
python src/evaluate.py     # runs the held-out evaluation, prints the table
python -m pytest tests/ -v # runs all 33 unit tests
```
