# Theory — the ideas this project stands on (PPT: slides 1–2)

## 1. IAM in one minute

Cloud IAM answers three questions for every API call: **who** is calling
(Principal — a user, service, or role), **what** they may do (Permission/Action —
`read a file`, `delete a VM`, `mint a new user`), and **where** (Resource — a
bucket, table, project). A **Role** bundles permissions; a **Policy** writes the
bundle down as a versioned document (`v1 → v2 → …`). An **access log**
(CloudTrail / Audit Logs) records which keys were actually turned, when.

## 2. Least privilege

Everyone holds the *minimum* access their job needs. Violations look like
wildcards (`ec2:*`, `iam:*`) and dormant admin grants: one stolen credential
then opens every door (see `AttackGraphView` / `POST /api/duel`: BREACHED → HELD).

## 3. The core insight: NOT OBSERVED ≠ PROVEN UNNEEDED

Permissions divide into four fates (`GET /api/roles/{id}/temporal`):

| Class | Meaning | Action |
|---|---|---|
| FREQUENT | Used constantly, logged | Keep |
| RARE_BUT_CRITICAL | ~Zero logs, but required (annual DR, year-end billing) | **Keep — this is where naive tools kill prod** |
| SEASONAL_CANDIDATE | Periodic spikes | Human review |
| DEAD | Nothing needs it | Remove with proof |

## 4. Hidden transitive couplings (the trap)

Real systems hide dependencies *between* services: reading an S3 object
encrypted with a customer KMS key (SSE-KMS) silently requires `kms:Decrypt`;
reading a CMEK-encrypted GCS object silently requires
`cloudkms.cryptoKeyDecrypter`. Neither appears in access logs. Only
**counterfactual simulation** (rehearsing the removal against real workflows)
plus **dependency-graph discovery** (`PaymentService → S3 → KMS`) catches them —
which is why this product simulates *before* mutating, replans on failure,
and verifies after.
