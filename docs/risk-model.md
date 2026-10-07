# SupplyGuard risk model

Every finding gets a score from 0 to 100. The same inputs always produce the same score,
and each factor's contribution is stored with the finding (`risk_breakdown`).

| Factor | Max points | How it is derived |
|---|---|---|
| Severity | 45 | CVSS v3 base score (computed from the advisory vector) x 4.5. Without a vector, the advisory's severity label is mapped to an assumed score. |
| Exploit | 20 | Listed in the CISA Known Exploited Vulnerabilities catalog. |
| Exposure | 10 | Project is marked internet-facing. |
| Component role | 7 | Package inferred (by name) to be authentication or crypto = 7; web framework, database or serialization = 5. |
| Attack path | 5 | Dependency chain passes through a web framework entry point = 5; any established chain = 2. |
| Dependency type | 3 | Direct dependency. |
| Application criticality | 10 | Project criticality: low 0, medium 4, high 7, critical 10. |

Scope multiplier: development-only dependencies are multiplied by 0.4.

Risk levels: critical >= 75, high >= 55, medium >= 35, otherwise low.

Overall scan score: 0.7 x highest finding score + 0.3 x mean of the top five scores (0 with no findings).

Findings are ranked by score, then CVSS, then advisory id, so rankings are stable.

## What is and is not established

- Established from the lockfile: the dependency chain from the application to the vulnerable package.
- Inferred: package roles (from a curated name list).
- Not analyzed: whether the vulnerable code is reachable at runtime.
- Not included yet: EPSS probability and outdated-version signals.