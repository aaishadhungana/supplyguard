# Demo walkthrough

About five minutes. You need the stack running (`docker compose up -d`) and the lockfile for `fixtures/npm-vulnerable` generated.

## 1. Set up the project

Sign in, create a project called "Demo Shop", and mark it internet-facing with high criticality. The scores below depend on those two settings, so set them before the first scan.

## 2. Scan the vulnerable app

Upload `fixtures/npm-vulnerable/package-lock.json`. When the scan finishes, the overview shows an overall risk score, the counts per risk level and the AI summary.

Things worth pointing out:

- **A vulnerable direct dependency.** `lodash 4.17.15` and `minimist 1.2.5` appear in the findings list with CVSS scores and fixed versions from OSV.
- **A vulnerable transitive dependency.** Open the Vulnerabilities tab, find a finding marked transitive (several come in through `express`), and open it. The attack path shows Application, then `express`, then the vulnerable package.
- **An internet-facing component.** `express` is recognized as a web framework, so findings reached through it get extra points and the path is marked as passing through an entry point.
- **A high-risk production dependency.** `jsonwebtoken` is treated as an authentication library, which adds to its score.
- **A development-only finding.** Anything that comes from `mocha` is scored at 40% of its production equivalent. Open one and look at the scope multiplier at the bottom of the score breakdown.

## 3. Read one finding closely

Open the top finding. The page shows the evidence, a factor-by-factor score, the dependency chain, a remediation hint built from OSV's fixed versions, and the Gemini analysis. The AI text is labelled and the score above it is not affected by it.

## 4. Fix and rescan

Upload `fixtures/npm-remediated/package-lock.json` to the same project. Open Compare scans, pick the first scan as Before and the second as After. You get both overall scores, counts per level, resolved and new findings, and the package versions that changed. The remediated versions are newer, but OSV may still report advisories against them. Whatever it reports is what shows up.

## 5. Gemini unavailable

Empty `GEMINI_API_KEY` in `.env` and run `docker compose up -d --force-recreate backend`. Scan again. The scan completes with the same scores and attack paths, and the overview says AI analysis is unavailable and why. Put the key back, recreate the backend and use Re-run on the overview to get the AI text.

## 6. Scan SupplyGuard with itself

Upload `backend/requirements.txt` (a Python scan) and `frontend/package-lock.json` to a new project. This is a good habit for the real repository: if either file shows findings with fixed versions, bump them and commit.

