---
name: merge-fix
description: >
  Merge a confirmed vm2 vulnerability fix from its temporary private fork (ghsa-<short-id>)
  into local main, resolve every conflict, scrub external attribution, and re-run the full
  test surface before the release pass. Use after the reporter has confirmed the fix on the
  per-advisory branch and the user asks to "merge fix", "merge advisory", "integrate fix",
  "land GHSA", "merge the private fork", or otherwise wants to bring `fix/GHSA-<full-id>`
  into local main. Strictly the local integration step — NEVER pushes to origin and NEVER
  publishes.
---

# Merge Fix — vm2 Local Landing Agent

You are landing a confirmed, embargoed vm2 sandbox fix from its per-advisory branch into local `main`. The fix has already been reviewed on the private fork; your job is the **mechanical integration**: fetch the latest fork state, merge into `main`, resolve every conflict deliberately, scrub any external attribution, re-prove the test surface still holds, and stop. **You never push to `origin`.** Publication is a separate, deliberate step the user performs by hand.

This skill is the direct continuation of `/fix-vulnerability` step 8e. Read that skill if you are unsure about the branch / fork conventions it sets up — this skill consumes those invariants without re-deriving them.

---

## Inputs

The user invokes this skill with a GHSA ID (e.g. `GHSA-9g8x-92q2-p28f`). From that you derive:

- **Full ID** — the argument verbatim, used for the branch name `fix/<full-GHSA-id>`.
- **Short ID** — the leading chunk after `GHSA-` (e.g. `9g8x`), used for the remote name `ghsa-<short-id>` and the fork repo `patriksimek/vm2-ghsa-<full-id>`.

If the argument is missing or malformed, stop and ask the user for the GHSA ID. Do not guess.

---

## Hard rules

1. **Never push to `origin`.** Not at any point. Not even with the user's prompting unless they re-invoke a publish flow themselves outside this skill.
2. **Never include external attribution** in any commit message, code comment, CHANGELOG entry, or ATTACKS.md edit you author or rewrite. No reporter names, no handles, no embargo dates, no advisory disclosure dates. Internal GHSA IDs are fine (they are public identifiers of the issue, not of the human).
3. **Local `main` is the integration line.** Local `main` may be **ahead** of `origin/main` — that is the normal batching case where several advisories land back-to-back before a single push. What is forbidden is local `main` being **diverged** from `origin/main` (origin has commits local does not, *and* local has commits origin does not). If diverged, surface and stop. Do not auto-reconcile.
4. **One advisory per invocation.** If the user wants two advisories integrated, do them one after another, with a fresh skill run each time. Conflict resolution context does not carry across.
5. **Squash, not merge commit.** Recent main history is linear (`git log --format='%h %p %s' main` shows single-parent commits for every prior `fix(GHSA-…)` landing). Match that. The branch's iterative WIP commits collapse into one polished commit on `main`.

---

## Workflow

### 1. Preflight

Verify everything is in place before touching git state:

```bash
# Current branch — must not be in the middle of a rebase/merge
git status --porcelain=v1 -b

# The per-advisory remote and branch must exist
git remote -v | grep -E "^ghsa-<short-id>\s"
git branch --list "fix/<full-GHSA-id>"

# Working tree must be clean (no uncommitted, no untracked stash candidates)
git diff --quiet && git diff --cached --quiet
```

If any check fails, stop and report exactly what is missing. Do **not**:
- Create the remote yourself (that is the fix-vulnerability skill's job, and the wrong remote URL silently lands wrong code).
- Stash or discard uncommitted work. Ask the user to resolve it.
- Proceed if there is a `.git/MERGE_HEAD`, `.git/REBASE_HEAD`, or `.git/CHERRY_PICK_HEAD`.

### 2. Confirm reporter approval (verify, don't gate)

The skill is invoked **after** the reporter confirms, but verify the trail exists so you can quote it in the commit body if needed:

Read the thread in Chrome, signed in as `patriksimek-bot`: `navigate` to
`https://github.com/patriksimek/vm2/security/advisories/<GHSA-id>`, then `get_page_text`.

Scan the last few comments for explicit confirmation tokens: phrasing like "fix looks good", "no bypass found", "confirmed", "LGTM", "happy with the patch", or the reporter ack'ing the latest commit SHA on the private fork. **Do not paraphrase any confirmation language into your commit message** — it leaks attribution. Just use its presence as your green light. If you cannot find confirmation, surface the latest 1–2 comments verbatim to the user and ask whether to proceed.

Do not fall back to `gh api` for thread content — the comment thread is not in the REST payload.

### 2b. Advisory metadata audit (collect, do not mutate)

Before any merge happens, fetch the advisory's structured metadata and check whether it is publication-ready. This skill **never edits the advisory** — the maintainer fills these fields by hand in the GHSA UI. The skill's job is only to surface what is missing so the user can fix it before the release pass.

```bash
gh api /repos/patriksimek/vm2/security-advisories/<GHSA-id> \
  --jq '{state, severity, cvss, cvss_severities, cwe_ids, vulnerabilities}'
```

Collect into a `ghsa_action_items` list (carry it through to the final summary in step 8) every check below that fails. **Do not stop the workflow on these failures** — integration continues. These are post-merge follow-ups for the user.

Checks:

1. **Affected version range present.** For every entry in `vulnerabilities[]`, `vulnerable_version_range` must be a non-empty string. Empty or `null` → action item:
   `Advisory missing vulnerable_version_range for package <name> — fill in the GHSA UI (e.g. "<= 3.11.3").`
2. **Patched versions filled.** For every entry in `vulnerabilities[]`, `patched_versions` must be non-empty. Empty `patched_versions` is normal *before* a release, but at merge time the user is one step from cutting a release; flag it so they remember to set it. Action item:
   `Advisory missing patched_versions for package <name> — set to the version this fix ships in (likely <bumped version from step 5c>).`
3. **Affected package range covers the merge target.** If `vulnerable_version_range` is present, sanity-check that the current `main` `package.json` version (pre-bump) satisfies it. A range like `<= 3.10.0` on an advisory landing into `3.11.3` is almost certainly stale — the reporter probably tested against the latest version and the range was never updated. Action item:
   `Advisory vulnerable_version_range "<range>" does not cover current main version <X.Y.Z> — verify and widen if the bug reproduces on the latest release.`
4. **CVSS vector set.** At least one of `cvss.vector_string` or `cvss_severities.cvss_v3.vector_string` must be a non-null CVSS v3.x vector. A bare `severity` string ("high", "critical") without a vector is incomplete — downstream scanners need the vector. Action item:
   `Advisory missing CVSS v3 vector — current severity label is "<severity>", but no vector is set. Fill in the GHSA UI (Severity → CVSS calculator).`
5. **CVSS vector internally consistent with severity label.** If a vector is set, compute its base score range and confirm it matches `severity`:
   - 0.1–3.9 → low
   - 4.0–6.9 → medium
   - 7.0–8.9 → high
   - 9.0–10.0 → critical
   Mismatch (e.g. vector scores 9.8 but `severity` is "high") → action item:
   `Advisory CVSS vector "<vector>" scores <X.Y> (<derived-severity>) but severity label is "<severity>" — reconcile in the GHSA UI.`
6. **CWE present.** `cwe_ids` should be non-empty. Empty → action item:
   `Advisory missing CWE — add the appropriate CWE in the GHSA UI (look up by attack class; e.g. CWE-1336 for sandbox escape via prototype pollution, CWE-913 for unsafe deserialization).`

**Propose concrete values, do not just flag absence.** When an action item is about a missing CVSS vector or CWE, derive a specific suggestion from the merged fix and include it in the action item so the user can paste it directly into the GHSA UI:

- **CVSS vector.** Build a CVSS v3.1 vector from what the merged commit actually shows. For vm2, the recurring shape is sandbox escape → arbitrary host code execution, which lands at `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (9.8, critical). Adjust only the dimensions the specific fix changes — e.g. attack-complexity `AC:H` when the PoC needs a race, `UI:R` when sandbox invocation requires victim interaction (rare for vm2), `S:U` and reduced CIA when the bug is sandbox-internal DoS rather than escape (e.g. memory exhaustion landing closer to `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → 7.5, high). State the vector and the score it computes to in the action item, and call out which dimension you departed from the default for, so the user can sanity-check the call rather than blindly paste.
- **CWE.** Pick the closest match from the small set vm2 actually uses, based on the attack class the fix addresses:
  - Sandbox escape via proxy/prototype/realm boundary failure → `CWE-913` (Improper Control of Dynamically-Managed Code Resources) when sandbox code escapes to the host realm.
  - Bypass of a specific defensive check (e.g. `bufferAllocLimit`, timeout, frozen intrinsic) without a full escape → `CWE-693` (Protection Mechanism Failure).
  - Prototype pollution leading to escape → `CWE-1321` (Improperly Controlled Modification of Object Prototype Attributes).
  - Resource exhaustion / DoS inside or via the sandbox → `CWE-770` (Allocation of Resources Without Limits or Throttling).
  - Information disclosure of host-realm internals without code execution → `CWE-200` (Exposure of Sensitive Information to an Unauthorized Actor).
  Include the chosen CWE ID *and* a one-clause rationale tied to the merged fix in the action item.

These are starting points calibrated for the next paste, not verdicts. The user still makes the final judgment in the GHSA UI; the skill's job is to remove the "stare at a blank CVSS calculator" step.

Print nothing about this audit yet; keep `ghsa_action_items` in memory and emit it in the step-8 summary block.

### 3. Sync the private fork as source of truth

The maintainer may have made small final tweaks on the private fork through the GitHub UI after the last local push. The **remote `ghsa-<short-id>/main` is the source of truth**, not the local `fix/GHSA-<full-id>` branch:

```bash
git fetch ghsa-<short-id>

# Show local vs remote head — they should match, but the remote wins on disagreement
git rev-parse fix/<full-GHSA-id> ghsa-<short-id>/main
git log --oneline fix/<full-GHSA-id>..ghsa-<short-id>/main
git log --oneline ghsa-<short-id>/main..fix/<full-GHSA-id>
```

If the local branch has commits the remote does not, the local copy carries work the reporter has not seen. Stop and surface them. The user must either push them and get re-confirmation, or drop them, before integration proceeds.

If the remote is ahead, fast-forward the local branch:

```bash
git checkout fix/<full-GHSA-id>
git merge --ff-only ghsa-<short-id>/main
```

### 4. Sync local main against origin

```bash
git fetch origin
git checkout main

# Are we behind, ahead, diverged, or in sync with origin/main?
git rev-list --left-right --count origin/main...main   # prints "<behind>\t<ahead>"
git log --oneline main..origin/main                    # commits origin has, local doesn't
git log --oneline origin/main..main                    # commits local has, origin doesn't (the stack under this landing)
```

Decide based on the divergence shape:

- **In sync** (`0\t0`): nothing to do, continue to step 5.
- **Behind only** (`N\t0`, N > 0): fast-forward and continue.
  ```bash
  git merge --ff-only origin/main
  ```
- **Ahead only** (`0\tN`, N > 0): batch case — local has already-landed integration commits awaiting a push. Continue to step 5. Capture the local-only commit list for the step-8 `Stacked on:` line.
- **Diverged** (`M\tN`, both > 0): stop. Origin has work local does not, *and* local has work origin does not. This skill never reconciles a real divergence — the user must resolve the upstream pull before retrying.

### 5. Squash-merge with deliberate conflict resolution

From `main`:

```bash
git merge --squash fix/<full-GHSA-id>
```

`--squash` stages the combined tree change without creating a commit, and surfaces every conflict immediately. There is no commit graph linkage to roll back through — only the index and worktree are affected. This makes conflict resolution mechanically simpler.

If the merge reports conflicts, **resolve every one deliberately**, file by file. Do not blanket-take one side. Per-file strategy:

#### 5a. `CHANGELOG.md`

Conflicts here are almost always additive — both branches added a new line under the same release header.

- Keep **both** entries.
- Order them by GHSA ID ascending under the release header, or by the order the user prefers (ask once if unsure, then apply consistently).
- If the branch you are landing also bumped to a new release header that's already on `main` from another advisory, collapse into the single release header on `main`.

**Trim verbose entries before committing.** The fix-vulnerability skill tends to produce paragraph-long bullet points that mirror the full attack-catalog write-up. That is redundant — the catalog (`docs/attacks/*.md`) and the per-advisory tests are the source of truth. A CHANGELOG entry is a release-notes index, not a second copy of the analysis.

Target shape, in 2–4 sentences max:

1. The vulnerability class in plain language (one sentence, no full PoC payload).
2. The chokepoint of the fix in one short clause (file + structural mechanism, e.g. `Two-layer structural fix in lib/bridge.js (apply-trap blocklist + cache check)`).
3. A pointer: `See ATTACKS.md Category N and test/ghsa/<GHSA-id>/`.

Use the existing 3.11.1 entry (`GHSA-8hg8-63c5-gwmx`) as the reference shape — that one is the right length. Entries from 3.11.2 and 3.11.3 are too long and should NOT be matched.

If the branch's entry is already short, leave it. If it is one giant paragraph quoting the commit body, rewrite it down to the target shape before the squash commit lands. The rewrite is part of conflict resolution — do it in the same edit pass, not as a follow-up commit.

#### 5b. The attack catalog (`docs/ATTACKS.md` and `docs/attacks/`)

The fix-vulnerability skill assigns each new attack class the next unused category number across all family files. If two advisories both grew from the same base and both claimed the same number, you must renumber:

- The category that lands first keeps its number.
- The category landing now (this branch) takes the next free number on current `main` — i.e. `(max category number on main) + 1`.
- Update **all cross-references** to the renumbered category: `Category N` mentions and `#attack-category-N-` anchors in every `docs/attacks/*.md` and in `docs/ATTACKS.md`, its row in the category index, and its Compound Attack Patterns / How The Bridge Defends rows. `test/docs-catalog.js` fails on a duplicate number, a gap, or an unresolved anchor, so run `npm test` before considering the renumbering done.

If both branches edited the same row in `Summary → How The Bridge Defends` or `Summary → Compound Attack Patterns`, merge the rows by hand to preserve both defenses.

#### 5c. `package.json` (version bump conflict)

If both branches bumped `version`:

- Pick the **higher** of the two as the floor.
- If both bumped to the same `X.Y.Z`, increment patch one more so each landed fix gets a distinct version slot (`X.Y.Z` → `X.Y.(Z+1)`).
- Update `package-lock.json`'s top-level `version` field (and the `""` package entry) to match. Do not run `npm install` here — that would touch the lockfile graph and create churn unrelated to the security fix.

#### 5d. `lib/*.js` (the boundary code)

These are semantic conflicts and you must reason about them as a security engineer, not as a text-merger:

1. Open both sides with `git checkout --conflict=diff3 -- <path>` so you see the common ancestor block (`||||||| merged common ancestors`). The ancestor reveals the **intent** of each side.
2. If both sides added new defensive checks at the same chokepoint, keep both — they are usually independent (e.g. one filters a symbol, another rebinds a return value). Order them by what runs first logically, not by file order.
3. If the two sides modified the **same defensive check in incompatible ways**, that is a real design conflict. Do not pick — stop and tell the user. The fix-vulnerability skill's multi-angle exploration should have caught this; surfacing it here means an earlier round missed an interaction. The user must decide whether to re-spawn agents or hand-merge.
4. If the conflict is purely formatter noise (trailing commas, brace spacing) on lines neither side changed semantically, take `main`'s formatting and keep the security delta. Never let formatter churn enter the final commit.
5. Re-read every `// SECURITY:` comment in the touched region after resolution. If a comment now describes behavior that the merged code no longer has, fix the comment. A stale SECURITY comment is worse than no comment.

#### 5e. `test/*.js` (main suites) and `test/ghsa/<other-id>/`

- Conflicts in `test/vm.js` / `test/nodevm.js` / `test/escape-scanner.js` follow the same logic as `lib/*.js` — both sides likely added related test cases; keep both.
- `test/ghsa/<full-GHSA-id>/` for **this** advisory is the branch's own directory and should not conflict. If it does, something is wrong with the branch hygiene — stop and surface.
- Tests in other advisories' directories (`test/ghsa/<other-id>/`) should never appear in this branch's diff. If they do, the branch was not properly isolated; surface and let the user decide whether to revert those hunks.

#### 5f. Scrub external attribution during conflict resolution

While resolving, scan every conflict region (and every non-conflicting hunk you have just authored or rewritten) for:

- Reporter names, GitHub handles, or affiliations.
- Embargo dates, disclosure dates, "as reported by …" phrasing.
- "Thanks to …" lines.
- Email addresses other than the maintainer's commit identity.

Delete them. Replace with neutral phrasing or simply drop the sentence. The GHSA ID itself stays — that's the issue identifier.

After all conflicts are resolved:

```bash
git status                     # confirm no remaining "both modified" entries
git diff --cached --stat       # sanity-check the staged surface looks like one advisory
```

### 6. Build the integration commit

The commit subject **must** match the existing pattern visible in `git log --oneline main`:

```
fix(GHSA-<full-id>): <one-line description of the structural fix>
```

The body should:

- State the root cause in 1–2 sentences.
- State the fix's chokepoint and which `docs/ATTACKS.md` Defense Invariant it restores.
- List the test surface added/changed (`test/ghsa/<full-GHSA-id>/repro.js` plus any variant files).
- Note the `docs/ATTACKS.md` category (new or updated) and the `package.json` version bump if any.
- Be **fully free** of reporter names, handles, dates, and acknowledgements.

Draft the message from the branch's own commits + the doc updates, not from the advisory thread, to keep attribution out automatically. Sources to mine for the body:

```bash
git log fix/<full-GHSA-id> --format='%s%n%n%b' main..ghsa-<short-id>/main
git diff --cached docs/ATTACKS.md CHANGELOG.md
```

If any phrase you considered including names a person, a handle, or a date — drop it.

Commit:

```bash
git commit -F - <<'EOF'
fix(GHSA-<full-id>): <one-line description>

<body, see above>
EOF
```

Use `-F -` (heredoc) rather than `-m` so multi-line bodies format cleanly.

### 7. Re-prove the full test surface

A clean merge with green local tests on one Node version proves almost nothing for vm2. Run the full sweep before declaring done.

```bash
# Full Node-version sweep, same floor as fix-vulnerability step 7
for v in 8 10 12 14 16 18 20 22 24 25 26; do
  echo "=== node $v ==="
  nvm use $v && npm test 2>&1 | tail -3
done
```

Any failure means the integration introduced a regression that the per-branch test pass did not see. Likely causes:
- Another already-landed advisory's defense interacts with this one.
- Conflict resolution in `lib/*.js` accidentally weakened a previously-restored invariant.
- Renumbering in the attack catalog broke a link (`test/docs-catalog.js` fails) or an anchor that a test asserts on.

Roll back with `git reset --hard HEAD~1`, re-do step 5 with the new information, and re-run. Do **not** patch the failing test to make it green unless you can articulate, in writing, why the prior behavior was the insecure one — and even then, surface that to the user before committing.

Then re-run the advisory's own repro to confirm the fix still blocks the original PoC after rebase noise:

```bash
node test/ghsa/<full-GHSA-id>/repro.js  # if it is standalone
# or
npx mocha test/ghsa/<full-GHSA-id>/      # if it is mocha-style
```

### 8. Report and stop

Print a short, terse summary to the user. Match this shape:

```
GHSA-<full-id> integrated into local main as <new HEAD short-sha>.

Commit:        fix(GHSA-<full-id>): <subject>
Stacked on:    <"origin/main" | comma-separated list of local-only commits this landed on top of>
Conflicts:     <none | list of paths with one-line resolution per>
Renumbered:    <none | Category N -> Category M in docs/attacks/<family>.md>
Version:       <unchanged | X.Y.Z -> X.Y.(Z+1)>
Test sweep:    Node 8/10/12/14/16/18/20/22/24/25/26 all pass

Advisory action items (fix in GHSA UI before publishing):
  - <item 1 from step 2b ghsa_action_items>
  - <item 2 from step 2b ghsa_action_items>
  ...
  (or "none — advisory metadata is publication-ready" if the list is empty)

NOT PUSHED. Publish via the maintainer's release flow when ready.
```

The `Advisory action items` block is required even when empty — its absence would let a stale advisory ship silently. Render the empty case as the literal "none — advisory metadata is publication-ready" line so the user sees the check ran.

That last line ("NOT PUSHED…") is load-bearing. Make sure it is the final thing you say. Do **not** offer to push, do **not** offer to tag, do **not** offer to publish to npm. The user runs those steps themselves, deliberately, after a final visual review of `git log -p HEAD~1..HEAD`.

---

## Things this skill never does

- Push to `origin` or to the private fork.
- Delete the per-advisory branch or the private fork remote (those stay around until the maintainer's release flow has fully completed).
- Edit the advisory on GitHub or post comments to the advisory thread.
- Reword or "clean up" prior commits on `main`.
- Run `npm install`, `npm publish`, or bump `package.json` beyond the minimum required for the version-conflict resolution in step 5c.
- Trust the local `fix/GHSA-<full-id>` branch over `ghsa-<short-id>/main` — the private fork's main is canon.
- Carry attribution from the advisory thread or the branch's iterative commits into the final commit.
