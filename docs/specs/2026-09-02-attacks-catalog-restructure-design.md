# Attack catalog restructure — design

Date: 2026-09-02
Status: approved design, not yet implemented.
Scope: documentation and its consumers only. No `lib/` changes. No new attack
research. No renumbering of existing categories.

## 1. Why

`docs/ATTACKS.md` is 4686 lines holding 52 numbered categories, 14 defense
invariants, 29 compound attack patterns, a defense table, and three appendix
sections. It is the institutional memory that `/fix-vulnerability`, `/hacker`,
`/maintainer` and `/merge-fix` all read cover to cover, and every advisory fix
appends to it.

Two problems have accumulated:

**The word "category" changed meaning around entry 16.** Categories 1–15 are
genuine attack classes. Categories 16–52 are one entry per advisory. Closely
related mechanisms are therefore scattered by fix date instead of grouped by
mechanism: the Promise and async surface alone spans entries 7, 19, 29, 31,
33, 43 and 51, and a reader who wants "everything vm2 knows about Promise
species" has to know that in advance.

**Nothing forces an entry to stay true after later fixes land.** Concrete
examples found while surveying the file:

- "NOW FIXED" appears about 15 times. Everything in the catalog is fixed by
  definition, so the marker is noise, and Category 9 carries three
  retrospective "Why X Was Dangerous (NOW FIXED)" subsections.
- "Future Risks" still lists WASM JSPI as upcoming. It is Category 33.
- "Considered Attack Surfaces" still says `Error.cause` is safe. Category 38
  is the `Error.cause` host reference leak.
- Five entries carry a "Known Residual", "Residual Risk" or "Accepted
  Residual" section (22, 36, 45, 46, 47). None records when it was last
  re-tested, and Category 23 shows the failure mode: its residual was closed
  by Category 36 and patched inline with a "Now capped — see Category 36"
  note rather than trimmed.
- Only 9 of 52 categories link to a regression test, although `test/ghsa/`
  holds 59 advisory directories with the actual PoCs and variants.
- One cited advisory, GHSA-m3pp-qgq7-gwm6, has no `test/ghsa/` directory. It
  is a recorded duplicate of GHSA-wjwh-qqvp-g4p4, so the fix is a note, not
  a test.
- `CLAUDE.md` references `test/escape-scanner.js`, which does not exist.

## 2. Goals and non-goals

Goals:

1. One file per mechanism family under `docs/attacks/`, plus one index and
   common document at `docs/ATTACKS.md`.
2. Category numbers are permanent identifiers. No entry is renumbered,
   merged, or split. `CHANGELOG.md`, four `test/ghsa/*/repro.js` comments,
   and the `/merge-fix` renumbering check all key on "Category N".
3. Every category is verified against current `main`: cited mitigation code
   exists, cited advisories have tests, canonical PoCs are blocked, residuals
   are still residual.
4. Every category links to the tests that reproduce it.
5. A mechanical guard against link rot and renumbering, so the next 50
   entries do not need this exercise again.
6. Every consumer of the old layout (`CLAUDE.md`, four skills, `README.md`)
   points at the new one.

Non-goals:

- Rewriting prose for style. Edits are limited to what the staleness
  checklist in §6 requires.
- Adding new regression tests. Reviewers report coverage gaps; writing tests
  is a follow-up with its own review.
- Any change to `lib/`.
- Touching `CHANGELOG.md` history. Old entries say "See ATTACKS.md Category
  N"; the number still resolves through the index, so they stay correct.

## 3. Target layout

```
docs/
  ATTACKS.md                      index + common material (see §4)
  attacks/
    host-reference-primitives.md
    error-sanitization.md
    promise-async.md
    host-prototype-mutation.md
    bridge-internals.md
    transformer-and-modules.md
    nodevm-require.md
    host-resources.md
```

### 3.1 Family mapping

Families group by the mechanism the attacker exploits and the invariant the
fix restores, not by impact and not by date. Every category appears in
exactly one family. Cross-family relationships are carried by the existing
`**Uses**` and `**Supersedes**` lines, which become cross-file links.

| Family file | Mechanism | Categories | Invariants |
|---|---|---|---|
| `host-reference-primitives.md` | Reaching a raw host object or host `Function` through language-level channels: constructor chains, prototype walks, symbols, `caller`, descriptors, built-in conduits, species | 1, 2, 3, 5, 8, 10, 15, 18 | 1, 4, 7, 8 |
| `error-sanitization.md` | Exceptions and error containers as carriers of host references past `handleException` | 4, 16, 17, 38, 39, 48, 49 | 2, 3, 5 |
| `promise-async.md` | Deferred execution: species, thenable assimilation, cross-realm Promise prototypes, engine protectors, `allowAsync` | 7, 19, 29, 31, 33, 43, 51 | 4, 12, 14 |
| `host-prototype-mutation.md` | Writing into host intrinsic prototypes through bridge write traps, setter primitives, or `Receiver` confusion | 20, 26, 30, 32, 37, 50 | 6 |
| `bridge-internals.md` | Exploiting the bridge's own machinery: proxy traps, handler exposure, monkey-patched primitives, internal containers, internal state, read-only views | 6, 9, 11, 14, 27, 28, 44 | 8, 11 |
| `transformer-and-modules.md` | Syntax the transformer cannot see and dynamic code or module loading paths | 12, 13 | 9, 10 |
| `nodevm-require.md` | `NodeVM` builtin and external allowlists, `require.root`, `nesting`, host-authority members of allowed builtins | 21, 24, 25, 34, 35, 40, 45, 46, 47, 52 | 13 |
| `host-resources.md` | Host memory, heap, process lifetime and the `timeout` guarantee: DoS and memory disclosure | 22, 23, 36, 41, 42 | none yet; see §8 |

Placement notes for the entries that could go two ways:

- **18 (Array species self-return)** sits with the primitives because it is
  the canonical `ArraySpeciesCreate` case that invariant 4 is written
  around, and 28 ("Supersedes" it in part) links back across files.
- **19 (host `prepareStackTrace` via `Array.fromAsync`)** is an error-side
  fallback reached through a Promise path. It goes with Promise and async
  because the bypass is the async delivery; the error half is invariant 5 and
  is linked.
- **22 (Promise executor unhandled rejection)** is a Promise mechanism with a
  DoS impact. It goes with host resources because a reader assessing
  process-lifetime risk needs it next to 42, and 31 links to it from the
  Promise file.
- **39 (rejection sanitizer bypass via `call`/`apply`)** is about the
  sanitizer gate, so it sits with 38 in error sanitization, not with
  Promises.
- **40 (host-authority builtin members)** is a `NodeVM` allowlist problem
  even though `ReadOnlyHandler` is involved. It goes with `nodevm-require`.
- **41 (shared buffer pool)** is memory disclosure, not exhaustion. Host
  resources is still the right home; the file's scope line says "memory and
  process lifetime", not "DoS".
- **12 and 13** make a thin family on purpose. It is where every future
  transformer blind spot (invariant 9) lands, and folding them into another
  family would hide that.

### 3.2 Tiers

The Tier 1 / 2 / 3 headings do not survive the split; a tier spanning eight
files is not a heading. The distinction they encoded is kept two ways:

- An entry with no `**Uses**` line is a primitive. An entry with one is a
  technique or compound. This is already how the entries are written.
- The index table (§4) has a `Kind` column with values `primitive`,
  `technique`, `compound`, assigned from the current tier membership.

`/fix-vulnerability` step "classify against Tier 1 primitives (1–5) and Tier
2 techniques (6–15)" becomes "classify against the primitives in
`host-reference-primitives.md`, `error-sanitization.md` and
`bridge-internals.md`, then the techniques listed as `Kind: technique` in the
index".

## 4. `docs/ATTACKS.md` after the split

Order, top to bottom:

1. **Title and how to use.** Same content as today, with paths updated.
2. **Category index.** One table, all 52 rows, sorted by number:
   `N | Title | Family (link) | Kind | Advisories | Tests`. This is the
   lookup that makes "Category N" resolvable from `CHANGELOG.md` and repro
   comments without opening every file.
3. **Entry format.** Rewritten for the new layout (§5).
4. **Fundamentals.** Unchanged content.
5. **Defense invariants.** Unchanged content; links into families updated.
6. **Compound attack patterns.** Unchanged content minus the "(NOW FIXED)"
   markers; category links become cross-file links.
7. **How the bridge defends.** Unchanged table; category links updated.
8. **Key security invariant: Promise species resolution timing.** Moves
   into `promise-async.md` as that file's scope preamble. It is
   family-specific, not common.
9. **Security checklist for bridge changes.** Unchanged.
10. **Runtime-dependent attack surface: sandbox `Proxy` availability.**
    Unchanged.
11. **Considered attack surfaces.** Corrected per §6.
12. **Future risks.** Corrected per §6.

Estimated size after the split: roughly 600 lines. The category index is the
only new material.

### 4.1 Family file shape

```
# <Family title>

<One paragraph: the mechanism, which invariants it lives under, which
families it most often composes with. Links to ../ATTACKS.md sections.>

Categories in this file: 4, 16, 17, 38, 39, 48, 49.

---

## Attack Category 4: Error Object Exploitation
**Advisories**: GHSA-..., GHSA-...
**Tests**: test/ghsa/GHSA-.../repro.js, test/vm.js ("<describe title>")
**Uses**: ...
**Supersedes**: ...

### Description
...
```

Entries are moved verbatim. Their `## Attack Category N:` headings are
untouched, so the GitHub anchor `#attack-category-N-<slug>` is the same
string it is today, just in a different file.

### 4.2 Link rules

- Category links always carry the file: `[Category 4](error-sanitization.md#attack-category-4-error-object-exploitation)`
  from a sibling family file, `[Category 4](attacks/error-sanitization.md#...)`
  from the index. Same-file links also carry the file name. One rule, no
  special case, and a link survives if an entry is ever moved.
- Links to common material go to `../ATTACKS.md#defense-invariants`,
  `../ATTACKS.md#fundamentals`, and so on.
- The split script rewrites every `(#attack-category-N-...)` occurrence by
  looking N up in the mapping table. Any anchor it cannot resolve is a hard
  error, not a warning.

## 5. Entry format, revised

The format section in `ATTACKS.md` is replaced with:

- **Heading**: `## Attack Category N: <Short title>`. N is the next unused
  number across all families. Numbers are never reused or reassigned.
- **`**Advisories**:`** — required. Every GHSA ID the entry covers, including
  duplicates, marked `(dup of GHSA-...)`.
- **`**Tests**:`** — required. Paths to the regression tests. A `test/ghsa/`
  directory per advisory is the norm; suite tests are cited by file and
  `describe` title.
- **`**Uses**:`** — required for techniques and compounds, absent for
  primitives.
- **`**Supersedes**:`** — optional, unchanged meaning.
- Sections `Description`, `Attack Flow`, `Canonical Example(s)`, `Why It
  Works`, `Mitigation`, `Detection Rules`, `Considered Attack Surfaces`,
  unchanged meaning.
- Present tense only. An entry describes a closed hole and the structure
  that keeps it closed. "NOW FIXED", "historically", "was dangerous" are not
  used; the fix is the Mitigation section.
- A `### Known Residual` section must name the condition under which it
  becomes a bug, and the entry that closes it once one exists.

After adding an entry:

1. Add the entry to its family file. If no family fits, add a family file
   and a row to the family table in `ATTACKS.md`; that is expected to be
   rare.
2. Add the row to the category index.
3. Add the row to "How the bridge defends" and, for compounds, the pattern
   to "Compound attack patterns".
4. Run `npm test`; the docs link test (§7) fails on any unresolved link or
   duplicate number.
5. One-line `CHANGELOG.md` entry.

## 6. Staleness review: the per-family checklist

Each family file gets one review agent. The agent works only inside its file
and writes findings to a scratch report; it does not touch `ATTACKS.md`, other
families, `lib/`, or tests. For every category in the file:

1. **Mitigation cites live code.** Every function, file, constant or option
   named in Mitigation is grepped in `lib/`. A miss is a finding and the
   sentence is corrected to the current name, or marked as a finding if the
   defense moved in a way the reviewer cannot confirm.
2. **Advisories have tests.** Every GHSA ID in the entry maps to a
   `test/ghsa/<id>/` directory. A miss is either a recorded duplicate (note
   it inline) or a coverage gap (report it; do not write a test).
3. **Tests line is complete.** The reviewer reads the matching `repro.js`,
   `adversarial.js`, `structural-leak*.js` and any `test/vm.js` or
   `test/nodevm.js` block for the category, and lists them. Where a test
   file holds a variant the entry does not mention, the reviewer adds it as
   a one-line canonical example pointing at the test, not by copying the
   test body.
4. **Canonical examples are blocked.** Every code block that is a PoC is
   either matched to a test that asserts it is blocked, or run by the
   reviewer against current `main` on the current Node. A PoC that is not
   blocked stops the review and is reported immediately. A PoC that needs a
   Node version the reviewer does not have is marked as unverified in the
   report, not silently passed.
5. **Residuals are still residual.** Every `Known Residual`, `Residual
   Risk`, `Accepted Residual` is re-tested. Closed residuals get a one-line
   pointer to the closing category and the section is trimmed.
6. **Tense and markers.** "NOW FIXED", retrospective subsections, and
   "historically" narratives are rewritten in present tense per §5. Content
   is preserved; only framing changes.
7. **Cross-references are intact.** `Uses`, `Supersedes`, "Related
   Categories" and inline category links still name the right entries after
   the split script rewrote them.
8. **Version claims.** Node version statements ("since ~Node 23",
   "enabled by default on Node 25") are checked against the current
   `.github/workflows` matrix and `bun-skips.js`; unverifiable ones are
   reported, not edited.

The two appendix sections in `ATTACKS.md` get the same treatment from the
cross-cutting reviewer (§7): each "Considered Attack Surface" bullet is
checked against the category list for contradiction, and each "Future Risk"
that has become a category is removed with a pointer.

Reviewers must not: renumber, merge, split or delete a category; delete a
code block; change a Mitigation claim without running code that supports the
change; add prose beyond what the checklist requires.

Report format per family, appended to one scratch file:

```
## <family file>
### Edits made
- Category N: <one line>
### Findings needing a human
- Category N: <what, evidence, suggested action>
### Unverified
- Category N: <PoC, why not run>
### Coverage gaps
- GHSA-...: no test directory
```

## 7. Cross-cutting verification

A second-pass reviewer runs after all family reviews finish and owns the
shared files. Checks, all mechanical where possible:

- `## Attack Category N:` count across `docs/attacks/*.md` is 52 and each N
  from 1 to 52 appears exactly once.
- The set of GHSA IDs across the new files equals the set in the original
  `ATTACKS.md` at the split commit.
- The count of fenced code blocks across the new files is not lower than the
  original, except where a family report lists a deliberate trim.
- Every markdown link to a `#attack-category-` anchor resolves to a heading
  in the named file. Every link to `ATTACKS.md#...` resolves.
- Every category has a row in the index, a `**Advisories**` line, a
  `**Tests**` line, and a row in "How the bridge defends".
- Every compound pattern's bracketed category list names existing entries.
- "Considered Attack Surfaces" and "Future Risks" contradict no category.
- Every family scope paragraph names the invariants from the §3.1 table.

The link and numbering checks are committed as `test/docs-catalog.js`, a
Mocha test that runs in the main suite. It parses `docs/ATTACKS.md` and
`docs/attacks/*.md`, asserts unique sequential numbers, asserts every
category-anchor link resolves, and asserts every category has Advisories and
Tests lines. It is fast, has no runtime dependency, and turns the `/merge-fix`
"renumbering broke an anchor" worry into a test failure.

## 8. Known gap surfaced by the mapping

`host-resources.md` (22, 23, 36, 41, 42) has no defense invariant. Every
other family enforces at least one. The categories describe three distinct
guarantees, `timeout` bounds all sandbox-triggered execution, sandbox
allocations are bounded by `bufferAllocLimit`, and no sandbox-triggered host
rejection is unhandled, that are currently stated only inside individual
mitigations. Writing invariant 15 is out of scope for this restructure
because it is a security claim that needs its own review, but the family
scope paragraph will say the gap exists, and it is listed here so it is not
forgotten.

## 9. Consumer updates

| File | Change |
|---|---|
| `CLAUDE.md` | Security section points at the index and the family layout. "Updating ATTACKS.md" becomes "Updating the attack catalog" with the §5 steps. Remove `test/escape-scanner.js` from the Tests table; describe `test/ghsa/` instead. |
| `.claude/skills/fix-vulnerability/SKILL.md` | Step reading "cover-to-cover" reads the index, invariants, and the relevant family. Classification step per §3.2. Entry-format links and the ATTACKS.md checklist item updated to the family file plus index row. |
| `.claude/skills/hacker/SKILL.md` | Reads the index, then the family files; the "three tiers" sentence becomes the families table. |
| `.claude/skills/maintainer/SKILL.md` | Wording only; three mentions stay true, one path becomes "the attack catalog under `docs/`". |
| `.claude/skills/merge-fix/SKILL.md` | Section 5b covers family file plus index row. The renumbering check names `test/docs-catalog.js`. |
| `README.md` | Two links stay valid; wording checked. |
| `test/ghsa/*/repro.js` (4 files) | Comments stay valid because they cite a number. Optionally add the family file name; not required. |

## 10. Execution order

1. **Split script.** A one-off Node script in the scratchpad, not committed.
   Input: `docs/ATTACKS.md` at HEAD and the §3.1 mapping. Output: the eight
   family files, the rewritten `ATTACKS.md` with the index table generated
   from headings, and the link rewrites of §4.2. It moves text; it does not
   edit prose. It fails hard on any unresolved anchor or any category number
   not in the mapping.
2. **Baseline commit.** "docs: split ATTACKS.md into per-family files (pure
   move)". The diff of every later step is then reviewable as intent, not
   as movement. `git diff -M` on this commit should show the family files as
   partial renames of the original.
3. **Family reviews.** Eight agents in parallel, one per family file, each
   under the §6 contract. They run in the working tree, not worktrees, since
   each owns a disjoint file and the shared files are off limits.
4. **Cross-cutting review.** One agent under §7, plus the `test/docs-catalog.js`
   test. It also applies the appendix corrections and any index or defense
   table changes the family reports called for.
5. **Consumer updates** per §9.
6. **Verification**: `npm run lint`, `npm test` on the current Node, and the
   §7 checklist run once more by the maintainer against the final tree.
7. **Commit** the review pass separately from the baseline: "docs: staleness
   review of the attack catalog" with the compiled family reports in the
   commit body, and a third commit for the consumer updates.

## 11. Decisions taken in this design

- Family grouping with permanent numbers, not one file per category.
- Tier headings dropped; `Kind` column and `Uses` line carry the
  distinction.
- Mechanical split first, content review second, so every prose change is a
  readable diff.
- Reviewers report missing tests; they do not write them.
- A docs test guards numbering and links from now on.
- The Promise species timing note moves into the Promise family; everything
  else that is cross-cutting stays in the root document.
- `host-resources.md` ships without an invariant and says so.
