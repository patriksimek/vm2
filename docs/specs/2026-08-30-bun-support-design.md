# Bun support — phase 1 design

Date: 2026-08-30
Status: approved, not yet implemented
Scope: test suite + CI only. No `lib/` changes, no security claim for Bun.

## 1. Why

The stated goal is "run vm2 on Bun". That undersells the return, and this spec is
written around the larger reason.

Within an hour of pointing Bun at the suite, the second engine found a **vacuous
security regression test**. In `test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js`,
the test named *".message accessor returning a host object (must be treated as
non-primitive)"* opens with:

```js
const agg = new AggregateError([agg = undefined], 'placeholder');
```

Evaluating `agg = undefined` while `agg` is in its temporal dead zone throws a
host-realm `ReferenceError`. The payload function therefore aborts before it ever
throws the crafted `a2`; the sandbox catches the `ReferenceError`, walks it,
finds no marker, and reports `NO-LEAK`. The test has been green since it was
written without once exercising the `.message` accessor path it names.

Confirmed empirically on Node v26.7.0:

```
what the sandbox actually catches: ReferenceError: Cannot access 'agg' before initialization
was the crafted AggregateError (a2) ever thrown? -> NO - test is vacuous
```

Repairing it (deleting the dead line) makes the payload run, and the defence does
hold — `NO-LEAK`. So this is a test-quality defect, not a vulnerability. Node
could not surface it. Bun's transpiler statically rejects the line, which is what
forced anyone to look.

**That is the thesis of phase 1: a second engine is a differential oracle for a
test suite whose entire value is that it means what it says.** Bun compatibility
is the by-product. The work is justified even if a Bun security guarantee is
never shipped.

## 2. Goals / non-goals

### Goals

- The full suite runs to completion on Bun with an understood, enumerated result.
- Assertions stay exactly as strict on Node as they are today.
- Version gating stops lying (see §4.1 — Bun spoofs `process.versions.node`).
- A CI job that exercises Bun without ever endangering the Node signal.
- A timeboxed sweep for other vacuous tests of the `GHSA-x965` shape.

### Non-goals

- Fixing the 13 behavioural divergences (§3). They are phase-2 input.
- Any change to `lib/`.
- Any security claim for Bun. See §6.

## 3. Measured starting state

Measured on this branch (`fe71e2b`, which unblocked sandbox setup), Node v26.7.0
and Bun 1.4.0. All figures re-measured in the `bun-support` worktree; do not
carry forward numbers quoted from the `fix/GHSA-6454-5x88-m6jw` branch, which
has 17 additional ghsa tests.

| Suite | Node v26.7.0 | Bun 1.4.0 |
|---|---|---|
| `test/vm.js` | 116 / 116 | 99 / 116 (17 fail) |
| `test/nodevm.js` | 51 / 51 | 47 / 51 (4 fail) |
| `test/ghsa` (59 dirs) | 655 / 655 | **cannot run — see §3.1** |
| total | 822 | — |

### 3.1 `test/ghsa` does not run at all on Bun

This is the single most important measured fact, and it outranks everything else
in §4. On a clean checkout Bun's transpiler rejects
`test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js` at load, and the failure aborts
the **entire `test/ghsa` run** — not just that file. Zero of the 655 security
regression tests execute:

```
Exception during run: 104 | const agg = new AggregateError([agg = undefined], 'placeholder');
error: This assignment will throw because "agg" is a constant
```

So the repair in §4.4 is a blocking prerequisite for any ghsa measurement on Bun,
not a tidy-up. It lands first, alongside §4.1.

With that one file excluded, the remaining failures are as characterised below.

**~34 failures, in two populations.**

**~21 cosmetic** — tests regex-matching V8 error text. Every corresponding
payload was re-run directly under Bun and the host `process` remained unreachable
in all of them. The defence holds; only the wording differs:

| Symbolic | V8 | JSC |
|---|---|---|
| not-a-constructor | `Proxy is not a constructor` | `undefined is not a constructor` |
| proxy define falsish | `'defineProperty' on proxy: trap returned falsish` | `Proxy's 'defineProperty' trap returned falsy value` |
| read of undefined | `Cannot read properties of undefined (reading 'x')` | `undefined is not an object (evaluating 'x')` |

**~13 genuine divergences**, which split into three kinds that must not be
conflated — only kind A is vm2's problem:

**A. vm2 behaves differently on JSC** (real phase-2 work)

- `Error.captureStackTrace` on a caught sandbox error repopulates `.stack` with
  host frames including absolute paths — the GHSA-x6m4-chr9-cg97 redaction does
  not hold on JSC. Information disclosure. *Security-relevant.*
- `Buffer.from(arrayLike)` returns a zero-length buffer (GHSA-fcqc / GHSA-gmc2).
- `Object.freeze` on a frozen host object with a non-configurable accessor throws
  a proxy-invariant `TypeError`; GHSA-633r-hq9m-c4ff regression-tests that it
  must *not* throw.
- The CallSite shim is shallow — `getThis()` is `undefined`, one frame captured,
  `getFileName()` `undefined`. `VMScript` `filename`/`lineOffset`/`columnOffset`
  metadata is lost. Note this *coincidentally* removes the FormatStackTrace
  attack class, which also means vm2's defences there go unexercised.

**B. Bun's Node-compat layer differs** (not vm2 bugs; candidates to file upstream)

- `util.inspect` renders cross-realm arrays as `Array { '0': 1 }` rather than
  `[ 1, 2, 3 ]` (tests for #566 / #567).
- `node:assert` `deepStrictEqual` does not treat a cross-realm array as equal to
  a host array (GHSA-2cm2, GHSA-m5q2, GHSA-vwrp, GHSA-248r).
- `node:sqlite` refuses extension loading with its own error, so vm2's forced
  `allowExtension: false` is not what blocks it (GHSA-6w8r). Still blocked, but
  the defence is unverified on Bun.

**C. Test-harness assumptions** (fix in the tests)

- Deep recursion does not stack-overflow promptly on JSC, so two tests that rely
  on a fast `RangeError` to terminate instead run until a timeout. A `VM` with no
  `timeout` option can run unbounded where Node terminates in ~0.5s.

**D. Performance divergence, large enough to be functional**

`new VM().run('Buffer.allocUnsafe(64 * 1024 * 1024).length')` — the same code,
clean checkout, same machine:

| Node v26.7.0 | Bun 1.4.0 |
|---|---|
| 1 681 ms | > 400 000 ms (killed, never completed) |

A >240× divergence in the Buffer bridge, severe enough to read as a hang: it is
what stalls `test/ghsa/GHSA-6785-pvv7-mvg7` and blocks whole-suite measurement.
Root cause unknown; belongs to kind A or B depending on what it turns out to be.
Phase 1 skips the test and records the number. Phase 2 decides whether a
sandbox that is 240× slower at moving bytes across the boundary is a DoS
consideration in its own right.

**Plus one parse-blocker**: `GHSA-x965.../adversarial.js`, per §1.

## 4. Design

Four pieces, plus one unresolved prerequisite (§4.0). A dedicated runner in the
style of `scripts/legacy-test-runner.js` is probably **not** needed — mocha does
run under Bun — but see §4.0 before treating that as settled.

### 4.0 Result integrity on Bun (UNRESOLVED — must be settled first)

Mocha's behaviour under Bun does not scale with run size, and the large-run
failure mode is the dangerous direction.

| Run | Result |
|---|---|
| `test/ghsa/GHSA-m5q2-4fm3-vfqp` (15 tests, 1 failing) | `rc=1`, full TAP epilogue. Correct. |
| a 2-test file with 1 failure | `rc=1`. Correct. |
| `test/ghsa` full, output piped | output stops at ~426 of ~626 tests, **no TAP epilogue**, and **`rc=0` despite 5 failures** |

A CI job that exits 0 while swallowing failures is worse than no CI job. Every
other part of this design assumes the runner reports honestly, so this is settled
before anything else is built.

Working hypothesis, not yet confirmed: Bun loses buffered stdout on exit for
large piped outputs, and the same exit path drops mocha's `process.exitCode`.
That would explain the truncation, the missing epilogue, and the wrong exit code
as one root cause. It would be a Bun bug (kind B, §3), not a vm2 one.

Candidate mitigations, in order of preference — investigation task, not a
decision to make on paper:

1. Redirect to a file rather than a pipe, and/or use a reporter that flushes
   synchronously; re-measure.
2. Have CI assert the epilogue exists and that the reported counts match, so a
   truncated run fails loudly instead of passing quietly. Worth doing regardless
   of root cause, as defence in depth.
3. Shard the Bun job per directory. Known to work — the per-directory runs are
   reliable — at the cost of a slower, noisier job.
4. Only if all of the above fail: a thin runner, as a last resort.

If this cannot be made honest, phase 1 should stop and be reconsidered rather
than ship a job that reports success it has not verified.

### 4.1 `test/engine.js` — engine detection and gating (the correctness prerequisite)

Bun reports `process.versions.node = 26.3.0`. Every one of the ~35 `NODE_VERSION`
/ `it.cond` gates in `test/vm.js` and `test/nodevm.js` therefore takes the
Node-26 branch on Bun and asserts V8-26 semantics on JavaScriptCore.

This is not cosmetic. Until it is fixed, **no Bun result means anything**, in
either direction — a pass may be asserting the wrong thing, and a failure may be
gate misfire. This lands first.

Exports `ENGINE` (`'v8' | 'jsc'`), `IS_BUN`, and an engine-aware replacement for
the existing `NODE_VERSION` gate. Detection is on `typeof Bun`, never on
`process.versions.node`.

### 4.2 `test/engine-messages.js` — symbolic message table

Maps a symbolic name to the exact expected pattern per engine, so assertions stay
as tight on both engines as they are on Node today. Adding a third engine later
is a column, not a rewrite.

```js
NOT_A_CONSTRUCTOR: {
  v8:  /Proxy is not a constructor/,
  jsc: /undefined is not a constructor/,
},
```

Rejected alternative: widening each regex to match both engines. Every widened
pattern is a permanently weaker assertion on Node — the runtime that actually
carries the guarantee.

### 4.3 `test/bun-skips.js` — one centralized skip list

`{ test, reason, phase }` per entry, wired through the existing `it.cond`. No new
machinery. Honors `VM2_BUN_NO_SKIP=1` to run everything anyway. The skip count is
printed at the end of a Bun run; the target is zero, and the list *is* the
phase-2 backlog.

Rejected alternative: an enforced xfail registry where a passing xfail fails the
build. Once the Bun job is `continue-on-error` (§5), a stale entry cannot break
anything, so xfail's enforcement value collapses and only machinery remains.

The one thing plain skip loses is notification when Bun fixes a divergence. The
`VM2_BUN_NO_SKIP=1` canary (§5) recovers that signal without gating anything.

### 4.4 The `adversarial.js` repair and the vacuity sweep

**Ordering: this lands first, with §4.1.** Per §3.1 it is not a tidy-up — until
it is done, zero ghsa tests run on Bun and there is nothing to measure.

Delete the dead TDZ line. Verified: the test then throws its real payload and
still reports `NO-LEAK`. This simultaneously unblocks Bun's parser and repairs
Node coverage.

Then a **timeboxed sweep** for other tests of the same shape — payloads that
throw before reaching the behaviour they name. Findings are filed, not
necessarily fixed inline; an unbounded repair effort does not belong in phase 1.

## 5. CI

A **separate `bun` job, not a matrix entry.** This is what actually protects the
Node signal: `test.yml`'s matrix has no `fail-fast:`, so it defaults to `true`,
and a Bun entry inside it would cancel in-flight Node jobs on failure. Job
separation makes the runtimes independent by construction, regardless of any
leniency setting.

- `bun` job: pinned `bun-version: 1.4.0`, `continue-on-error: true`. Pinned
  because every other runtime in this CI is pinned, and because a skip's
  documented reason cites specific engine behaviour that must stay reproducible
  from the commit.
- Node matrix: add `fail-fast: false`. Today one Node version failing cancels the
  rest and hides information. Small, adjacent, worth doing while in here.
- Weekly canary on `bun-version: latest` with `VM2_BUN_NO_SKIP=1`, informational
  only. Reports which skips have gone stale because Bun fixed something.
- Bumping the pin is a deliberate PR that shows exactly which skips changed —
  which is the phase-2 progress signal.

## 6. Posture, and what phase 2 actually costs

Phase 1 ships Bun as **experimental, functional parity only, explicitly NOT a
security boundary**, stated in `README.md` and `SECURITY.md`. An escape
reproducible only on Bun is out of scope for coordinated disclosure until Bun
reaches supported status; it is handled as a public bug.

This is not a formality. `docs/ATTACKS.md` is 52 categories derived from V8
internals — ArraySpeciesCreate, FormatStackTrace, PromiseResolveThenableJob,
`WebAssembly.JSTag`. JavaScriptCore has its own equivalents and none have been
audited against this bridge. The 59 GHSA regression suites are written against V8
attack primitives, so **passing them on JSC does not demonstrate safety on JSC**.

Phase 1 is roughly two days and is unambiguously worth it on the §1 argument
alone. Phase 2 is not a continuation of it — it is a second security program:
re-deriving the threat model against JSC internals, roughly doubling the standing
audit surface of a project whose entire value proposition is the audit. It should
be a separate decision made on its own merits, not a scheduled follow-on.
"Experimental" should be expected to hold for a long time.

## 7. Risks

- **Dishonest green (§4.0).** The largest risk, and currently unresolved: on the
  full suite Bun exits 0 while dropping failures and truncating output. Until
  §4.0 is settled, no Bun run can be believed in either direction. This is a
  gating item, not a caveat.
- **Green that means less.** Two layers of leniency — skipped tests plus a
  non-blocking job — make Bun results easy to stop reading. The printed skip
  count and the canary are the antidotes. If the count does not trend down, that
  is the signal the effort has stalled.
- **Measurement fragility.** The §3 numbers were themselves misreported once
  during investigation, from an instrumented working copy — the Buffer timings
  were ~240× off until re-measured on clean code. Every number in this spec must
  be reproducible from a clean checkout of this branch, and the plan should
  re-derive rather than quote them.
- **The vacuity sweep may find more than expected.** Good news that is also more
  work. Mitigated by timeboxing and filing rather than fixing inline.
- **Bun's Node-compat layer is a moving target.** Kind-B divergences may resolve
  upstream, or shift. The pinned version plus canary is the control.

## 8. Success criteria

0. **§4.0 resolved**: a Bun run reports honestly — complete output, an epilogue,
   and an exit code that reflects failures — verified by deliberately breaking a
   test and confirming the Bun job reports that failure. (It will not fail the
   workflow, per the `continue-on-error` in §5; the requirement is that the
   result is *visible and true*, not that it gates.) Nothing else counts until
   this holds.
1. `npm test` on Node: unchanged — 822 passing, 0 failing, no assertion weakened.
2. The suite runs to completion on Bun with every failure either fixed or listed
   in `test/bun-skips.js` with a reason and an owning phase.
3. `VM2_BUN_NO_SKIP=1` runs everything, and its output is the phase-2 backlog.
4. CI: Bun job exists and cannot affect the Node signal; the Node matrix no
   longer cancels siblings.
5. `README.md` / `SECURITY.md` state the experimental, non-boundary posture.
6. The `GHSA-x965` test is repaired and the vacuity sweep's findings are filed.
