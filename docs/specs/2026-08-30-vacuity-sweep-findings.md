# Vacuity Sweep Findings — 2026-08-30

## Context

Task 1 of this plan found that `test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js` had
been passing for its entire life without ever executing the behaviour it named:
the payload opened with `const agg = new AggregateError([agg = undefined],
'placeholder')`, which throws a host `ReferenceError` from the temporal dead
zone before the crafted error is ever thrown. The sandbox caught that
`ReferenceError`, found no marker, and reported `NO-LEAK`. Green, and
meaningless.

A **vacuous test**, for this sweep, is a test that passes for a reason other
than the security property it claims to verify — most commonly because its
payload never reaches the line that exercises the property at all.

This document is the output of a timeboxed (~2 hour) sweep for other tests of
that shape. It is scoped to *finding and evidencing* candidates, not fixing
them — no file under `lib/` or any existing test file was modified.

## What was searched

1. **TDZ self-reference in payload setup** (the exact GHSA-x965 shape) —
   a bracket-aware script scanning every `test/**/*.js` file for
   `const X = ...X...=` on one line, since the brief's literal grep command
   produces false positives under BSD/PCRE `\b` handling differences. Also
   ran the brief's literal command for completeness.
2. **`assert.throws(fn)` with no expected-error argument** — a bracket- and
   string-aware parser (not plain grep, which mis-splits on commas inside
   template literals) that located every `assert.throws(...)` call in `test/`
   and classified it by argument count.
3. **Cross-engine disagreement (Node vs. Bun)** — ran the full suite under
   both `node` and `bun` via mocha with a TAP reporter, intending to diff
   line-by-line results.
4. **Targeted manual review** of the highest-risk candidates from (1)-(3),
   plus the brief's additional suggested shapes: error-message assertions
   that a different/unrelated error could also satisfy, "must be blocked"
   tests whose block could occur solely because the attack primitive is
   absent from the runtime, and assertions living inside callbacks that
   might never fire (`.then()`/`setTimeout` without a `done()`/return-promise
   guarantee).
5. Spot-read of `catch (e) { /* blocked */ }`-shaped negative tests in
   `test/ghsa/` to see whether "no escape marker set" is corroborated by an
   independent "the payload actually ran" marker, as GHSA-x965's fix now
   does with `reachedThrow`.

## What was NOT covered (timebox limits)

- Full manual read of all ~170 `catch { }`/`catch { /* comment */ }` sites
  across `test/ghsa/`. A representative sample (~15 files) was read; the
  rest were only grep-triaged. Most of the sampled files already carry
  fine-grained "reached" markers (e.g. `GHSA-9qj6-qjgg-37qq`'s
  `gotCtorCtor`/`arrLeaked`, `GHSA-27g9-p43v-cw3v`'s `speciesCalled`), which
  is the correct shape and was not flagged.
- `test/vm.js` and `test/nodevm.js` were reviewed only for the specific
  patterns above, not read end-to-end (both are several thousand lines).
- The Node/Bun TAP diff (Step 3) did not complete — see Finding 3 below —
  so cross-engine disagreement as a discovery signal was only partially
  exercised.
- `test/compilers.js` and `test/escape-scanner.js` were not audited.
- No fixes were attempted for any finding, per the task's scope.

## Findings

### Finding 1 (PROVED): `test/vm.js` — "WebAssembly.JSTag escape via wasm exception handling" never reaches its exploit code

- **File / test**: `test/vm.js`, `it.cond('WebAssembly.JSTag escape via wasm
  exception handling', ...)`, ~line 2810.
- **Claim the test makes**: that even if wasm `try_table`/`catch` exception
  handling is used to catch a JS exception thrown across the host/sandbox
  boundary (bypassing the transformer's `catch`-block instrumentation
  entirely — see `docs/ATTACKS.md` Category 17), the raw host error still
  cannot be used to reach `process`.
- **Why it may be vacuous**: `lib/setup-sandbox.js:611-613` deletes
  `WebAssembly.JSTag` from the sandbox at bootstrap as the actual fix for
  Category 17. The test's payload builds a WASM module whose import table
  requires `{ js: { tag: WebAssembly.JSTag } }`. Since `JSTag` is `undefined`
  inside the sandbox, `new WebAssembly.Instance(...)` fails to link *before*
  the module can be instantiated — the `trigger()` import (which contains
  `err.stack`, the actual "catch a host exception" step) and the exploit line
  (`hostError.constructor.constructor("return process")()`) are never
  reached.
- **Evidence (PROVED)**: reproduced the exact payload from `test/vm.js`
  against the local `lib/main.js` in a throwaway script
  (`/private/tmp/.../scratchpad/wasm_jstag_probe.js`, not committed),
  instrumented with `globalThis.__reachedTrigger` set inside the `trigger()`
  import and `globalThis.__reachedExploit` set just before the exploit line:
  ```
  WebAssembly.JSTag in sandbox: undefined
  THREW: Error - WebAssembly.Instance(): Import #1 "js" "tag": tag import requires a WebAssembly.Tag
  reachedTrigger: false
  reachedExploit: undefined
  ```
  The throw happens at module-linking time, not at the `err.stack` access or
  the exploit call. `assert.throws(...)` in the real test has no
  expected-error argument, so it cannot distinguish this link-time
  `TypeError`/`LinkError` from the exploit actually being attempted and
  blocked.
- **Is this a live security gap?** No. The JSTag deletion is a real,
  effective, and separately-tested defense (`test/vm.js`, "WebAssembly.JSTag
  is not accessible in sandbox", ~line 2843, which directly asserts
  `typeof WebAssembly.JSTag === 'undefined'`). The "escape via wasm exception
  handling" test is not *wrong* about the outcome (the attack is blocked);
  it is redundant with its neighbor and provides **zero additional
  coverage** of the mechanism its own name and docstring describe (raw
  host-error sanitization across a wasm-caught exception). If the
  err.stack/exception-value sanitization path had a bug independent of the
  JSTag deletion, this test could not catch it, because JSTag's absence
  prevents the module from ever reaching that code. It would also stay green
  under a hypothetical future engine change that let wasm obtain a working
  exception tag through some path other than the literal
  `WebAssembly.JSTag` property.
- **Recommended action**: Either (a) accept and document explicitly (in the
  test's docstring and/or `docs/ATTACKS.md` Category 17) that this test is
  intentionally a second confirmation of the *same* JSTag-deletion defense
  rather than an independent test of exception-value sanitization, so a
  future reader doesn't mistake it for covering a different mechanism than
  the "is not accessible" test; or (b) remove it as pure duplication once
  its historical value (it was likely the original PoC-turned-regression-test
  for Category 17) is preserved elsewhere. No urgency — this is a test-suite
  clarity issue, not a sandbox weakness.

### Finding 2 (negative result, PROVED): No further TDZ self-reference bugs

- **Search**: bracket-aware scan of every `test/**/*.js` file for
  `const X = <expr containing X> =`, the exact GHSA-x965 shape (a `const`
  whose own initializer writes back to the not-yet-initialized binding,
  throwing a host `ReferenceError` from the TDZ before the payload's real
  work runs).
- **Result**: zero genuine hits. The brief's literal grep command
  (`grep -rnE 'const ([A-Za-z_$][\w$]*) = [^;]*\b\1\s*=' test/`) also
  produces zero matches post-Task-1 as expected, though it silently fails
  under this shell's `ugrep`-backed `grep` alias (reports an "invalid
  escape" parse error) — re-ran it explicitly through `/usr/bin/grep`/
  `command grep` to confirm. A second, independent Node-based regex scan
  (not relying on shell grep flavors) turned up a handful of superficially
  similar lines (e.g. `const r = vm.run('ArrayBuffer.prototype.constructor
  === ArrayBuffer')`, `const sst = ...new Error().stack...`), all of which
  are false positives of the naive pattern — the "self-reference" is inside
  a string/template literal passed to `vm.run()`, not a real TDZ hazard in
  the outer JS. Manually confirmed `test/ghsa/GHSA-x965-fc75-jpqh/
  adversarial.js` no longer contains the buggy pattern (all `AggregateError`
  constructions now use `new AggregateError([], 'x')` plus a separate
  assignment, not a self-referencing array literal).
- **Conclusion**: Task 1's fix appears to be the only instance of this
  specific bug class in the current suite.

### Finding 3 (inconclusive, not a vacuity finding): Bun cross-engine diff did not complete

- **What happened**: `node ./node_modules/mocha/bin/mocha.js test --recursive
  --ignore test/compilers.js --reporter tap` completed cleanly (836 passing,
  0 failing, matches `npm test` baseline). The equivalent `bun` invocation
  stalled after printing test 398 of ~450
  (`GHSA-6785-pvv7-mvg7 (Buffer.alloc DoS) configured cap rejects deprecated
  new Buffer(100 MB)`) and made no further progress for 6+ minutes at ~99%
  CPU before being killed. The next test in the Node run at that position is
  `GHSA-6785-pvv7-mvg7 (Buffer.alloc DoS) default is permissive (Infinity):
  large allocations are allowed without an explicit cap`
  (`test/ghsa/GHSA-6785-pvv7-mvg7/repro.js:78-87`), which does an uncapped
  `Buffer.allocUnsafe(64 * 1024 * 1024)` inside the sandbox under a
  `this.timeout(30000)` guard.
- **Why this is not being filed as a vacuity finding**: a hang is the
  opposite signal from what this sweep is chasing (a test that passes too
  easily). It's plausibly a Bun-specific large-allocation or timer
  performance characteristic (mocha's 30s timeout apparently not firing,
  or firing but Bun not yielding), which is exactly the class of Bun
  runtime quirk this plan's earlier tasks (`test/bun-skips.js`) were built
  to triage and skip. Chasing it further would be Bun-compatibility
  debugging, not a vacuity finding, and is out of scope for this task ("do
  not attempt to fix what you find").
- **Recommendation**: hand this specific hang (test at
  `test/ghsa/GHSA-6785-pvv7-mvg7/repro.js:78-87`, and possibly its siblings
  in the same `describe` block) to whoever owns the Bun-compat backlog
  (`VM2_BUN_NO_SKIP=1` failure list per this plan's final verification step)
  for triage — it may need a `test/bun-skips.js` entry, a Bun-specific
  timeout bump, or turn out to be a genuine Bun bug worth reporting upstream.
  This was not independently confirmed to reproduce outside this one run;
  treat it as a lead, not a filed defect.

### Candidates from `assert.throws(fn)` with no expected-error argument

Per the brief's Step 2 ask, every `assert.throws(...)` call across `test/`
with fewer than 2 arguments (i.e. no expected-error class/regex/predicate)
was located with a bracket- and string-aware parser (the brief's literal
`grep -rn "assert.throws" test/ghsa/ | grep -vE "/[^/]+/"` produces zero
output — the second `grep -v` filters out every line, since every path under
`test/ghsa/` contains an extra path segment; ran the corrected, broader
search instead). 10 of 177 total `assert.throws` call sites have no
expected-error argument:

| Location | Test | Disposition |
|---|---|---|
| `test/vm.js:1305` | "Error.prepareStackTrace attack" — `WeakMap.prototype.set` poisoning variant | **Investigated, PROVED not vacuous.** Instrumented with a `reachedStack` flag inside the attacker's `prepareStackTrace` callback: the callback *does* fire and *does* run the real `c.map(c => c.getThis()).find(a => a)` leak attempt; the throw comes from `stack` being `undefined` because no callsite's `this` was truthy (the attack genuinely fails to find anything to leak), not from unrelated setup breakage. |
| `test/vm.js:1317` | "Error.prepareStackTrace attack" — `global.Error` reassignment variant | **Investigated, PROVED not vacuous.** Instrumented the same way. In this sandboxed run the attacker's `prepareStackTrace` callback never fires (`reachedStack2: false`) because `global.Error` is a sealed, non-writable slot in the sandbox (`lib/setup-sandbox.js`, issue #467) so the reassignment is a silent no-op; the throw comes from indexing `.mainModule` off the resulting plain-string `.stack`. As a control, the identical payload run in bare Node (no vm2 at all) *does* have the callback fire (`reachedStack2: true`), confirming the sandboxed behavior differs specifically because of the Error-sealing defense, not because the attack is inert everywhere. |
| `test/vm.js:2867` | Proxy sealed: sandbox cannot re-`defineProperty` a removed, sealed global | Not deeply instrumented — single-expression payload (`Object.defineProperty(globalThis, "Proxy", {...})` against a slot that's `writable:false, configurable:false`) has essentially one possible throw source (the spec-mandated `TypeError` for a rejected `[[DefineOwnProperty]]`). Low risk; not the GHSA-x965 shape (no multi-statement setup that could throw early for an unrelated reason). |
| `test/vm.js:3143`, `3150`, `3157` | `vm.protect()` — strict-mode writes to a protected host object's properties must throw | Same reasoning as above: single-expression strict-mode assignment against a non-writable property. `vm.protect()` is a convenience feature, not the core sandbox boundary (see `CLAUDE.md`'s file table). Not deeply instrumented given the timebox; flagged as low priority. |
| `test/vm.js:3161` | `vm.protect()` — `Object.defineProperty` with a getter on a protected object's `toString` | Same reasoning; low priority. |
| `test/nodevm.js:670` | "does not find a TS module with the default settings" | Functional test (module resolution), not a security assertion — any throw during `require('./data/custom_extension')` satisfies it, including an unrelated resolver bug. Worth tightening (e.g. assert the module-not-found shape) but not evidence of an actual bug; not investigated further given the timebox. |
| `test/ghsa/GHSA-2cm2-m3w5-gp2f/repro.js:127` | "regression: import() in source is rewritten to throw" | **SUSPECT, not proved.** `assert.throws(() => new VM().run("import('fs')"))` with no expected error. The transformer is documented (`CLAUDE.md`) to cap at `ecmaVersion: 2022` and rewrite dynamic `import()`; a parse-level rejection of `import()` syntax for a completely unrelated reason would also satisfy this assertion. Not instrumented due to time; recommend adding the expected `VMError`/message (the file already does this correctly for its sibling test two lines below, `/Use of internal vm2 state variable/`, so the fix is a one-line pattern match away). |

All ten are legitimate candidates for tightening per the brief ("each is a
candidate for tightening"); two were escalated to full investigation because
they sit inside a named "attack" test in the core suite, and both came back
clean (not vacuous — see Findings above disguised as table rows). The
remaining eight are lower-priority hygiene items, concentrated in
non-boundary features (`vm.protect()`, module resolution) or already
well-covered by an adjacent, correctly-scoped test (`Proxy` sealing).

## Other shapes checked, no findings

- **Error-message assertions matched by an unrelated error**: searched for
  `assert.throws(fn, /generic-pattern/)` where the pattern is a bare
  `TypeError`/`Error`/`Cannot read`/`is not a function`/`undefined` — no
  hits. The suite's message-matching `assert.throws` calls consistently use
  specific, purpose-built regexes or the `msg()` helper
  (`test/engine-messages.js`) keyed to a named constant, not generic
  substrings.
- **"Must be blocked" tests that would pass on an engine lacking the
  attack primitive**: the closest match found was Finding 1 above (WASM
  JSTag), which is a variant of this shape — the primitive isn't *absent
  from the engine*, it's *deliberately removed by vm2's own defense*,
  which is a more subtle version of the same root problem (the test can't
  tell "removed by defense" from "removed by something else / never worked
  here"). No pure engine-absence case (i.e. an unconditional `it(...)`,
  not `it.cond(...)`, that would silently pass because a feature simply
  doesn't exist on the host) was found; the suite is disciplined about
  gating feature-dependent tests behind `it.cond`.
- **Assertions inside a callback that might never fire**: sampled every
  `.then(` site in `test/ghsa/` (14 files). All either `return` the promise
  chain (mocha awaits it correctly) or use `setTimeout(..., done)` with the
  assertion unconditionally inside the timeout callback (so a callback that
  never fires would time out and fail loudly, not pass silently) — e.g.
  `test/ghsa/GHSA-27g9-p43v-cw3v/repro.js`'s three `it.cond(..., done)`
  tests, which additionally each check both "attack primitive did not fire"
  and a companion "legitimate use still works" assertion, avoiding the
  false-negative-by-omission trap. No instance found where a `.then()`
  callback carrying the actual assertion was both (a) not returned/awaited
  and (b) had no independent timeout/failure path.

## Summary

- **1 finding PROVED as a vacuous test**: `test/vm.js` "WebAssembly.JSTag
  escape via wasm exception handling" throws for a link-time reason
  (missing `WebAssembly.JSTag` import) before ever reaching the wasm
  exception-catch / raw-error-sanitization code path its name and docstring
  describe. Not a live security gap — the underlying defense (JSTag
  deletion) works and is independently, correctly tested by the neighboring
  "WebAssembly.JSTag is not accessible in sandbox" test — but the test
  provides no coverage of what it claims to cover.
- **2 candidates investigated and PROVED NOT vacuous**: both
  `assert.throws(fn)`-with-no-expected-error sites inside `test/vm.js`'s
  "Error.prepareStackTrace attack" test were instrumented and confirmed to
  exercise real, defense-sensitive code paths (confirmed via a bare-Node
  control run for the second one).
- **8 further candidates listed, not deeply investigated** (timebox): all
  `assert.throws(fn)` call sites with no expected-error argument, per the
  brief's Step 2. Recommended for tightening; none flagged as evidence of
  an actual live bug.
- **1 inconclusive lead, not a vacuity finding**: the Bun cross-engine run
  hung partway through and was not completed; the stall point is identified
  for the Bun-compat backlog but was not chased further, per this task's
  scope.
- **Negative result**: no other instance of the exact GHSA-x965 TDZ
  self-reference shape exists in `test/` today.

Given the timebox, this sweep prioritized depth on the highest-signal
candidates (assert.throws-without-expected-error sites inside named
"attack" tests, and the WASM JSTag test flagged by the brief's own list of
shapes) over exhaustively re-deriving every negative-result test in the
~170-site `catch { }` population. That population was triaged by sampling
and by the design pattern it consistently follows (independent "reached"/
"primitive fired" markers alongside the "did not escape" assertion), which
is the correct shape and was not found to be violated in the files sampled.
