# Bun Support Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make vm2's full test suite run to completion and report honestly under Bun, with every remaining divergence enumerated in one skip list, and a CI job that can never report a success it did not verify.

**Architecture:** Four small flat helper modules under `test/` (following the `test/fs-compat.js` precedent — feature detection, never version detection), a run-completeness checker under `scripts/`, and a separate non-blocking CI job. No changes to `lib/`. No security claim for Bun.

**Tech Stack:** Node.js (>= 20 for the modern suite), Bun 1.4.0, mocha 12, GitHub Actions.

**Spec:** `docs/specs/2026-08-30-bun-support-design.md` — read it first. This plan implements it; where they disagree, the spec wins.

## Global Constraints

- **No `lib/` changes.** Phase 1 is tests and CI only. If a task appears to require a `lib/` edit, stop and escalate — it means a divergence was misclassified.
- **No assertion may be weakened on Node.** `npm test` must stay at **822 passing, 0 failing** after every task. This is the single most important invariant in this plan.
- **Feature-detect, never version-detect.** The stated principle of `test/fs-compat.js`. `process.versions.node` is `26.3.0` on Bun and must never be used to decide engine behaviour.
- **Bun is experimental and NOT a security boundary.** No task may imply otherwise in code, comments, or docs.
- **Pinned Bun version: `1.4.0`.** Every measurement in the spec was taken there.
- **Node baseline for comparison:** v26.7.0 → `test/vm.js` 116, `test/nodevm.js` 51, `test/ghsa` 655, total 822.
- **Code style:** tabs for indentation, `'use strict';` at the top of helper modules, single quotes. Match surrounding files. `npm run lint` must not gain new problems (2 pre-existing are expected: a parse error in `test/additional-modules/my-es-module/index.js` and one unused-eslint-disable warning).
- **Commit after every task.** Small, focused commits.

---

### Task 1: Repair the vacuous GHSA-x965 test (unblocks `test/ghsa` on Bun)

Until this lands, Bun's transpiler rejects the file at load and **the entire `test/ghsa` run aborts — zero of 655 tests execute.** The same line also makes the test vacuous on Node, so this task proves the vacuity before removing the cause.

**Files:**
- Modify: `test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js:104`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing importable. Unblocks `test/ghsa` file loading under Bun for every later task.

- [ ] **Step 1: Read the test as it stands**

Run: `sed -n '100,112p' test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js`

You should see the test `'.message accessor returning a host object (must be treated as non-primitive)'` beginning with:

```js
const agg = new AggregateError([agg = undefined], 'placeholder');
```

`agg` is never read again in this test — the test body uses `a2` throughout. Evaluating `agg = undefined` while `agg` is in its temporal dead zone throws a host `ReferenceError`, so the payload aborts before `throw a2` is ever reached.

- [ ] **Step 2: Write the failing assertion that proves vacuity**

Add a host-side flag that is set immediately before the crafted error is thrown, and assert it was reached. Replace the whole `it(...)` block with:

```js
	it('.message accessor returning a host object (must be treated as non-primitive)', function () {
		let reachedThrow = false;
		assert.strictEqual(probe(function () {
			const agg = new AggregateError([agg = undefined], 'placeholder');
			const a2 = new AggregateError([], 'x'); a2.errors = [a2];
			Object.defineProperty(a2, 'message', {get: function () { return process; }, configurable: true});
			a2.leak = process;
			reachedThrow = true;
			throw a2;
		}), 'NO-LEAK');
		assert.ok(reachedThrow, 'payload never reached its throw - the test is vacuous');
	});
```

- [ ] **Step 3: Run it on Node and watch it FAIL**

Run: `node ./node_modules/mocha/bin/mocha.js test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js --reporter spec --grep "message accessor"`

Expected: **FAIL** — `payload never reached its throw - the test is vacuous`.

This is the point of the task. The test has been green for its entire life without executing the behaviour it names; this step is the proof.

- [ ] **Step 4: Delete the dead TDZ line**

Remove exactly this line from the block you just edited:

```js
			const agg = new AggregateError([agg = undefined], 'placeholder');
```

Leave the `reachedThrow` flag and its assertion in place permanently — it is the guard against this regressing.

- [ ] **Step 5: Run it again and watch it PASS**

Run: `node ./node_modules/mocha/bin/mocha.js test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js --reporter spec --grep "message accessor"`

Expected: **PASS**. The crafted `a2` is now genuinely thrown, its `.message` accessor returns host `process`, and vm2's sanitizer still yields `NO-LEAK`. The defence was always sound; only the test was broken.

- [ ] **Step 6: Verify Bun can now load the file**

Run: `bun ./node_modules/mocha/bin/mocha.js test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js --reporter tap`

Expected: the file parses and tests run. It is fine if some fail — later tasks handle that. What must NOT appear is `error: This assignment will throw because "agg" is a constant`.

- [ ] **Step 7: Confirm the Node suite is unchanged**

Run: `npm test`
Expected: `822 passing`, `0 failing`.

- [ ] **Step 8: Commit**

```bash
git add test/ghsa/GHSA-x965-fc75-jpqh/adversarial.js
git commit -m "test(GHSA-x965): repair vacuous .message accessor test

A TDZ self-reference in the payload threw a host ReferenceError before the
crafted AggregateError was ever thrown, so the sandbox caught the
ReferenceError, found no marker, and reported NO-LEAK. The test has been
green without exercising the path it names.

Remove the dead line and add a reachedThrow guard so the vacuity cannot
return. The defence itself is unaffected - the repaired test still passes.

Also unblocks test/ghsa under Bun, whose transpiler statically rejects the
line and aborts the entire run."
```

---

### Task 2: `test/engine.js` — honest engine and version predicates

**Files:**
- Create: `test/engine.js`
- Create: `test/engine-selftest.js`

**Interfaces:**
- Produces (relied on by Tasks 3–6):
  - `IS_BUN: boolean`
  - `ENGINE: 'v8' | 'jsc'`
  - `NODE_MAJOR: number | null` — real Node major, `null` on Bun
  - `atLeastNode(n: number): boolean` — "runtime is at least this modern"; `true` on Bun
  - `nodeOlderThan(n: number): boolean` — "runtime is Node older than n"; `false` on Bun

**Background the implementer needs:** Bun reports `process.versions.node = '26.3.0'`. Most existing gates are *lower* bounds (`NODE_VERSION > 8`, `>= 11`) meaning "not ancient Node" — Bun legitimately satisfies those, so they must keep returning true. The dangerous shape is the *upper* bound at `test/vm.js:102` (`NODE_VERSION < 26`), which on Bun silently means the opposite of what its author intended. The two directions therefore get two differently-named predicates so the author must choose deliberately.

- [ ] **Step 1: Write the failing selftest**

Create `test/engine-selftest.js`:

```js
/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {IS_BUN, ENGINE, NODE_MAJOR, atLeastNode, nodeOlderThan} = require('./engine');

describe('test/engine.js', function () {
	it('detects the engine without consulting process.versions.node', function () {
		assert.strictEqual(IS_BUN, typeof globalThis.Bun !== 'undefined');
		assert.strictEqual(ENGINE, IS_BUN ? 'jsc' : 'v8');
	});

	it('NODE_MAJOR is null on Bun and a number on Node', function () {
		if (IS_BUN) {
			assert.strictEqual(NODE_MAJOR, null);
		} else {
			assert.ok(typeof NODE_MAJOR === 'number' && NODE_MAJOR > 0);
		}
	});

	it('atLeastNode treats Bun as a modern runtime', function () {
		assert.strictEqual(atLeastNode(8), true);
		assert.strictEqual(atLeastNode(20), true);
	});

	it('nodeOlderThan is always false on Bun (Bun is not old Node)', function () {
		if (IS_BUN) {
			assert.strictEqual(nodeOlderThan(26), false);
			assert.strictEqual(nodeOlderThan(8), false);
		} else {
			assert.strictEqual(nodeOlderThan(NODE_MAJOR + 1), true);
			assert.strictEqual(nodeOlderThan(NODE_MAJOR), false);
		}
	});
});
```

- [ ] **Step 2: Run it and verify it fails**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: FAIL — `Cannot find module './engine'`.

- [ ] **Step 3: Implement `test/engine.js`**

```js
'use strict';

// Engine detection for the regression suites.
//
// Bun reports `process.versions.node` as '26.3.0', so every version gate in
// this suite sees "Node 26" when running on Bun. Most of those gates are lower
// bounds meaning "not ancient Node", which Bun legitimately satisfies -- but a
// Node version number is the wrong axis for a question about a different
// engine, and an UPPER bound (`NODE_VERSION < 26`) silently means the opposite
// of what its author intended.
//
// Following test/fs-compat.js: prefer feature detection to either of these.
// Reach for ENGINE only where the divergence is genuinely about the engine
// rather than about a capability that can be probed directly.

const IS_BUN = typeof globalThis.Bun !== 'undefined';

// 'jsc' (JavaScriptCore, via Bun) or 'v8' (Node). Derived from the runtime's
// own identity, never from a version string.
const ENGINE = IS_BUN ? 'jsc' : 'v8';

// The real Node major version, or null when not running on Node at all.
// Deliberately null rather than a number so that arithmetic comparisons
// against it are visibly wrong on Bun instead of quietly claiming Node 26.
const NODE_MAJOR = IS_BUN ? null : parseInt(process.versions.node.split('.')[0], 10);

// "The runtime is at least this modern." True on Bun: it is a current runtime,
// and these gates exist to skip tests on genuinely ancient Node.
function atLeastNode(n) {
	return IS_BUN ? true : NODE_MAJOR >= n;
}

// "The runtime is Node, older than n." False on Bun, which is not Node at any
// version. Use this for upper-bound gates, where treating Bun as Node 26 would
// silently invert the author's intent.
function nodeOlderThan(n) {
	return IS_BUN ? false : NODE_MAJOR < n;
}

module.exports = {IS_BUN, ENGINE, NODE_MAJOR, atLeastNode, nodeOlderThan};
```

- [ ] **Step 4: Run the selftest on both runtimes**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: 4 passing.

Run: `bun ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: 4 passing.

- [ ] **Step 5: Convert the one upper-bound gate**

In `test/vm.js`, add above line 9's `NODE_VERSION` declaration:

```js
const {nodeOlderThan} = require('./engine');
```

Import **only** `nodeOlderThan` — it is the only member this task uses here.
Skipping is owned by `test/bun-setup.js` (Task 3), so spec files never import
`IS_BUN` or `ENGINE`. Unused bindings would risk the no-new-lint-problems
constraint.

Then at `test/vm.js:102`, replace:

```js
		if (NODE_VERSION < 26) assert.throws(() => inspect(doubleProxy), /Expected/);
```

with:

```js
		if (nodeOlderThan(26)) assert.throws(() => inspect(doubleProxy), /Expected/);
```

Leave every *lower*-bound `NODE_VERSION` comparison alone for now — they resolve correctly on Bun and churning them adds risk without benefit.

- [ ] **Step 6: Verify both runtimes**

Run: `npm test`
Expected: **`826 passing`, `0 failing`** — the 822 baseline plus this task's 4 selftests. If you see anything other than 826/0, stop.

Running count of Node tests as this plan proceeds: baseline 822 → Task 2 **826** → Task 3 **828** → Task 4 **832** → Task 5 **836**. Each number is the baseline plus the selftests added so far; no task may change the 822 that came before.

Run: `bun ./node_modules/mocha/bin/mocha.js test/vm.js --reporter tap`
Expected: `# fail 17` — unchanged from the baseline. This task is not meant to fix Bun failures.

- [ ] **Step 7: Commit**

```bash
git add test/engine.js test/engine-selftest.js test/vm.js
git commit -m "test: add engine detection with honest version predicates

Bun reports process.versions.node = 26.3.0, so every version gate sees
'Node 26' there. Lower-bound gates ('not ancient Node') are satisfied
legitimately, but the upper-bound gate at test/vm.js:102 silently inverted
its author's intent.

Add test/engine.js with two differently-named predicates so the direction
must be chosen deliberately: atLeastNode() is true on Bun, nodeOlderThan()
is false on Bun. Convert the one upper-bound gate."
```

---

### Task 3: `test/bun-skips.js` — one central skip list

This is what lets a full Bun run survive. It must include `GHSA-v27g-jcqj-v8rw`, which **terminates the mocha process** under Bun (spec §4.0).

**Files:**
- Create: `test/bun-skips.js`
- Create: `test/bun-setup.js`
- Modify: `package.json` (the `test` script)

**Interfaces:**
- Consumes: `IS_BUN` from `test/engine.js` (Task 2).
- Produces:
  - `skipReason(fullTitle: string): string | null` — the reason this test is skipped on Bun, or `null`. `fullTitle` is the suite path plus the test name.
  - `SKIPS: Array<{match: string, reason: string, phase: number, security: boolean}>`
  - `NO_SKIP: boolean`

Note: `test/vm.js` and `test/nodevm.js` are **not** modified by this task — see Step 5.

- [ ] **Step 1: Write the failing test**

Append to `test/engine-selftest.js`:

```js
describe('test/bun-skips.js', function () {
	const {SKIPS, skipReason} = require('./bun-skips');

	it('every entry has a reason and an owning phase', function () {
		assert.ok(SKIPS.length > 0);
		for (const s of SKIPS) {
			assert.ok(typeof s.match === 'string' && s.match.length > 0, 'match required');
			assert.ok(typeof s.reason === 'string' && s.reason.length > 10, 'reason must be substantive: ' + s.match);
			assert.ok(s.phase === 2, 'phase must be 2 - phase 1 fixes nothing behavioural');
			assert.strictEqual(typeof s.security, 'boolean');
		}
	});

	it('matches by substring of the full test title', function () {
		assert.ok(skipReason('GHSA-v27g-jcqj-v8rw (CallSite path leak via prepareStackTrace) getFileName on host frames returns null (no absolute path leaked)'));
		assert.strictEqual(skipReason('some completely unrelated test name'), null);
	});
});
```

- [ ] **Step 2: Run and verify it fails**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: FAIL — `Cannot find module './bun-skips'`.

- [ ] **Step 3: Implement `test/bun-skips.js`**

```js
'use strict';

// Tests skipped when running under Bun.
//
// This list IS the phase-2 backlog. Every entry is a divergence between
// JavaScriptCore and V8 that phase 1 deliberately does not fix -- fixing them
// is security work, and Bun has no threat model yet (see
// docs/specs/2026-08-30-bun-support-design.md section 6).
//
// The goal is to drive this list to zero. Run with VM2_BUN_NO_SKIP=1 to
// ignore it entirely and see what now passes.
//
// `security: true` marks a divergence where a vm2 defence does not hold on
// JSC, as opposed to a functional or Bun-Node-compat difference.

const SKIPS = [
	{
		// DELIBERATELY BROAD: this matches all 7 tests in the file, including
		// ones that might otherwise pass. Any test here can construct a sandbox
		// prepareStackTrace, and doing so terminates the Bun process outright --
		// so the whole file is quarantined rather than risk losing the run.
		// Phase 2 should narrow this once the crash is understood.
		match: 'GHSA-v27g-jcqj-v8rw',
		reason:
			'CallSite objects handed to a sandbox Error.prepareStackTrace have no ' +
			'methods on JSC (getFileName is undefined), so the host-frame redaction ' +
			'this advisory added is untestable there. The resulting TypeError also ' +
			'terminates the Bun process, taking the whole run with it. Whole file ' +
			'quarantined (7 tests).',
		phase: 2,
		security: true,
	},
	{
		match: 'Error.captureStackTrace re-capture on the caught error',
		reason:
			'JSC repopulates .stack with host frames including absolute paths, ' +
			'bypassing the GHSA-x6m4 redactor. Information disclosure.',
		phase: 2,
		security: true,
	},
	{
		match: 'custom Error.prepareStackTrace + captureStackTrace over the caught error',
		reason: 'Same root cause as the GHSA-x6m4 re-capture entry above.',
		phase: 2,
		security: true,
	},
	{
		match: "a sandbox buffer's .buffer never exceeds its own length",
		reason:
			'Buffer.from(arrayLike) returns a zero-length buffer on Bun, so the ' +
			'pool-ownership invariant cannot be exercised.',
		phase: 2,
		security: false,
	},
	{
		match: 'legitimate small Buffer.from(arrayLike) works',
		reason: 'Buffer.from(arrayLike) returns length 0 on Bun. Same root cause.',
		phase: 2,
		security: false,
	},
	{
		match: 'default (Infinity) bufferAllocLimit leaves Buffer.from(arrayLike) unrestricted',
		reason: 'Buffer.from(arrayLike) returns length 0 on Bun. Same root cause.',
		phase: 2,
		security: false,
	},
	{
		match: 'does not throw a proxy-invariant error (regression)',
		reason:
			'Object.freeze on a frozen host object with a non-configurable accessor ' +
			'throws a proxy-invariant TypeError on JSC where V8 does not.',
		phase: 2,
		security: false,
	},
	{
		match: 'allowExtension is forced off',
		reason:
			"Bun's node:sqlite refuses extension loading with its own error, so " +
			"vm2's forced allowExtension:false is not what blocks it. Still blocked, " +
			'but the defence is unverified on Bun.',
		phase: 2,
		security: true,
	},
	{
		match: 'isDangerousSymbol covers full nodejs.* set',
		reason:
			"Bun's node:assert deepStrictEqual does not treat a cross-realm array as " +
			'equal to a host array. A Bun Node-compat gap, not a vm2 defect.',
		phase: 2,
		security: false,
	},
	{
		match: '.next/.return/.throw on async generator instances all sanitize results',
		reason: "Bun's node:assert cross-realm reference equality. Same class as above.",
		phase: 2,
		security: false,
	},
	{
		match: 'Object.getOwnPropertyNames does not expose the state name',
		reason: "Bun's node:assert deepStrictEqual cross-realm array handling.",
		phase: 2,
		security: false,
	},
	{
		match: 'does not block sandbox-local writes (negative control)',
		reason: "Bun's node:assert deepStrictEqual cross-realm array handling.",
		phase: 2,
		security: false,
	},
	{
		match: 'inspect array (issue #566)',
		reason:
			"Bun's util.inspect renders cross-realm arrays as \"Array { '0': 1 }\" " +
			'rather than "[ 1, 2, 3 ]". A Bun Node-compat gap.',
		phase: 2,
		security: false,
	},
	{
		match: 'inspect nested object and array (issue #566)',
		reason: "Bun's util.inspect cross-realm array rendering. Same root cause.",
		phase: 2,
		security: false,
	},
	{
		match: 'VMScript options',
		reason:
			'CallSite getFileName() returns undefined on JSC, so VMScript filename / ' +
			'lineOffset / columnOffset metadata is not observable.',
		phase: 2,
		security: false,
	},
	{
		match: 'default is permissive (Infinity): large allocations are allowed',
		reason:
			'Buffer.allocUnsafe(64MB) across the bridge takes >400s on Bun versus ' +
			'1.7s on Node - a >240x divergence that reads as a hang.',
		phase: 2,
		security: false,
	},
	{
		match: 'Node internal prepareStackTrace attack',
		reason:
			'The payload recurses until a stack overflow terminates it. JSC does not ' +
			'overflow promptly, so the VM runs unbounded and the test hits mocha\'s ' +
			'timeout instead. Adding a VM timeout would change the error the test ' +
			'asserts on, so this is left for phase 2 to re-express without relying ' +
			'on a fast RangeError.',
		phase: 2,
		security: false,
	},
	{
		match: 'transformer attack',
		reason:
			'Same unbounded-recursion shape as the prepareStackTrace attack above: ' +
			'JSC does not stack-overflow promptly, so the test times out.',
		phase: 2,
		security: false,
	},
];

const NO_SKIP = process.env.VM2_BUN_NO_SKIP === '1';

// Returns the reason this test is skipped under Bun, or null to run it.
// `fullTitle` is the suite path plus the test name, so an entry may match
// either a describe block (quarantining a whole file) or a single test.
function skipReason(fullTitle) {
	if (NO_SKIP) return null;
	for (let i = 0; i < SKIPS.length; i++) {
		if (fullTitle.indexOf(SKIPS[i].match) !== -1) return SKIPS[i].reason;
	}
	return null;
}

module.exports = {SKIPS, skipReason, NO_SKIP};
```

No skip *counter* is exported: nothing consumes one. CI counts skips by
grepping `# SKIP` out of the TAP output, which is the runner's own record
rather than a parallel tally that could drift from it.

- [ ] **Step 4: Run and verify the selftest passes**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: 6 passing.

- [ ] **Step 5: Create `test/bun-setup.js`**

**Do not wire skipping through `it.cond` in the spec files.** That approach was
tried and rejected during the pre-flight scan, for two independent reasons:

1. **Load order is the opposite of what it needs to be.** `test/ghsa` loads
   *first* (its tests are numbered from 1) and `test/vm.js` loads *last* (test
   753). The ghsa files install their own fallback `it.cond` at load time and
   call it during registration, long before `test/vm.js` could rewire anything.
   Skips would have applied to none of them — and that is where 12 of the 16
   entries point.
2. **Most targeted tests are plain `it()`,** not `it.cond`, so an `it.cond`
   wrapper would miss them regardless of ordering.

Instead, create `test/bun-setup.js`, loaded via `--require` so it runs before
any spec file:

```js
'use strict';

// Applies test/bun-skips.js when running under Bun.
//
// Loaded via `--require` so it runs BEFORE any spec file. That ordering is the
// whole point: test/ghsa loads first and test/vm.js last, so wiring installed
// from inside a spec file could never reach the ghsa suites, where most
// skipped tests live.
//
// Two globals are wrapped:
//
//   describe -- to maintain the suite-name stack, because skip patterns match
//               the FULL title and an `it` wrapper alone sees only the test's
//               own name. This is what lets one entry quarantine a whole file.
//   it       -- to register a pending test when the full title matches.
//
// mocha installs both on the global once per spec file, so the assignment is
// intercepted with an accessor rather than wrapping a value that does not yet
// exist at --require time.

const {IS_BUN} = require('./engine');
const {skipReason} = require('./bun-skips');

// On Node this module does nothing at all.
if (IS_BUN) {
	const suiteStack = [];

	function fullTitle(name) {
		return suiteStack.length ? suiteStack.join(' ') + ' ' + name : name;
	}

	function intercept(prop, wrap) {
		let current;
		Object.defineProperty(global, prop, {
			configurable: true,
			get: function () {
				return current;
			},
			set: function (incoming) {
				if (typeof incoming !== 'function' || incoming.__vm2BunWrapped) {
					current = incoming;
					return;
				}
				const wrapped = wrap(incoming);
				// Carry mocha's own attachments (skip, only, aliases).
				Object.keys(incoming).forEach(function (k) {
					wrapped[k] = incoming[k];
				});
				wrapped.skip = incoming.skip;
				wrapped.only = incoming.only;
				wrapped.__vm2BunWrapped = true;
				current = wrapped;
			},
		});
	}

	intercept('describe', function (original) {
		return function (name, fn) {
			// Forward ALL arguments: describe.skip passes a third internally.
			if (typeof fn !== 'function') return original.apply(this, arguments);
			const args = Array.prototype.slice.call(arguments);
			args[1] = function () {
				suiteStack.push(name);
				try {
					return fn.apply(this, arguments);
				} finally {
					suiteStack.pop();
				}
			};
			return original.apply(this, args);
		};
	});

	intercept('it', function (original) {
		return function (name, fn) {
			// Register the skip by calling the original with NO callback, which
			// is how mocha marks a test pending. Do NOT call original.skip():
			// mocha's it.skip delegates to context.it, which is this wrapper,
			// and recurses until the stack overflows.
			if (typeof name === 'string' && skipReason(fullTitle(name))) {
				return original(name);
			}
			return original.apply(this, arguments);
		};
	});
}
```

`test/vm.js` and `test/nodevm.js` keep their existing `it.cond` definitions
unchanged — `it.cond` calls `it()`, which is already wrapped.

This module is also collected as a spec file by `mocha test --recursive`. That
is harmless: the module cache dedupes, so the body executes exactly once on
both runtimes (verified).

- [ ] **Step 6: Register the setup module**

In `package.json`, change the `test` script to:

```json
"test": "mocha test --recursive --ignore test/compilers.js --require ./test/bun-setup.js"
```

The module is inert on Node, so this is a no-op there — but it keeps one
command working on both runtimes rather than needing a Bun-specific invocation.

- [ ] **Step 7: Sanity-check the patterns for over- and under-matching**

`skipReason` matches by substring of the test title, so a short pattern can
disable more than intended. Check each one against the **source** titles:

```bash
grep -rhoE "it(\.cond)?\(\s*'[^']+'" test/ | sed -E "s/.*'([^']+)'.*/\1/" | sort -u > /tmp/titles.txt
wc -l /tmp/titles.txt
```

Then for each `match` string, confirm the hit count is what you expect. Only
`GHSA-v27g-jcqj-v8rw` should match more than one test (7, deliberately).

**Trap:** do NOT verify these against TAP output. Mocha's TAP reporter strips
`#` from test names, so `inspect array (issue #566)` appears there as
`inspect array (issue 566)` and a correct pattern looks like a miss. The
matcher runs against the real mocha title, not the TAP rendering.

- [ ] **Step 8: Verify Node is untouched and Bun survives**

Run: `npm test`
Expected: `828 passing`, `0 failing` (822 + 4 from Task 2 + 2 here). Skips must not engage on Node.

Run: `bun ./node_modules/mocha/bin/mocha.js test/ghsa/GHSA-v27g-jcqj-v8rw/repro.js --require ./test/bun-setup.js --reporter tap`
Expected: the process no longer dies. All 7 tests appear marked `# SKIP`, and a TAP epilogue is printed. Without `--require` this file still kills the process — that is expected and is why Step 6 puts the flag in the `test` script.

Then confirm the skips reach the ghsa suites in a full run, which is the whole point of Ruling 1:

Run: `bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --require ./test/bun-setup.js --reporter tap > /tmp/t3.tap 2>&1; grep -c '# SKIP' /tmp/t3.tap`
Expected: a count comfortably above the 19 tests that are already pending on Node. If it equals the Node pending count, the wiring is not reaching the ghsa files — stop and investigate before proceeding.

- [ ] **Step 9: Commit**

```bash
git add test/bun-skips.js test/bun-setup.js test/engine-selftest.js package.json
git commit -m "test: add central Bun skip list

One file listing every JSC divergence phase 1 does not fix, each with a
reason, an owning phase, and whether a vm2 defence is implicated. This list
is the phase-2 backlog; the goal is to drive it to zero.

Includes GHSA-v27g, whose sandbox prepareStackTrace payload terminates the
Bun process outright and takes the rest of the run with it.

VM2_BUN_NO_SKIP=1 ignores the list entirely."
```

---

### Task 4: `scripts/check-run-complete.js` — the durable fix for dishonest green

The skip list stops today's crash. This stops the *next* one from passing silently. Per spec §4.0 this is the actual requirement, and it is what makes every later measurement believable.

**Files:**
- Create: `scripts/check-run-complete.js`
- Create: `test/check-run-complete-selftest.js`

**Interfaces:**
- Consumes: nothing.
- Produces: a CLI. `node scripts/check-run-complete.js <tap-file> --min-tests <n>` exits 0 if the run is complete, 1 with a diagnostic otherwise.

- [ ] **Step 1: Write the failing test**

Create `test/check-run-complete-selftest.js`:

```js
/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {checkTap} = require('../scripts/check-run-complete');

const COMPLETE = ['ok 1 a', 'ok 2 b', '1..2', '# tests 2', '# pass 2', '# fail 0'].join('\n');
const TRUNCATED = ['ok 1 a', 'ok 2 b'].join('\n');
const SHORT = ['ok 1 a', '1..1', '# tests 1', '# pass 1', '# fail 0'].join('\n');
const FAILING = ['not ok 1 a', '1..1', '# tests 1', '# pass 0', '# fail 1'].join('\n');

describe('scripts/check-run-complete', function () {
	it('accepts a complete passing run', function () {
		assert.deepStrictEqual(checkTap(COMPLETE, 2), {ok: true, problems: []});
	});

	it('rejects a run with no epilogue (the dishonest-green case)', function () {
		const r = checkTap(TRUNCATED, 2);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('epilogue'));
	});

	it('rejects a run that reports fewer tests than expected', function () {
		const r = checkTap(SHORT, 2);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('expected at least 2'));
	});

	it('rejects a run with failures', function () {
		const r = checkTap(FAILING, 1);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('1 failing'));
	});
});
```

- [ ] **Step 2: Run and verify it fails**

Run: `node ./node_modules/mocha/bin/mocha.js test/check-run-complete-selftest.js --reporter spec`
Expected: FAIL — `Cannot find module '../scripts/check-run-complete'`.

- [ ] **Step 3: Implement `scripts/check-run-complete.js`**

```js
'use strict';

// Verify that a mocha TAP run actually finished.
//
// A test runner that dies mid-run and still exits 0 is worse than no test
// runner: it reports a success it never verified. That is exactly what mocha
// under Bun did before test/bun-skips.js -- a single file terminated the
// process, 112 tests never ran, and the exit status was 0.
//
// A skip list fixes one such crash. This check fixes the class: any future
// mid-run death becomes a loud failure instead of a quiet pass.

function checkTap(text, minTests) {
	const problems = [];
	const lines = String(text).split('\n');

	let reported = null;
	let failing = null;
	let sawPlan = false;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (/^1\.\.\d+$/.test(line)) sawPlan = true;
		const t = /^# tests (\d+)/.exec(line);
		if (t) reported = parseInt(t[1], 10);
		const f = /^# fail (\d+)/.exec(line);
		if (f) failing = parseInt(f[1], 10);
	}

	if (!sawPlan || reported === null || failing === null) {
		problems.push(
			'run did not finish: TAP epilogue missing (plan=' + sawPlan +
				', "# tests"=' + reported + ', "# fail"=' + failing + '). ' +
				'The process almost certainly died mid-run.'
		);
	}

	if (reported !== null && typeof minTests === 'number' && reported < minTests) {
		problems.push('only ' + reported + ' tests reported, expected at least ' + minTests);
	}

	if (failing !== null && failing > 0) {
		problems.push(failing + ' failing');
	}

	return {ok: problems.length === 0, problems};
}

module.exports = {checkTap};

if (require.main === module) {
	const fs = require('fs');
	const args = process.argv.slice(2);
	const file = args[0];
	const minIdx = args.indexOf('--min-tests');
	const minTests = minIdx === -1 ? null : parseInt(args[minIdx + 1], 10);

	if (!file) {
		console.error('usage: check-run-complete.js <tap-file> [--min-tests <n>]');
		process.exit(2);
	}

	const result = checkTap(fs.readFileSync(file, 'utf8'), minTests);
	if (result.ok) {
		console.log('run complete: ok');
		process.exit(0);
	}
	console.error('RUN NOT TRUSTWORTHY:');
	for (let i = 0; i < result.problems.length; i++) console.error('  - ' + result.problems[i]);
	process.exit(1);
}
```

- [ ] **Step 4: Run and verify it passes**

Run: `node ./node_modules/mocha/bin/mocha.js test/check-run-complete-selftest.js --reporter spec`
Expected: 4 passing.

- [ ] **Step 5: Prove it catches the real historical failure**

Reproduce the original dishonest-green run and confirm the checker rejects it:

```bash
git stash push -u -m "bun-checker-probe"
bun ./node_modules/mocha/bin/mocha.js test/ghsa --recursive --reporter tap > /tmp/probe.tap 2>&1 || true
git stash pop
node scripts/check-run-complete.js /tmp/probe.tap --min-tests 655
```

Expected: exit 1, reporting a missing epilogue. If it exits 0, the checker is wrong — stop and fix it.

Note the CLAUDE.md worktree warning about a shared stash: use the `-m` tag above and pop by tag if anything else is stashed concurrently.

- [ ] **Step 6: Commit**

```bash
git add scripts/check-run-complete.js test/check-run-complete-selftest.js
git commit -m "test: add TAP run-completeness checker

A runner that dies mid-run and exits 0 reports a success it never verified.
Under Bun, one file killed the mocha process, 112 tests never ran, and the
exit status was 0.

The skip list fixes that one crash; this fixes the class. CI runs it over
the TAP output so any future mid-run death is a loud failure rather than a
quiet pass."
```

---

### Task 5: `test/engine-messages.js` — engine-keyed assertion messages

**Files:**
- Create: `test/engine-messages.js`
- Modify: `test/vm.js` (13 assertions), `test/nodevm.js` (3 assertions)

**Interfaces:**
- Consumes: `ENGINE` from `test/engine.js` (Task 2).
- Produces: `msg(key: string): RegExp` — the expected pattern for the current engine. Throws on an unknown key so a typo fails loudly rather than matching nothing.

- [ ] **Step 1: Write the failing test**

Append to `test/engine-selftest.js`:

```js
describe('test/engine-messages.js', function () {
	const {msg, MESSAGES} = require('./engine-messages');
	const {ENGINE} = require('./engine');

	it('returns a RegExp for the current engine', function () {
		assert.ok(msg('NOT_A_CONSTRUCTOR') instanceof RegExp);
	});

	it('every key defines a pattern for BOTH engines', function () {
		for (const key of Object.keys(MESSAGES)) {
			assert.ok(MESSAGES[key].v8 instanceof RegExp, key + ' missing v8 pattern');
			assert.ok(MESSAGES[key].jsc instanceof RegExp, key + ' missing jsc pattern');
		}
	});

	it('throws on an unknown key rather than silently matching nothing', function () {
		assert.throws(() => msg('NO_SUCH_KEY'), /unknown message key/);
	});

	it('selects by engine', function () {
		assert.strictEqual(msg('NOT_A_CONSTRUCTOR'), MESSAGES.NOT_A_CONSTRUCTOR[ENGINE]);
	});
});
```

- [ ] **Step 2: Run and verify it fails**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: FAIL — `Cannot find module './engine-messages'`.

- [ ] **Step 3: Implement `test/engine-messages.js`**

```js
'use strict';

// Expected error-message patterns, keyed by engine.
//
// Many security tests assert on the exact wording a rejection produces. That
// wording is engine-specific, and widening each pattern until it matches both
// V8 and JSC would permanently weaken the assertion on Node -- the runtime
// that actually carries the guarantee. So the patterns stay exactly as tight
// as they are today and are selected by engine instead.
//
// Adding a third engine is a column, not a rewrite.

const {ENGINE} = require('./engine');

const MESSAGES = {
	NOT_A_CONSTRUCTOR: {
		v8: /Proxy is not a constructor/,
		jsc: /undefined is not a constructor/,
	},
	PROXY_DEFINE_FALSISH: {
		v8: /'defineProperty' on proxy: trap returned falsish/,
		jsc: /Proxy's 'defineProperty' trap returned falsy value/,
	},
	PROXY_SET_FALSISH: {
		v8: /'set' on proxy: trap returned falsish for property 'a'/,
		jsc: /Proxy object's 'set' trap returned falsy value for property 'a'/,
	},
	READ_MAINMODULE_OF_UNDEFINED: {
		v8: /Cannot read propert.*mainModule/,
		jsc: /undefined is not an object \(evaluating '.*mainModule'\)/,
	},
	READ_TOSTRING_OF_NULL: {
		v8: /Cannot read propert.*toString/,
		jsc: /null is not an object \(evaluating '.*toString'\)/,
	},
	SUPPRESSED_ERROR_ACCESS: {
		v8: /process is not defined|properties of null/,
		jsc: /null is not an object \(evaluating 'e\.(suppressed|error)'\)/,
	},
	PREPARE_STACK_TRACE_GETTHIS: {
		v8: /TypeError: Cannot read propert.*constructor/,
		jsc: /undefined is not an object \(evaluating 'sst\[0\]\.getThis\(\)\.constructor'\)/,
	},
};

function msg(key) {
	const entry = MESSAGES[key];
	if (!entry) throw new Error('unknown message key: ' + key);
	return entry[ENGINE];
}

module.exports = {MESSAGES, msg, ENGINE};
```

- [ ] **Step 4: Run and verify the selftest passes**

Run: `node ./node_modules/mocha/bin/mocha.js test/engine-selftest.js --reporter spec`
Expected: 10 passing.

- [ ] **Step 5: Convert the assertions**

Add to the requires at the top of `test/vm.js` and `test/nodevm.js`:

```js
const {msg} = require('./engine-messages');
```

Then replace each engine-specific literal with the corresponding `msg(...)` call. The full list, verified against a Bun run:

| File:line | Replace | With |
|---|---|---|
| `test/vm.js:790` | `/Proxy is not a constructor/, '#4'` | `msg('NOT_A_CONSTRUCTOR'), '#4'` |
| `test/vm.js:798` | `/Proxy is not a constructor/, '#5'` | `msg('NOT_A_CONSTRUCTOR'), '#5'` |
| `test/vm.js:937` | `/Proxy is not a constructor/` | `msg('NOT_A_CONSTRUCTOR')` |
| `test/vm.js:975` | `/'defineProperty' on proxy: trap returned falsish for property 'toString'/, '#2'` | `msg('PROXY_DEFINE_FALSISH'), '#2'` |
| `test/vm.js:1034` | the `NODE_VERSION > 8 ? … : …` ternary | `msg('NOT_A_CONSTRUCTOR'), '#2'` |
| `test/vm.js:1173` | `/Cannot read propert.*mainModule/, '#1'` | `msg('READ_MAINMODULE_OF_UNDEFINED'), '#1'` |
| `test/vm.js:1197` | `/Cannot read propert.*mainModule/, '#1'` | `msg('READ_MAINMODULE_OF_UNDEFINED'), '#1'` |
| `test/vm.js:1224` | the `NODE_VERSION > 8 ? … : …` ternary | `msg('NOT_A_CONSTRUCTOR'), '#1'` |
| `test/vm.js:1279` | `/Proxy is not a constructor/` | `msg('NOT_A_CONSTRUCTOR')` |
| `test/vm.js:1302` | `/TypeError: Cannot read propert.*constructor/` | `msg('PREPARE_STACK_TRACE_GETTHIS')` |
| `test/vm.js:2678` | `/process is not defined\|properties of null/` | `msg('SUPPRESSED_ERROR_ACCESS')` |
| `test/vm.js:2701` | `/process is not defined\|properties of null/` | `msg('SUPPRESSED_ERROR_ACCESS')` |
| `test/vm.js:2718` | `/process is not defined\|properties of null/` | `msg('SUPPRESSED_ERROR_ACCESS')` |
| `test/vm.js:3024` | `/'set' on proxy: trap returned falsish for property 'a'/` | `msg('PROXY_SET_FALSISH')` |
| `test/nodevm.js:66` | `/Cannot read propert.*toString/` | `msg('READ_TOSTRING_OF_NULL')` |
| `test/nodevm.js:152` | the `'defineProperty' on proxy…` string comparison | `msg('PROXY_DEFINE_FALSISH')` |
| `test/nodevm.js:387` | `/Cannot read propert.*toString/` | `msg('READ_TOSTRING_OF_NULL')` |

Line numbers will drift as you edit. Locate each by its surrounding test name, not by line number alone.

For `test/vm.js:1034` and `:1224`, the ternary's `NODE_VERSION > 8` branch is the modern one and the `else` branch targets Node ≤ 8, which the `>= 20` suite never runs. Replacing the whole ternary with `msg('NOT_A_CONSTRUCTOR')` is therefore not a behaviour change on any supported Node. Confirm with the Node run in the next step.

- [ ] **Step 6: Verify Node is byte-for-byte unchanged in behaviour**

Run: `npm test`
Expected: `836 passing`, `0 failing` (822 + 14 selftests). **If any test fails, you have weakened or broken an assertion — revert that row and investigate before continuing.**

- [ ] **Step 7: Verify Bun improved**

Run: `bun ./node_modules/mocha/bin/mocha.js test/vm.js --reporter tap`
Expected: `# fail 0`. Every remaining `test/vm.js` divergence is either converted here or skipped in Task 3.

Run: `bun ./node_modules/mocha/bin/mocha.js test/nodevm.js --reporter tap`
Expected: `# fail 0`.

- [ ] **Step 8: Commit**

```bash
git add test/engine-messages.js test/engine-selftest.js test/vm.js test/nodevm.js
git commit -m "test: key engine-specific assertion messages by engine

Many security tests assert the exact wording of a rejection, and that
wording differs between V8 and JSC. Widening each pattern to match both
would permanently weaken the assertion on Node, which is the runtime that
carries the guarantee.

Select by engine instead, so the patterns stay exactly as tight as they
are today on both. Unknown keys throw rather than silently matching
nothing."
```

---

### Task 6: CI — a Bun job that cannot lie and cannot hurt Node

**Files:**
- Modify: `.github/workflows/test.yml`
- Create: `.github/workflows/bun-canary.yml`

**Interfaces:**
- Consumes: `scripts/check-run-complete.js` (Task 4), `VM2_BUN_NO_SKIP` (Task 3).
- Produces: nothing importable.

**Background:** `test.yml`'s matrix has no `fail-fast:`, so it defaults to `true`. Adding Bun as a matrix *entry* would let a Bun failure cancel in-flight Node jobs. A separate job makes the runtimes independent by construction — that, not `continue-on-error`, is what protects the Node signal.

- [ ] **Step 1: Add `fail-fast: false` to the Node matrix**

In `.github/workflows/test.yml`, under `jobs.test.strategy`, add `fail-fast: false` above `matrix:`:

```yaml
        strategy:
            fail-fast: false
            matrix:
                node-version: [26, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8]
```

This is an independent improvement: today one Node version failing cancels the rest and hides information.

- [ ] **Step 2: Add the separate Bun job**

Append to `.github/workflows/test.yml`, as a sibling of `jobs.test`:

```yaml
    bun:
        # Bun is EXPERIMENTAL for vm2 and is NOT a supported security boundary.
        # See docs/specs/2026-08-30-bun-support-design.md section 6.
        #
        # A separate job, deliberately not a matrix entry: the Node matrix is
        # fail-fast and a Bun entry inside it could cancel in-flight Node jobs.
        runs-on: ubuntu-latest
        continue-on-error: true
        permissions:
            contents: read
        timeout-minutes: 15
        steps:
            - name: Checkout
              uses: actions/checkout@v4

            - name: Setup Node (for npm ci and the completeness checker)
              uses: actions/setup-node@v4
              with:
                  node-version: 24
                  cache: 'npm'

            - name: Setup Bun
              uses: oven-sh/setup-bun@v2
              with:
                  # Pinned deliberately. Every divergence reason in
                  # test/bun-skips.js cites behaviour of this exact version, so
                  # a floating version would make those reasons unverifiable.
                  # Bumping is a reviewed PR that shows which skips changed.
                  bun-version: 1.4.0

            - name: Install dependencies
              run: npm ci

            - name: Run unit tests under Bun
              run: bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap | tee bun-tap.txt
              continue-on-error: true

            - name: Verify the run actually finished
              # The important step. Without it a mid-run crash exits 0 and the
              # job reports a success it never verified.
              run: node scripts/check-run-complete.js bun-tap.txt --min-tests 800

            - name: Report skip count
              if: always()
              run: |
                  echo "Bun skips (phase-2 backlog): $(grep -c '# SKIP' bun-tap.txt || true)"
```

- [ ] **Step 3: Create the weekly canary**

Create `.github/workflows/bun-canary.yml`:

```yaml
name: Bun canary

# Informational only. Runs the suite on the LATEST Bun with the skip list
# disabled, to reveal which entries in test/bun-skips.js Bun has since fixed.
# Never gates anything.

on:
    schedule:
        - cron: '0 6 * * 1'
    workflow_dispatch:

jobs:
    canary:
        runs-on: ubuntu-latest
        continue-on-error: true
        permissions:
            contents: read
        timeout-minutes: 20
        steps:
            - name: Checkout
              uses: actions/checkout@v4

            - name: Setup Node
              uses: actions/setup-node@v4
              with:
                  node-version: 24
                  cache: 'npm'

            - name: Setup Bun (latest)
              uses: oven-sh/setup-bun@v2
              with:
                  bun-version: latest

            - name: Install dependencies
              run: npm ci

            - name: Run with skips disabled
              env:
                  VM2_BUN_NO_SKIP: '1'
              run: bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap | tee canary-tap.txt
              continue-on-error: true

            - name: Summarise
              if: always()
              run: |
                  echo "Bun version: $(bun --version)"
                  echo "Failures with skips disabled:"
                  grep '^not ok' canary-tap.txt || echo "  none - every skip in test/bun-skips.js is now stale"
```

- [ ] **Step 4: Validate the workflow files parse**

Run: `node -e "const fs=require('fs');['./.github/workflows/test.yml','./.github/workflows/bun-canary.yml'].forEach(f=>{const s=fs.readFileSync(f,'utf8');if(/\t/.test(s))throw new Error('tab in YAML: '+f);console.log('ok',f)})"`
Expected: `ok` for both. YAML forbids tabs for indentation; this repo's workflows use 4 spaces.

- [ ] **Step 5: Dry-run the completeness gate locally**

```bash
bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap > /tmp/bun-full.tap 2>&1 || true
node scripts/check-run-complete.js /tmp/bun-full.tap --min-tests 800
```

Expected: exit 0. If it reports a missing epilogue, a test is still killing the process — find it by comparing the last directory in the TAP output against the alphabetical file list, and add it to `test/bun-skips.js`.

- [ ] **Step 6: Prove the gate actually fires**

Temporarily truncate the TAP file and confirm CI would fail:

```bash
head -50 /tmp/bun-full.tap > /tmp/bun-truncated.tap
node scripts/check-run-complete.js /tmp/bun-truncated.tap --min-tests 800
```

Expected: **exit 1**, reporting a missing epilogue. This is success criterion 0 from the spec.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/test.yml .github/workflows/bun-canary.yml
git commit -m "ci: add non-blocking Bun job and weekly canary

Bun runs as a SEPARATE job, not a matrix entry: the Node matrix is
fail-fast, so a Bun entry inside it could cancel in-flight Node jobs. Job
separation is what protects the Node signal; continue-on-error only stops
it gating merges.

The run is piped through scripts/check-run-complete.js so a mid-run crash
fails the step instead of exiting 0 with a partial run.

Also set fail-fast: false on the Node matrix, which today cancels the
remaining versions when one fails.

The weekly canary runs latest Bun with VM2_BUN_NO_SKIP=1 to reveal skips
Bun has since fixed."
```

---

### Task 7: Document the posture

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `CHANGELOG.md` (the `## [Unreleased]` section added by `fe71e2b`)

- [ ] **Step 1: Add a Runtimes section to `README.md`**

Place it immediately after the installation section:

```markdown
## Runtimes

| Runtime | Status |
|---------|--------|
| Node.js | Supported. The sandbox is a security boundary. |
| Bun | **Experimental.** Functional parity only — **not** a security boundary. |

vm2's threat model, the attack catalogue in [`docs/ATTACKS.md`](docs/ATTACKS.md),
and every regression test in `test/ghsa/` are derived from V8 internals.
JavaScriptCore, which Bun uses, has its own equivalents, and none have been
audited against vm2's bridge. The suite passing under Bun demonstrates
functional compatibility; it does **not** demonstrate that the sandbox holds
there.

Known divergences are enumerated in `test/bun-skips.js`. Do not use vm2 on Bun
to isolate untrusted code.
```

- [ ] **Step 2: Add the scope statement to `SECURITY.md`**

```markdown
## Runtime scope

Coordinated disclosure covers vm2 running on **Node.js**.

Bun support is experimental and Bun is explicitly not a supported security
boundary (see the Runtimes section of the README). An escape reproducible only
under Bun and not under Node.js is out of scope for the advisory process and
will be handled as a public bug report until Bun reaches supported status.
```

- [ ] **Step 3: Add the CHANGELOG entry**

Under the existing `## [Unreleased]` heading, above the `### Maintenance` section:

```markdown
### Added

- **Experimental Bun support (test suite and CI only).** The suite now runs
  under Bun, with engine-keyed assertion messages so patterns stay exactly as
  strict on Node, a central `test/bun-skips.js` listing every JavaScriptCore
  divergence, and a non-blocking CI job whose output is verified complete
  before it is believed. Bun is **not** a supported security boundary — vm2's
  threat model is derived from V8 internals and JavaScriptCore has not been
  audited against the bridge. See the README Runtimes section.
```

- [ ] **Step 4: Verify nothing broke**

Run: `npm test`
Expected: `836 passing`, `0 failing`.

Run: `npm run lint`
Expected: the same 2 pre-existing problems, no new ones.

- [ ] **Step 5: Commit**

```bash
git add README.md SECURITY.md CHANGELOG.md
git commit -m "docs: state the experimental, non-boundary Bun posture

vm2's threat model and every ghsa regression are derived from V8 internals.
Passing under Bun shows functional compatibility, not that the sandbox
holds on JavaScriptCore. Say so in the README, and put Bun-only escapes
out of advisory scope in SECURITY.md until that changes."
```

---

### Task 8: Timeboxed vacuity sweep

Task 1 found one security test that had never executed the behaviour it named. This task looks for others. **Timebox: 2 hours.** File what you find; do not fix it all here.

**Files:**
- Create: `docs/specs/2026-08-30-vacuity-sweep-findings.md`

- [ ] **Step 1: Find payloads that can throw before their assertion**

The `GHSA-x965` shape is a payload that aborts early, so the assertion passes for the wrong reason. Search for the highest-risk pattern — a TDZ self-reference inside its own initializer:

Run: `grep -rnE 'const ([A-Za-z_$][\w$]*) = [^;]*\b\1\s*=' test/ | grep -v node_modules`
Expected: no hits after Task 1. Any hit is the same bug.

- [ ] **Step 2: Find assertions that can pass on the wrong error**

Run: `grep -rn "assert.throws" test/ghsa/ | grep -vE "/[^/]+/" | head -40`

These are `assert.throws` calls with **no** expected-error argument — they pass on *any* throw, including a typo in the payload. List them in the findings doc; each is a candidate for tightening.

- [ ] **Step 3: Cross-check the two engines for disagreement**

A test that passes on Node and fails on Bun for a *non*-message reason is a signal that one of the two is not exercising what it claims.

```bash
node ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap > /tmp/n.tap 2>&1 || true
bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap > /tmp/b.tap 2>&1 || true
diff <(grep -oE '^(ok|not ok) [0-9]+ .*' /tmp/n.tap | sed 's/^[a-z ]*[0-9]* //') \
     <(grep -oE '^(ok|not ok) [0-9]+ .*' /tmp/b.tap | sed 's/^[a-z ]*[0-9]* //') | head -40
```

- [ ] **Step 4: Write the findings document**

Create `docs/specs/2026-08-30-vacuity-sweep-findings.md` with, for each finding: the file and test name, why it may be vacuous, the evidence, and a recommended action. If the sweep finds nothing beyond Task 1, say that explicitly — a negative result is a real result and worth recording.

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-08-30-vacuity-sweep-findings.md
git commit -m "docs: record vacuity sweep findings

Task 1 found a security regression test that never executed the behaviour
it named. This is the timeboxed sweep for others of the same shape."
```

---

## Final verification

- [ ] `npm test` → **836 passing, 0 failing** on Node (822 baseline + 14 selftests).
- [ ] `npm run lint` → 2 pre-existing problems, no new ones.
- [ ] `bun ./node_modules/mocha/bin/mocha.js test --recursive --ignore test/compilers.js --reporter tap > /tmp/f.tap; node scripts/check-run-complete.js /tmp/f.tap --min-tests 800` → exit 0.
- [ ] `head -50 /tmp/f.tap > /tmp/t.tap; node scripts/check-run-complete.js /tmp/t.tap --min-tests 800` → **exit 1** (the gate fires).
- [ ] `VM2_BUN_NO_SKIP=1` produces a non-empty failure list — that list is the phase-2 backlog.
- [ ] README and SECURITY.md state the experimental, non-boundary posture.
