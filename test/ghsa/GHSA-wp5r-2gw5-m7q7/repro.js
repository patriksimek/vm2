'use strict';

/**
 * GHSA-wp5r-2gw5-m7q7 — Transformer fast-path bypass
 *
 *
 * ## Vulnerability
 * `lib/transformer.js` had a performance fast-path that skipped AST
 * parsing/instrumentation entirely when the source contained none of
 * `catch`, `import`, `async`. The AST walker also handles two security
 * controls that the regex did not represent:
 *
 *   1. The `INTERNAL_STATE_NAME` (`VM2_INTERNAL_STATE_…`) identifier
 *      check — sandbox code that names this identifier is rejected.
 *   2. `with()` statement instrumentation — the head expression is
 *      wrapped in `wrapWith()` which enforces an unscopable invariant
 *      that hides `INTERNAL_STATE_NAME` from `with`'s scope chain.
 *
 * Code that contained none of `catch` / `import` / `async` could
 * therefore reach `VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL`
 * and use `with(...)` to obtain `wrapWith` / `handleException` /
 * `import`. Today these are defensive utilities only, but it is a
 * complete bypass of a security control and a latent surface for any
 * future addition to `INTERNAL_STATE_NAME`.
 *
 * ## Fix
 * The fast-path regex now also matches `with` (so any source that
 * contains `with()` triggers full AST instrumentation), and a
 * substring check for `INTERNAL_STATE_NAME` runs unconditionally, so
 * a source that names that identifier always reaches the AST-walker
 * rejection regardless of which other keywords appear. The fast-path
 * still skips for genuinely-clean code (e.g. `1 + 2`).
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-wp5r-2gw5-m7q7 (transformer fast-path bypass)', function () {
	it('rejects VM2_INTERNAL_STATE access in code without catch/import/async', function () {
		assert.throws(function () {
			new VM().run(`var x = VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL; x;`);
		}, /Use of internal vm2 state variable/);
	});

	it('instruments with() statements even without catch/import/async', function () {
		assert.throws(function () {
			new VM().run(`
				var captured;
				with (VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL) { captured = handleException; }
			`);
		}, /Use of internal vm2 state variable/);
	});

	it('rejects bare "VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL"', function () {
		assert.throws(function () {
			new VM().run(`VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL`);
		}, /Use of internal vm2 state variable/);
	});

	it('regression: clean code without instrumented keywords still runs', function () {
		assert.strictEqual(new VM().run('1 + 2'), 3);
		assert.strictEqual(new VM().run('var x = 5; x * 2'), 10);
	});

	it('regression: code with catch/import/async still runs unchanged', function () {
		assert.strictEqual(new VM().run(`try { throw new Error('x'); } catch(e) { e.message }`), 'x');
	});
});
