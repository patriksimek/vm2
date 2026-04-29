'use strict';

/**
 * GHSA-hw58-p9xv-2mjh — Promise executor unhandled rejection escapes to host
 *
 *
 * ## Vulnerability
 * Sandbox code creates a `Promise` whose executor synchronously triggers a
 * host-realm `TypeError` (e.g. `new Promise((r,j) => { var e = new Error();
 * e.name = Symbol(); e.stack; })` — V8's FormatStackTrace coerces the
 * Symbol-named `name` to a string and throws). Since no `.catch()` is
 * attached, the rejection propagates to the host process as an unhandled
 * rejection. Node 15+ default behaviour terminates the process — a single
 * ~150-byte sandbox payload crashes the entire host service. `allowAsync:
 * false` makes it worse because `.catch()` is blocked, guaranteeing the
 * rejection is unhandled.
 *
 * ## Fix
 * `localPromise` is given a constructor that wraps the user-supplied
 * executor in try/catch — any synchronous throw is funnelled through
 * `handleException` and `reject`ed as a sandbox-realm value. A benign
 * swallow tail (`then(undefined, noop)`) is attached to every
 * sandbox-constructed Promise so that, even when no `.catch()` is attached,
 * the rejection is consumed and the host's `unhandledRejection` event
 * never fires. The tail uses the cached host `then` (captured before the
 * sandbox-side then override is installed) and a re-entrancy guard prevents
 * infinite species-protocol recursion.
 *
 * ## Known residual (NOT yet fixed in v3.10.6)
 * V8 creates async-function and async-generator promises via the realm's
 * intrinsic `globalPromise`, NOT our `localPromise` subclass — so the
 * executor wrap above is bypassed. Three working DoS variants confirmed
 * during pre-tag red-team:
 *
 *   1. `(async function(){ var e = new Error(); e.name = Symbol(); e.stack; })()`
 *   2. `(async function*(){ throw e })().next()`
 *   3. `await using x = { [Symbol.asyncDispose]() { throw Symbol() } };`
 *
 * Each ~50–80 bytes, each terminates the host process on Node 15+. Closing
 * this requires either a process-level `unhandledRejection` filter scoped
 * to sandbox-realm errors, or rebinding the realm's intrinsic Promise
 * inside `vm.runInContext` — both architectural changes deferred past
 * v3.10.6. The `it.skip` blocks below pin the residuals so any future
 * regression is visible.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

// Capture host-side unhandled rejections during a test, then assert.
function withRejectionCapture(fn) {
	return function (done) {
		const captured = [];
		const handler = function (reason) {
			captured.push(reason);
		};
		process.on('unhandledRejection', handler);
		try {
			fn(captured);
		} finally {
			// Drain the microtask queue before checking + cleaning up.
			setImmediate(function () {
				process.removeListener('unhandledRejection', handler);
				done && done(captured);
			});
		}
	};
}

// Node 8/10's sandbox Promise wrapper has different internal mechanics that
// cause spurious "this.timeout is not a function" rejections from the swallow
// tail; the GHSA-hw58 fix targets Node 12+ async/Promise semantics. Gate the
// whole suite accordingly.
const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
const HW58_RUNS = NODE_MAJOR >= 12;

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-hw58-p9xv-2mjh (Promise executor unhandled rejection DoS)', function () {
	it.cond(
		'canonical PoC: Symbol-named Error stack throw inside executor produces no host unhandled rejection',
		HW58_RUNS,
		function (done) {
			const captured = [];
			function handler(reason) {
				captured.push(reason);
			}
			process.on('unhandledRejection', handler);
			new VM({ timeout: 5000, allowAsync: false }).run(`
			new Promise(function(r, j) {
				var e = new Error();
				e.name = Symbol();
				e.stack;
			});
		`);
			setImmediate(function () {
				process.removeListener('unhandledRejection', handler);
				assert.strictEqual(
					captured.length,
					0,
					'host should not see unhandled rejection; got: ' + (captured[0] && captured[0].message),
				);
				done();
			});
		},
	);

	it.cond('plain executor throw is also swallowed', HW58_RUNS, function (done) {
		const captured = [];
		function handler(reason) {
			captured.push(reason);
		}
		process.on('unhandledRejection', handler);
		new VM({ timeout: 5000 }).run(`new Promise(function(r, j) { throw new Error('boom'); });`);
		setImmediate(function () {
			process.removeListener('unhandledRejection', handler);
			assert.strictEqual(captured.length, 0, 'plain throw must not produce host unhandled rejection');
			done();
		});
	});

	it.cond('sandbox-side .catch still observes the (sanitised) rejection', HW58_RUNS, function () {
		// When the sandbox attaches its own .catch, it should still run with
		// the sanitised value — the swallow tail consumes the host event but
		// does not block user-attached handlers.
		const r = new VM({ timeout: 5000 }).run(`
			new Promise(function(r, j) {
				throw new Error('boom-observed');
			}).catch(function(e) {
				return String(e && e.message || e);
			});
		`);
		return r.then(function (observed) {
			assert.ok(
				typeof observed === 'string' && /boom-observed/.test(observed),
				'sandbox .catch did not observe the rejection; got: ' + observed,
			);
		});
	});

	it('non-callable executor still throws TypeError synchronously (native semantics preserved)', function () {
		const r = new VM().run(`
			let threw = null;
			try { new Promise(undefined); } catch (e) { threw = e && e.constructor && e.constructor.name; }
			threw;
		`);
		assert.strictEqual(r, 'TypeError', 'non-callable executor must still throw TypeError; got: ' + r);
	});

	it('resolved-path .then(onFulfilled) still works (regression)', function () {
		const r = new VM().run(`
			new Promise(function(r) { r(42); }).then(function(v) { return v + 1; });
		`);
		return r.then(function (v) {
			assert.strictEqual(v, 43);
		});
	});

	// SECURITY (KNOWN RESIDUAL — NOT YET FIXED): async-function / async-generator
	// / AsyncDisposableStack paths bypass the localPromise executor wrap because
	// V8 creates their rejection promises via the realm's intrinsic Promise.
	// These three DoS variants are skipped (would crash the test runner) but
	// kept here so the residual is visible and any future fix is testable.
	// See ATTACKS.md Category 22 "Known Residual".
	describe('async-fn host-process abort (known residual; pinned for visibility)', function () {
		it.skip('async function with Symbol-named Error.stack throw (kills host)', function () {
			// Running this would terminate the test process. The fix needs a
			// process-level unhandledRejection filter or a realm-Promise rebind.
			// new VM({ allowAsync: false }).run(`
			//   (async function(){ var e=new Error(); e.name=Symbol(); e.stack; })();
			// `);
		});

		it.skip('async generator throw on .next() (kills host)', function () {
			// new VM({ allowAsync: false }).run(`
			//   (async function*(){ throw new Error('boom') })().next();
			// `);
		});

		it.skip('AsyncDisposableStack with throwing Symbol.asyncDispose (kills host)', function () {
			// new VM({ allowAsync: false }).run(`
			//   await using x = { [Symbol.asyncDispose]() { throw Symbol() } };
			// `);
		});
	});
});
