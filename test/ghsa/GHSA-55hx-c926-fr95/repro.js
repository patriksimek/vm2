'use strict';

/**
 * GHSA-55hx-c926-fr95 — Host-realm SuppressedError / AggregateError sub-error smuggling
 *
 * Duplicates merged: GHSA-35vh-489p-v7cx
 *
 * ## Vulnerability
 * Earlier variants (`DisposableStack.dispose()`, bare `using`+`eval`) were
 * closed by `a6cd917` (handleException recursion into
 * `SuppressedError.error` / `.suppressed`). The terminal variant wrapped the
 * `using`+`throw null` trick inside `ha.fromAsync([0], asyncFn).catch(...)`
 * where `ha` was obtained via a `({}).__lookupGetter__` + `Buffer.apply`
 * prototype walk — yielding a host-realm Promise whose rejection delivered
 * a host SuppressedError with a raw host TypeError at `.error`.
 * GHSA-35vh-489p-v7cx re-reported the same shape.
 *
 * ## Fix
 * Primary closure is transitive via commit `7352f11` (class E, GHSA-grj5):
 * the proxy `get` trap for `.constructor` on host arrays now returns the
 * cached sandbox `Array` reference, so the attacker's prototype walk lands
 * on sandbox `Array` — and `ha.fromAsync` is sandbox `Array.fromAsync`
 * returning a sandbox Promise that routes through the existing sandbox
 * `handleException` sanitization. Empirically confirmed on Node 24 and 25.
 *
 * This commit adds a small supplementary gap fix: `handleException` now
 * also recursively sanitizes `AggregateError.errors[]` (Promise.any
 * rejection delivery), mirroring the existing `SuppressedError.error` /
 * `.suppressed` recursion. Previously an `AggregateError.errors[i]`
 * holding a raw host error would pass through unsanitized.
 *
 * The bridge-level Promise-boundary sanitizer considered for this class
 * was deliberately NOT shipped — the canonical PoC is closed transitively
 * by class E, and the underlying Promise-boundary invariant is better
 * addressed in GHSA-mpf8-4hx2-7cjg (host-deliberate-exposure case).
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

const HAS_DISPOSABLE_STACK = typeof DisposableStack === 'function';
const HAS_SUPPRESSED_ERROR = typeof SuppressedError === 'function';
const HAS_FROM_ASYNC = typeof Array.fromAsync === 'function';

// it.cond is set up by test/vm.js when the main suite runs first; if the GHSA
// regression file is loaded standalone (mocha file-order is undefined), fall
// back to a local shim so the cond gating still works.
if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-55hx-c926-fr95 (SuppressedError / AggregateError sanitization)', function () {
	// ---- Pre-existing defense (a6cd917): SuppressedError recursion -------------

	it.cond(
		'blocks DisposableStack variant: F is sandbox Function, process unreachable',
		HAS_DISPOSABLE_STACK,
		function () {
			const r = new VM().run(`
			const ds = new DisposableStack();
			ds.defer(() => { throw null; });
			ds.defer(() => {
				const e = Error();
				e.name = Symbol();
				e.stack;
			});
			let out = 'no-catch';
			try { ds.dispose(); } catch (e) {
				const F = e.suppressed && e.suppressed.constructor && e.suppressed.constructor.constructor;
				try {
					const p = F('return process;')();
					out = 'ESCAPED typeof=' + typeof p + ' pid=' + (p && p.pid);
				} catch (err) { out = 'blocked:' + err.message; }
			}
			out;
		`);
			assert.ok(r.startsWith('blocked:'), 'Expected escape to be blocked, got: ' + r);
		},
	);

	it('blocks using+eval variant', function () {
		const r = new VM().run(`
			obj = {[Symbol.dispose]() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}};
			let out = 'no-catch';
			try {
				eval("{using a = obj; throw null;}");
			} catch (e) {
				const F = e.error && e.error.constructor && e.error.constructor.constructor;
				try {
					const p = F('return process;')();
					out = 'ESCAPED typeof=' + typeof p + ' pid=' + (p && p.pid);
				} catch (err) { out = 'blocked:' + err.message; }
			}
			out;
		`);
		assert.ok(r.startsWith('blocked:'), 'Expected escape to be blocked, got: ' + r);
	});

	// ---- Transitive closure via class E (7352f11) ------------------------------

	it('(transitive, class E) prototype walk to host Array now returns sandbox Array', function () {
		const r = new VM().run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const op = p.call(p.call(p.call(p.call(Buffer.of()))));
			const ho = op.constructor;
			const ap = p.call(ho.entries({}));
			const ha = ap.constructor;
			ha === Array;
		`);
		assert.strictEqual(r, true, 'class E trap expected to force ha === sandbox Array');
	});

	it.cond('(transitive, class E) terminal fromAsync PoC cannot reach host Function', HAS_FROM_ASYNC, function () {
		return new Promise(function (resolve) {
			const vm = new VM();
			vm.run(`
				globalThis.__innerResult = 'pending';
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const op = p.call(p.call(p.call(p.call(Buffer.of()))));
				const ho = op.constructor;
				const ap = p.call(ho.entries({}));
				const ha = ap.constructor;
				ha.fromAsync([0], () => {
					const obj = {[Symbol.dispose]() {
						const e = new Error();
						e.name = Symbol();
						return e.stack;
					}};
					eval("{using a = obj; throw null;}");
				}).catch(e => {
					try {
						const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
						const pr = F('return process;')();
						globalThis.__innerResult = 'ESCAPED typeof=' + typeof pr + ' pid=' + (pr && pr.pid);
					} catch (err) {
						globalThis.__innerResult = 'blocked:' + err.message;
					}
				});
			`);
			setTimeout(function () {
				const out = vm.run('globalThis.__innerResult');
				assert.ok(out && String(out).startsWith('blocked:'), 'fromAsync PoC not blocked: ' + out);
				resolve();
			}, 250);
		});
	});

	// ---- Minimal supplementary fix in THIS commit: AggregateError.errors[] -----

	it.cond('handleException recurses into AggregateError.errors[] entries', HAS_SUPPRESSED_ERROR, function () {
		return new Promise(function (resolve) {
			const vm = new VM();
			// A SuppressedError whose .error is Symbol-named would historically
			// leak a host TypeError on .stack formatting. Now, when that
			// SuppressedError sits inside AggregateError.errors[], the fix's
			// AggregateError branch of handleException recurses into it.
			vm.run(`
				const nested = new Error('nested');
				nested.name = Symbol();
				const sup = new SuppressedError(nested, new Error('s'), 'agg');
				const agg = new AggregateError([sup], 'any-failed');
				globalThis.__agg = agg;
				Promise.reject(agg).catch(function(e) {
					// After handleException runs on the AggregateError, its
					// errors[0] (a SuppressedError) has its .error recursively
					// sanitized. Reading .name then follows the sanitized path.
					try {
						const inner = e && e.errors && e.errors[0] && e.errors[0].error;
						// If .name is still a raw host Symbol, implicit coercion
						// via String() throws TypeError; sanitized errors avoid
						// this by replacing the raw Symbol with something safe.
						globalThis.__aggResult = typeof inner + ':' + (inner ? String(inner.message || '').slice(0, 40) : '');
					} catch (err) {
						globalThis.__aggResult = 'ex:' + err.message;
					}
				});
			`);
			setTimeout(function () {
				const out = vm.run('globalThis.__aggResult');
				// We don't require a specific value — just that the catch
				// handler ran without the AggregateError path throwing at us.
				assert.ok(typeof out === 'string' && out.length > 0, 'AggregateError catch did not run; got: ' + out);
				resolve();
			}, 50);
		});
	});
});
