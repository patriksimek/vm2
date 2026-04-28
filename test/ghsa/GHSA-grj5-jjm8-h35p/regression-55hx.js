'use strict';

/**
 * Regression tests migrated from GHSA-55hx-c926-fr95
 *
 * GHSA-55hx-c926-fr95 covered three variants of the
 * SuppressedError/AggregateError sub-error smuggling primitive. After
 * bisection on Node 25.9.0:
 *
 *   - Variant 1 (DisposableStack)
 *     Closed on public main by `a6cd917` (handleException recursion into
 *     SuppressedError.error / .suppressed) — predates this advisory.
 *
 *   - Variant 2 (using+eval+throw null in catch)
 *     Closed by the same `a6cd917`.
 *
 *   - Variant 3 (fromAsync wrapping the using+eval)
 *     Different vulnerability class — the host Promise rejection from
 *     `Array.fromAsync` bypasses the transformer's instrumented catch, so
 *     handleException never fires. **Closed by GHSA-grj5-jjm8-h35p's class E
 *     trap** (`.constructor` on host arrays returns the cached sandbox
 *     `Array`), which forces `ha === sandbox Array` in the prototype walk
 *     and routes the rest of the chain through sandbox `Array.fromAsync` /
 *     sandbox `Promise` — where `handleException` does fire.
 *
 * GHSA-55hx publishes for variant 1's disclosure (fix `a6cd917`); variant
 * 3 graduates to GHSA-grj5. Tests live here because grj5 is the
 * load-bearing fix.
 *
 * Each test passes via host-side `hostMark` ground truth, not sandbox
 * `globalThis` (the original test in the 55hx fork was vacuous: its
 * `const obj = {...}` was invisible to the inner `eval`, so the PoC threw
 * `ReferenceError: obj is not defined` before any SuppressedError existed).
 *
 * Failure-without-fix (verified on Node 25.9.0):
 *   - Vanilla main `d43f637`: variants 1 & 2 blocked (a6cd917), variant 3
 *     escapes with `hostMark.pid === host process.pid`.
 *   - main + GHSA-grj5: all three blocked.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

const HAS_DISPOSABLE_STACK = typeof DisposableStack === 'function';
const HAS_FROM_ASYNC = typeof Array.fromAsync === 'function';

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) { return cond ? it(name, fn) : it.skip(name, fn); };
}

describe('GHSA-grj5-jjm8-h35p — regression from GHSA-55hx-c926-fr95', function () {

	it.cond('DisposableStack PoC: host process.pid not extractable', HAS_DISPOSABLE_STACK, function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			const ds = new DisposableStack();
			ds.defer(() => { throw null; });
			ds.defer(() => {
				const e = Error();
				e.name = Symbol();
				e.stack;
			});
			try {
				ds.dispose();
			} catch (e) {
				try {
					hostMark.pid = e.suppressed.constructor.constructor("return process.pid")();
				} catch (ex) { hostMark.err = ex.message; }
			}
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it('using+eval PoC: host process.pid not extractable', function () {
		const hostMark = {pid: null, err: null};
		const vm = new VM({sandbox: {hostMark}});
		vm.run(`
			obj = {[Symbol.dispose]() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}};
			try {
				eval("{using a = obj; throw null;}");
			} catch (e) {
				try {
					hostMark.pid = e.error.constructor.constructor("return process.pid")();
				} catch (ex) { hostMark.err = ex.message; }
			}
		`);
		assert.strictEqual(hostMark.pid, null,
			'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
	});

	it.cond('fromAsync chain (load-bearing for GHSA-grj5): host process.pid not extractable', HAS_FROM_ASYNC, function () {
		return new Promise(function (resolve) {
			const hostMark = {pid: null, err: null};
			const vm = new VM({sandbox: {hostMark}});
			vm.run(`
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				const op = p.call(p.call(p.call(p.call(Buffer.of()))));
				const ho = op.constructor;
				const ap = p.call(ho.entries({}));
				const ha = ap.constructor;
				ha.fromAsync([0], () => {
					obj = {[Symbol.dispose]() {
						const e = new Error();
						e.name = Symbol();
						return e.stack;
					}};
					eval("{using a = obj; throw null;}");
				}).catch(e => {
					try {
						hostMark.pid = e.error.constructor.constructor("return process.pid")();
					} catch (ex) { hostMark.err = ex.message; }
				});
			`);
			setTimeout(function () {
				assert.strictEqual(hostMark.pid, null,
					'host process.pid was extracted: hostMark.pid=' + hostMark.pid + ', host pid=' + process.pid);
				resolve();
			}, 250);
		});
	});

	it('ha === Array probe: prototype walk lands on sandbox Array (class E invariant)', function () {
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
		assert.strictEqual(r, true, 'GHSA-grj5 class E trap should force ha === sandbox Array');
	});
});
