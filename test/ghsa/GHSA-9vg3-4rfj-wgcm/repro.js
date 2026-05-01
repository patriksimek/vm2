'use strict';

/**
 * GHSA-9vg3-4rfj-wgcm — Sandbox breakout via null-proto throw / handleException
 *
 * ## Vulnerability
 * Post-GHSA-mpf8 hardening switched `handleException` (the catch-block
 * sanitiser) from `ensureThis(e)` to `from(e)`. `from()` always wraps the
 * value in a bridge proxy assuming it came from the *other* (host) realm.
 *
 * That assumption holds for V8-internal throws into a sandbox catch (the
 * GHSA-mpf8 motivating case), but breaks for **sandbox-realm null-proto
 * objects thrown by sandbox code**:
 *
 *   const o = {__proto__: null};
 *   try { throw o; } catch (e) { ... }
 *
 * `from(o)` walks the prototype chain — finds none — and creates a bridge
 * proxy whose internal target is `o` itself. The proxy's `set` trap treats
 * the underlying target as host-realm, so when sandbox code does
 *
 *   e.f = Buffer.prototype.inspect;
 *
 * the trap *unwraps* the sandbox-side proxy of `Buffer.prototype.inspect`
 * back to its raw host function and writes it directly onto `o.f`. Reading
 * `o.f` (via the original sandbox reference, not the proxy `e`) returns
 * the raw host function, and `o.f.constructor` is host `Function`.
 *
 * ## Fix
 * `handleException` must not blindly proxy a value that is already a
 * sandbox-realm object. Sandbox-realm objects pass through unchanged
 * (they cannot leak host references on their own); only unmapped
 * cross-realm values get wrapped via `from()`.
 */

const assert = require('assert');
const { VM, VMError } = require('../../../lib/main.js');

describe('GHSA-9vg3-4rfj-wgcm (null-proto throw / handleException)', function () {
	it('null-proto throw + Buffer.prototype.inspect cannot reach host Function', function () {
		const vm = new VM();
		const result = vm.run(`
			const o = {__proto__: null};
			let leaked = null;
			let trapped = null;
			try {
				try {
					throw o;
				} catch (e) {
					e.f = Buffer.prototype.inspect;
					// Through original sandbox ref \`o\`, was the raw host
					// Buffer.prototype.inspect installed?  If yes, .constructor
					// is host Function and the next line escapes.
					leaked = o.f && o.f.constructor;
				}
			} catch (err) {
				trapped = err;
			}
			({
				leakedTypeofConstructor: typeof leaked,
				leakedIsFunction: typeof leaked === 'function',
				// If the host Function constructor leaked, calling it would
				// return process. Guard with try/catch so the test still
				// returns a value either way.
				leakedCanCompile: (function () {
					if (typeof leaked !== 'function') return false;
					try {
						const fn = leaked('return typeof process');
						return fn() === 'object';
					} catch (_) {
						return false;
					}
				})(),
				trappedMessage: trapped && trapped.message,
			})
		`);

		// Whether the assignment is rejected or accepted, the host Function
		// constructor must NOT be reachable through the sandbox reference.
		assert.notStrictEqual(
			result.leakedIsFunction && result.leakedCanCompile,
			true,
			'host Function constructor leaked via null-proto throw escape',
		);
	});

	it('PoC from advisory does not perform RCE', function () {
		// Direct PoC translation — runs the exact attack and asserts the
		// child_process require chain throws or yields something safe.
		const vm = new VM();
		let escaped = false;
		let captured = null;
		try {
			vm.run(`
				const o = {__proto__: null};
				try {
					throw o;
				} catch (e) {
					e.f = Buffer.prototype.inspect;
					return o.f.constructor("return process")().mainModule.require('child_process');
				}
			`);
			// If we got here without throwing, the sandbox was escaped.
			escaped = true;
		} catch (e) {
			captured = e;
		}
		assert.strictEqual(escaped, false, 'sandbox escape: PoC reached child_process');
		assert.ok(captured, 'PoC must throw rather than return a host module');
	});

	// --- Variant probes (related null-proto / catch / write-through paths) ---

	it('variant: null-proto throw + Promise.then onFulfilled does not leak host fn', function (done) {
		// The same write-through bug existed on the sandbox-side
		// `globalPromise.prototype.then` onFulfilled wrapper which also
		// called `from(value)` on every resolved value. Async-function
		// returned Promises are globalPromise instances that hit this
		// path. Confirm the fix closes the Promise.then variant too.
		const vm = new VM();
		vm.run(
			`
			(async () => {
				const o = {__proto__: null};
				const p = Promise.resolve(o);
				return p.then(e => {
					try { e.f = Buffer.prototype.inspect; } catch (_) {}
					if (typeof o.f !== 'function' || !o.f.constructor) return 'no-leak';
					try {
						return o.f.constructor('return typeof process')() === 'object'
							? 'ESCAPED'
							: 'no-leak';
					} catch (_) { return 'no-leak'; }
				});
			})()
		`,
		).then(r => {
			try {
				assert.notStrictEqual(r, 'ESCAPED', 'Promise.then null-proto write-through leak');
				done();
			} catch (e) {
				done(e);
			}
		}, done);
	});

	it('variant: null-proto throw inside SuppressedError chain does not leak', function () {
		// The handleException SuppressedError walk recurses on .error/.suppressed.
		// Verify that wrapping a sandbox null-proto object in those slots also
		// does not produce a writable host-treating proxy.
		const vm = new VM();
		// Skip if SuppressedError isn't supported on this Node version.
		const supported = vm.run(`typeof SuppressedError`);
		if (supported !== 'function') return;
		const r = vm.run(`
			const o = {__proto__: null};
			let raw = null;
			try {
				throw new SuppressedError(o, new Error('x'), 'msg');
			} catch (e) {
				try { e.error.f = Buffer.prototype.inspect; } catch (_) {}
				raw = o.f && o.f.constructor;
			}
			typeof raw === 'function' && (function () {
				try { return raw('return process')() ? 'ESCAPED' : null; } catch (_) { return null; }
			})();
		`);
		assert.notStrictEqual(r, 'ESCAPED', 'SuppressedError-wrapped null-proto leak');
	});

	it('regression: sandbox catch on a sandbox-realm Error still works', function () {
		const vm = new VM();
		const msg = vm.run(`
			try {
				throw new Error('boom');
			} catch (e) {
				e.message;
			}
		`);
		assert.strictEqual(msg, 'boom');
	});

	it('regression: V8-internal TypeError into sandbox catch does not leak host Function', function () {
		// V8 may throw a TypeError from internal C++ code reachable from
		// sandbox JS (e.g. coercing a Symbol to a string). Whatever realm
		// the resulting error lives in, sandbox code must not be able to
		// reach a host-realm `Function` constructor through it. The
		// `defaultSandboxPrepareStackTrace` defense (GHSA-v27g) plus the
		// bridge throw-conversion (`thisFromOtherForThrow`) together
		// guarantee the caught value's `.constructor` is sandbox-bound.
		const vm = new VM();
		const escaped = vm.run(`
			let canCompile = false;
			try {
				const e = new Error();
				e.name = Symbol();
				e.stack;
				// Force a TypeError via Symbol→string coercion if .stack
				// did not already throw on this Node version.
				'' + Symbol();
			} catch (err) {
				try {
					const f = err && err.constructor && err.constructor;
					if (typeof f === 'function') {
						const fn = f('return typeof process');
						canCompile = fn() === 'object';
					}
				} catch (_) {}
			}
			canCompile;
		`);
		assert.strictEqual(escaped, false, 'TypeError caught in sandbox leaked host Function');
	});

	it('regression: null-proto host object via Promise.then is still wrapped (GHSA-mpf8)', async function () {
		const nullProto = Object.create(null);
		nullProto.tag = 'NP';
		nullProto.hostFn = function () {
			return 'OK';
		};
		const vm = new VM({ sandbox: { p: Promise.resolve(nullProto) } });
		const r = await vm.run(`p.then(v => ({ tag: v.tag, fn: v.hostFn() }))`);
		assert.strictEqual(r.tag, 'NP');
		assert.strictEqual(r.fn, 'OK');
	});
});
