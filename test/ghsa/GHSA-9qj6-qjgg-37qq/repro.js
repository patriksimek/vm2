/**
 * GHSA-9qj6-qjgg-37qq — Sandbox breakout via `neutralizeArraySpeciesBatch`
 *
 * ## Vulnerability
 * The species-defense helper `neutralizeArraySpeciesBatch` (added by the fix
 * for GHSA-grj5-jjm8-h35p) accumulates per-call saved-state records inside a
 * fresh array literal `[]`. That literal is created by the *sandbox-side*
 * bridge closure, so it inherits sandbox `Array.prototype`. The function then
 * appends entries with `saved[saved.length] = c`, an ordinary index assignment
 * that walks the prototype chain when no own slot exists.
 *
 * If sandbox code installs a setter on `Array.prototype[0]` before triggering
 * a host call (e.g., `new Buffer(a)` with sandbox array `a` as argument), the
 * append fires that setter and hands `c` to attacker-controlled code. `c` is a
 * `{ arr, originalDesc, marker }` record whose `arr` field is the host-realm
 * proxy of the sandbox argument array — a host-realm reference is not meant to
 * be addressable from the sandbox at this point. From `c.arr` the attacker
 * walks `arr.f.constructor.constructor("return process")()` to host
 * `process` → RCE.
 *
 * ## Fix
 * `neutralizeArraySpeciesBatch` now installs entries with
 * `thisReflectDefineProperty(saved, i, { value, ... })` instead of `saved[i] =`.
 * `Reflect.defineProperty` creates a data own property and bypasses the
 * prototype-chain setter completely, restoring the invariant that the bridge
 * never invokes sandbox-controlled getters/setters with raw saved state.
 * `restoreArraySpeciesBatch` is symmetric: indexed reads now hit own data
 * properties only and cannot be intercepted by `Array.prototype` getters.
 *
 * Cross-reference: docs/ATTACKS.md Category 21 (Bridge Internal-State Leak via
 * Sandbox-Realm Array Setter).
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

function tryEscape(code) {
	const vm = new VM();
	let result;
	let thrown = null;
	try {
		result = vm.run(code);
	} catch (e) {
		thrown = e;
	}
	return { result, thrown };
}

describe('GHSA-9qj6-qjgg-37qq — neutralizeArraySpeciesBatch setter leak', () => {
	it('Array.prototype[0] setter cannot capture host-realm saved-state record', () => {
		// SECURITY: canonical PoC from the advisory, instrumented to surface
		// whether a host `process` reference reached sandbox code.
		const { result } = tryEscape(`
			const a = [];
			const out = Object.create(null);
			Object.defineProperty(Array.prototype, 0, {
				configurable: true,
				set(value) {
					try {
						out.captured = true;
						a.f = Buffer.prototype.inspect;
						const arr = value && value.arr;
						out.arrLeaked = arr !== undefined && arr !== null;
						if (arr && arr.f && arr.f.constructor && arr.f.constructor.constructor) {
							out.gotCtorCtor = true;
							const proc = arr.f.constructor.constructor('return process')();
							out.escaped = !!proc;
						}
					} catch (e) {
						out.setterErr = (e && e.message) || String(e);
					}
				},
				get() { return undefined; }
			});
			try { new Buffer(a); } catch (e) { out.bufferErr = e.message; }
			out;
		`);

		const out = result || {};
		assert.notStrictEqual(out.escaped, true, 'sandbox obtained host process via setter capture');
		assert.notStrictEqual(out.gotCtorCtor, true, 'sandbox reached arr.f.constructor.constructor');
		assert.notStrictEqual(out.arrLeaked, true, 'host-realm proxy `arr` leaked into sandbox setter');
	});

	it('numeric setter at higher indices also cannot leak host state', () => {
		// SECURITY: variant — installs the setter at index 1 (saved-state list
		// can grow when both context and one arg are host arrays). Defense must
		// be index-agnostic.
		const { result } = tryEscape(`
			const a = [];
			const b = [];
			const out = Object.create(null);
			for (const idx of [0, 1, 2]) {
				Object.defineProperty(Array.prototype, idx, {
					configurable: true,
					set(value) {
						out['captured_' + idx] = true;
						const arr = value && value.arr;
						if (arr && arr.f && arr.f.constructor && arr.f.constructor.constructor) {
							out.escaped = true;
						}
					},
					get() { return undefined; }
				});
			}
			a.f = Buffer.prototype.inspect;
			b.f = Buffer.prototype.inspect;
			try { Buffer.from(a, b); } catch (e) {}
			try { Buffer.concat([a, b]); } catch (e) {}
			out;
		`);

		const out = result || {};
		assert.notStrictEqual(out.escaped, true, 'sandbox escaped via higher-index setter');
	});

	it('Array.prototype getter cannot mutate saved-state during restore', () => {
		// SECURITY: the symmetric concern for restoreArraySpeciesBatch. With the
		// fix, savedList[i] reads land on own data properties; no sandbox getter
		// on `Array.prototype[i]` is invoked between neutralize and restore.
		const { result } = tryEscape(`
			const a = [];
			const out = Object.create(null);
			let getterCalls = 0;
			Object.defineProperty(Array.prototype, 0, {
				configurable: true,
				get() {
					getterCalls++;
					out.getterFired = true;
					return undefined;
				},
				set() { /* swallow; we still want the host call to proceed */ }
			});
			try { new Buffer(a); } catch (e) {}
			out.getterCalls = getterCalls;
			out;
		`);

		const out = result || {};
		assert.notStrictEqual(
			out.getterFired,
			true,
			'sandbox getter on Array.prototype[0] fired during species batch lifecycle',
		);
	});
});
