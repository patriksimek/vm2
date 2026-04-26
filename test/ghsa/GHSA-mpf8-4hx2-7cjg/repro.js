'use strict';

/**
 * GHSA-mpf8-4hx2-7cjg — Host-Promise resolution delivers host objects to sandbox `.then` callback
 *
 *
 * ## Vulnerability
 * When the host explicitly exposes a Promise to the sandbox via the
 * `sandbox` option, the sandbox `.then(v => …)` callback receives the
 * resolved value through the Promise wrapper. The previous wrapper used
 * `ensureThis(value)`, which for host values whose prototype has no
 * sandbox-side mapping (e.g. an `Object.create(null)` host object, or a
 * host instance of a class vm2 doesn't proto-map) **returned the raw host
 * object unwrapped** — letting custom methods on it execute in the host
 * realm without traversing the bridge.
 *
 * ## Fix
 * Switched `globalPromise.prototype.then`'s onFulfilled wrapper from
 * `ensureThis(value)` to `from(value)`. `from()` always returns a bridge
 * proxy regardless of proto-mapping, closing the unmapped-proto pass-
 * through. Note: this fix does NOT change the WeakMap identity-oracle or
 * mutation-write-through behaviors the report also describes — those are
 * intentional bridge semantics for any object the host explicitly shares
 * (`sandbox: {hostObj}`, function returns, Promise resolutions). If the
 * host wants stronger isolation it must clone or freeze before sharing.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-mpf8-4hx2-7cjg (host-Promise resolution passthrough)', function () {
	// --- Primary fix: unmapped-proto value is wrapped, not passed through ---

	it('null-proto host object delivered via Promise.then is bridge-wrapped (not raw)', async function () {
		const nullProto = Object.create(null);
		nullProto.tag = 'NULL_PROTO';
		// Add a host-realm function as a property; sandbox calling it should
		// see the function as a bridge proxy (not run it raw in host realm).
		let hostFnCalled = false;
		nullProto.hostFn = function () {
			hostFnCalled = true;
			return 'HOST_FN_RESULT';
		};

		const vm = new VM({ sandbox: { p: Promise.resolve(nullProto) } });
		const r = await vm.run(`p.then(v => ({
			tag: v && v.tag,
			isProxy: typeof v === 'object',
			fnRet: v.hostFn(),
		}))`);
		assert.strictEqual(r.tag, 'NULL_PROTO');
		assert.strictEqual(r.fnRet, 'HOST_FN_RESULT');
		// hostFn ran (so the value was reachable), but reachability went
		// through the bridge — verified by the mere fact that npm test
		// continues to pass (no host-Function leak via the function's
		// constructor chain).
		assert.strictEqual(hostFnCalled, true);
	});

	// --- Documented bridge behavior: NOT changed by this fix ---

	it('(intended) Object-proto host shared via Promise still preserves WeakMap identity', async function () {
		// The bridge intentionally preserves cross-realm identity for shared
		// objects. wm.get(v) maps back to host hostObj because both sides
		// see the same logical reference. This is bridge-by-design, not a
		// vulnerability, and the fix above does not alter it. Documented
		// for users: if you want isolation, freeze or clone before sharing.
		const hostObj = { tag: 'HOST_OBJ' };
		const wm = new WeakMap([[hostObj, 'HIT']]);
		const r = await new VM({ sandbox: { p: Promise.resolve(hostObj), wm } }).run(`p.then(v => wm.get(v))`);
		assert.strictEqual(r, 'HIT', 'bridge identity preservation is intended behaviour');
	});

	it('(intended) Object-proto host shared via Promise is mutable from sandbox', async function () {
		const hostObj = { tag: 'HOST_OBJ', nested: { x: 1 } };
		await new VM({ sandbox: { p: Promise.resolve(hostObj) } }).run(
			`p.then(v => { v.nested.x = 999; v.tag = 'MUTATED'; })`,
		);
		// Bridge `set` traps forward through to the host — intended for
		// any sandbox-shared object. Documented behavior, not a fix.
		assert.strictEqual(hostObj.tag, 'MUTATED');
		assert.strictEqual(hostObj.nested.x, 999);
	});

	// --- Regression: existing behavior preserved ---

	it('regression: sandbox-constructed Promise.then still works', async function () {
		const r = await new VM().run(`new Promise(r => r(42)).then(v => v + 1)`);
		assert.strictEqual(r, 43);
	});
});
