/**
 * GHSA-c4cf-2hgv-2qv6 — Bridge `set` trap ignores `receiver`, leaking
 * prototype-inheriting writes through to the wrapped host object.
 *
 * ## Vulnerability class
 *
 * Per ECMA-262 9.5.9 `[[Set]] (P, V, Receiver)`, when sandbox code writes
 * to an object that *inherits* from a bridge proxy (rather than to the
 * proxy itself), the proxy's `set` trap is invoked with `receiver` set to
 * the original recipient — not to the proxy. The spec-correct behaviour
 * is to install the property on `receiver` (or refuse), NOT on the proxy
 * target. `BaseHandler.set` in `lib/bridge.js` historically ignored the
 * `receiver` argument and unconditionally wrote through to the host
 * object via `otherReflectSet(object, key, value)`. The consequence: any
 * sandbox-side child built via `Object.create(hostObj)` becomes a write
 * channel onto the host object, bypassing any write-side hardening
 * keyed on the direct-assignment path.
 *
 * ## Canonical PoC (from the advisory)
 *
 *     const kCustom = Symbol.for('nodejs.util.promisify.custom');
 *     const child   = Object.create(hostFn);
 *     child[kCustom] = function () { return Promise.resolve('HIJACKED'); };
 *     // Host side: util.promisify(hostFn) now returns the sandbox's fn.
 *
 * No proxy trap on the host side intervenes because the write went via
 * the proxy's `set` trap with `receiver === child`, and the trap blindly
 * called `otherReflectSet(hostFn, kCustom, hijackedFn)`.
 *
 * ## Fix (lib/bridge.js)
 *
 * `BaseHandler.set` records the canonical sandbox-facing proxy at
 * construction time and, when invoked, refuses to write through to the
 * host target unless `receiver` is one of the bridge's own proxies for
 * that target. For any other receiver — a sandbox-side `Object.create`
 * child, an arbitrary `Reflect.set(..., custom)` receiver — the property
 * is installed on `receiver` itself via `Reflect.defineProperty`, which
 * matches both the ECMA-262 [[Set]] semantics and the existing
 * `ReadOnlyHandler.set` shape. The host object is never mutated for
 * non-proxy receivers.
 *
 * ## Invariant
 *
 * "Sandbox writes reach a host-realm object only through the canonical
 * bridge proxy for that object." Restated: the bridge `set` trap MUST
 * honour the spec `receiver`; child-of-proxy writes never cross the
 * realm boundary.
 */

'use strict';

const assert = require('assert');
const util = require('util');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-c4cf-2hgv-2qv6 (set trap receiver ignored — write-through via Object.create child)', function () {
	// ---- PRIMARY POC ----------------------------------------------------------

	it('blocks PoC: Object.create(hostFn) + child[Symbol.for(...)]=fn must NOT install on host', function () {
		const hostFn = function api(cb) {
			cb(null, 'ok');
		};
		const vm = new VM();
		vm.sandbox.hostFn = hostFn;

		try {
			vm.run(`
				const kCustom = Symbol.for('nodejs.util.promisify.custom');
				const child = Object.create(hostFn);
				child[kCustom] = function () {
					return Promise.resolve('HIJACKED-VIA-RECEIVER-BUG');
				};
			`);
		} catch (_) {
			/* either trap threw or symbol stripped — both acceptable */
		}

		// Host-side: no own property must have leaked onto hostFn, regardless of
		// whether the key materialised as the dangerous host-realm symbol or as
		// a sandbox-local symbol.
		const ownSyms = Object.getOwnPropertySymbols(hostFn);
		for (const s of ownSyms) {
			const desc = String(s);
			assert.notStrictEqual(
				desc,
				'Symbol(nodejs.util.promisify.custom)',
				'host fn must not carry a sandbox-installed nodejs.util.promisify.custom symbol',
			);
		}

		// And util.promisify must use Node's default behaviour, not the sandbox fn.
		const promisified = util.promisify(hostFn);
		return promisified().then(v => {
			assert.strictEqual(v, 'ok', 'promisify must not be hijacked');
		});
	});

	// ---- VARIANTS -------------------------------------------------------------

	it('blocks variant: plain string-key write on Object.create child must NOT leak to host', function () {
		const hostObj = { tag: 'host-original' };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;

		try {
			vm.run(`
				const child = Object.create(hostObj);
				child.injectedString = 'sandbox-value';
				child.tag = 'overwritten-by-sandbox';
			`);
		} catch (_) {
			/* trap-refusal is also acceptable */
		}

		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, 'injectedString'),
			false,
			'host object must not gain an injected own property via Object.create-child write',
		);
		assert.strictEqual(hostObj.tag, 'host-original', 'host object existing property must be unchanged');
	});

	it('blocks variant: Reflect.set(hostObj, k, v, customReceiver) must NOT leak to host', function () {
		const hostObj = function () {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;

		try {
			vm.run(`
				const customReceiver = { __proto__: null };
				Reflect.set(hostObj, 'reflectInjected', 'sandbox-value', customReceiver);
				Reflect.set(hostObj, Symbol.for('nodejs.util.promisify.custom'),
					function () { return Promise.resolve('HIJACK-VIA-REFLECT'); },
					customReceiver);
			`);
		} catch (_) {
			/* trap-refusal acceptable */
		}

		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, 'reflectInjected'),
			false,
			'Reflect.set with explicit receiver must not leak to host',
		);
		const ownSyms = Object.getOwnPropertySymbols(hostObj);
		for (const s of ownSyms) {
			assert.notStrictEqual(
				String(s),
				'Symbol(nodejs.util.promisify.custom)',
				'Reflect.set with explicit receiver must not install dangerous symbol on host',
			);
		}
	});

	it('blocks variant: nested Object.create chain (grandchild → child → host) must NOT leak', function () {
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;

		try {
			vm.run(`
				const child = Object.create(hostObj);
				const grand = Object.create(child);
				grand.depthInjected = 'leaked';
			`);
		} catch (_) {
			/* acceptable */
		}

		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, 'depthInjected'),
			false,
			'deep proto-chain writes must not surface on the host object',
		);
	});

	it('blocks variant: Object.assign(child, src) where child inherits from host must NOT leak', function () {
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;

		try {
			vm.run(`
				const child = Object.create(hostObj);
				Object.assign(child, { assignedKey: 'leaked' });
			`);
		} catch (_) {
			/* acceptable */
		}

		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, 'assignedKey'),
			false,
			'Object.assign onto Object.create-child must not leak to host',
		);
	});

	// ---- NEGATIVE CONTROL -----------------------------------------------------
	// Sanity: legitimate proxy writes still work — direct property assignment on
	// a host object handed to the sandbox should still mutate the host object.
	// (Without this, our fix has gone too far and broken the embedder contract.)

	it('negative-control: direct write proxy.x = v still mutates host object', function () {
		const hostObj = { existing: 1 };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;

		vm.run(`hostObj.newField = 42;`);

		assert.strictEqual(
			hostObj.newField,
			42,
			'direct sandbox-side writes to the proxy must still mutate the host object',
		);
	});
});
