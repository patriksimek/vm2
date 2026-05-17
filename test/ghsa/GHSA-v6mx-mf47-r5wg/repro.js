/**
 * GHSA-v6mx-mf47-r5wg — Sandbox escape via host intrinsic prototype severance
 *
 * ## Vulnerability class
 * The sandbox can corrupt the prototype chain of a host-realm object by calling
 * the host `Object.prototype.__proto__` setter (obtained via
 * `({}).__lookupSetter__('__proto__')`, which `connect()` routes to host) with
 * a wrapped host object as the `this` argument. The apply trap unwraps the
 * proxy back to the raw host object and lets the host setter mutate it
 * directly — the proxy `setPrototypeOf` trap (which throws `OPNA`) is
 * bypassed entirely.
 *
 * Once a non-protected host prototype (e.g. a Node-internal `NodeError`
 * subclass of `TypeError`) has its `__proto__` severed to `null`, any
 * subsequent host-realm value with that prototype that crosses into the
 * sandbox bypasses the bridge's recognition of host intrinsics. The bug
 * surfaces inside `thisEnsureThis` (lib/bridge.js): its proto-chain walk
 * looks up `protoMappings` for each prototype on the chain, and on
 * fallthrough (no mapping found, chain reaches `null`) it returned `other`
 * AS-IS. For a host-realm value with a severed chain, this returns the raw
 * host object to sandbox code — `e.constructor.constructor === host.Function`
 * → RCE.
 *
 * ## PoC summary
 * 1. `Buffer.call.call({}.__lookupGetter__, Buffer, '__proto__')` extracts
 *    the host `Object.prototype.__proto__` getter via `connect()`.
 * 2. `Buffer.call.call({}.__lookupSetter__, Buffer, '__proto__')` extracts
 *    the host `__proto__` setter.
 * 3. `await WebAssembly.compileStreaming()` rejects with a host `NodeError`
 *    extending `TypeError` (Node's `ERR_INVALID_ARG_TYPE`).
 * 4. `getProto.call(e)` yields a bridge proxy wrapping
 *    `host.NodeError.prototype`.
 * 5. `setProto.call(p1, null)` apply-traps into host realm, unwraps `p1` to
 *    the raw host prototype, and sets `host.NodeError.prototype.__proto__ =
 *    null` — severing the link to `host.TypeError.prototype`.
 * 6. A second `WebAssembly.compileStreaming()` rejects with a fresh
 *    `NodeError`. The bridge's `thisEnsureThis` walk reaches `null` without
 *    finding any mapping → returns the raw host error → sandbox reads
 *    `e.constructor.constructor` and obtains host `Function` → RCE.
 *
 * ## Fix
 * Structural: every host-realm primitive chokepoint already wraps on
 * fallthrough with `thisProxyOther(defaultFactory, other, thisObjectPrototype)`
 * — `thisFromOtherWithFactory` (line ~1947) and `thisFromOtherForThrow`
 * (line ~1876). `thisEnsureThis` was the lone exception, returning `other`
 * as-is. Make it consistent: on fallthrough, when the proto chain reaches
 * `null` without producing any sandbox or host intrinsic recognition AND
 * `other` is sandbox-side (`!isHost`), wrap defensively. Sandbox-native
 * values whose chain naturally reaches a known intrinsic still take the
 * fast path; sandbox-native values with a primordial null proto
 * (`Object.create(null)`) are caught by the early `!proto` return. Only the
 * narrow "non-null proto chain that never hits any known intrinsic" case is
 * wrapped — and that case is exactly the attacker-corrupted host signature.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// WebAssembly.compileStreaming exists on Node 14+; the PoC relies on its
// rejection producing a host Node-internal error.
const HAS_WASM_STREAMING = NODE_MAJOR >= 14;

// Sandbox-side sentinel: the escape path sets a key on `global`. Polling
// after a microtask tick lets unhandled-rejection / promise resolution
// settle.
function escapeAttempt(code) {
	const vm = new VM({ timeout: 2000 });
	const pwnKey = '__GHSA_v6mx_pwned_' + Math.random().toString(36).slice(2);
	global[pwnKey] = false;
	try {
		vm.run(code.replace(/__PWN_KEY__/g, JSON.stringify(pwnKey)));
	} catch (_) {
		/* bridge-level throws are also blocked */
	}
	return new Promise(function (resolve) {
		setTimeout(function () {
			const escaped = global[pwnKey] === true;
			delete global[pwnKey];
			resolve(escaped);
		}, 300);
	});
}

describe('GHSA-v6mx-mf47-r5wg (host intrinsic prototype severance → ensureThis fallthrough escape)', function () {
	it.cond(
		'blocks the canonical PoC (compileStreaming twice with proto severance between)',
		HAS_WASM_STREAMING,
		async function () {
			this.timeout(5000);
			const escaped = await escapeAttempt(`
			"use strict";
			const getProto = Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__");
			const setProto = Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__");
			async function f() {
				try { await WebAssembly.compileStreaming(); }
				catch (e) { setProto.call(getProto.call(e), null); }
				try { await WebAssembly.compileStreaming(); }
				catch (e) {
					try {
						const HostFunction = e.constructor.constructor;
						new HostFunction("globalThis[" + JSON.stringify(__PWN_KEY__) + "] = true")();
					} catch (_) {}
				}
			}
			f().catch(() => {});
		`);
			assert.strictEqual(escaped, false, 'canonical PoC succeeded');
		},
	);

	it.cond('catch-block error never exposes host Function after proto severance attempt', HAS_WASM_STREAMING, async function () {
		this.timeout(5000);
		// Even if the attacker attempts to corrupt the NodeError prototype, the
		// value delivered to the sandbox catch must never pivot to host
		// `Function` via `e.constructor.constructor`. The test does NOT check
		// `e.isProxy` because, with the write-side defense blocking the
		// `setProto.call` primitive, the proto chain stays intact and the bridge
		// wraps via the protoMappings hit at host `TypeError.prototype` — at
		// that point `e.constructor` resolves to *sandbox* `TypeError` and
		// `e.constructor.constructor` is *sandbox* `Function`, which is
		// harmless. The escape check looks for host `process` reachability.
		const vm = new VM({ timeout: 2000, sandbox: { __probe: {} } });
		vm.run(`
			"use strict";
			const getProto = Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__");
			const setProto = Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__");
			async function f() {
				try { await WebAssembly.compileStreaming(); }
				catch (e) { try { setProto.call(getProto.call(e), null); } catch (_) {} }
				try { await WebAssembly.compileStreaming(); }
				catch (e) {
					try {
						const HF = e.constructor.constructor;
						const probe = new HF("return typeof process !== 'undefined' && process && process.mainModule ? 'HOST' : 'SANDBOX'")();
						__probe.realm = probe;
					} catch (_) {
						__probe.realm = 'BLOCKED';
					}
				}
			}
			f().catch(() => {});
		`);
		await new Promise(function (r) {
			setTimeout(r, 300);
		});
		assert.notStrictEqual(
			vm.sandbox.__probe.realm,
			'HOST',
			'e.constructor.constructor reached host Function (host process visible)',
		);
	});

	it.cond('variant: severing host Error.prototype via the same primitive', HAS_WASM_STREAMING, async function () {
		this.timeout(5000);
		// Even if the attacker picks a different host-realm prototype to
		// sever, the fallthrough path must remain wrapped. This walks one
		// level deeper before the setProto call.
		const escaped = await escapeAttempt(`
			"use strict";
			const getProto = Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__");
			const setProto = Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__");
			async function f() {
				try { await WebAssembly.compileStreaming(); }
				catch (e) {
					try {
						// Walk two levels of proto chain before severing — try to
						// hit host TypeError.prototype's parent (host Error.prototype).
						setProto.call(getProto.call(getProto.call(e)), null);
					} catch (_) {}
				}
				try { await WebAssembly.compileStreaming(); }
				catch (e) {
					try {
						const HF = e.constructor.constructor;
						new HF("globalThis[" + JSON.stringify(__PWN_KEY__) + "] = true")();
					} catch (_) {}
				}
			}
			f().catch(() => {});
		`);
		assert.strictEqual(escaped, false, 'deeper proto-severance variant succeeded');
	});

	it('sandbox-native catch values with intact prototype chain are returned identity-stable', function () {
		// Regression guard for the fix: sandbox-realm errors caught in a
		// sandbox catch block must NOT be wrapped in a bridge proxy
		// (preserves identity comparisons, instanceof, and prevents
		// proxy-of-proxy churn).
		const vm = new VM();
		const out = vm.run(`
			let caught = null;
			let sameIdentity = false;
			try { throw new Error("local"); }
			catch (e) { caught = e; sameIdentity = (e instanceof Error) && e.message === "local"; }
			({ sameIdentity });
		`);
		assert.strictEqual(out.sameIdentity, true, 'sandbox-native error lost identity through catch');
	});

	it('Object.create(null) sandbox values still pass through ensureThis untouched', function () {
		// The early `!proto` return in ensureThis must continue to short-
		// circuit primordial null-proto objects so they are not wrapped.
		const vm = new VM();
		const out = vm.run(`
			const nullProto = Object.create(null);
			nullProto.kind = "marker";
			let caught = null;
			try { throw nullProto; } catch (e) { caught = e; }
			({ kind: caught && caught.kind, sameRef: caught === nullProto });
		`);
		assert.strictEqual(out.kind, 'marker', 'null-proto throw lost data');
		assert.strictEqual(out.sameRef, true, 'null-proto throw was wrapped');
	});
});
