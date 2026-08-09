/**
 * GHSA-cfcw-xp6x-25gj — Stacked-indirection bypass of the v6mx peel-loop
 *
 * ## Vulnerability class
 * GHSA-v6mx-mf47-r5wg's apply-trap guard peels exactly ONE layer of
 * `Function.prototype.call` / `Function.prototype.apply` / `Function.prototype.bind`
 * indirection: when the apply trap target is one of those primitives, it unwraps
 * `context` (the underlying function) once and checks it against the dangerous
 * host-prototype-mutator set. An attacker who stacks TWO layers of indirection —
 * `Buffer.call.call(Buffer.call, setProto, target, null)` — defeats that peel:
 *
 *   outer apply target  : `Buffer.call` (Function.prototype.call)
 *   outer context       : `Buffer.call` (the underlying function, also call)
 *   outer args          : [setProto, target, null]
 *
 * The peel inspects `context = Buffer.call` and finds it is itself
 * `Function.prototype.call` — also tracked in `applyIndirectionPrimitives` but
 * NOT in `dangerousHostProtoMutators`. The check passes; the apply proceeds; the
 * inner `Function.prototype.call` then invokes `setProto.call(target, null)`,
 * severing the host prototype as in v6mx. From there the canonical
 * `e.constructor.constructor` pivot to host `Function` works.
 *
 * ## PoC summary
 * ```js
 * const setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__");
 * // setProto is a reference to the host Object.prototype.__proto__ setter.
 * try { await WebAssembly.compileStreaming(); }
 * catch (e) { Buffer.call.call(Buffer.call, setProto, target, null); }
 * try { await WebAssembly.compileStreaming(); }
 * catch (e) { e.constructor.constructor("return process")() ... }
 * ```
 *
 * ## Fix — defense-in-depth (independent of the v6mx peel)
 * The structural answer is upstream: refuse to ever DELIVER a reference to a
 * host-realm prototype-mutator into the sandbox. The dangerous-mutator set
 * collected at bridge-init time (Object.prototype.__proto__ setter,
 * Object.setPrototypeOf, Reflect.setPrototypeOf, Object.defineProperty,
 * Reflect.defineProperty, Object.prototype.__defineGetter__ /
 * __defineSetter__) is consulted in `thisFromOtherWithFactory`,
 * `thisFromOtherForThrow`, and `thisEnsureThis` after the cache-hit short
 * circuit. If the bridged value is one of these and is NOT a connect()-mapped
 * sandbox surrogate, return `emptyFrozenObject` (the same sentinel used for
 * dangerous Function constructors). The sandbox can no longer obtain a callable
 * reference to wrap in any number of indirection layers, so the entire family
 * of stacked-indirection bypasses collapses at the root primitive.
 *
 * This is independent of the apply-trap peel: even if the peel has gaps
 * (multiple layers, novel intrinsics that act as `.call` substitutes, future
 * built-ins that expose the same primitive), the upstream filter denies the
 * underlying reference from ever crossing the bridge.
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
// WebAssembly.compileStreaming exists on Node 14+; the PoC depends on its
// rejection producing a host Node-internal error.
const HAS_WASM_STREAMING = NODE_MAJOR >= 14;

function escapeAttempt(code) {
	const vm = new VM({ timeout: 2000 });
	const pwnKey = '__GHSA_cfcw_pwned_' + Math.random().toString(36).slice(2);
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

describe('GHSA-cfcw-xp6x-25gj (stacked indirection bypass of v6mx peel)', function () {
	it.cond(
		'blocks the canonical stacked PoC (Buffer.call.call(Buffer.call, setProto, ...))',
		HAS_WASM_STREAMING,
		async function () {
			this.timeout(5000);
			const escaped = await escapeAttempt(`
				"use strict";
				const getProto = Buffer.call.call(Buffer.call, {}.__lookupGetter__, Buffer, "__proto__");
				const setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__");
				async function f() {
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							Buffer.call.call(Buffer.call, setProto,
								Buffer.call.call(Buffer.call, getProto, e), null);
						} catch (_) {}
					}
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
			assert.strictEqual(escaped, false, 'stacked-indirection PoC succeeded');
		},
	);

	it('refuses to deliver the host __proto__ setter via the apply-call indirection paths the PoC needs', function () {
		// The structural property: the apply-call indirection extraction paths
		// that the PoC requires must NOT yield a callable host reference. The
		// defense collapses the host setter reference to a non-callable
		// sentinel (`emptyFrozenObject`), so any number of subsequent
		// indirection wrappers cannot resurrect the primitive.
		const vm = new VM({ sandbox: { __out: {} } });
		vm.run(`
			"use strict";
			// Path 1: stacked apply-call indirection (the canonical PoC primitive)
			const sp1 = Buffer.call.call(Buffer.call, ({}).__lookupSetter__, Buffer, '__proto__');
			__out.path1IsFunction = typeof sp1 === 'function';

			// Path 2: Function.prototype.apply with the host setter as 'this'
			const lookupSetter = ({}).__lookupSetter__;
			const sp2 = Buffer.call.apply(lookupSetter, [Buffer, '__proto__']);
			__out.path2IsFunction = typeof sp2 === 'function';

			// Path 3: through Function.prototype.bind layered with .call
			const sp3 = Buffer.call.call(Buffer.call.bind(({}).__lookupSetter__, Buffer), '__proto__');
			__out.path3IsFunction = typeof sp3 === 'function';
		`);
		assert.strictEqual(vm.sandbox.__out.path1IsFunction, false, 'path1 leaked host setter as callable');
		assert.strictEqual(vm.sandbox.__out.path2IsFunction, false, 'path2 leaked host setter as callable');
		assert.strictEqual(vm.sandbox.__out.path3IsFunction, false, 'path3 leaked host setter as callable');
	});

	it.cond(
		'three-layer-deep indirection is also blocked (Buffer.call.call.call(...))',
		HAS_WASM_STREAMING,
		async function () {
			this.timeout(5000);
			// If the primary peel-loop fix only handles N=2 layers, an attacker
			// would simply add another. The reference-denial defense is
			// independent of layer count.
			const escaped = await escapeAttempt(`
				"use strict";
				const C = Buffer.call;
				const getProto = C.call.call(C, ({}).__lookupGetter__, Buffer, "__proto__");
				const setProto = C.call.call(C, ({}).__lookupSetter__, Buffer, "__proto__");
				async function f() {
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							// 3-layer-deep indirection
							C.call.call(C, C.call.call(C, setProto),
								C.call.call(C, getProto, e), null);
						} catch (_) {}
					}
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							new (e.constructor.constructor)("globalThis[" + JSON.stringify(__PWN_KEY__) + "] = true")();
						} catch (_) {}
					}
				}
				f().catch(() => {});
			`);
			assert.strictEqual(escaped, false, 'three-layer indirection PoC succeeded');
		},
	);

	it('legitimate sandbox use of __defineGetter__ / __defineSetter__ is preserved', function () {
		// The defense filters on the *uncached, raw host reference* path — the
		// sandbox-realm surrogates registered via connect() must continue to
		// work for normal code. Regression guard for issue #176.
		const vm = new VM();
		assert.strictEqual(
			vm.run('Buffer.prototype.__defineGetter__ === ({}).__defineGetter__;'),
			true,
			'sandbox surrogate identity broke',
		);
		// And it must still be callable via the surrogate.
		assert.strictEqual(
			vm.run('global.__defineGetter__("__cfcwT", () => 42); global.__cfcwT;'),
			42,
			'sandbox __defineGetter__ stopped working',
		);
	});

	it('legitimate sandbox use of Object.setPrototypeOf on sandbox objects is preserved', function () {
		// Object.setPrototypeOf on sandbox-realm targets must continue to work;
		// only host-targeted mutations are blocked. The dangerous-mutator set
		// holds the HOST function reference — the sandbox Object.setPrototypeOf
		// is a different function entirely.
		const vm = new VM();
		const out = vm.run(`
			const a = {};
			const b = { kind: 'parent' };
			Object.setPrototypeOf(a, b);
			a.kind;
		`);
		assert.strictEqual(out, 'parent', 'legitimate setPrototypeOf broke');
	});

	it('legitimate sandbox use of Object.defineProperty on sandbox objects is preserved', function () {
		// Object.defineProperty on sandbox-realm targets must continue to work.
		const vm = new VM();
		const out = vm.run(`
			const a = {};
			Object.defineProperty(a, 'x', { value: 7, configurable: true });
			a.x;
		`);
		assert.strictEqual(out, 7, 'legitimate defineProperty broke');
	});

	// ----------------------------------------------------------------------
	// Second bypass (reporter follow-up, 2026-05-25): host-side laundering of
	// the dangerous invocation through `Function.prototype.bind` + a host
	// higher-order method (`Array.prototype.map`).
	//
	// The reference-deny and apply-trap-peel defenses are both *identity*
	// based. This PoC defeats both because the dangerous `__proto__` setter is
	// never delivered to sandbox code as a value, and its invocation never
	// re-crosses the bridge apply trap:
	//
	//   const ca = Buffer.call.call(Buffer.bind, Buffer.apply, Buffer.call, Buffer.call);
	//   // ca === host Function.prototype.apply.bind(call, call) — a FRESH host
	//   // function identity (not in applyIndirectionPrimitives, not in
	//   // dangerousHostProtoMutators).
	//   function caar(a){ const r = Buffer.of().toJSON().data; r[0]=a; return r.map(ca); }
	//   // r is a genuine HOST array; r.map(ca) runs host Array.prototype.map,
	//   // which calls the host `ca` callback host-side. Every dangerous call
	//   // (`__lookupSetter__`, the `__proto__` setter) executes entirely within
	//   // the host realm — zero bridge crossings to inspect.
	//
	// Instrumenting the apply trap shows ZERO host applies of any dangerous /
	// indirection primitive: the whole chain is laundered host-side.
	// ----------------------------------------------------------------------

	it.cond(
		'blocks the map/bind host-side laundering bypass (reporter PoC 2026-05-25)',
		HAS_WASM_STREAMING,
		async function () {
			this.timeout(5000);
			const escaped = await escapeAttempt(`
				"use strict";
				const ca = Buffer.call.call(Buffer.bind, Buffer.apply, Buffer.call, Buffer.call);
				function caar(a){ const r = Buffer.of().toJSON().data; r[0] = a; return r.map(ca); }
				async function f() {
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							const g = caar([{}.__lookupGetter__, Buffer, "__proto__"]); g[1] = e;
							const s = caar([{}.__lookupSetter__, Buffer, "__proto__"]); s[1] = ca(g); s[2] = null;
							ca(s);
						} catch (_) {}
					}
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							e.constructor.constructor("globalThis[" + JSON.stringify(__PWN_KEY__) + "] = true")();
						} catch (_) {}
					}
				}
				f().catch(() => {});
			`);
			assert.strictEqual(escaped, false, 'map/bind host-side laundering PoC succeeded');
		},
	);

	it('refuses to surface a host universal-applicator (apply/call/bind composed via bind)', function () {
		// Structural property: the sandbox must not be able to obtain a host
		// function that, when invoked host-side with a sandbox-seeded host array,
		// performs an arbitrary host call WITHOUT re-crossing the bridge. We
		// assert it cannot launder the host __proto__ setter onto a host object
		// via map + a bound host applicator.
		const vm = new VM({ sandbox: { __out: {} } });
		vm.run(`
			"use strict";
			const ca = Buffer.call.call(Buffer.bind, Buffer.apply, Buffer.call, Buffer.call);
			// Attempt to sever a host object's prototype host-side via map laundering.
			const r = Buffer.of().toJSON().data; // host array
			r[0] = [{}.__lookupSetter__, Buffer, "__proto__"];
			let threw = false, leakedSetter = false;
			try {
				const s = r.map(ca);
				// If the laundering worked, s[0] is the host __proto__ setter and is callable.
				leakedSetter = (typeof s[0] === 'function');
				s[1] = {}; s[2] = null;
				ca(s);
			} catch (e) { threw = true; }
			__out.leakedSetter = leakedSetter;
			__out.blocked = threw;
		`);
		assert.strictEqual(vm.sandbox.__out.leakedSetter, false, 'host __proto__ setter leaked via map laundering');
	});

	it.cond(
		'blocks reduce/forEach host-side laundering variants',
		HAS_WASM_STREAMING,
		async function () {
			this.timeout(5000);
			// Same primitive, different host higher-order method. If the fix is
			// structural (deny the host applicator / re-route the invocation), all
			// iteration methods are covered; if it special-cases `map`, this slips.
			const escaped = await escapeAttempt(`
				"use strict";
				const ca = Buffer.call.call(Buffer.bind, Buffer.apply, Buffer.call, Buffer.call);
				function caar(a){
					const r = Buffer.of().toJSON().data; r[0] = a;
					let out;
					r.forEach(function(x){ out = ca(x); });
					return [out];
				}
				async function f() {
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							const g = caar([{}.__lookupGetter__, Buffer, "__proto__"]); g[1] = e;
							const s = caar([{}.__lookupSetter__, Buffer, "__proto__"]); s[1] = ca(g); s[2] = null;
							ca(s);
						} catch (_) {}
					}
					try { await WebAssembly.compileStreaming(); }
					catch (e) {
						try {
							e.constructor.constructor("globalThis[" + JSON.stringify(__PWN_KEY__) + "] = true")();
						} catch (_) {}
					}
				}
				f().catch(() => {});
			`);
			assert.strictEqual(escaped, false, 'forEach host-side laundering PoC succeeded');
		},
	);
});
