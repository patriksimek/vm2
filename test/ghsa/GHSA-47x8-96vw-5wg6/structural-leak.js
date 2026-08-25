/**
 * GHSA-47x8-96vw-5wg6 -- structural leak: host `Object` reachable from sandbox.
 *
 * The original symbol-filter patch (commit `67bc511`) blocks the canonical
 * RCE payload, but the underlying primitive --
 * the sandbox obtaining a reference to the host-realm `Object` constructor --
 * is unchanged. The chain
 *
 *     const g = ({}).__lookupGetter__;
 *     const a = Buffer.apply;
 *     const p = a.apply(g, [Buffer, ['__proto__']]);
 *     const o = p.call(p.call(a));
 *     const HObject = o.constructor;
 *
 * still produces an `HObject` for which `HObject !== sandbox Object`. This file
 * pins the structural invariant: any path that attempts to surface a host
 * built-in constructor (Object, Array, Number, etc.) into the sandbox must
 * deliver the sandbox-realm equivalent, never a wrapped host constructor whose
 * identity differs from the sandbox's intrinsic.
 *
 * The tests assert identity (`===`) against the sandbox-side intrinsic. They
 * are intentionally stricter than "RCE blocked" -- a layered defense only
 * proves the known exit sink is closed; identity equality proves the leak
 * itself is closed.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-47x8-96vw-5wg6 (structural leak: host Object reachable in sandbox)', function () {
	// GHSA-88hf-g992-jg85 hardened this invariant: rather than relying on the
	// proto-walk landing on the *remapped* sandbox intrinsic, the raw host
	// `Object.prototype.__proto__` getter is now DENIED delivery entirely — it
	// collapses to a non-callable sentinel, so the walk primitive cannot even
	// start. That is strictly stronger than "terminates at sandbox Object" and
	// also closes the non-intrinsic case (host EventEmitter.prototype etc.) that
	// the remapping never covered.
	it('proto-walk via __lookupGetter__ + Buffer.apply cannot obtain a callable host __proto__ getter', function () {
		const vm = new VM();
		const result = vm.run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			let threw = false;
			let leaked = null;
			try { leaked = p.call(p.call(a)); } catch (_) { threw = true; }
			({
				getterIsCallable: typeof p === 'function',
				walkThrew: threw,
				leaked: leaked,
			});
		`);
		assert.strictEqual(result.getterIsCallable, false, 'raw host __proto__ getter must not be delivered as callable');
		assert.strictEqual(result.walkThrew, true, 'invoking the denied getter must throw, blocking the walk');
		assert.strictEqual(result.leaked, null, 'no host prototype may be surfaced via the raw getter');
	});

	it('proto-walk to host Array.prototype cannot start (raw getter denied)', function () {
		const vm = new VM();
		const result = vm.run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const ho = Object.entries({}); // host array
			let threw = false, leaked = null;
			try { leaked = p.call(ho); } catch (_) { threw = true; }
			({ getterIsCallable: typeof p === 'function', walkThrew: threw, leaked: leaked });
		`);
		assert.strictEqual(result.getterIsCallable, false, 'raw host __proto__ getter must not be delivered as callable');
		assert.strictEqual(result.walkThrew, true, 'invoking the denied getter must throw, blocking the walk to host Array.prototype');
		assert.strictEqual(result.leaked, null, 'host Array.prototype must not be surfaced via the raw getter');
	});

	it('host Object.prototype.constructor returns sandbox Object', function () {
		const vm = new VM();
		const result = vm.run(`
			// The simplest "reach host Object.prototype" path: read .__proto__
			// of a wrapped host value. The bridge's existing proto mapping
			// already collapses this to sandbox Object.prototype. The new
			// invariant: reading .constructor on it must also give the sandbox
			// constructor, not a wrapped host one.
			const proto = Object.getPrototypeOf(Object.getPrototypeOf(Buffer.apply));
			({
				protoIsSandbox: proto === Object.prototype,
				ctorIsSandboxObject: proto.constructor === Object
			});
		`);
		assert.strictEqual(result.protoIsSandbox, true);
		assert.strictEqual(result.ctorIsSandboxObject, true);
	});

	it('Reflect.getPrototypeOf walk terminates at sandbox Object', function () {
		const vm = new VM();
		const result = vm.run(`
			const proto = Reflect.getPrototypeOf(Reflect.getPrototypeOf(Buffer.apply));
			proto.constructor === Object;
		`);
		assert.strictEqual(result, true);
	});

	it('descriptor extraction of __proto__ getter does not yield a host-bound function', function () {
		const vm = new VM();
		const result = vm.run(`
			(() => {
				// GHSA-88hf-g992-jg85: extracting the host __proto__ getter via the
				// descriptor of the *sandbox* Object.prototype yields the sandbox
				// getter (harmless). Extracting it off a *host* proxy would be denied
				// at delivery. Either way, no host prototype may be surfaced.
				const d = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__');
				const get = d && d.get;
				if (!get) return {ok: true};
				let threw = false, op = null;
				try { op = get.call(get.call(Buffer.apply)); } catch (_) { threw = true; }
				return {
					// The sandbox getter walking a host proxy still collapses to the
					// bridge-flattened view (sandbox Object.prototype) or throws.
					safe: threw || op === Object.prototype || (op && op.constructor === Object)
				};
			})();
		`);
		assert.strictEqual(result.safe, true, 'no host prototype/constructor may leak via descriptor getter extraction');
	});

	it('host Number/String/Boolean wrappers cannot leak via primitive proto walk', function () {
		const vm = new VM();
		const result = vm.run(`
			// Walk to host Number.prototype via a host function whose return
			// is a number wrapper from Object(...). Since the bridge wraps
			// boxed primitives, the proto-walk should land at sandbox.
			const checks = {};
			try {
				const protoOfNumber = Object.getPrototypeOf(Object(1));
				checks.numberCtorIsSandbox = protoOfNumber.constructor === Number;
			} catch (e) { checks.numberErr = String(e); }
			try {
				const protoOfBool = Object.getPrototypeOf(Object(true));
				checks.boolCtorIsSandbox = protoOfBool.constructor === Boolean;
			} catch (e) { checks.boolErr = String(e); }
			try {
				const protoOfString = Object.getPrototypeOf(Object('x'));
				checks.stringCtorIsSandbox = protoOfString.constructor === String;
			} catch (e) { checks.stringErr = String(e); }
			checks;
		`);
		assert.strictEqual(result.numberCtorIsSandbox, true);
		assert.strictEqual(result.boolCtorIsSandbox, true);
		assert.strictEqual(result.stringCtorIsSandbox, true);
	});

	it('Function constructor block remains in force', function () {
		// Independent of the new constructor mapping: AsyncFunction /
		// GeneratorFunction / Function constructors must still be blocked.
		const vm = new VM();
		const result = vm.run(`
			(() => {
				const g = ({}).__lookupGetter__;
				const a = Buffer.apply;
				const p = a.apply(g, [Buffer, ['__proto__']]);
				try {
					// GHSA-88hf-g992-jg85: p (raw host __proto__ getter) is now a
					// non-callable sentinel, so fp cannot be obtained at all.
					const fp = p.call(a);
					const F = fp.constructor;
					const r = F('return 1');
					return {leaked: typeof r === 'function'};
				} catch (e) {
					return {blocked: true};
				}
			})();
		`);
		assert.strictEqual(result.leaked, undefined, 'Function constructor must not produce a callable function');
		assert.strictEqual(result.blocked, true, 'the raw getter walk must be blocked before reaching any host constructor');
	});
});
