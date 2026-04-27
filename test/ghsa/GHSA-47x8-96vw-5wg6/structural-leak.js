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
	it('proto-walk via __lookupGetter__ + Buffer.apply terminates at sandbox Object', function () {
		const vm = new VM();
		const result = vm.run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			({
				oIsObjectProto: o === Object.prototype,
				ctorIsSandboxObject: o.constructor === Object,
				ctorIsSandboxFunction: o.constructor.constructor === Function
			});
		`);
		assert.strictEqual(result.oIsObjectProto, true, 'walked proto must be sandbox Object.prototype');
		assert.strictEqual(
			result.ctorIsSandboxObject,
			true,
			'host Object must NOT leak as a wrapped proxy: o.constructor !== sandbox Object',
		);
		assert.strictEqual(
			result.ctorIsSandboxFunction,
			true,
			'host Function must NOT leak via Object.constructor.constructor',
		);
	});

	it('proto-walk to host Array.prototype terminates at sandbox Array', function () {
		const vm = new VM();
		const result = vm.run(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			// host Array.prototype: Buffer extends Uint8Array extends TypedArray;
			// or [] gives sandbox Array.prototype directly. Use a host array
			// returned by a host function:
			const ho = Object.entries({});
			const ap = p.call(ho);
			({
				ctorIsSandboxArray: ap === Array.prototype || ap.constructor === Array
			});
		`);
		assert.strictEqual(result.ctorIsSandboxArray, true, 'host Array constructor must not leak as a wrapped proxy');
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
				const d = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__');
				const get = d && d.get;
				if (!get) return {ok: true};
				const op = get.call(get.call(Buffer.apply));
				return {
					ctorIsSandboxObject: op.constructor === Object,
					ctorOfCtorIsSandboxFunction: op.constructor.constructor === Function
				};
			})();
		`);
		assert.strictEqual(result.ctorIsSandboxObject, true);
		assert.strictEqual(result.ctorOfCtorIsSandboxFunction, true);
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
				const fp = p.call(a);
				try {
					const F = fp.constructor;
					const r = F('return 1');
					return {leaked: typeof r === 'function'};
				} catch (e) {
					return {blocked: true};
				}
			})();
		`);
		assert.strictEqual(result.leaked, undefined, 'Function constructor must not produce a callable function');
	});
});
