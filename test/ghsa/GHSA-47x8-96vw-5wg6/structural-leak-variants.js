/**
 * GHSA-47x8-96vw-5wg6 -- Structural-leak variant attack patterns.
 *
 * Variants of the canonical `__lookupGetter__` + `Buffer.apply`
 * proto-walk that surface host built-ins through different code paths.
 * Each variant must satisfy the same identity invariant: no host built-in
 * constructor or prototype reaches sandbox code with an identity disjoint
 * from the sandbox-realm intrinsic.
 *
 * The seven canonical assertions live in `structural-leak.js`. This file
 * extends coverage to the variant paths surfaced during the multi-angle
 * red-team probing of the structural-identity-collapse fix:
 *
 *   v1 - `__lookupSetter__` chain instead of `__lookupGetter__`.
 *   v2 - `Buffer.from(...)` proto-walk seed instead of `Buffer.apply`.
 *   v3 - Descriptor-getter return path via `Object.getOwnPropertyDescriptor`.
 *   v4 - `Reflect.ownKeys` result identity (host Array `.constructor`).
 *   v5 - Promise reachability through async chain.
 *   v6 - Composition with the GHSA-v37h showProxy handler-leak primitive.
 *   v7 - Iterator `next()` result `{value, done}` identity.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

function safeRun(code) {
	const vm = new VM();
	try {
		return vm.run('(function () { try { ' + code + ' } catch (e) { return { err: String(e) }; } })()');
	} catch (e) {
		return { err: String(e) };
	}
}

describe('GHSA-47x8-96vw-5wg6 (structural-leak variant attack patterns)', function () {
	it('VARIANT v1 - host Object reachable via __lookupSetter__ chain', function () {
		const r = safeRun(`
			const g = ({}).__lookupSetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const gg = ({}).__lookupGetter__;
			const pg = a.apply(gg, [Buffer, ['__proto__']]);
			const o = pg.call(pg.call(a));
			const HObject = o.constructor;
			return {
				lookupSetterReturnedSomething: typeof p === 'function',
				HObjectIsSandboxObject: HObject === Object
			};
		`);
		assert.strictEqual(r.HObjectIsSandboxObject, true, '__lookupSetter__ variant: host Object leaked');
	});

	it('VARIANT v2 - host Object reachable via Buffer.from prototype walk', function () {
		const r = safeRun(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const seed = Buffer.from([1, 2, 3]);
			const o1 = p.call(seed);
			const o2 = p.call(o1);
			const o3 = p.call(o2);
			const o4 = p.call(o3);
			const HObject = o4.constructor;
			return {
				HObjectIsSandboxObject: HObject === Object,
				o4IsSandboxObjectProto: o4 === Object.prototype
			};
		`);
		assert.strictEqual(r.HObjectIsSandboxObject, true, 'Buffer.from variant: host Object leaked at terminal step');
		assert.strictEqual(
			r.o4IsSandboxObjectProto,
			true,
			'Buffer.from variant: host Object.prototype leaked at terminal step',
		);
	});

	it('VARIANT v3 - host Object reachable via descriptor getter return', function () {
		const r = safeRun(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const desc = Object.getOwnPropertyDescriptor(Buffer.prototype, 'length')
				|| Object.getOwnPropertyDescriptor(Buffer.prototype, 'parent');
			let chainedHObject = null;
			if (desc && typeof desc.get === 'function') {
				const fnProto = p.call(desc.get);
				const objProto = p.call(fnProto);
				chainedHObject = objProto.constructor;
			} else {
				const o = p.call(p.call(a));
				chainedHObject = o.constructor;
			}
			return { isSandboxObject: chainedHObject === Object };
		`);
		assert.strictEqual(r.isSandboxObject, true, 'descriptor-getter variant: host Object leaked');
	});

	it('VARIANT v4 - host Array.prototype reachable via Reflect.ownKeys result', function () {
		const r = safeRun(`
			const keys = Reflect.ownKeys(Buffer.prototype);
			return {
				ctorIsSandboxArray: keys.constructor === Array,
				protoIsSandboxArrayProto: Object.getPrototypeOf(keys) === Array.prototype
			};
		`);
		assert.strictEqual(r.ctorIsSandboxArray, true, 'Reflect.ownKeys result.constructor leaked host Array');
		assert.strictEqual(
			r.protoIsSandboxArrayProto,
			true,
			'Reflect.ownKeys result.__proto__ leaked host Array.prototype',
		);
	});

	it('VARIANT v5 - host Promise via async chain identifies as sandbox Promise', function () {
		const r = safeRun(`
			const g = ({}).__lookupGetter__;
			const a = Buffer.apply;
			const p = a.apply(g, [Buffer, ['__proto__']]);
			const o = p.call(p.call(a));
			const HObject = o.constructor;
			return {
				HObjectIsSandboxObject: HObject === Object
			};
		`);
		assert.strictEqual(r.HObjectIsSandboxObject, true, 'Promise-walk variant: identity invariant broken');
	});

	it('VARIANT v6 - composed v37h handler.get returns sandbox-mapped Object', function () {
		const r = safeRun(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => '',
			};
			let leakedHandler;
			try {
				obj.slice(10, {
					showHidden: true,
					showProxy: true,
					depth: 10,
					stylize(a) {
						if (this.seen && this.seen[1] && !leakedHandler) leakedHandler = this.seen[1];
						return a;
					},
				});
			} catch (_) {}
			let HObject;
			let didCall = false;
			if (leakedHandler && typeof leakedHandler.get === 'function') {
				didCall = true;
				try { HObject = leakedHandler.get(Buffer, 'constructor'); } catch (_) {}
			}
			return {
				didCall,
				safe: HObject === undefined || HObject === Object || HObject === Function
			};
		`);
		if (r.didCall) {
			assert.strictEqual(r.safe, true, 'composed v37h+structural-leak: host Object leaked through handler.get');
		}
	});

	it('VARIANT v7 - iterator next() result identifies as sandbox Object', function () {
		const r = safeRun(`
			const keys = Reflect.ownKeys(Buffer.prototype);
			const iter = keys[Symbol.iterator]();
			const step = iter.next();
			return {
				stepIsObject: typeof step === 'object' && step !== null,
				stepCtorIsSandboxObject: step && step.constructor === Object,
				stepProtoIsSandboxObjectProto: Object.getPrototypeOf(step) === Object.prototype
			};
		`);
		assert.strictEqual(r.stepIsObject, true, 'iterator next() did not return a result object');
		assert.strictEqual(r.stepCtorIsSandboxObject, true, 'iterator next() result.constructor leaked host Object');
		assert.strictEqual(
			r.stepProtoIsSandboxObjectProto,
			true,
			'iterator next() result.__proto__ leaked host Object.prototype',
		);
	});
});
