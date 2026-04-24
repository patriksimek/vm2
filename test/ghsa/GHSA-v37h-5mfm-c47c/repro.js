/**
 * GHSA-v37h-5mfm-c47c — Handler class reconstruction via util.inspect showProxy leak
 *
 *
 * ## Vulnerability
 * `util.inspect({showHidden:true, showProxy:true, ...})` traverses proxy
 * internals and stashes the host-side `BaseHandler` instance into the inspect
 * context. An attacker harvests the handler via a crafted `stylize` callback,
 * walks `Object.getPrototypeOf(handler)` to reach `BaseHandler.prototype`, then
 * reads `.constructor` and invokes it with an attacker-controlled sandbox
 * object as the handler's wrapped object:
 *
 *     new pp.constructor(s).set(null, 'obj', s);
 *     s.obj.x = hostFn;
 *     s.x.constructor("return process")();
 *
 * Because the freshly constructed handler wraps a sandbox object `s`, the
 * handler's own `set` trap treats `s` as the "other realm" and writes the
 * passed-in host function directly onto `s`, giving the attacker a raw
 * cross-realm read/write channel.
 *
 * The core invariant violated is: **handler classes must never be instantiable
 * by sandbox code**. Prior fixes moved handler state into closure-scoped
 * WeakMaps (a6cd917, f1d9cf4, 57971fa, 9084cd6), but the classes themselves
 * remained reachable as constructors via the leaked prototype.
 *
 * ## Fix
 * Defense-in-depth in `lib/bridge.js`:
 *
 * 1. Handler constructors now require a per-bridge construction token. Every
 *    legitimate construction site (defaultFactory, protectedFactory,
 *    readonlyFactory, readOnlyMockFactory) passes the token explicitly. Any
 *    `new Handler(...)` / `Reflect.construct(Handler, ...)` / subclass
 *    invocation by sandbox code throws VMError immediately.
 * 2. `BaseHandler.prototype.constructor` is rebound to a throw-on-invoke
 *    sentinel (the same applies to `ProtectedHandler`/`ReadOnlyHandler`
 *    subclasses) so the `new pp.constructor(s)` chain cannot even reach the
 *    real constructor.
 * 3. Every handler trap method (`get`, `set`, `apply`, `construct`, ...)
 *    short-circuits when called on a `this` that is not a registered handler
 *    (i.e., has no entry in `handlerToObject`). This defuses attempts to call
 *    `pp.set.call(forgedHandler, ...)` or `Object.setPrototypeOf({}, pp)`
 *    tricks that bypass construction entirely.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

// Shared prelude: harvest the BaseHandler instance `p` via util.inspect showProxy.
const PRELUDE = `
	const obj = {
		subarray: Buffer.prototype.inspect,
		slice: Buffer.prototype.slice,
		hexSlice:()=>''
	};
	let p;
	obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
		if (this.seen?.[1]?.get) { p = this.seen[1]; }
		return a;
	}});
	if (!p) throw new Error('PRELUDE_NO_HANDLER');
	const pp = Object.getPrototypeOf(p); // BaseHandler.prototype
`;

function runBlocked(label, body) {
	const vm = new VM();
	let result, thrown = null;
	try {
		result = vm.run(PRELUDE + body);
	} catch (e) {
		thrown = e;
	}
	// Valid outcomes:
	//   'BLOCKED'    — attack path threw inside the sandbox (caught in user try/catch)
	//   'NO_ESCAPE'  — attack completed but failed to establish the cross-realm channel
	// Any 'ESCAPE...' string means the exploit landed.
	if (thrown) return; // bridge-level throw counts as blocked
	assert.ok(
		result === 'BLOCKED' || result === 'NO_ESCAPE',
		`[${label}] expected BLOCKED or NO_ESCAPE, got: ${JSON.stringify(result)}`,
	);
}

describe('GHSA-v37h-5mfm-c47c (handler class reconstruction escape)', () => {

	// Variant 1 — canonical PoC from the advisory.
	it('blocks canonical new pp.constructor(s).set(...) chain', () => {
		runBlocked('canonical-new', `
			try {
				const s = {__proto__: null};
				const inst = new pp.constructor(s);
				inst.set(null, 'obj', s);
				if (s.obj === s) { 'ESCAPE:alias' }
				else if (typeof s.obj !== 'undefined') { 'ESCAPE:wrote:' + typeof s.obj }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 2 — Reflect.construct without 'new' keyword.
	it('blocks Reflect.construct(pp.constructor, [s])', () => {
		runBlocked('reflect-construct', `
			try {
				const s = {__proto__: null};
				const inst = Reflect.construct(pp.constructor, [s]);
				inst.set(null, 'obj', s);
				if (typeof s.obj !== 'undefined') { 'ESCAPE:reflect' }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 3 — Reflect.construct with a different newTarget to confuse prototype resolution.
	it('blocks Reflect.construct with substituted newTarget', () => {
		runBlocked('reflect-construct-newtarget', `
			try {
				const s = {__proto__: null};
				function Alt() {}
				const inst = Reflect.construct(pp.constructor, [s], Alt);
				inst.set(null, 'obj', s);
				if (typeof s.obj !== 'undefined') { 'ESCAPE:newtarget' }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 4 — class extension of the handler class.
	it('blocks class extends pp.constructor { constructor(o){super(o)} }', () => {
		runBlocked('class-extends', `
			try {
				const s = {__proto__: null};
				const Ctor = pp.constructor;
				let Derived;
				try { Derived = eval('class X extends Ctor { constructor(o){super(o);} }; X'); } catch(e) {}
				if (!Derived) { 'BLOCKED' }
				else {
					const inst = new Derived(s);
					inst.set(null, 'obj', s);
					if (typeof s.obj !== 'undefined') { 'ESCAPE:subclass' }
					else { 'NO_ESCAPE' }
				}
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 5 — setPrototypeOf + direct trap invocation (no construction).
	it('blocks Object.setPrototypeOf({}, pp) + set/get trap invocation', () => {
		runBlocked('setproto-inherit', `
			try {
				const s = {__proto__: null};
				const fake = {};
				Object.setPrototypeOf(fake, pp);
				// Attempt to invoke inherited trap methods with a forged 'this'.
				let wrote = false;
				try { fake.set(null, 'obj', s); wrote = true; } catch (e) {}
				try { fake.get(null, 'x'); } catch (e) {}
				if (wrote && typeof s.obj !== 'undefined') { 'ESCAPE:setproto' }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 6 — constructor.call on a manually prototyped object.
	it('blocks pp.constructor.call(Object.create(pp), s)', () => {
		runBlocked('ctor-call-as-function', `
			try {
				const s = {__proto__: null};
				const forged = Object.create(pp);
				let built = null;
				try { built = pp.constructor.call(forged, s); } catch(e) {}
				if (!built && !forged.isProxy) { /* try using forged directly */ }
				// Try to drive trap methods on the manually prototyped object.
				try { forged.set(null, 'obj', s); } catch (e) {}
				if (typeof s.obj !== 'undefined') { 'ESCAPE:ctor-call' }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 7 — direct method call on a forged handler state (no construction at all).
	it('blocks pp.set.call(forgedHandler, null, k, v)', () => {
		runBlocked('direct-method-call', `
			try {
				const s = {__proto__: null};
				const forged = {};
				Object.setPrototypeOf(forged, pp);
				let threw = false;
				try { pp.set.call(forged, null, 'obj', s); } catch (e) { threw = true; }
				try { pp.get.call(forged, null, 'constructor'); } catch (e) {}
				if (!threw && typeof s.obj !== 'undefined') { 'ESCAPE:method-this' }
				else { 'NO_ESCAPE' }
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 8 — reach BaseHandler via ProtectedHandler.prototype.constructor.__proto__.constructor
	// (only applicable if a ProtectedHandler is reachable; we approximate by using any reachable
	// handler and walking up the chain).
	it('blocks reaching parent class via prototype chain walk', () => {
		runBlocked('parent-via-proto-chain', `
			try {
				const s = {__proto__: null};
				// walk up until we find something constructible
				let cur = pp;
				let hit = null;
				for (let i = 0; i < 10 && cur; i++) {
					try {
						if (typeof cur.constructor === 'function') {
							hit = new cur.constructor(s);
							break;
						}
					} catch (e) {}
					cur = Object.getPrototypeOf(cur);
				}
				if (!hit) { 'NO_ESCAPE' }
				else {
					try { hit.set(null, 'obj', s); } catch (e) {}
					if (typeof s.obj !== 'undefined') { 'ESCAPE:chain-walk' }
					else { 'NO_ESCAPE' }
				}
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 9 — getPrototypeOf on a ProtectedHandler/ReadOnlyHandler instance.
	// Since we can only reach one class via showProxy (BaseHandler for the sandbox obj),
	// we assert that all handler classes share the same construction-token rule by
	// attempting to construct via the raw getPrototypeOf of whatever handler we have.
	it('blocks construction from any reachable handler class prototype', () => {
		runBlocked('any-handler-proto', `
			try {
				const s = {__proto__: null};
				let target = pp;
				let built = null;
				// Try each prototype level's constructor
				for (let depth = 0; depth < 5 && target; depth++) {
					const C = target.constructor;
					if (typeof C === 'function') {
						try {
							built = new C(s);
							break;
						} catch (e) {}
						try {
							built = Reflect.construct(C, [s]);
							break;
						} catch (e) {}
					}
					target = Object.getPrototypeOf(target);
				}
				if (!built) { 'NO_ESCAPE' }
				else {
					try { built.set(null, 'obj', s); } catch (e) {}
					if (typeof s.obj !== 'undefined') { 'ESCAPE:any-proto' }
					else { 'NO_ESCAPE' }
				}
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Variant 10 — brute-force prototype chain walking looking for any constructible.
	it('blocks brute-force prototype chain constructor discovery', () => {
		runBlocked('brute-force-chain', `
			try {
				const s = {__proto__: null};
				const seen = new Set();
				let cur = p;
				let built = null;
				for (let i = 0; i < 20 && cur && !seen.has(cur); i++) {
					seen.add(cur);
					const C = cur.constructor;
					if (typeof C === 'function' && C !== Object) {
						try { built = new C(s); break; } catch (e) {}
						try { built = Reflect.construct(C, [s]); break; } catch (e) {}
					}
					cur = Object.getPrototypeOf(cur);
				}
				if (!built) { 'NO_ESCAPE' }
				else {
					try { built.set(null, 'obj', s); } catch (e) {}
					try { built.get(null, 'x'); } catch (e) {}
					if (typeof s.obj !== 'undefined') { 'ESCAPE:brute' }
					else { 'NO_ESCAPE' }
				}
			} catch (e) { 'BLOCKED' }
		`);
	});

	// Final — the full RCE chain from the advisory, with the actual Function-ctor step
	// asserted to fail. This is the "full exploit" integration test.
	it('blocks full RCE chain from advisory', () => {
		const vm = new VM();
		let thrown = null;
		let leaked = false;
		try {
			leaked = vm.run(`
				try {
					const obj = {
						subarray: Buffer.prototype.inspect,
						slice: Buffer.prototype.slice,
						hexSlice:()=>''
					};
					let p;
					obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
						if (this.seen?.[1]?.get){p=this.seen[1];}
						return a;
					}});
					const pp = Object.getPrototypeOf(p);
					const s = {__proto__: null};
					new pp.constructor(s).set(null, 'obj', s);
					s.obj.x = obj.slice;
					// If we got here, attacker has cross-realm channel. Check if Function
					// constructor is reachable.
					typeof s.x.constructor === 'function';
				} catch (e) { false }
			`);
		} catch (e) {
			thrown = e;
		}
		assert.strictEqual(leaked, false, 'full RCE chain must be blocked');
	});
});
