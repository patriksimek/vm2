/**
 * GHSA-88hf-g992-jg85 — NodeVM sandbox escape via host `__proto__` getter
 * prototype-chain climb → host builtin prototype poisoning → RCE.
 *
 * ## Vulnerability class
 * A sibling of GHSA-v6mx-mf47-r5wg / GHSA-cfcw-xp6x-25gj. Those closed the
 * host `__proto__` *setter* (a prototype MUTATOR). This report uses the host
 * `__proto__` *getter*, which only reads, so it was never classified as
 * dangerous and stayed reachable via the same `connect()`-routed primitive:
 *
 *     const gP = Buffer.call.call(__lookupGetter__, 67, '__proto__');
 *
 * `gP` is the raw host `Object.prototype.__proto__` getter. `gP.call(x)`
 * returns the raw host `[[Prototype]]` of any host object `x`, letting the
 * sandbox WALK UP an arbitrary host prototype chain:
 *
 *     console._stdout  (NodeVM default `console: 'inherit'`)
 *       -> Socket -> Duplex -> Readable -> Stream -> EventEmitter.prototype
 *
 * `EventEmitter.prototype` is a Node builtin prototype, NOT a JS intrinsic, so
 * it is absent from `protectedHostObjects`; its bridge wrapper is a plain
 * `BaseHandler` whose `set` trap forwards writes to the raw host object. The
 * sandbox overwrites host `EventEmitter.prototype.emit` with a sandbox
 * function. `process` is an `EventEmitter`; the next host-side `process.emit`
 * runs the sandbox function with `this === host process`, and
 * `this.getBuiltinModule('child_process').execSync(...)` executes on the host.
 * Also bypasses `--disallow-code-generation-from-strings`.
 *
 * ## Fix (two independent layers, both in lib/bridge.js)
 * 1. READ side — the raw host proto-readers (`Object.prototype.__proto__`
 *    getter, `Object.getPrototypeOf`, `Reflect.getPrototypeOf`) are refused at
 *    the delivery chokepoints (`thisFromOtherWithFactory` / `thisEnsureThis` /
 *    `thisFromOtherForThrow`) and the apply trap, collapsing to a non-callable
 *    `emptyFrozenObject`. The sandbox can no longer hold the raw reader to
 *    climb host chains. Legitimate `Object.getPrototypeOf` on a bridge proxy
 *    still works via the `getPrototypeOf` trap (flattened wrapped proto).
 * 2. WRITE side (defense-in-depth) — host `[[Prototype]]` objects are marked at
 *    delivery (`looksLikeHostPrototype`); `BaseHandler.set` / `defineProperty`
 *    divert sandbox FUNCTION / accessor writes off marked prototypes onto the
 *    sandbox-side proxy target, so no callable can be planted on a shared host
 *    prototype even if some future read path reaches one. Leaf host objects are
 *    never marked, preserving the embedder write contract.
 *
 * ## Sound oracle & test safety
 * The escape mutates the GLOBAL host `EventEmitter.prototype.emit`, which also
 * drives the mocha runner. If the mutation ever lands, leaving it in place for
 * one event-loop tick corrupts the test process. So each attempt snapshots the
 * pristine `emit` descriptor, runs the PoC, then — SYNCHRONOUSLY, before
 * returning control to mocha — detects whether the shared host prototype was
 * mutated (the sound escape signal: the sandbox reached and wrote it) and
 * restores the pristine descriptor. `process.pid` / `[object process]` are NOT
 * used — they are identical across realms and would be unsound.
 */

'use strict';

const assert = require('assert');
const { NodeVM } = require('../../../lib/main.js');
const EventEmitter = require('events').EventEmitter;

// Snapshot / mutation-detect / restore, all synchronous — no host emit happens
// between the sandbox write and the restore, so the runner is never corrupted,
// even on the UNPATCHED tree where the escape lands (the test then fails rather
// than hanging). Returns true iff the sandbox mutated the shared host emit slot.
function attemptEscape(pocBody, vmOpts) {
	const pristineDesc = Object.getOwnPropertyDescriptor(EventEmitter.prototype, 'emit');
	const pristineEmit = pristineDesc && pristineDesc.value;
	let mutated = false;
	try {
		const vm = new NodeVM(vmOpts);
		vm.run(pocBody);
	} catch (e) {
		/* a bridge-level throw is a blocked escape */
	} finally {
		const nowDesc = Object.getOwnPropertyDescriptor(EventEmitter.prototype, 'emit');
		// Mutated iff the emit slot changed shape or value (plain-assignment or
		// accessor-injection vectors both surface here).
		mutated =
			!nowDesc ||
			nowDesc.get !== (pristineDesc && pristineDesc.get) ||
			nowDesc.set !== (pristineDesc && pristineDesc.set) ||
			nowDesc.value !== pristineEmit;
		if (mutated) {
			// Restore the pristine slot immediately so the runner is healthy again.
			Object.defineProperty(EventEmitter.prototype, 'emit', pristineDesc);
		}
	}
	return mutated;
}

// Canonical PoC: climb console._stdout's host proto chain to EventEmitter.prototype.
const POC = `
	const gP = Buffer.call.call(__lookupGetter__, 67, '__proto__');
	let p = console._stdout;
	while (p && p.pipe) { p = gP.call(p); }
	p.emit = function () { try { this.__GHSA_88hf_pwned = 'HOST'; } catch (e) {} };
`;

// Same climb, but the poisoning write is an Object.defineProperty value.
const POC_DEFINEPROPERTY = `
	const gP = Buffer.call.call(__lookupGetter__, 67, '__proto__');
	let p = console._stdout;
	while (p && p.pipe) { p = gP.call(p); }
	Object.defineProperty(p, 'emit', { value: function () {
		try { this.__GHSA_88hf_pwned = 'HOST'; } catch (e) {}
	}, writable: true, configurable: true });
`;

// Same climb, poisoning write is an accessor descriptor (getter returns the fn).
const POC_ACCESSOR = `
	const gP = Buffer.call.call(__lookupGetter__, 67, '__proto__');
	let p = console._stdout;
	while (p && p.pipe) { p = gP.call(p); }
	Object.defineProperty(p, 'emit', { configurable: true, get: function () {
		return function () { try { this.__GHSA_88hf_pwned = 'HOST'; } catch (e) {} };
	} });
`;

// Stacked call-indirection around the getter (the GHSA-cfcw bypass class): the
// one-layer apply-trap peel cannot reach the underlying reader.
const POC_STACKED = `
	const call = Buffer.call.call;
	const gP = call.call(call, __lookupGetter__, 67, '__proto__');
	let p = console._stdout;
	while (p && p.pipe) { p = call.call(gP, p); }
	p.emit = function () { try { this.__GHSA_88hf_pwned = 'HOST'; } catch (e) {} };
`;

describe('GHSA-88hf-g992-jg85 (host __proto__ getter climb → host prototype poisoning)', function () {
	it('blocks the canonical PoC (default NodeVM, console:inherit)', function () {
		assert.strictEqual(attemptEscape(POC), false, 'sandbox poisoned host EventEmitter.prototype.emit');
	});

	it('blocks the PoC with an explicit console:inherit option', function () {
		assert.strictEqual(attemptEscape(POC, { console: 'inherit' }), false, 'sandbox escaped via console:inherit stream chain');
	});

	it('blocks the Object.defineProperty(value) poisoning vector', function () {
		assert.strictEqual(attemptEscape(POC_DEFINEPROPERTY), false, 'defineProperty value write reached the host prototype');
	});

	it('blocks the accessor-descriptor poisoning vector', function () {
		assert.strictEqual(attemptEscape(POC_ACCESSOR), false, 'accessor injection reached the host prototype');
	});

	it('blocks the stacked call-indirection climb variant (GHSA-cfcw bypass class)', function () {
		assert.strictEqual(attemptEscape(POC_STACKED), false, 'stacked-indirection climb reached the host prototype');
	});

	it('the raw host __proto__ getter cannot be used to install a callable on a host prototype', function () {
		// Variant independent of the console stream: the climb primitive itself
		// must not yield a raw/writable host prototype.
		const vm = new NodeVM();
		const leaked = vm.run(`
			const gP = Buffer.call.call(__lookupGetter__, 67, '__proto__');
			let reached = null;
			try {
				let p = Buffer;
				for (let i = 0; i < 20 && p; i++) { p = gP.call(p); }
				reached = p;
			} catch (e) { reached = 'threw:' + e.message; }
			let installed = false;
			try {
				if (reached && typeof reached === 'object') {
					reached.__GHSA_88hf_probe = function () { return 'x'; };
					installed = true;
				}
			} catch (e) {}
			module.exports = { installed };
		`);
		assert.strictEqual(leaked.installed, false, 'sandbox installed a function onto a raw host prototype');
		assert.strictEqual(Object.prototype.__GHSA_88hf_probe, undefined, 'host Object.prototype was poisoned');
		delete Object.prototype.__GHSA_88hf_probe;
	});

	it('legitimate Object.getPrototypeOf on a host proxy still works (not over-blocked)', function () {
		const vm = new NodeVM({ sandbox: { hostObj: { a: 1 } } });
		// getPrototypeOf on a bridged host object must return a usable (wrapped)
		// prototype, not throw and not the denied sentinel — the fix denies only
		// the RAW extracted reader, not the trap-mediated read.
		const ok = vm.run(`
			const proto = Object.getPrototypeOf(hostObj);
			module.exports = (proto !== null && typeof proto === 'object' && typeof proto.hasOwnProperty === 'function');
		`);
		assert.strictEqual(ok, true, 'Object.getPrototypeOf on a host proxy was over-blocked');
	});

	// ---- Embedder-contract guards: the fix must NOT break documented behavior ----

	it('preserves the contract: sandbox may still set DATA properties on an exposed host object', function () {
		const hostObj = {};
		const vm = new NodeVM({ sandbox: { hostObj } });
		vm.run(`hostObj.tag = 'from-sandbox'; hostObj.count = 42;`);
		assert.strictEqual(hostObj.tag, 'from-sandbox', 'sandbox data-string write did not reach the exposed host object');
		assert.strictEqual(hostObj.count, 42, 'sandbox data-number write did not reach the exposed host object');
	});

	it('preserves the contract: sandbox may still set a FUNCTION on an exposed leaf host object', function () {
		// A leaf object (not a prototype) is never marked, so a function write
		// still reaches it — matching test/vm.js `freeze, protect > without freeze`.
		const hostObj = {};
		const vm = new NodeVM({ sandbox: { hostObj } });
		vm.run(`hostObj.fn = function () { return 'sandbox-fn'; };`);
		assert.strictEqual(typeof hostObj.fn, 'function', 'sandbox function write to a leaf host object was wrongly diverted');
		assert.strictEqual(hostObj.fn(), 'sandbox-fn', 'sandbox function on leaf host object did not run');
	});

	it('preserves the contract: sandbox event listeners registered via emitter.on still fire (apply path)', function () {
		const ee = new EventEmitter();
		const vm = new NodeVM({ sandbox: { ee, counter: { n: 0 } } });
		vm.run(`
			ee.on('ping', function () { counter.n++; });
			ee.emit('ping');
			ee.emit('ping');
		`);
		assert.strictEqual(vm.sandbox.counter.n, 2, 'sandbox listener registered via .on did not fire');
	});
});
