/**
 * GHSA-r4fx-v8hh-22mv — timeout bypass via FinalizationRegistry cleanup callback
 *
 * ## Vulnerability
 * The `timeout` option only bounds the synchronous body of `run()` (V8's
 * TerminateExecution unblocks the running call and nothing else). A
 * `FinalizationRegistry` cleanup callback is invoked by the garbage collector at
 * an unpredictable later time — AFTER `run()` has returned — so a busy-loop
 * inside it runs entirely outside any timeout accounting and blocks the host
 * event loop for an arbitrary duration. Timers and queueMicrotask are already
 * withheld from the VM sandbox, and Promise continuations (the same class) are
 * closed by `allowAsync: false`; FinalizationRegistry was the remaining
 * out-of-band executor, and `allowAsync: false` does NOT close it.
 *
 * ## Fix
 * Remove `FinalizationRegistry` and `WeakRef` from the default sandbox globals
 * (lib/setup-sandbox.js), the same way timers are withheld. NodeVM inherits the
 * removal. Neither constructor has literal syntax, so once the global binding is
 * gone the sandbox cannot reconstruct it.
 *
 * Sound oracle: the constructor is unreachable inside the sandbox (typeof
 * 'undefined', and no prototype/getOwnPropertyNames recovery path), so the
 * out-of-band callback can never be registered in the first place.
 */

'use strict';

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

describe('GHSA-r4fx-v8hh-22mv — FinalizationRegistry/WeakRef timeout-bypass removal', () => {
	it('FinalizationRegistry and WeakRef are not exposed in a default VM', () => {
		const vm = new VM();
		assert.strictEqual(vm.run('typeof FinalizationRegistry'), 'undefined');
		assert.strictEqual(vm.run('typeof WeakRef'), 'undefined');
		assert.strictEqual(vm.run('typeof globalThis.FinalizationRegistry'), 'undefined');
		assert.strictEqual(vm.run('typeof globalThis.WeakRef'), 'undefined');
	});

	it('FinalizationRegistry and WeakRef are not exposed in a default NodeVM', () => {
		const vm = new NodeVM();
		assert.strictEqual(vm.run('module.exports = typeof FinalizationRegistry', 'x.js'), 'undefined');
		assert.strictEqual(vm.run('module.exports = typeof WeakRef', 'x.js'), 'undefined');
	});

	it('the timeout-bypass PoC can no longer register an out-of-band callback', () => {
		// Before the fix this registered a GC callback that blocked the host event
		// loop long after run() returned; now the constructor is gone, so the very
		// first line throws synchronously inside run() (bounded by the sandbox).
		const vm = new VM({ timeout: 500 });
		assert.throws(() => vm.run(`
			let target = {};
			const registry = new FinalizationRegistry(() => {});
			registry.register(target, 'x');
			target = null;
		`), /FinalizationRegistry is not defined/);
	});

	it('the constructors cannot be recovered from within the sandbox', () => {
		const vm = new VM();
		const recovered = vm.run(`
			const names = Object.getOwnPropertyNames(globalThis);
			const probes = {
				inOwnNames: names.includes('FinalizationRegistry') || names.includes('WeakRef'),
				// A surviving sibling weak collection must not leak a route back to
				// the removed constructors via its constructor/prototype chain.
				viaWeakMap: (() => {
					try {
						const proto = Object.getPrototypeOf(new WeakMap());
						return typeof proto.constructor.constructor === 'function'
							&& /FinalizationRegistry|WeakRef/.test(String(proto.constructor.constructor));
					} catch (e) { return false; }
				})(),
				reflectGet: typeof Reflect.get(globalThis, 'FinalizationRegistry'),
				// The canonical recovery vector: the Function constructor resolves free
				// identifiers against the sandbox global, which no longer binds them.
				viaFunctionCtor: (() => {
					try { Function('return FinalizationRegistry')(); return 'recovered'; }
					catch (e) { return e.constructor.name; }
				})(),
				viaGeneratorCtor: (() => {
					// A generator function only runs its body on .next(), so force execution.
					try { return (function*(){}).constructor('return WeakRef')().next().value ? 'recovered' : 'empty'; }
					catch (e) { return e.constructor.name; }
				})(),
			};
			probes;
		`);
		assert.strictEqual(recovered.inOwnNames, false, 'removed constructor still enumerable on globalThis');
		assert.strictEqual(recovered.viaWeakMap, false, 'a sibling weak collection leaked the removed constructor');
		assert.strictEqual(recovered.reflectGet, 'undefined', 'Reflect.get recovered the removed constructor');
		assert.strictEqual(recovered.viaFunctionCtor, 'ReferenceError', 'Function constructor recovered FinalizationRegistry');
		assert.strictEqual(recovered.viaGeneratorCtor, 'ReferenceError', 'GeneratorFunction constructor recovered WeakRef');
	});

	it('does not over-block sibling weak collections or Promise', () => {
		// Only FinalizationRegistry/WeakRef are withheld; WeakMap/WeakSet/Promise stay.
		const vm = new VM();
		const out = vm.run(`({
			WeakMap: typeof WeakMap,
			WeakSet: typeof WeakSet,
			Promise: typeof Promise,
			weakMapWorks: (() => { const m = new WeakMap(); const k = {}; m.set(k, 1); return m.get(k); })(),
		})`);
		assert.strictEqual(out.WeakMap, 'function');
		assert.strictEqual(out.WeakSet, 'function');
		assert.strictEqual(out.Promise, 'function');
		assert.strictEqual(out.weakMapWorks, 1);
	});

	// FinalizationRegistry / WeakRef only exist on the host from Node 14.6+; skip
	// the opt-in assertion on older majors where there is nothing to re-expose.
	const hostHasWeakRefApis = typeof FinalizationRegistry === 'function' && typeof WeakRef === 'function';
	(hostHasWeakRefApis ? it : it.skip)('an embedder can still expose them explicitly via the sandbox option', () => {
		// Mirrors the timers story: withheld by default, available on opt-in.
		const vm = new VM({ sandbox: { FinalizationRegistry, WeakRef } });
		assert.strictEqual(vm.run('typeof FinalizationRegistry'), 'function');
		assert.strictEqual(vm.run('typeof WeakRef'), 'function');
	});
});
