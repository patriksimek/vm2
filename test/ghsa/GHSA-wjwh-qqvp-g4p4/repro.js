/**
 * GHSA-wjwh-qqvp-g4p4 (dup: GHSA-m3pp-qgq7-gwm6) — VM sandbox escape via
 * `WebAssembly.compileStreaming` / `instantiateStreaming` Promise-species.
 *
 * ## Vulnerability class
 * Sibling of GHSA-6j2x-vhqr-qr7q (WASM JSPI). `WebAssembly.compileStreaming(x)`
 * and `instantiateStreaming(x)` return a Promise whose `[[Prototype]]` chain
 * crosses into the HOST realm (host `Promise.prototype`), so vm2's sandbox-side
 * `globalPromise.prototype.then/catch` overrides and `resetPromiseSpecies`
 * never run on it. The sandbox installs an attacker `constructor[Symbol.species]`
 * on that promise and calls `p.finally()` (no callback); V8's SpeciesConstructor
 * + native-then path constructs the attacker species with control of the native
 * reaction's resolve/reject, delivering the raw host-realm rejection (a host
 * `TypeError`) to the attacker's reject closure. From there
 * `e.constructor.constructor("return globalThis")()` yields the host global and
 * `process` → RCE. Bypasses `--disallow-code-generation-from-strings`.
 *
 * ## Fix
 * `lib/setup-sandbox.js`: extend the WASM JSPI hardening block to also remove
 * `WebAssembly.compileStreaming` and `WebAssembly.instantiateStreaming`, the two
 * remaining APIs that hand the sandbox a host-realm-proto Promise the bridge
 * cannot interpose on. (They require a `Response`/streaming source the sandbox
 * has no way to obtain anyway, so removal has no legitimate-use cost; the
 * non-streaming `WebAssembly.compile` / `instantiate` remain.)
 *
 * ## Sound oracle
 * The escape is observed HOST-SIDE: the attacker reject closure, if it reaches
 * the host realm, calls a frozen host callback. `process.version` etc. are not
 * used as the trigger — the host callback firing is unambiguous host reach.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const HAS_WASM_STREAMING =
	typeof WebAssembly !== 'undefined' && typeof WebAssembly.compileStreaming === 'function';

const POC = api => `{
	const API = ${JSON.stringify(api)};
	let p = WebAssembly[API](0);
	Object.defineProperty(p, "constructor", { value: { [Symbol.species]: class {
		constructor(executor) {
			executor(() => {}, e => {
				try {
					const g = e.constructor.constructor("return globalThis")();
					if (g && g.process && g.process.version) { __hostEscape(); }
				} catch (err) {}
			});
		}
	} } });
	p.finally();
}`;

describe('GHSA-wjwh-qqvp-g4p4 (WebAssembly.*Streaming Promise-species escape)', function () {
	it('removes WebAssembly.compileStreaming / instantiateStreaming from the sandbox', function () {
		const present = new VM().run(`({
			compileStreaming: typeof (WebAssembly && WebAssembly.compileStreaming),
			instantiateStreaming: typeof (WebAssembly && WebAssembly.instantiateStreaming),
			compile: typeof (WebAssembly && WebAssembly.compile)
		})`);
		assert.strictEqual(present.compileStreaming, 'undefined', 'WebAssembly.compileStreaming still reachable in the sandbox');
		assert.strictEqual(present.instantiateStreaming, 'undefined', 'WebAssembly.instantiateStreaming still reachable in the sandbox');
		// Non-streaming compile stays available (legitimate wasm use is unaffected).
		assert.strictEqual(present.compile, 'function', 'WebAssembly.compile was wrongly removed');
	});

	it.cond('blocks the compileStreaming Promise-species escape', HAS_WASM_STREAMING, function (done) {
		this.timeout(5000);
		let escaped = false;
		const vm = new VM({ timeout: 3000, allowAsync: true });
		vm.freeze(() => { escaped = true; }, '__hostEscape');
		const onUnhandled = () => {};
		process.on('unhandledRejection', onUnhandled);
		try { vm.run(POC('compileStreaming')); } catch (e) { /* throwing on a removed API is a block */ }
		setTimeout(() => {
			process.removeListener('unhandledRejection', onUnhandled);
			assert.strictEqual(escaped, false, 'sandbox reached the host realm via compileStreaming species+finally');
			done();
		}, 800);
	});

	it.cond('blocks the instantiateStreaming Promise-species escape', HAS_WASM_STREAMING, function (done) {
		this.timeout(5000);
		let escaped = false;
		const vm = new VM({ timeout: 3000, allowAsync: true });
		vm.freeze(() => { escaped = true; }, '__hostEscape');
		const onUnhandled = () => {};
		process.on('unhandledRejection', onUnhandled);
		try { vm.run(POC('instantiateStreaming')); } catch (e) { /* block */ }
		setTimeout(() => {
			process.removeListener('unhandledRejection', onUnhandled);
			assert.strictEqual(escaped, false, 'sandbox reached the host realm via instantiateStreaming species+finally');
			done();
		}, 800);
	});
});
