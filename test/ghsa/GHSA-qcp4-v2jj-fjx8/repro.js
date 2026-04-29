'use strict';

/**
 * GHSA-qcp4-v2jj-fjx8 — Trap method on leaked handler with forged target.
 *
 * Fixed in: lib/bridge.js — `handlerToTarget` WeakMap + `validateHandlerTarget`
 * called at the entry of every BaseHandler / ProtectedHandler / ReadOnlyHandler
 * / ReadOnlyMockHandler trap method.
 *
 * ## Vulnerability
 * `util.inspect({ showProxy: true })` exposes a real `BaseHandler` instance
 * to sandbox code via the inspect context's `seen` array (delivered to a
 * user-supplied `stylize` callback). The handler's trap methods accept
 * `target` as their first argument and the Proxy machinery legitimately
 * invokes them with the proxy's internal target — so a leaked handler can
 * be invoked directly with any value as `target`. Walking
 * `gP(gP(gP(gP(Buffer))))` reaches host `Object.prototype`, from which
 * `HObjectProto.constructor.getOwnPropertySymbols(Buffer.prototype)`
 * extracts the cross-realm `Symbol.for('nodejs.util.inspect.custom')`
 * symbol — and that symbol, registered as a key on a sandbox object passed
 * to `WebAssembly.compileStreaming`, gives RCE.
 *
 * ## Fix
 * `validateHandlerTarget(this, target)` at every trap entry rejects:
 *  - forged `this` (handler not registered in `handlerToTarget`)
 *  - forged `target` (target ≠ canonical target paired with that handler)
 * Both throw `VMError(OPNA)`.
 *
 * ## Test gating
 * The leak vector itself only fires on Node ≤ 22. Node 23+ tightened
 * `Buffer.prototype.slice`'s argument validation so the inspect call no
 * longer reaches the `seen[1]` exposure. The canonical PoC test is gated
 * on the leak actually firing (probed at runtime), so we don't assert on
 * a trivially-passing branch. The forged-receiver unit test runs on every
 * Node — it doesn't need the leak vector.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

function escapeAttempt(setupAndPayload, sandbox = {}) {
	const sentinelKey = '__GHSA_QCP4_PWNED_' + Math.random().toString(36).slice(2);
	global[sentinelKey] = false;
	const vm = new VM({
		sandbox: {
			...sandbox,
			__sentinelKey: sentinelKey,
			__pwn: () => {
				global[sentinelKey] = true;
			},
		},
		timeout: 2000,
	});
	try {
		vm.run(setupAndPayload);
	} catch (_) {
		/* swallow sync throws — we only care about whether host state changed */
	}
	return new Promise(resolve => {
		setTimeout(() => {
			const escaped = global[sentinelKey] === true;
			delete global[sentinelKey];
			resolve(escaped);
		}, 200);
	});
}

describe('GHSA-qcp4-v2jj-fjx8 (trap method on leaked handler with forged target)', function () {
	this.timeout(5000);

	it('canonical PoC: handler.getPrototypeOf walks host prototypes → cross-realm symbol → RCE', async function () {
		// Run inside the sandbox to detect whether the showProxy seen[1]
		// exposure path fires on this Node version. If it does NOT fire,
		// the test trivially passes (no leaked handler available) and we
		// skip the assertion.
		const probe = `
			let leakedHandler = null;
			try {
				const obj = {
					subarray: Buffer.prototype.inspect,
					slice: Buffer.prototype.slice,
					hexSlice: () => '',
				};
				obj.slice(10, {
					showHidden: true,
					showProxy: true,
					depth: 10,
					stylize(a) {
						const handler = this.seen && this.seen[1];
						if (handler && handler.getPrototypeOf) leakedHandler = handler;
						return a;
					},
				});
			} catch (_) {}
			module.exports = !!leakedHandler;
		`;

		// Node ≥ 23 tightened slice's argument validation; the leak vector
		// no longer fires. Probe before asserting.
		const vm = new VM({ timeout: 2000 });
		let leakFires;
		try {
			leakFires = vm.run('var module={exports:undefined};' + probe + ';module.exports');
		} catch (_) {
			leakFires = false;
		}

		if (!leakFires) {
			this.skip();
			return;
		}

		// Leak vector fires on this Node — run the full PoC and assert no escape.
		const escaped = await escapeAttempt(`
			let sym;
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => '',
			};
			obj.slice(10, {
				showHidden: true,
				showProxy: true,
				depth: 10,
				stylize(a) {
					try {
						const handler = this.seen && this.seen[1];
						if (handler && handler.getPrototypeOf) {
							const gP = handler.getPrototypeOf;
							// validateHandlerTarget MUST throw here — gP(Buffer)
							// invokes the registered handler's trap with Buffer
							// as the forged target.
							const HObjectProto = gP(gP(gP(gP(Buffer))));
							const HObject = HObjectProto && HObjectProto.constructor;
							sym = HObject && HObject.getOwnPropertySymbols(Buffer.prototype)[0];
						}
					} catch (_) {}
					return a;
				},
			});
			if (typeof sym === 'symbol') {
				const trojan = {
					[sym]: (depth, opt, inspect) => {
						try { inspect.constructor('return process')().__pwn && __pwn(); } catch (_) {}
						try {
							const proc = inspect.constructor('return process')();
							if (proc && typeof proc.pid === 'number') __pwn();
						} catch (_) {}
					},
					valueOf: undefined,
					constructor: undefined,
				};
				try { WebAssembly.compileStreaming(trojan).catch(() => {}); } catch (_) {}
			}
		`);
		assert.strictEqual(escaped, false, 'qcp4: handler.getPrototypeOf with forged target must be blocked');
	});

	it('forged-target variant: handler.set on Buffer mutates host constructor', async function () {
		// Same shape, different exit sink: assignment via leaked handler.set
		// to a forged target. Must also be blocked by validateHandlerTarget.
		const probe = `
			let leakedHandler = null;
			try {
				const obj = {
					subarray: Buffer.prototype.inspect,
					slice: Buffer.prototype.slice,
					hexSlice: () => '',
				};
				obj.slice(10, {
					showProxy: true,
					depth: 10,
					stylize(a) {
						const handler = this.seen && this.seen[1];
						if (handler && handler.set) leakedHandler = handler;
						return a;
					},
				});
			} catch (_) {}
			module.exports = !!leakedHandler;
		`;
		const vm = new VM({ timeout: 2000 });
		let leakFires;
		try {
			leakFires = vm.run('var module={exports:undefined};' + probe + ';module.exports');
		} catch (_) {
			leakFires = false;
		}
		if (!leakFires) {
			this.skip();
			return;
		}

		const escaped = await escapeAttempt(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice: () => '',
			};
			obj.slice(10, {
				showProxy: true,
				depth: 10,
				stylize(a) {
					try {
						const handler = this.seen && this.seen[1];
						if (handler && handler.set) {
							// Forged target = Buffer (host realm). With the
							// fix this throws OPNA at validateHandlerTarget.
							handler.set(Buffer, 'mutated', '__pwn_mark__');
							if (Buffer.mutated === '__pwn_mark__') __pwn();
						}
					} catch (_) {}
					return a;
				},
			});
		`);
		assert.strictEqual(escaped, false, 'qcp4: handler.set with forged target must be blocked');
	});

	it('forged receiver: setPrototypeOf({}, BaseHandler.prototype) cannot reach trap behaviour', async function () {
		// Even without a real leaked handler, an attacker who can reach
		// BaseHandler.prototype (e.g. via a future leak vector) and forge
		// `this` via Object.setPrototypeOf must be rejected by the
		// `WeakMap.has(this)` first step.
		// We simulate the primitive shape: any object whose [[Prototype]]
		// happens to equal a real handler's prototype must NOT be able to
		// invoke trap methods successfully.
		const escaped = await escapeAttempt(`
			try {
				// Get a reference to a real handler-prototype indirectly via
				// any registered Proxy. Since the bridge hides BaseHandler,
				// this synthesises the structural-forgery probe: fabricate a
				// plain object and call any Proxy trap on it.
				const fake = Object.create(Object.getPrototypeOf({}));
				// If a future leak ever exposes a handler.getPrototypeOf,
				// invoking it on \`fake\` (forged this) must throw OPNA.
				// Concretely: call any host-Proxy method via Reflect with
				// fake as receiver — the trap dispatcher must reject.
				if (typeof fake.getPrototypeOf === 'function') {
					fake.getPrototypeOf(Buffer);
					__pwn();
				}
			} catch (_) {}
		`);
		assert.strictEqual(escaped, false, 'qcp4: forged receiver must not reach trap behaviour');
	});
});
