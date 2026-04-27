/**
 * GHSA-55hx-c926-fr95 -- structural leak: host-promise callback rejection
 * value reaches sandbox without sanitization.
 *
 * The previous AggregateError recursion fix closes the canonical PoCs but
 * does NOT close the underlying primitive. When an embedder exposes a host-realm async
 * function via `{sandbox: {f: async () => {}}}`, calling `f()` returns a
 * host-realm Promise. The bridge wraps it as a sandbox proxy whose
 * `.then` / `.catch` / `.finally` reads return the *host-realm* methods
 * (proxy-wrapped). When sandbox calls those, host machinery schedules
 * the callback — bypassing the sandbox-side `globalPromise.prototype.then`
 * override that would normally route the rejection value through
 * `handleException`. The sandbox catch handler therefore receives a raw
 * host SuppressedError whose `.error.constructor.constructor` is host
 * `Function`, giving RCE.
 *
 * This file pins the structural invariant: a sandbox catch handler
 * receiving a rejected promise -- regardless of whether the promise
 * originated in the host or sandbox realm -- must NEVER see a value
 * whose `.error.constructor.constructor` resolves to the host Function
 * constructor (or any host built-in constructor).
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

function escapeAttempt(setupAndPayload, sandbox = {}) {
	const sentinelKey = '__GHSA_55HX_PWNED_' + Math.random().toString(36).slice(2);
	global[sentinelKey] = false;
	const vm = new VM({
		sandbox: {
			...sandbox,
			__sentinelKey: sentinelKey,
			__pwn: () => { global[sentinelKey] = true; }
		},
		timeout: 2000
	});
	try {
		vm.run(setupAndPayload);
	} catch (_) { /* swallow sync throws — we're checking for async escape */ }
	return new Promise((resolve) => {
		setTimeout(() => {
			const escaped = global[sentinelKey] === true;
			delete global[sentinelKey];
			resolve(escaped);
		}, 400);
	});
}

describe('GHSA-55hx-c926-fr95 (structural leak: host-promise rejection callbacks bypass sanitization)', function () {
	this.timeout(5000);

	it('exposed async function .catch receives sanitized error (cannot reach host Function)', async function () {
		const escaped = await escapeAttempt(`
			f().finally(() => {
				obj = {[Symbol.dispose]() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}};
				eval("{using a = obj;throw null;}");
			}).catch(e => {
				try {
					const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			});
		`, { f: async () => {} });
		assert.strictEqual(escaped, false,
			'PoC succeeded — host Function reached via exposed-async-function host-Promise rejection chain');
	});

	it('exposed async function .then(_, onRejected) receives sanitized error', async function () {
		const escaped = await escapeAttempt(`
			f().then(undefined, () => 'never reached')
				.then(() => {
					obj = {[Symbol.dispose]() {
						const e = new Error();
						e.name = Symbol();
						return e.stack;
					}};
					eval("{using a = obj;throw null;}");
				})
				.then(undefined, e => {
					try {
						const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
						if (typeof F === 'function') {
							const proc = F("return process")();
							if (proc && typeof proc.pid === 'number') __pwn();
						}
					} catch (_) {}
				});
		`, { f: async () => {} });
		assert.strictEqual(escaped, false,
			'.then(_, onRejected) on host promise must sanitize rejection value');
	});

	it('host-rejected promise .catch receives sanitized error', async function () {
		const escaped = await escapeAttempt(`
			rejectingF().catch(e => {
				try {
					const F = e && e.constructor && e.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			});
		`, {
			rejectingF: async () => {
				// A real host function that rejects with a host-realm error after a microtask hop.
				const e = new Error('host realm error');
				throw e;
			}
		});
		assert.strictEqual(escaped, false,
			'host-rejected promise .catch must sanitize rejection value');
	});

	it('exposed sync function returning host promise does not bypass sanitization', async function () {
		const escaped = await escapeAttempt(`
			syncF().finally(() => {
				obj = {[Symbol.dispose]() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}};
				eval("{using a = obj;throw null;}");
			}).catch(e => {
				try {
					const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			});
		`, { syncF: () => Promise.resolve() });
		assert.strictEqual(escaped, false,
			'sync host function returning host promise must equally sanitize rejection');
	});

	it('chained .then().then().catch() through host promise still sanitizes', async function () {
		const escaped = await escapeAttempt(`
			f()
				.then(() => 'first')
				.then(() => {
					obj = {[Symbol.dispose]() {
						const e = new Error();
						e.name = Symbol();
						return e.stack;
					}};
					eval("{using a = obj;throw null;}");
				})
				.catch(e => {
					try {
						const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
						if (typeof F === 'function') {
							const proc = F("return process")();
							if (proc && typeof proc.pid === 'number') __pwn();
						}
					} catch (_) {}
				});
		`, { f: async () => {} });
		assert.strictEqual(escaped, false,
			'multi-link chain on host promise must sanitize at the catch terminus');
	});

	it('Promise.race / Promise.any with host contributors sanitizes rejection', async function () {
		const escaped = await escapeAttempt(`
			Promise.any([f()]).then(() => {
				obj = {[Symbol.dispose]() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}};
				eval("{using a = obj;throw null;}");
			}).catch(e => {
				try {
					const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			});
		`, { f: async () => {} });
		assert.strictEqual(escaped, false,
			'Promise.any/race with host contributors must produce sanitized errors');
	});
});
