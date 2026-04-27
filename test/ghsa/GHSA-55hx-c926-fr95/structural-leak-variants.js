/**
 * GHSA-55hx-c926-fr95 -- Structural-leak variant attack patterns.
 *
 * Variants of the canonical XmiliaH PoC that route the host-realm
 * rejection value to sandbox catch handlers through paths that a fix
 * focused only on `.then`/`.catch`/`.finally` interception might miss.
 * The structural fix in `lib/bridge.js` (apply-trap identity match
 * against cached host `Promise.prototype.{then,catch,finally}`) closes
 * all four — verified by running these against the patched build.
 *
 *   v1 - Promise.allSettled extracting rejected entry from result array
 *   v2 - Synchronous transformer-instrumented try/catch around using+eval
 *   v3 - await on a host promise inside a sandbox async function
 *   v4 - AggregateError contributing entry with arbitrary host taint shape
 *
 * The six canonical assertions live in `structural-leak.js`. This file
 * extends coverage to the variant paths surfaced during the multi-angle
 * red-team probing of the apply-trap structural fix.
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
	} catch (_) { /* swallow sync throws — checking for async escape */ }
	return new Promise(resolve => {
		setTimeout(() => {
			const escaped = global[sentinelKey] === true;
			delete global[sentinelKey];
			resolve(escaped);
		}, 400);
	});
}

describe('GHSA-55hx-c926-fr95 (structural-leak variant attack patterns)', function () {
	this.timeout(5000);

	it('v1: Promise.allSettled extracts rejected entry without sanitization', async function () {
		const escaped = await escapeAttempt(`
			Promise.allSettled([f().finally(() => {
				obj = {[Symbol.dispose]() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}};
				eval("{using a = obj;throw null;}");
			})]).then(results => {
				try {
					const reason = results && results[0] && results[0].reason;
					const F = reason && reason.error && reason.error.constructor && reason.error.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			});
		`, { f: async () => {} });
		assert.strictEqual(escaped, false, 'v1: Promise.allSettled rejected.reason must be sanitized');
	});

	it('v2: synchronous transformer-instrumented try/catch around using+eval', async function () {
		const escaped = await escapeAttempt(`
			try {
				obj = {[Symbol.dispose]() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}};
				eval("{using a = obj;throw null;}");
			} catch (e) {
				try {
					const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
					if (typeof F === 'function') {
						const proc = F("return process")();
						if (proc && typeof proc.pid === 'number') __pwn();
					}
				} catch (_) {}
			}
		`);
		assert.strictEqual(escaped, false,
			'v2: synchronous try/catch around using+eval must sanitize via handleException');
	});

	it('v3: await on a host promise inside a sandbox async function', async function () {
		const escaped = await escapeAttempt(`
			(async () => {
				try {
					await f().finally(() => {
						obj = {[Symbol.dispose]() {
							const e = new Error();
							e.name = Symbol();
							return e.stack;
						}};
						eval("{using a = obj;throw null;}");
					});
				} catch (e) {
					try {
						const F = e && e.error && e.error.constructor && e.error.constructor.constructor;
						if (typeof F === 'function') {
							const proc = F("return process")();
							if (proc && typeof proc.pid === 'number') __pwn();
						}
					} catch (_) {}
				}
			})();
		`, { f: async () => {} });
		assert.strictEqual(escaped, false,
			'v3: await on a host promise inside a sandbox async function must sanitize');
	});

	it('v4: AggregateError contributing entry that is itself host-tainted', async function () {
		const escaped = await escapeAttempt(`
			Promise.any([
				f().finally(() => {
					obj = {[Symbol.dispose]() {
						const e = new Error();
						e.name = Symbol();
						return e.stack;
					}};
					eval("{using a = obj;throw null;}");
				}),
				rejectingF()
			]).catch(agg => {
				try {
					for (let i = 0; i < (agg && agg.errors && agg.errors.length) || 0; i++) {
						const entry = agg.errors[i];
						const target = (entry && entry.error) || entry;
						const F = target && target.constructor && target.constructor.constructor;
						if (typeof F === 'function') {
							try {
								const proc = F("return process")();
								if (proc && typeof proc.pid === 'number') { __pwn(); break; }
							} catch (_) {}
						}
					}
				} catch (_) {}
			});
		`, {
			f: async () => {},
			rejectingF: async () => { throw new Error('host realm rejection'); }
		});
		assert.strictEqual(escaped, false,
			'v4: AggregateError.errors[] contributing entries must be deeply sanitized');
	});
});
