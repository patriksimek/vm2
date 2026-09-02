/**
 * GHSA-6454-5x88-m6jw — host-realm Promise rejection sanitizer bypass via
 * Symbol.species hijack + a missing onRejected handler.
 *
 * When the embedder exposes a host API returning a host-realm Promise, vm2's
 * apply-trap sanitizer (`normalizeHostPromiseCallbacks` -> `wrapPromiseSlot`)
 * wraps the then/catch callback SLOTS so an incoming rejection reason is routed
 * through the m283 rebuild. But `wrapPromiseSlot` only wraps a slot that holds a
 * function. Calling `p.then()` (or `p.then(onFulfilled)`) with NO onRejected
 * leaves the reject slot empty, so V8 substitutes its internal `Thrower`, which
 * re-throws the RAW host rejection into the result capability. By hijacking
 * `p.constructor[Symbol.species]` on the host Promise (the sandbox-side species
 * neutralization from GHSA-27g9 is installed only on the SANDBOX Promise
 * prototype, not a host one), the attacker captures V8's raw resolve/reject
 * closures in the sandbox and receives the untouched host rejection — a live
 * bridge proxy -> host RCE. The symmetric fulfill path (missing onFulfilled ->
 * Identity) leaks a host fulfillment value the same way.
 *
 * These tests assert the escape condition (sandbox obtains a host-pivotable
 * reference) via a host callback, so detection is realm-correct. They fail
 * (escape) on the unpatched tree and pass once every sandbox-initiated host
 * then/catch reject/fulfill path routes through the sanitizer regardless of
 * whether the sandbox supplied a handler.
 */
'use strict';

const assert = require('assert');
const {VM} = require('../../../lib/main.js');

// Run `code` in a VM with a host `hostReject`/`hostResolve` and a host `report`
// callback the sandbox reaction calls with what it observed. Returns the last
// reported string after the microtask/timer drains.
function runAndReport(sandboxExtra, code) {
	return new Promise(resolve => {
		let reported = 'NO-REACTION';
		const sandbox = Object.assign({
			report: v => { reported = String(v); }
		}, sandboxExtra);
		const vm = new VM({allowAsync: true, sandbox});
		try { vm.run(code); } catch (e) { reported = 'run-threw:' + e.message.slice(0, 40); }
		setTimeout(() => resolve(reported), 150);
	});
}

// A reaction body (string) that, given `reason`, probes whether it is a live
// host-pivotable proxy and reports back. 'HOSTREACH' means escape.
const PROBE = `function(reason){
	try {
		if (reason && reason.mainModule && typeof reason.mainModule.require === 'function') { report('HOSTREACH'); }
		else if (reason && reason.isProxy === true) { report('HOSTPROXY'); }
		else { report('sanitized'); }
	} catch (e) { report('sanitized-threw'); }
}`;

describe('GHSA-6454-5x88-m6jw — host Promise species+missing-handler rejection bypass', function () {

	it('reject: p.then() with no onRejected + species hijack must NOT deliver a live host reason', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 p.then();`);
		assert.notStrictEqual(r, 'HOSTREACH', 'sandbox reached host process via missing-onRejected reject bypass');
		assert.notStrictEqual(r, 'HOSTPROXY', 'sandbox received a raw host proxy via reject bypass');
	});

	it('reject: p.then(onFulfilled) with no onRejected + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 p.then(function(v){ return v; });`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: p.catch() with no onRejected + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 p.catch();`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('fulfill: p.then() with no onFulfilled + species hijack must NOT deliver a live host value', async function () {
		const r = await runAndReport(
			{hostResolve: () => Promise.resolve(process)},
			`const p = hostResolve();
			 p.constructor = { [Symbol.species]: function (ex) { ex(${PROBE}, function(){}); } };
			 p.then();`);
		assert.notStrictEqual(r, 'HOSTREACH', 'sandbox reached host process via missing-onFulfilled fulfill bypass');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: p.finally() + species hijack must NOT leak (finally reads SpeciesConstructor, no callback slot)', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 p.finally(function(){});`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: p.then.call(p, onF) .call-indirection with no onRejected + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 p.then.call(p, function(v){ return v; });`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('fulfill: p.catch() with fulfill-side species hijack must NOT leak (internal onFulfilled is off the apply-trap path; closed at SpeciesConstructor)', async function () {
		const r = await runAndReport(
			{hostResolve: () => Promise.resolve(process)},
			`const p = hostResolve();
			 p.constructor = { [Symbol.species]: function (ex) { ex(${PROBE}, function(){}); } };
			 p.catch();`);
		assert.notStrictEqual(r, 'HOSTREACH', 'fulfill leaked through .catch internal onFulfilled');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: a NON-CONFIGURABLE hijacked constructor must fail closed (no live host reason), not leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 try {
			   Object.defineProperty(p, 'constructor', {
			     value: { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } },
			     configurable: false, writable: false
			   });
			 } catch (e) {}
			 p.then();`);
		assert.notStrictEqual(r, 'HOSTREACH', 'non-configurable-constructor hijack leaked a live host reason');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('does not over-block: a normal host-promise rejection is still delivered (sanitized) to a real handler', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(new Error('boom'))},
			`hostReject().then(undefined, function(e){ report('handled:' + (e && e.message)); });`);
		assert.strictEqual(r, 'handled:boom', 'legitimate rejection handling broke');
	});

	it('does not over-block: a normal host-promise fulfillment reaches a real handler', async function () {
		const r = await runAndReport(
			{hostResolve: () => Promise.resolve(42)},
			`hostResolve().then(function(v){ report('got:' + v); });`);
		assert.strictEqual(r, 'got:42', 'legitimate fulfillment handling broke');
	});
});
