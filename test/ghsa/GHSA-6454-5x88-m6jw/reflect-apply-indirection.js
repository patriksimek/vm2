/**
 * GHSA-6454-5x88-m6jw — follow-up: host `Reflect.apply` indirection.
 *
 * The species-neutralization (and the m283 callback rebuild) both gate on
 * `peelEffectivePromiseCall`, which unwinds the ways a sandbox can invoke a host
 * `Promise.prototype.then/catch/finally`. The original fix peeled
 * `Function.prototype.call` / `.apply` (and `.bind`, which the bridge unwraps to
 * its target), but NOT host `Reflect.apply`. An embedder that exposes host
 * `Reflect` (or any object reachable to it) therefore let the sandbox do
 *
 *     Reflect.apply(p.then, p, [])          // missing onRejected
 *
 * so the apply trap saw `object === Reflect.apply` (unrecognized), the peel
 * returned null, and neither the species neutralization nor the m283 wrapping
 * fired — re-opening the exact missing-handler species escape the advisory
 * closed. These tests expose host `Reflect` and assert the escape is closed for
 * the direct and nested-indirection shapes, that present handlers still receive
 * a SANITIZED reason through the same path, and that legitimate `Reflect.apply`
 * on a normal host function is unaffected.
 */
'use strict';

const assert = require('assert');
const {VM} = require('../../../lib/main.js');

function runAndReport(sandboxExtra, code) {
	return new Promise(resolve => {
		let reported = 'NO-REACTION';
		const sandbox = Object.assign({
			report: v => { reported = String(v); },
			R: Reflect
		}, sandboxExtra);
		const vm = new VM({allowAsync: true, sandbox});
		try { vm.run(code); } catch (e) { reported = 'run-threw:' + e.message.slice(0, 40); }
		setTimeout(() => resolve(reported), 150);
	});
}

const PROBE = `function(reason){
	try {
		if (reason && reason.mainModule && typeof reason.mainModule.require === 'function') { report('HOSTREACH'); }
		else if (reason && reason.isProxy === true) { report('HOSTPROXY'); }
		else { report('sanitized'); }
	} catch (e) { report('sanitized-threw'); }
}`;

describe('GHSA-6454-5x88-m6jw — host Reflect.apply indirection', function () {

	it('reject: Reflect.apply(p.then, p, []) with no onRejected + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 R.apply(p.then, p, []);`);
		assert.notStrictEqual(r, 'HOSTREACH', 'sandbox reached host process via Reflect.apply missing-onRejected bypass');
		assert.notStrictEqual(r, 'HOSTPROXY', 'sandbox received a raw host proxy via Reflect.apply bypass');
	});

	it('fulfill: Reflect.apply(p.then, p, []) with no onFulfilled + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostResolve: () => Promise.resolve(process)},
			`const p = hostResolve();
			 p.constructor = { [Symbol.species]: function (ex) { ex(${PROBE}, function(){}); } };
			 R.apply(p.then, p, []);`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: Reflect.apply(p.catch, p, []) with no onRejected + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 R.apply(p.catch, p, []);`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: Reflect.apply(p.finally, p, []) + species hijack must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 R.apply(p.finally, p, []);`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('reject: nested Reflect.apply(then.call, then, [p]) indirection must NOT leak', async function () {
		const r = await runAndReport(
			{hostReject: () => Promise.reject(process)},
			`const p = hostReject();
			 p.constructor = { [Symbol.species]: function (ex) { ex(function(){}, ${PROBE}); } };
			 const then = p.then;
			 R.apply(then.call, then, [p]);`);
		assert.notStrictEqual(r, 'HOSTREACH');
		assert.notStrictEqual(r, 'HOSTPROXY');
	});

	it('does not over-block: a PRESENT onRejected supplied through Reflect.apply still runs and is m283-sanitized', async function () {
		// Reject with a throwaway Error (not the real `process`): a present handler
		// is delivered the SANITIZED reason, and sanitizing marks the delivered
		// host object inert — mirroring the repro.js over-block convention so we
		// never freeze the test runner's own `process`.
		const r = await runAndReport(
			{hostReject: () => Promise.reject(new Error('boom'))},
			`R.apply(hostReject().then, hostReject(), [undefined, function(e){
				report('handled:' + (e && e.message) + '/proxy=' + (e && e.isProxy));
			}]);`);
		assert.strictEqual(r, 'handled:boom/proxy=undefined', 'present onRejected via Reflect.apply must run and receive a sanitized (non-proxy) reason');
	});

	it('does not over-block: legitimate Reflect.apply on a normal host function still works', async function () {
		const r = await runAndReport(
			{hostAdd: (a, b) => a + b},
			`report('sum=' + R.apply(hostAdd, null, [2, 3]));`);
		assert.strictEqual(r, 'sum=5');
	});
});
