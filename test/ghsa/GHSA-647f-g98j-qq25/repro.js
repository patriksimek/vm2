/**
 * GHSA-647f-g98j-qq25 — m283 fix bypass via call/apply indirection → host RCE
 *
 * ## Vulnerability class
 *
 * This is a *patch bypass* of the published GHSA-m283-3h24-438v fix
 * (CVE-2026-47686). That fix rebuilds capability-bearing host rejection
 * values as fresh sandbox-realm errors before a sandbox `onRejected` callback
 * runs — stripping own properties (e.g. `err.detail = process`), the host
 * prototype chain, and the `SuppressedError`/`AggregateError`/`Error.cause`
 * side-channels. The rebuild is driven by the bridge apply-trap gate that
 * wraps the callbacks a sandbox passes to a host Promise's `.then` / `.catch`
 * (lib/bridge.js) via the sanitizers installed by setup-sandbox.js
 * (`bridge.setHostPromiseSanitizers(e => handleException(from(e)), from)`).
 *
 * The gate identity-checks only the *direct* apply target: it wraps the
 * callbacks only when the applied function IS host `Promise.prototype.then` /
 * `.catch`. Registering the rejection handler through `Function.prototype.call`
 * / `Function.prototype.apply` indirection makes the intercepted apply target
 * host `Function.prototype.call` (the sandbox's `.call` is `connect()`ed to
 * host's), so the identity check misses, the callbacks are never wrapped, and
 * the raw host rejection value reaches sandbox code:
 *
 *     const p = fetchUser();                       // proxy of a host Promise
 *     p.then.call(p, undefined, (e) => {           // .call indirection
 *       e.detail.mainModule.require('child_process').execSync(...);  // host RCE
 *     });
 *
 * `.apply` and a stacked `call.call` behave identically. The `bind` and
 * sandbox-realm `Reflect.apply` forms already route through the direct gate
 * (they invoke `then` as the apply target), so they were never vulnerable.
 *
 * ## Fix shape
 *
 * The apply trap already peels one layer of `Function.prototype.call/apply/bind`
 * indirection for the host-proto-mutator defense (GHSA-v6mx / GHSA-cfcw). The
 * fix normalizes the same indirection for the host-Promise sanitizer gate:
 * unwind call/apply indirection (including stacked forms) to the *effective*
 * applied function and the *effective* callback slots, and if that effective
 * function is host `.then` / `.catch`, wrap the callbacks in-place — so the
 * m283 rebuild runs regardless of how `then`/`catch` was invoked.
 *
 * ## Oracle
 *
 * An embedder-exposed host async fn rejects with an Error carrying
 * `err.detail = process`. Sandbox code registers `onRejected` through each
 * indirection form and attempts `e.detail.mainModule.require('child_process')
 * .execSync('echo PWN')`. The escape condition is that the sandbox reaches
 * host `child_process` (marker 'PWN'). The sanitized path yields a rebuilt
 * error whose `.detail` is `undefined`, so the deref throws inside the sandbox
 * and no host reference is ever obtained.
 *
 * Rejection assimilation fires in a microtask AFTER run() returns, so every
 * case awaits a tick before asserting.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// Host async fn that rejects with a host Error carrying process on an own prop.
function makeSandbox(probe) {
	return {
		fetchUser() {
			return new Promise(function (resolve, reject) {
				const err = new Error('db connection failed');
				err.detail = process; // embedder-attached host reference
				reject(err);
			});
		},
		mark(v) { probe.mark = v; },
	};
}

// Drain microtasks/timers so PromiseResolveThenableJob + the onRejected job run.
function tick() {
	return new Promise(function (resolve) { setImmediate(resolve); });
}

// The escape payload the sandbox onRejected runs on its received error `e`.
// If `e.detail` is a live host proxy this reaches child_process and marks PWN;
// if the error was rebuilt (detail stripped) the deref throws → marks SAFE.
const PAYLOAD =
	"(e) => { try {" +
	"  mark(e.detail.mainModule.require('child_process').execSync('echo PWN').toString().trim());" +
	"} catch (x) { mark('SAFE:' + (x && x.message ? String(x.message).slice(0, 24) : 'throw')); } }";

function runReject(registerExpr) {
	const probe = { mark: undefined };
	const vm = new VM({ sandbox: makeSandbox(probe) });
	// registerExpr receives the promise `p` and the callback `cb` in scope.
	vm.run(
		'const p = fetchUser();\n' +
		'const cb = ' + PAYLOAD + ';\n' +
		registerExpr + '\n' +
		'1;'
	);
	return probe;
}

describe('GHSA-647f-g98j-qq25 (m283 bypass via call/apply indirection → RCE)', function () {

	it('canonical PoC: p.then.call(p, undefined, cb) must not deliver a live host error', async function () {
		const probe = runReject('p.then.call(p, undefined, cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via .call indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0,
			'onRejected should still fire with a sanitized (detail-stripped) error; got ' + probe.mark);
	});

	it('variant: p.then.apply(p, [undefined, cb]) must not deliver a live host error', async function () {
		const probe = runReject('p.then.apply(p, [undefined, cb]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via .apply indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('variant: stacked p.then.call.call(p.then, p, undefined, cb) must not deliver a live host error', async function () {
		const probe = runReject('p.then.call.call(p.then, p, undefined, cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via stacked call.call indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('variant: stacked p.then.apply.call(p.then, p, [undefined, cb]) must not deliver a live host error', async function () {
		const probe = runReject('p.then.apply.call(p.then, p, [undefined, cb]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via stacked apply.call indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('variant: .catch via call indirection — p.catch.call(p, cb) must not deliver a live host error', async function () {
		const probe = runReject('p.catch.call(p, cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via p.catch.call indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('variant: .catch via apply indirection — p.catch.apply(p, [cb]) must not deliver a live host error', async function () {
		const probe = runReject('p.catch.apply(p, [cb]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via p.catch.apply indirection');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	// Same-class siblings: mixed / deeper call+apply nesting orders. These are the
	// identical vulnerability with a different nesting order — a hardcoded-6 patch
	// would leave them open for the next patch-bypass, so the normalizer must peel
	// arbitrary call/apply order to bounded depth.
	it('sibling: p.then.call.apply(p.then, [p, undefined, cb]) must not deliver a live host error', async function () {
		const probe = runReject('p.then.call.apply(p.then, [p, undefined, cb]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via then.call.apply');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('sibling: p.then.apply.apply(p.then, [p, [undefined, cb]]) must not deliver a live host error', async function () {
		const probe = runReject('p.then.apply.apply(p.then, [p, [undefined, cb]]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via then.apply.apply');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('sibling: triple stack p.then.call.call.call(p.then.call, p.then, p, undefined, cb) must not deliver a live host error', async function () {
		const probe = runReject('p.then.call.call.call(p.then.call, p.then, p, undefined, cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'sandbox reached host child_process via triple call.call.call');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	// ---- Negative controls: the direct + already-safe forms must STILL sanitize ----

	it('regression: direct p.then(undefined, cb) stays sanitized (m283 invariant preserved)', async function () {
		const probe = runReject('p.then(undefined, cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'direct .then regressed');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('regression: direct p.catch(cb) stays sanitized', async function () {
		const probe = runReject('p.catch(cb);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'direct .catch regressed');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('regression: sandbox Reflect.apply(p.then, p, [undefined, cb]) stays sanitized', async function () {
		const probe = runReject('Reflect.apply(p.then, p, [undefined, cb]);');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'Reflect.apply path regressed');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	it('regression: bound then — p.then.bind(p, undefined, cb)() stays sanitized', async function () {
		const probe = runReject('p.then.bind(p, undefined, cb)();');
		await tick();
		assert.notStrictEqual(probe.mark, 'PWN', 'bound .then path regressed');
		assert.ok(probe.mark && probe.mark.indexOf('SAFE') === 0, 'got ' + probe.mark);
	});

	// ---- Over-block guards: indirection on benign host methods must keep working ----

	it('over-block guard: onFulfilled via .call indirection still receives the resolved value', async function () {
		const probe = { mark: undefined };
		const vm = new VM({ sandbox: {
			fetchOk() { return Promise.resolve(42); },
			mark(v) { probe.mark = v; },
		}});
		vm.run('const p = fetchOk(); p.then.call(p, (v) => mark(v)); 1;');
		await tick();
		assert.strictEqual(probe.mark, 42, 'onFulfilled via .call must still receive the (sanitized) resolved value');
	});

	it('over-block guard: Function.prototype.call on a non-promise host method is unaffected', function () {
		const vm = new VM({ sandbox: {
			host: { add(a, b) { return a + b; } },
		}});
		const out = vm.run('host.add.call(host, 2, 3);');
		assert.strictEqual(out, 5, 'call indirection on an ordinary host method must still work');
	});

	it('over-block guard: onRejected callback is actually invoked (not silently dropped) via .call', async function () {
		const probe = { mark: undefined };
		const vm = new VM({ sandbox: {
			boom() { return Promise.reject(new Error('plain-reason')); },
			mark(v) { probe.mark = v; },
		}});
		vm.run('const p = boom(); p.then.call(p, undefined, (e) => mark(e && e.message)); 1;');
		await tick();
		assert.strictEqual(probe.mark, 'plain-reason', 'sanitized onRejected must still fire with the message preserved');
	});
});
