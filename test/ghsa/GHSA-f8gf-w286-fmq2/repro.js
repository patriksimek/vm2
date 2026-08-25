/**
 * GHSA-f8gf-w286-fmq2 — `allowAsync: false` bypass via Promise thenable assimilation
 *
 * ## Vulnerability class
 * With `allowAsync: false`, vm2 must reject asynchronous execution. Direct
 * `Promise.prototype.then` is replaced by an `AsyncErrorHandler` that throws
 * `VMError: Async not available`. But thenable *assimilation* never goes
 * through `Promise.prototype.then`: when a native promise is resolved with a
 * thenable, V8's internal `PromiseResolveThenableJob` reads the value's own
 * `.then` and calls it directly in a microtask — AFTER `vm.run()` has already
 * returned. That lets sandboxed code keep executing once the host believes the
 * synchronous run is complete, outside the configured `timeout`.
 *
 * Reported entry points (all schedule the attacker `.then` after run() returns):
 *   - `Promise.resolve(thenable)`
 *   - `Promise.all([thenable])`, `Promise.race([thenable])`,
 *     `Promise.any([thenable])`, `Promise.allSettled([thenable])`
 *
 * Additional entry points in the same class (found while generalizing the fix):
 *   - `new Promise(res => res(thenable))`           — constructor resolve capability
 *   - `Promise.withResolvers().resolve(thenable)`   — same capability
 *   - `Promise.try(() => thenable)`
 *   - `Array.fromAsync([thenable])`
 *   - the realm-intrinsic base reached via `Object.getPrototypeOf(Promise)` /
 *     `Object.getPrototypeOf(Promise.prototype).constructor` and constructed
 *     directly (`new base(res => res(thenable))` / `Reflect.construct(...)`).
 *
 * Under `allowAsync: false` the sandbox exposes no `setTimeout`,
 * `setImmediate`, or `queueMicrotask`, so thenable assimilation is the ONLY way
 * to run sandbox code after run() returns — closing it restores the boundary.
 *
 * ## Fix (lib/setup-sandbox.js, all gated to allowAsync:false)
 *  1. The assimilating static methods (`resolve`, `all`, `race`, `any`,
 *     `allSettled`, `try`) throw `VMError: Async not available` synchronously.
 *  2. localPromise's wrapped executor guards the resolve capability: it refuses
 *     any object/function value WITHOUT reading `.then` (TOCTOU-safe). Because
 *     every capability — `new Promise`, `withResolvers`, combinator internals —
 *     is built by Constructing localPromise, this one guard covers them all.
 *  3. `Array.fromAsync` is replaced by a non-configurable throwing stub.
 *  4. The native base intrinsic (reachable because `localPromise extends
 *     globalPromise`) is wrapped by a construct-guard Proxy installed as
 *     localPromise's [[Prototype]], which refuses every base construction except
 *     localPromise's own super() call; `globalPromise.prototype.constructor` is
 *     repointed at localPromise so the deep prototype walk can't reach the raw
 *     base either.
 *
 * Negative controls assert that `allowAsync: false` still allows synchronous
 * promise construction with primitive resolutions, and that `allowAsync: true`
 * is entirely unaffected (assimilation still works).
 */

'use strict';

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
const HAS_ALLSETTLED = typeof Promise.allSettled === 'function';
const HAS_ANY = typeof Promise.any === 'function';
const HAS_WITH_RESOLVERS = typeof Promise.withResolvers === 'function';
const HAS_PROMISE_TRY = typeof Promise.try === 'function';
const HAS_ARRAY_FROM_ASYNC = typeof Array.fromAsync === 'function';

// Run `code` in an allowAsync:false VM and return any values the sandbox passed
// to `mark()` after a macrotask tick (long enough for any scheduled microtask
// to have fired). The sandbox `then` payloads call `mark('leak')`; if the
// boundary holds, no such event is ever recorded.
function collectAsyncEvents(code, Ctor) {
	const events = [];
	const Klass = Ctor || VM;
	const vm = new Klass({ allowAsync: false, sandbox: { mark: function (v) { events.push(v); } } });
	let threw = null;
	try {
		vm.run(code);
	} catch (e) {
		threw = e;
	}
	return new Promise(function (resolve) {
		setTimeout(function () {
			resolve({ events: events, threw: threw });
		}, 100);
	});
}

const VM_SUFFIX = '; 1';
const NODEVM_SUFFIX = '; module.exports = 1;';

describe('GHSA-f8gf-w286-fmq2 (allowAsync:false bypass via Promise thenable assimilation)', function () {
	this.timeout(5000);

	// --- Reported static-method entry points -------------------------------

	it('Promise.resolve(thenable) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`Promise.resolve({then(){mark('leak')}})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1, 'thenable .then must not run');
	});

	it('Promise.all([thenable]) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`Promise.all([{then(){mark('leak')}}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it('Promise.race([thenable]) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`Promise.race([{then(){mark('leak')}}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it.cond('Promise.any([thenable]) does not run the thenable', HAS_ANY, async function () {
		const r = await collectAsyncEvents(`Promise.any([{then(){mark('leak')}}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it.cond('Promise.allSettled([thenable]) does not run the thenable', HAS_ALLSETTLED, async function () {
		const r = await collectAsyncEvents(`Promise.allSettled([{then(){mark('leak')}}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	// --- Additional entry points in the same class -------------------------

	it('new Promise(res => res(thenable)) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`new Promise(function(res){res({then(){mark('leak')}})})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it.cond('Promise.withResolvers().resolve(thenable) does not run the thenable', HAS_WITH_RESOLVERS, async function () {
		const r = await collectAsyncEvents(`var w=Promise.withResolvers();w.resolve({then(){mark('leak')}})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it.cond('Promise.try(() => thenable) does not run the thenable', HAS_PROMISE_TRY, async function () {
		const r = await collectAsyncEvents(`Promise.try(function(){return {then(){mark('leak')}}})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it.cond('Array.fromAsync([thenable]) does not run the thenable', HAS_ARRAY_FROM_ASYNC, async function () {
		const r = await collectAsyncEvents(`Array.fromAsync([{then(){mark('leak')}}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	// --- Realm-intrinsic base construction (the deep residual) -------------

	it('new (Object.getPrototypeOf(Promise))(res => res(thenable)) does not run the thenable', async function () {
		const r = await collectAsyncEvents(
			`var P=Object.getPrototypeOf(Promise);new P(function(res){res({then(){mark('leak')}})})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it('Reflect.construct(base, [exec]) does not run the thenable', async function () {
		const r = await collectAsyncEvents(
			`var P=Object.getPrototypeOf(Promise);Reflect.construct(P,[function(res){res({then(){mark('leak')}})}])` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it('Reflect.construct(base, [exec], Promise) with forged newTarget does not run the thenable', async function () {
		const r = await collectAsyncEvents(
			`var P=Object.getPrototypeOf(Promise);Reflect.construct(P,[function(res){res({then(){mark('leak')}})}],Promise)` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it('base reached via Object.getPrototypeOf(Promise.prototype).constructor does not run the thenable', async function () {
		const r = await collectAsyncEvents(
			`var P=Object.getPrototypeOf(Promise.prototype).constructor;new P(function(res){res({then(){mark('leak')}})})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	// --- Timeout bypass: nothing executes after run() returns --------------

	it('a thenable cannot execute sandbox code after run() returns (timeout bypass)', async function () {
		const events = [];
		const vm = new VM({ allowAsync: false, timeout: 10, sandbox: { mark: function (v) { events.push(v); } } });
		const started = Date.now();
		let threw = null;
		try {
			vm.run(`Promise.resolve({then(){var t=Date.now();while(Date.now()-t<35){};mark('ran')}})` + VM_SUFFIX);
		} catch (e) {
			threw = e;
		}
		const afterRun = Date.now() - started;
		await new Promise(function (resolve) { setTimeout(resolve, 100); });
		assert.strictEqual(events.indexOf('ran'), -1, 'no sandbox code may run after run() returns');
		assert.ok(afterRun < 35, 'run() must return promptly without executing the deferred body');
		assert.ok(threw, 'the assimilation attempt is rejected synchronously');
	});

	// --- NodeVM inherits the same setup ------------------------------------

	it('NodeVM: Promise.resolve(thenable) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`Promise.resolve({then(){mark('leak')}})` + NODEVM_SUFFIX, NodeVM);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	it('NodeVM: new Promise(res => res(thenable)) does not run the thenable', async function () {
		const r = await collectAsyncEvents(`new Promise(function(res){res({then(){mark('leak')}})})` + NODEVM_SUFFIX, NodeVM);
		assert.strictEqual(r.events.indexOf('leak'), -1);
	});

	// --- Negative controls -------------------------------------------------

	it('direct .then() remains blocked with VMError', async function () {
		const r = await collectAsyncEvents(`Promise.resolve(1).then(function(){mark('leak')})` + VM_SUFFIX);
		assert.strictEqual(r.events.indexOf('leak'), -1);
		assert.ok(r.threw && r.threw.name === 'VMError', 'direct .then must throw VMError');
	});

	it('allowAsync:false still permits synchronous promise construction with primitive resolution', async function () {
		const r = await collectAsyncEvents(`var p=new Promise(function(res){res(42)});mark('ctor-ok')` + VM_SUFFIX);
		assert.notStrictEqual(r.events.indexOf('ctor-ok'), -1, 'sync promise construction must still work');
		assert.strictEqual(r.threw, null, 'constructing a promise that resolves a primitive must not throw');
	});

	it('allowAsync:false preserves instanceof Promise', async function () {
		const r = await collectAsyncEvents(`mark((new Promise(function(){}) instanceof Promise) ? 'inst-ok' : 'inst-bad')` + VM_SUFFIX);
		assert.notStrictEqual(r.events.indexOf('inst-ok'), -1);
	});

	it('allowAsync:true is unaffected — thenable assimilation still works', async function () {
		const seen = [];
		const vm = new VM({ allowAsync: true, sandbox: { mark: function (v) { seen.push(v); } } });
		vm.run(`Promise.resolve({then(r){r('assimilated')}}).then(function(v){mark(v)});` +
			`new Promise(function(res){res({then(r){r('ctor')}})}).then(function(v){mark(v)}); 1`);
		await new Promise(function (resolve) { setTimeout(resolve, 100); });
		assert.notStrictEqual(seen.indexOf('assimilated'), -1, 'assimilation must work when async is allowed');
		assert.notStrictEqual(seen.indexOf('ctor'), -1, 'constructor assimilation must work when async is allowed');
	});
});
