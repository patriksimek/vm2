/**
 * GHSA-j89j-5m6r-cr2q — sandbox escape to host RCE via a non-strict host
 * function's `this`.
 *
 * When an embedder exposes an ordinary (sloppy-mode) host function and sandbox
 * code calls it without a receiver, vm2's apply trap forwards the call with
 * `this === undefined` (`context = otherFromThis(context)` at lib/bridge.js
 * ~2273 leaves nullish as nullish). V8's OrdinaryCallBindThis then substitutes
 * the HOST realm's global object for a sloppy function's `this`, and the bridge
 * wraps that host global and hands it back — so the sandbox gets a live proxy of
 * the host global and reaches `this.process.getBuiltinModule('child_process')
 * .execSync(...)` = host RCE. Strict / ESM functions are unaffected (their
 * `this` stays `undefined`). Exposing functions is vm2's normal use case, so any
 * plain `function(){}` an embedder passes in is a trigger.
 *
 * NOTE: this test file runs in strict mode, which makes a literal `function(){}`
 * defined here strict too — so the sloppy host functions under test are built
 * with the `Function` constructor (sloppy by default regardless of the
 * surrounding module's strictness), matching a realistic embedder that exposes
 * a sloppy-mode function. Detection is realm-correct via a host `report`
 * callback; each escape test asserts the result is POSITIVELY a safe outcome.
 */
'use strict';

const assert = require('assert');
const {VM} = require('../../../lib/main.js');

// Sloppy-mode host functions (Function ctor bodies are non-strict).
const sloppyReturnThis = Function('return this;');
const sloppyStashThis = Function('store', 'store.g = this; return store;');

function run(sandboxExtra, code) {
	let reported = 'NO-REPORT';
	const sandbox = Object.assign({report: v => { reported = String(v); }}, sandboxExtra);
	try { new VM({sandbox}).run(code); } catch (e) { reported = 'run-threw:' + e.message.slice(0, 60); }
	return reported;
}

const PROBE = `function(v){
	try {
		if (v && v.process && typeof v.process.getBuiltinModule === 'function') {
			try { v.process.getBuiltinModule('child_process').execSync('echo x'); report('HOSTREACH'); }
			catch (e) { report('host-process-reachable'); }
		} else if (v === undefined) { report('undefined-safe');
		} else if (v === null) { report('null-safe');
		} else { report('leaked-object:' + typeof v); }
	} catch (e) { report('probe-threw:' + e.message.slice(0,40)); }
}`;

function assertSafe(r, msg) {
	assert.ok(r === 'undefined-safe' || r === 'null-safe', msg + ' (got: ' + r + ')');
}

describe('GHSA-j89j-5m6r-cr2q — nullish this on a non-strict host function must not leak the host global', function () {

	it('bare call: sloppy host fn returning `this`', function () {
		assertSafe(run({greet: sloppyReturnThis}, `const g = greet(); (${PROBE})(g);`),
			'sandbox obtained a host reference from a bare sloppy-fn call');
	});

	it('explicit .call(null)', function () {
		assertSafe(run({greet: sloppyReturnThis}, `const g = greet.call(null); (${PROBE})(g);`),
			'.call(null) leaked the host global');
	});

	it('explicit .apply(undefined)', function () {
		assertSafe(run({greet: sloppyReturnThis}, `const g = greet.apply(undefined); (${PROBE})(g);`),
			'.apply(undefined) leaked the host global');
	});

	it('Reflect.apply(fn, undefined, [])', function () {
		assertSafe(run({greet: sloppyReturnThis}, `const g = Reflect.apply(greet, undefined, []); (${PROBE})(g);`),
			'Reflect.apply with nullish this leaked the host global');
	});

	it('indirect: sloppy host fn stashes `this` into a sandbox object', function () {
		assertSafe(run({keep: sloppyStashThis}, `const s = {}; keep(s); (${PROBE})(s.g);`),
			'a stashed sloppy `this` leaked the host global');
	});

	it('over-block control: a host method called WITH a receiver still sees that receiver', function () {
		const r = run({obj: {tag: 'the-receiver', who: function () { return this.tag; }}},
			`report('method-this:' + obj.who());`);
		assert.strictEqual(r, 'method-this:the-receiver', 'legitimate method this-binding broke');
	});

	it('over-block control: a strict host fn called bare still returns undefined', function () {
		// literal function here is strict (file is strict) — its `this` stays undefined
		assertSafe(run({greetS: function () { return this; }}, `const g = greetS(); (${PROBE})(g);`),
			'strict-mode this-binding changed');
	});
});
