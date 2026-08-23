/**
 * GHSA-x6m4-chr9-cg97 — host filesystem path leak via host-realm error stack
 *
 * ## Vulnerability class
 *
 * This is an incomplete-fix / bypass of the published GHSA-v27g-jcqj-v8rw
 * host-path redaction. v27g installs `defaultSandboxPrepareStackTrace` and
 * `applyCallSiteGetters` so that when the SANDBOX realm formats an Error's
 * `.stack`, host frames (absolute paths, `node:`/`internal/` pseudo-paths) are
 * redacted — sandbox developers keep their own frames, host frames are blanked.
 *
 * That guarantee only covers stacks formatted IN the sandbox realm. A
 * host-realm Error carries a `.stack` string already formatted by the host
 * (V8's default formatter), and that string crosses the bridge to the sandbox
 * verbatim — v27g's redaction never runs on it.
 *
 * The canonical trigger needs no special config: sandbox code `eval`s
 * malformed source, which routes through vm2's HOST-side transformer
 * (`lib/transformer.js` `makeNiceSyntaxError`). The transformer throws a
 * host-realm `SyntaxError` whose `.stack` embeds absolute host paths for
 * `lib/transformer.js`, `lib/vm.js`, `lib/setup-sandbox.js`, Node internals,
 * AND the embedding application's own source file. The sandbox catches it (the
 * caught value is a bridge proxy of the host error) and reads `.stack`, which
 * the bridge `get` trap forwards to the host string. Any embedder-exposed host
 * function that throws is the same primitive.
 *
 * ## Oracle
 *
 * The `.stack` delivered to the sandbox must not contain host-realm frames:
 * no absolute filesystem paths, no `node:` / `internal/` pseudo-paths, and no
 * reference to the embedding application's source tree. The error's `.message`
 * (and sandbox-frame line info) must be preserved — the redaction must not
 * blank the whole stack.
 *
 * Information disclosure only (no code execution / object exposure).
 */

'use strict';

const assert = require('assert');
const path = require('path');
const { VM, NodeVM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// A stack string leaks host-realm info if it references an absolute host path,
// a node:/internal pseudo-path, a vm2 lib/ source file, or this test's own path.
const HOST_MARKERS = [
	/\/(?:Users|home|root|var|private|opt|usr|Applications)\//, // unix absolute host roots
	/[A-Za-z]:\\/,                                               // windows absolute
	/\bnode:/,                                                   // node: internals
	/\binternal\//,                                              // node internal/ modules
	/lib[\/\\](?:transformer|vm|setup-sandbox|bridge|nodevm)\.js/, // vm2 host source
];
const THIS_FILE = path.resolve(__filename);

function assertNoHostLeak(stack, label) {
	assert.strictEqual(typeof stack, 'string', label + ': stack should be a string');
	for (let i = 0; i < HOST_MARKERS.length; i++) {
		assert.ok(!HOST_MARKERS[i].test(stack),
			label + ': stack leaks host-realm info (matched ' + HOST_MARKERS[i] + '):\n' + stack);
	}
	// The embedding app's own absolute path (this test file) must not appear.
	assert.ok(stack.indexOf(THIS_FILE) === -1, label + ': stack leaks the embedding app path');
	assert.ok(stack.indexOf(process.cwd()) === -1, label + ': stack leaks host cwd');
}

describe('GHSA-x6m4-chr9-cg97 (host path leak via host-realm error stack)', function () {

	it('canonical PoC: eval("@@@ catch") SyntaxError stack is redacted of host paths', function () {
		const stack = new VM().run(
			'var s; try { eval("@@@ catch"); } catch (e) { s = String(e.stack); } s;'
		);
		assertNoHostLeak(stack, 'VM eval SyntaxError');
	});

	it('variant: stack read via Object.getOwnPropertyDescriptor(e, "stack").value', function () {
		const stack = new VM().run(
			'var s; try { eval("@@@ catch"); } catch (e) {' +
			'  var d = Object.getOwnPropertyDescriptor(e, "stack"); s = d ? String(d.value) : "<no-desc>";' +
			'} s;'
		);
		if (stack !== '<no-desc>') assertNoHostLeak(stack, 'VM getOwnPropertyDescriptor stack');
	});

	// Up to Node 20 V8 gives an Error an own DATA property `stack`; from Node 22
	// it is an own ACCESSOR, so a descriptor read yields a getter instead of a
	// value and `d.get.call(err)` pulls the raw host-formatted string through the
	// apply trap. Descriptor reads must be redacted in BOTH shapes, so this case
	// exercises the descriptor whatever V8 hands back rather than skipping when
	// `value` is absent.
	it('variant: descriptor read on a host error covers the accessor shape too', function () {
		const vm = new VM({ sandbox: {
			hostThrow() { Buffer.alloc(-1); },
		}});
		const out = vm.run(
			'var s = ""; var e;' +
			'try { hostThrow(); } catch (err) { e = err; }' +
			'var d = Object.getOwnPropertyDescriptor(e, "stack");' +
			'if (d) {' +
			'  if (d.get) s += String(d.get.call(e));' +
			'  if (d.set) s += "|HAS-SETTER";' +
			'  if (!d.get && !d.set) s += String(d.value);' +
			'}' +
			'var g = typeof e.__lookupGetter__ === "function" ? e.__lookupGetter__("stack") : undefined;' +
			'if (typeof g === "function") s += "|" + String(g.call(e));' +
			's;'
		);
		assertNoHostLeak(out, 'VM descriptor accessor stack');
	});

	it('variant: stack read via Reflect.get(e, "stack")', function () {
		const stack = new VM().run(
			'var s; try { eval("@@@ catch"); } catch (e) { s = String(Reflect.get(e, "stack")); } s;'
		);
		assertNoHostLeak(stack, 'VM Reflect.get stack');
	});

	it('variant: error thrown by an embedder-exposed host function', function () {
		const vm = new VM({ sandbox: {
			hostThrow() { throw new Error('host-boom'); },
		}});
		const stack = vm.run(
			'var s; try { hostThrow(); } catch (e) { s = String(e.stack); } s;'
		);
		assertNoHostLeak(stack, 'host-fn thrown Error');
	});

	it('variant: NodeVM default (console:inherit) eval SyntaxError stack is redacted', function () {
		const stack = new NodeVM().run(
			'var s; try { eval("@@@ catch"); } catch (e) { s = String(e.stack); } module.exports = s;',
			'poc.js'
		);
		assertNoHostLeak(stack, 'NodeVM eval SyntaxError');
	});

	it('variant: TypeError from a host builtin reached through the bridge', function () {
		// Buffer is exposed by default; call it wrong to get a host-thrown TypeError.
		const stack = new VM().run(
			'var s; try { Buffer.from(Symbol()); } catch (e) { s = String(e && e.stack); } s;'
		);
		if (stack && stack !== 'undefined') assertNoHostLeak(stack, 'host Buffer TypeError');
	});

	// ---- Over-block guards: the redaction must preserve useful sandbox info ----

	it('over-block guard: the error message survives redaction', function () {
		const msg = new VM().run(
			'var m; try { eval("@@@ catch"); } catch (e) { m = String(e.message); } m;'
		);
		assert.ok(/Unexpected/.test(msg), 'error message should be preserved, got: ' + msg);
	});

	it('over-block guard: a sandbox-thrown error keeps its own (sandbox) stack frames', function () {
		// v27g already lets sandbox frames through; the x6m4 fix must not regress that.
		const out = new VM().run(
			'function boom(){ throw new Error("sbx"); }\n' +
			'var s; try { boom(); } catch (e) { s = String(e.stack); } s;'
		);
		assert.strictEqual(typeof out, 'string');
		assert.ok(/sbx/.test(out), 'sandbox error message should be present');
		// and it must not leak host paths either
		assertNoHostLeak(out, 'sandbox-thrown error');
	});
});
