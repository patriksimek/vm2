'use strict';

/**
 * GHSA-x6m4-chr9-cg97 — adversarial coverage beyond the canonical eval() trigger.
 *
 * These cases probe host-path disclosure channels a string-frame redactor keyed
 * on "at (FILE…)" lines might miss, and confirm the interaction of the
 * transformer-source layer (lib/vm.js) with the existing v27g CallSite machinery.
 *
 * NEW leak vectors discovered while hardening (see NOTES.md):
 *   - Every Function-family constructor reaches the same host chokepoint: the
 *     GeneratorFunction / AsyncFunction / AsyncGeneratorFunction `.constructor`
 *     and multi-argument `new Function(a, b, body)` all funnel through
 *     `makeFunction -> host.transformAndCheck`, so a compile error on ANY of them
 *     leaked host paths pre-fix, not just `eval` / single-arg `Function`.
 *   - Re-formatting attempts (`Error.captureStackTrace` + custom
 *     `Error.prepareStackTrace`) do not re-expose the host origin: the error the
 *     sandbox holds is already sandbox-realm (rebuilt by handleException), so a
 *     re-capture records sandbox frames rendered as the opaque `CallSite {}`.
 *
 * Host errors that reach the sandbox through NON-transformer paths (e.g. a host
 * `Buffer` method throwing) are outside the lib/vm.js layer's reach and are
 * covered by the bridge-side redactor and by sanitizeHostOwnProps; the last case
 * below asserts that.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);

// Flags HOST-realm disclosure only. Per GHSA-v27g, redaction preserves clean
// SANDBOX frames (bare filenames like `at vm.js:3:16`, no path/scheme) — those
// reveal nothing about the host — while dropping host frames. So this checks
// for host paths / URL schemes / node internals / vm2 host source, NOT for the
// mere presence of an `at …` frame.
function leaksHostInfo(s) {
	if (typeof s !== 'string') return false;
	if (/\/(?:Users|home|root|var|private|opt|usr|Applications)\//.test(s)) return true; // unix absolute host roots
	if (/[A-Za-z]:\\/.test(s)) return true;                                               // windows absolute
	if (/\bnode:|\bnode_modules\b|file:\/\/|wasm:\/\//.test(s)) return true;              // node internals / URL-scheme frames
	if (/(?:^|[\s(/\\])internal\//.test(s)) return true;                                  // node internal/ modules
	if (/lib[\/\\](?:transformer|vm|setup-sandbox|bridge|nodevm)\.js/.test(s)) return true; // vm2 host source (always path-prefixed)
	return false;
}

function run(code) {
	return new VM().run(code);
}

describe('GHSA-x6m4-chr9-cg97 (adversarial)', function () {
	it('GeneratorFunction constructor compile error — no host path', function () {
		const stack = run("try { (function*(){}).constructor('@@@ catch'); } catch (e) { e.stack }");
		assert.ok(!leaksHostInfo(stack), 'leaked host info: ' + stack);
	});

	it('multi-argument new Function(a, b, body) compile error — no host path', function () {
		const stack = run("try { new Function('a', 'b', '@@@ catch'); } catch (e) { e.stack }");
		assert.ok(!leaksHostInfo(stack), 'leaked host info: ' + stack);
	});

	it('Error.captureStackTrace re-capture on the caught error does not re-expose host origin', function () {
		const stack = run(
			"try { eval('@@@ catch'); } catch (e) { try { Error.captureStackTrace(e); } catch (x) {} e.stack }",
		);
		assert.strictEqual(typeof stack, 'string');
		assert.ok(!leaksHostInfo(stack), 'leaked host info after re-capture: ' + stack);
	});

	it.cond(
		'custom Error.prepareStackTrace + captureStackTrace over the caught error yields no host filename',
		NODE_MAJOR >= 16,
		function () {
			const r = run(
				"Error.prepareStackTrace = function (er, s) { return s.map(function (f) { return f.getFileName(); }); };" +
					"try { eval('@@@ catch'); } catch (e) { try { Error.captureStackTrace(e); } catch (x) {} JSON.stringify(e.stack) }",
			);
			const names = JSON.parse(r);
			assert.ok(Array.isArray(names), 'expected array of filenames, got: ' + r);
			for (let i = 1; i < names.length; i++) {
				assert.strictEqual(names[i], null, 'host frame ' + i + ' leaked filename: ' + names[i]);
			}
		},
	);

	it('error toString() exposes only name + message (no host path)', function () {
		const s = run("try { eval('@@@ catch'); } catch (e) { '' + e }");
		assert.ok(!leaksHostInfo(s), 'leaked host info via toString: ' + s);
		assert.ok(/SyntaxError/.test(s), 'error identity lost: ' + s);
	});

	it('a valid eval() is unaffected by the redactor (common-path regression guard)', function () {
		const v = run("eval('1 + 2')");
		assert.strictEqual(v, 3);
	});

	// Classifier-hardening regressions (frame formats the v27g allow-list missed).
	// Injected via a host fn so the frame text is deterministic across Node versions.
	it('ESM file:// host frame is redacted', function () {
		const vm = new VM({ sandbox: { host: { f() {
			const e = new Error('esm');
			e.stack = 'Error: esm\n    at foo (file:///Users/app/index.mjs:1:1)\n    at vm.js:1:1';
			throw e;
		} } } });
		const s = vm.run("var s=''; try { host.f(); } catch (e) { s = String(e.stack); } s;");
		assert.ok(!/file:\/\//.test(s) && !/index\.mjs/.test(s), 'file:// frame leaked: ' + s);
		assert.ok(/esm/.test(s), 'message lost');
	});

	it('relative ".." traversal host frame is redacted', function () {
		const vm = new VM({ sandbox: { host: { f() {
			const e = new Error('rel');
			e.stack = 'Error: rel\n    at foo (../../secret/app.js:1:1)\n    at vm.js:1:1';
			throw e;
		} } } });
		const s = vm.run("var s=''; try { host.f(); } catch (e) { s = String(e.stack); } s;");
		assert.ok(!/\.\.[\/\\]/.test(s) && !/secret/.test(s), 'relative host frame leaked: ' + s);
		assert.ok(/rel/.test(s), 'message lost');
	});

	// Non-transformer delivery path. A host `Buffer` method throwing hands the
	// sandbox a host-formatted `.stack` without ever touching
	// `transformAndCheck`, so the lib/vm.js layer alone cannot close it — this
	// asserts the bridge / sanitizeHostOwnProps layers do.
	it('host Buffer method error stack is redacted (path-b: sanitizeHostOwnProps)', function () {
		const stack = run('try { Buffer.alloc(-1); } catch (e) { e.stack }');
		assert.ok(!leaksHostInfo(stack), 'leaked host info: ' + stack);
	});
});
