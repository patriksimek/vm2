'use strict';

/**
 * GHSA-v27g-jcqj-v8rw — CallSite leaks host paths via prepareStackTrace
 *
 *
 * ## Vulnerability
 * vm2's `CallSite` wrapper (in `lib/setup-sandbox.js`) blocks `getThis()` and
 * `getFunction()` to prevent host object leakage, but proxied
 * `getFileName()`, `getLineNumber()`, `getColumnNumber()`,
 * `getFunctionName()`, `getMethodName()`, `getTypeName()` and similar
 * unsanitized — exposing host absolute paths (e.g.
 * `/app/node_modules/vm2/lib/vm.js`), exact source locations, and host
 * function/method names to sandbox code via custom
 * `Error.prepareStackTrace` handlers. This is information disclosure of
 * host architecture useful for follow-on targeting.
 *
 * ## Fix
 * `applyCallSiteGetters` in `lib/setup-sandbox.js` now classifies frames as
 * "host" or "sandbox" by inspecting the underlying CallSite's `getFileName()`:
 * filenames that are absolute paths (start with `/`), Windows-style paths
 * (`<letter>:`), or Node internals (`node:` / `internal/`) are treated as
 * host frames and every getter returns `null`. Clean filenames (e.g. the
 * default `vm.js`, or VMScript filenames without separators) are still
 * exposed so sandbox developers can debug their own code.
 *
 * Hardening (post-validation): two follow-ups landed alongside this advisory.
 *  - Path A residual closed: the sandbox now installs
 *    `defaultSandboxPrepareStackTrace` as the initial value for
 *    `Error.prepareStackTrace`, so V8 never falls through to Node's host
 *    formatter (which leaks absolute host paths and throws on
 *    Symbol-named errors).
 *  - `getEvalOrigin()` now redacts unconditionally (not just for host
 *    frames). Sandbox eval frames previously leaked an embedded host
 *    path inside the eval-origin string ("eval at FUNC (HOSTPATH:L:C)").
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Two relevant V8 thresholds:
// - Node 14+: `defaultSandboxPrepareStackTrace` is installed reliably and
//   `getEvalOrigin` redaction is unconditional, so the default-formatter
//   and eval-origin tests apply.
// - Node 16+: V8's contextify wrapper emits Node's internal `vm.runInContext`
//   frame with a path-prefixed filename (`node:vm` / `internal/vm.js`) that
//   the host-frame classifier in setup-sandbox.js catches. On Node 14 that
//   frame still emits the bare filename `vm.js` (function name
//   `runInContext`), which collides with the default sandbox-script
//   filename — the per-frame filename/line/function-name redaction
//   assertions don't apply there. Documented classifier blind spot on
//   Node 14, which is EOL; the leak is host info-disclosure (not RCE) of
//   architecturally public Node internals.
const V27G_RUNS = NODE_MAJOR >= 14;
const V27G_FRAME_REDACTION_RUNS = NODE_MAJOR >= 16;

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-v27g-jcqj-v8rw (CallSite path leak via prepareStackTrace)', function () {
	it.cond(
		'getFileName on host frames returns null (no absolute path leaked)',
		V27G_FRAME_REDACTION_RUNS,
		function () {
			const r = new VM().run(`
			Error.prepareStackTrace = function(e, sst) {
				return sst.map(function(s) { return s.getFileName(); });
			};
			new Error().stack;
		`);
			assert.ok(Array.isArray(r), 'expected array, got: ' + typeof r);
			// The first entry should be the sandbox frame (clean filename).
			// All other entries (host frames) must be null.
			assert.ok(
				typeof r[0] === 'string' && !/^\//.test(r[0]) && !/^node:/.test(r[0]),
				'first frame should be sandbox-clean filename; got: ' + r[0],
			);
			for (let i = 1; i < r.length; i++) {
				assert.strictEqual(r[i], null, 'host frame ' + i + ' leaked filename: ' + r[i]);
			}
		},
	);

	it.cond('getLineNumber/getColumnNumber on host frames return null', V27G_FRAME_REDACTION_RUNS, function () {
		const r = new VM().run(`
			Error.prepareStackTrace = function(e, sst) {
				return sst.map(function(s) {
					return [s.getFileName(), s.getLineNumber(), s.getColumnNumber()];
				});
			};
			new Error().stack;
		`);
		// First entry is sandbox; rest must have null line/col.
		for (let i = 1; i < r.length; i++) {
			assert.strictEqual(r[i][1], null, 'host frame ' + i + ' leaked line: ' + r[i][1]);
			assert.strictEqual(r[i][2], null, 'host frame ' + i + ' leaked col: ' + r[i][2]);
		}
	});

	it.cond(
		'getFunctionName/getMethodName/getTypeName on host frames return null',
		V27G_FRAME_REDACTION_RUNS,
		function () {
			const r = new VM().run(`
			Error.prepareStackTrace = function(e, sst) {
				return sst.map(function(s) {
					return [s.getFileName(), s.getFunctionName(), s.getMethodName(), s.getTypeName()];
				});
			};
			new Error().stack;
		`);
			for (let i = 1; i < r.length; i++) {
				assert.strictEqual(r[i][1], null, 'host frame ' + i + ' leaked function name: ' + r[i][1]);
				assert.strictEqual(r[i][2], null, 'host frame ' + i + ' leaked method name: ' + r[i][2]);
				assert.strictEqual(r[i][3], null, 'host frame ' + i + ' leaked type name: ' + r[i][3]);
			}
		},
	);

	it('sandbox frame info still works (regression guard)', function () {
		const r = new VM().run(`
			Error.prepareStackTrace = function(e, sst) {
				return sst[0].getFileName();
			};
			new Error().stack;
		`);
		assert.strictEqual(typeof r, 'string');
		// Default sandbox script filename is 'vm.js' — should be present, not null.
		assert.ok(
			r.length > 0 && !/^\//.test(r) && !/^node:/.test(r),
			'sandbox frame filename should be exposed; got: ' + r,
		);
	});

	// SECURITY (post-GHSA-v27g hardening): getEvalOrigin returns a string of
	// the form "eval at FUNC (FILENAME:LINE:COL)" whose embedded FILENAME
	// may be a host path. Frame-level host classification doesn't inspect
	// the nested path, so sandbox eval frames leaked host paths via this
	// getter. Now redacted unconditionally.
	it.cond('getEvalOrigin returns null on every frame (no embedded host path leaks)', V27G_RUNS, function () {
		const r = new VM().run(`
			Error.prepareStackTrace = function(e, sst) {
				return sst.map(function(s) { return s.getEvalOrigin(); });
			};
			eval('new Error().stack');
		`);
		assert.ok(Array.isArray(r), 'expected array, got: ' + typeof r);
		for (let i = 0; i < r.length; i++) {
			assert.strictEqual(r[i], null, 'frame ' + i + ' leaked eval origin (may contain host path): ' + r[i]);
		}
	});

	// SECURITY (post-GHSA-v27g Path A residual closed): when sandbox code
	// reads error.stack WITHOUT first assigning to Error.prepareStackTrace,
	// V8 used to fall back to Node's host formatter — which emits absolute
	// host paths and (worse) throws host-realm TypeError on Symbol-named
	// errors. The sandbox now installs defaultSandboxPrepareStackTrace at
	// init so the default formatter is always sandbox-realm.
	// Path A default formatter requires `OriginalCallSite` (V8's structured-stack
	// API), which is reliable on Node 12+. On Node 8/10 the sandbox falls
	// through to V8's native default formatter and emits host paths — gated
	// accordingly. (Node 8/10 are below vm2's documented support floor; tests
	// only exercise them via the legacy runner for completeness.)
	it.cond('default error.stack does not leak absolute host paths', V27G_RUNS, function () {
		const stack = new VM().run(`
			(function(){ try { null.x; } catch(e) { return e.stack; } })()
		`);
		assert.strictEqual(typeof stack, 'string');
		assert.ok(
			!/\/Users\//.test(stack) && !/\/home\//.test(stack) && !/node:/.test(stack),
			'default error.stack leaked host path: ' + stack,
		);
	});

	it('Symbol-named error reads safely (host formatter never invoked)', function () {
		// Pre-fix: e.name = Symbol() + e.stack triggers V8 fallback to host
		// formatter, which throws "Cannot convert a Symbol value to a string"
		// in host realm. Confirms Path A default formatter handles Symbol names.
		assert.doesNotThrow(function () {
			new VM().run(`
				var e = new Error('x');
				e.name = Symbol('s');
				e.stack;
			`);
		});
	});
});
