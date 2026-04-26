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
 * NOTE: this fix covers the programmatic `prepareStackTrace`-based path
 * (the report's "Path B"). The default `error.stack` string emitted by V8
 * when `Error.prepareStackTrace` is `undefined` still includes host paths;
 * a sandbox default formatter that closes that path was attempted but
 * regressed SuppressedError handling (V8 calls prepareStackTrace during
 * SuppressedError construction, and the custom default interfered with
 * `.error` / `.suppressed` propagation). Closing Path A is tracked as a
 * follow-up that requires careful coexistence with the existing exception
 * sanitisation layer.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-v27g-jcqj-v8rw (CallSite path leak via prepareStackTrace)', function () {
	it('getFileName on host frames returns null (no absolute path leaked)', function () {
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
	});

	it('getLineNumber/getColumnNumber on host frames return null', function () {
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

	it('getFunctionName/getMethodName/getTypeName on host frames return null', function () {
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
	});

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
});
