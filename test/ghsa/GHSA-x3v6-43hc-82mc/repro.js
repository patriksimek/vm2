/**
 * GHSA-x3v6-43hc-82mc — NodeVM crypto sanitizer exposed process-wide
 * `crypto.setFips`.
 *
 * When an embedder allowlists the `crypto` builtin (`require: { builtin:
 * ['crypto'] }`), vm2 exposed the host `crypto` module through a readonly
 * wrapper after `sanitizeCryptoModule`. That sanitizer neutralized `setEngine`
 * (GHSA-46pr) but left `setFips` callable — and `crypto.setFips(bool)` flips the
 * FIPS mode of the ENTIRE host process. A readonly wrapper prevents property
 * replacement but not the side effect of a forwarded host call, so guest code
 * could change process-wide crypto configuration that trusted host code
 * observes afterwards (guest `setFips(1)` → host `getFips()` returns 1). Same
 * process-wide-mutator class as `crypto.setEngine` and
 * `tls.setDefaultCACertificates` (GHSA-98xx).
 *
 * Fix: `sanitizeCryptoModule` also neutralizes `setFips` (throws), matching
 * `setEngine`. `setEngine` and `setFips` are the only `set*` members crypto
 * exposes. `getFips()` (read-only) is unchanged.
 *
 * The host FIPS state is saved and restored around each test so a regression on
 * an unpatched tree cannot leak process state into the rest of the suite.
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {NodeVM} = require('../../../lib/main.js');

// crypto.getFips / setFips exist from Node 10; on Node 8 there is nothing to
// neutralize, so the FIPS cases are skipped there (the setEngine case still runs).
const HAS_FIPS = typeof crypto.getFips === 'function' && typeof crypto.setFips === 'function';
// `it.cond` is installed by test/vm.js; fall back to the same shape when this file runs alone.
const itCond = typeof it.cond === 'function' ? it.cond : function (name, cond, fn) {
	if (cond) it(name, fn); else it.skip(name, fn);
};

describe('GHSA-x3v6-43hc-82mc — crypto.setFips must not mutate host process FIPS state from the sandbox', function () {

	itCond('guest crypto.setFips is disabled (throws) and the host FIPS state is unchanged', HAS_FIPS, function () {
		const before = crypto.getFips();
		try {
			const res = new NodeVM({require: {external: false, builtin: ['crypto']}}).run(
				`const c = require('crypto');
				 let msg = null, val;
				 try { c.setFips(1); val = c.getFips(); } catch (e) { msg = String(e && e.message); }
				 module.exports = { msg: msg, val: val };`, 'p.js');
			// The host itself throws from setFips on a non-FIPS OpenSSL build, so a
			// bare "it threw" would pass on an unpatched tree there. Check the host
			// state first, then require the sandbox stub's own message.
			assert.strictEqual(crypto.getFips(), before, 'host process FIPS state was mutated from the sandbox');
			assert.ok(res.msg !== null && /disabled in vm2 sandboxes/.test(res.msg),
				'crypto.setFips was forwarded to the host inside the sandbox (got: ' + res.msg + ')');
		} finally {
			try { crypto.setFips(before); } catch (e) { /* restore best-effort */ }
		}
	});

	itCond('setFips(0) / setFips(true) variants are all disabled', HAS_FIPS, function () {
		const before = crypto.getFips();
		try {
			const res = new NodeVM({require: {external: false, builtin: ['crypto']}}).run(
				`const c = require('crypto');
				 const out = {};
				 for (const arg of [0, 1, true, false]) {
				   try { c.setFips(arg); out[String(arg)] = 'called'; } catch (e) { out[String(arg)] = String(e && e.message); }
				 }
				 module.exports = out;`, 'p.js');
			assert.strictEqual(crypto.getFips(), before, 'host FIPS state changed');
			for (const k of ['0', '1', 'true', 'false']) {
				assert.ok(/disabled in vm2 sandboxes/.test(res[k]), 'crypto.setFips(' + k + ') was not blocked by the sandbox stub (got: ' + res[k] + ')');
			}
		} finally {
			try { crypto.setFips(before); } catch (e) {}
		}
	});

	itCond('does not over-block: getFips() and ordinary crypto still work in the sandbox', HAS_FIPS, function () {
		const res = new NodeVM({require: {external: false, builtin: ['crypto']}}).run(
			`const c = require('crypto');
			 module.exports = {
			   fips: typeof c.getFips() === 'number' || typeof c.getFips() === 'boolean',
			   hash: c.createHash('sha256').update('x').digest('hex').length,
			   rand: c.randomBytes(8).length
			 };`, 'p.js');
		assert.strictEqual(res.fips, true, 'getFips() (read-only) should still work');
		assert.strictEqual(res.hash, 64, 'createHash regressed');
		assert.strictEqual(res.rand, 8, 'randomBytes regressed');
	});

	it('setEngine remains disabled too (the pre-existing GHSA-46pr neutralization)', function () {
		const res = new NodeVM({require: {external: false, builtin: ['crypto']}}).run(
			`try { require('crypto').setEngine('x'); module.exports = 'called'; }
			 catch (e) { module.exports = 'blocked'; }`, 'p.js');
		assert.strictEqual(res, 'blocked', 'crypto.setEngine regressed');
	});
});
