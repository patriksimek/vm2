/**
 * GHSA-r273-hxvj-fxhp — util.getCallSites() bypasses GHSA-v27g host-frame
 * redaction and leaks the host call stack to the sandbox.
 *
 * NodeVM exposes host `util` to the sandbox via an unfiltered shallow copy
 * (`Object.assign({}, util)` in `defaultBuiltinLoaderUtil`, lib/builtin.js), and
 * `sys` (a util alias) via the generic read-only loader. On Node >= 22.9 that
 * hands the sandbox `util.getCallSites()`, which returns the host process call
 * stack — absolute file paths (vm2's own lib/, the embedder entrypoint), Node
 * internals, function names and line numbers — as plain data. It is produced
 * host-side and never crosses the v27g sandbox-realm stack formatter, so v27g's
 * host-frame redaction (Defense Invariant #5) does not cover it.
 *
 * Info disclosure only (strings/numbers, no host object refs, no RCE). These
 * tests assert the SECURITY property (no host filesystem path reaches the
 * sandbox through util/sys), independent of how the fix neutralizes the member.
 * They fail on the unpatched tree and pass once util/sys are filtered.
 */
'use strict';

const assert = require('assert');
const path = require('path');
const {NodeVM} = require('../../../lib/main.js');

const HAS_GETCALLSITES = typeof require('util').getCallSites === 'function';

// A host path is anything absolute, or containing this repo's own path, or a
// `node:internal` / vm2 `lib/` frame. Sandbox-realm frames (e.g. `p.js`,
// `vm.js`) are fine.
const REPO_ROOT = path.resolve(__dirname, '../../..');
function leaksHostPath(names) {
	return names.some(n => typeof n === 'string' && (
		n.charAt(0) === '/' || /^[A-Za-z]:[\\/]/.test(n) ||
		n.indexOf(REPO_ROOT) === 0 || n.indexOf('node:internal') === 0 ||
		/[\\/]lib[\\/](bridge|nodevm|setup-sandbox|builtin)\.js/.test(n)
	));
}

// Returns the array of scriptNames getCallSites hands the sandbox, or a marker.
function callSiteScriptNames(builtinCfg, moduleName) {
	const code = `
		const u = require(${JSON.stringify(moduleName)});
		if (typeof u.getCallSites !== 'function') { module.exports = '__NO_API__'; }
		else {
			try { module.exports = u.getCallSites(16).map(function(f){ return f.scriptName; }); }
			catch (e) { module.exports = '__THREW__'; }
		}`;
	return new NodeVM({require: {builtin: builtinCfg}}).run(code, 'p.js');
}

(HAS_GETCALLSITES ? describe : describe.skip)('GHSA-r273-hxvj-fxhp — util.getCallSites host call-stack leak', function () {

	it('builtin:[util] — getCallSites must not deliver a host filesystem path', function () {
		const names = callSiteScriptNames(['util'], 'util');
		if (names === '__NO_API__' || names === '__THREW__') return; // neutralized by removal/stub — acceptable
		assert.ok(Array.isArray(names), 'getCallSites returned a non-array');
		assert.strictEqual(leaksHostPath(names), false,
			'sandbox read host frames via util.getCallSites: ' + JSON.stringify(names.filter(Boolean).slice(0, 4)));
	});

	it('builtin:[sys] — the util alias must not leak host frames either', function () {
		const names = callSiteScriptNames(['sys'], 'sys');
		if (names === '__NO_API__' || names === '__THREW__') return;
		assert.ok(Array.isArray(names), 'getCallSites returned a non-array');
		assert.strictEqual(leaksHostPath(names), false,
			'sandbox read host frames via sys.getCallSites: ' + JSON.stringify(names.filter(Boolean).slice(0, 4)));
	});

	it('builtin:[*] wildcard — same protection under the wildcard', function () {
		const names = callSiteScriptNames(['*'], 'util');
		if (names === '__NO_API__' || names === '__THREW__') return;
		assert.ok(Array.isArray(names), 'getCallSites returned a non-array');
		assert.strictEqual(leaksHostPath(names), false,
			'sandbox read host frames via util.getCallSites under wildcard: ' + JSON.stringify(names.filter(Boolean).slice(0, 4)));
	});

	it('does not over-block: ordinary util members still work', function () {
		const out = new NodeVM({require: {builtin: ['util']}}).run(`
			const u = require('util');
			module.exports = [u.format('%s-%d', 'x', 7), u.inspect({a:1}), typeof u.promisify, typeof u.types.isDate].join('|');
		`, 'p.js');
		assert.strictEqual(out, 'x-7|{ a: 1 }|function|function');
	});
});
