/**
 * GHSA-8686-vhfx-7r3j — NodeVM `node:`-prefixed negative builtin deny token
 * is a silent no-op, exposing host `child_process` under `builtin: ['*']`.
 *
 * ## Vulnerability
 * `makeBuiltinsFromLegacyOptions` expands `builtin: ['*']` by iterating the
 * un-prefixed `BUILTIN_MODULES` names and, for each `name`, adding it unless
 * `builtins.indexOf('-' + name) === -1`. The deny token is matched by exact
 * string, so a `node:`-spelled deny token — `'-node:child_process'` — never
 * equals `'-child_process'` and matches nothing. The result: `['*',
 * '-node:child_process']` still exposes the real host `child_process`, and the
 * sandbox does `require('child_process').execSync(...)` for host RCE. The
 * canonical `'-child_process'` token works, so an embedder who wrote the
 * `node:` spelling (equally idiomatic) has a silently ineffective denylist.
 *
 * ## Fix
 * `lib/builtin.js`: normalize the `node:` URL prefix when matching negative
 * deny tokens, so `-node:child_process` denies `child_process` (and vice
 * versa), exactly as the resolver already normalizes `node:` on the require
 * side.
 *
 * ## Sound oracle
 * `require('child_process')` returning a module with a real `execSync`/`spawn`
 * is host reach. Both `child_process` and `node:child_process` spellings must
 * be denied when either deny-token spelling is used.
 */

'use strict';

const assert = require('assert');
const { NodeVM } = require('../../../lib/main.js');

function probe(builtin) {
	const vm = new NodeVM({ require: { builtin } });
	return vm.run(`
		const out = {};
		for (const spec of ['child_process', 'node:child_process']) {
			try {
				const cp = require(spec);
				out[spec] = { loaded: true, execSync: typeof cp.execSync };
			} catch (e) {
				out[spec] = { loaded: false, code: e && e.code };
			}
		}
		module.exports = out;
	`);
}

describe('GHSA-8686-vhfx-7r3j (node:-prefixed negative builtin deny token no-op)', function () {
	it('deny token `-node:child_process` blocks BOTH child_process spellings', function () {
		const r = probe(['*', '-node:child_process']);
		assert.strictEqual(r['child_process'].loaded, false, 'require("child_process") reached the host module despite -node:child_process');
		assert.strictEqual(r['node:child_process'].loaded, false, 'require("node:child_process") reached the host module despite -node:child_process');
	});

	it('canonical deny token `-child_process` still blocks both spellings (control)', function () {
		const r = probe(['*', '-child_process']);
		assert.strictEqual(r['child_process'].loaded, false, 'require("child_process") reached the host module despite -child_process');
		assert.strictEqual(r['node:child_process'].loaded, false, 'require("node:child_process") reached the host module despite -child_process');
	});

	it('does not over-deny: `-node:child_process` leaves other builtins available', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-node:child_process'] } });
		const ok = vm.run(`
			const path = require('path');
			module.exports = (typeof path.join === 'function' && typeof require('events').EventEmitter === 'function');
		`);
		assert.strictEqual(ok, true, 'a benign builtin (path) was wrongly denied');
	});
});
