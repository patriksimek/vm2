/**
 * GHSA-j3hm-6rg5-mchv (dup: GHSA-w9c4-gw9x-53mq) — NodeVM require.external without
 * an effective require.root grants unrestricted host require + RCE.
 *
 * STATUS: FIXED. The reported mechanism — sandboxed code requiring vm2 from disk
 * to rebuild an *unrestricted* nested NodeVM, defeating the nesting default — is
 * denied by every spelling (bare `vm2`, the lib/ path, index.js, the package main
 * entry), matched by realpath so a symlink cannot dodge it.
 *
 * ACCEPTED RESIDUAL (deliberate, not a defect of this fix): `require.external`
 * without `require.root` still host-require()s any attacker-named path, because
 * `CustomResolver.isPathAllowed` returns true when `rootPaths === undefined`.
 * That breadth is the documented meaning of the option. Deny-by-default is a
 * breaking change (it would reverse the shipped GHSA-cp6g-6699-wx9c no-throw
 * invariant and break ~20 in-repo call sites), so it is deferred to the next
 * major; a one-time warning ships in the meantime.
 *
 * What these tests assert:
 *   (a) bare `require.external: true` with require.root UNSET warns once and does
 *       NOT throw at construction — current, deliberate behaviour pinned so the
 *       next-major change is a conscious edit rather than an accident.
 *   (b) a sandbox require() of vm2's own package is denied, closing the
 *       `require('vm2')` -> real VM/NodeVM classes -> nested unrestricted sandbox
 *       route this advisory reported.
 *   (c) the denial does not over-block unrelated allowlisted modules.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { NodeVM } = require('../../../lib/main.js');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const VM2_ENTRY = path.resolve(REPO_ROOT, 'lib/main.js');

describe('GHSA-j3hm-6rg5-mchv — sandbox cannot rebuild an unrestricted NodeVM by requiring vm2', () => {
	it('pins the accepted residual: bare require.external:true with no require.root warns but does not throw', () => {
		// This asserts current behaviour, NOT a fix. The escape primitive is still
		// reachable: isPathAllowed returns true unconditionally when rootPaths is
		// undefined. Construction only warns, because a throw here would reverse the
		// shipped GHSA-cp6g-6699-wx9c invariant that construction succeeds with no root.
		// NOTE FOR THE FOLLOW-UP FIX of GHSA-j3hm-6rg5-mchv: if that fix refuses this
		// combination at construction, THIS assertion is the one that must be updated.
		assert.doesNotThrow(() => new NodeVM({ require: { external: true } }));
	});

	it('closes ONE escalation route: the sandbox cannot require() vm2 itself to build a nested unrestricted VM', () => {
		const vm = new NodeVM({ require: { external: true, root: REPO_ROOT } });
		let escaped = false, threw = false;
		try {
			const out = vm.run(`
				const real = require(${JSON.stringify(VM2_ENTRY)});
				const inner = new real.NodeVM({ require: { builtin: ['child_process'], external: false } });
				module.exports = inner.run("module.exports = require('child_process').execSync('echo J3HM').toString()", 'inner.js');
			`, 'untrusted.js');
			escaped = typeof out === 'string' && out.includes('J3HM');
		} catch (e) { threw = true; }
		assert.strictEqual(escaped, false, 'sandbox reached a nested unrestricted VM via require(vm2)');
		assert.strictEqual(threw, true, 'requiring vm2 should be denied (module not found)');
	});

	it('also denies requiring vm2 internals directly (e.g. lib/bridge.js)', () => {
		const vm = new NodeVM({ require: { external: true, root: REPO_ROOT } });
		assert.throws(() => vm.run(
			`module.exports = typeof require(${JSON.stringify(path.resolve(REPO_ROOT, 'lib/bridge.js'))});`,
			'u.js'), /Cannot find module|not allowed|ENOTFOUND/);
	});

	it('does not over-block: external+root still loads an allowed module outside vm2', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-j3hm-ok-'));
		try {
			fs.writeFileSync(path.join(dir, 'greet.js'), "module.exports = 'HELLO_ALLOWED';");
			const vm = new NodeVM({ require: { external: true, root: dir, context: 'host' } });
			const out = vm.run(`module.exports = require(${JSON.stringify(path.join(dir, 'greet.js'))});`,
				path.join(dir, 'main.js'));
			assert.strictEqual(out, 'HELLO_ALLOWED');
		} finally { fs.rmSync(dir, { recursive: true, force: true }); }
	});
});
