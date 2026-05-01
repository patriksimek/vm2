/**
 * GHSA-8hg8-63c5-gwmx — `nesting: true` bypasses `require: false`
 *
 * ## Vulnerability
 * `new NodeVM({ nesting: true, require: false })` constructed a permissive
 * resolver containing the `NESTING_OVERRIDE` builtin (which exposes `vm2`)
 * despite `require: false`. Sandbox code could `require('vm2')`, construct
 * an inner `NodeVM` with attacker-chosen `require` config, and load
 * `child_process` for full host RCE. The mental-model mismatch — developer
 * sets `require: false` to lock down modules, then enables `nesting: true`
 * for legitimate child-VM use — silently produces an unsandboxed config.
 *
 * ## Fix
 * `NodeVM` constructor throws `VMError` immediately when both `nesting: true`
 * and `require: false` are set explicitly. Forces the developer to make a
 * deliberate choice: drop `nesting`, or replace `require: false` with an
 * explicit `require` config. Same shape as the cp6g eager FileSystem probe.
 *
 * ## Out of scope
 * `nesting: true` is fundamentally an escape hatch (sandbox can `require('vm2')`
 * and construct inner NodeVMs unconstrained by the outer config). This fix
 * closes the specific contradictory-config trap; the broader escape-hatch
 * nature of `nesting: true` is now documented prominently in README §
 * "`nesting: true` is an escape hatch".
 */

'use strict';

const assert = require('assert');
const { NodeVM, VMError } = require('../../../lib/main.js');

describe('GHSA-8hg8-63c5-gwmx — nesting: true bypasses require: false', () => {

	it('rejects { nesting: true, require: false } at construction', () => {
		assert.throws(
			() => new NodeVM({ nesting: true, require: false }),
			err => err instanceof VMError
				&& /nesting/.test(err.message)
				&& /require/.test(err.message)
				&& /GHSA-8hg8-63c5-gwmx/.test(err.message),
			'construction should fail with a VMError citing nesting, require, and the advisory'
		);
	});

	it('original PoC config is blocked at construction (cannot reach require(\'vm2\'))', () => {
		// Without the fix, this would succeed and the inner VM would execute
		// child_process.execSync('id'). With the fix, construction throws
		// before vm.run is ever called.
		assert.throws(() => {
			const vm = new NodeVM({ nesting: true, require: false });
			vm.run(`
				const { NodeVM: NVM } = require('vm2');
				const inner = new NVM({ require: { builtin: ['child_process'] } });
				module.exports = inner.run('module.exports = require("child_process").execSync("id").toString()');
			`);
		}, err => err instanceof VMError && /GHSA-8hg8-63c5-gwmx/.test(err.message));
	});

	it('accepts { nesting: true, require: { builtin: [] } } (explicit empty allowlist)', () => {
		// Legitimate use: nesting enabled, no other host modules. Developer
		// has explicitly acknowledged that vm2 will be requireable.
		assert.doesNotThrow(() => new NodeVM({ nesting: true, require: { builtin: [] } }));
	});

	it('accepts { nesting: true } alone (default require — escape-hatch use, documented)', () => {
		// Bare `nesting: true` continues to work as documented. The README
		// "`nesting: true` is an escape hatch" section explains the trade-off.
		// Not closed here (would require Option C constraint propagation —
		// out of scope for 3.11.1). This regression test ensures the narrow
		// fix doesn't accidentally break the bare-nesting case.
		assert.doesNotThrow(() => new NodeVM({ nesting: true }));
	});

	it('accepts { require: false } alone (no nesting — deny all requires)', () => {
		// Existing behavior: require: false without nesting is fine — sandbox
		// truly cannot require anything. Regression guard.
		assert.doesNotThrow(() => new NodeVM({ require: false }));
	});

	it('accepts { } (default config — no nesting, no require)', () => {
		// Regression guard for the most common case.
		assert.doesNotThrow(() => new NodeVM());
	});

});
