/**
 * GHSA-m4wx-m65x-ghrr — GHSA-8hg8-63c5-gwmx patch bypass via omitted `require`
 *
 * ## Vulnerability
 * The GHSA-8hg8-63c5-gwmx fix added a guard at the top of `NodeVM`:
 *
 *     if (options.nesting === true && options.require === false) throw VMError(...)
 *
 * The check used strict equality against the raw input `options.require`.
 * `options.require === false` is only true when the embedder *explicitly*
 * sets `require: false`. Omitting `require` entirely (the much more common
 * case) leaves `options.require === undefined`, the check is skipped, and
 * the destructuring default a few lines below (`require: requireOpts = false`)
 * yields the exact `requireOpts = false` the patch was meant to prevent.
 *
 * `makeResolverFromLegacyOptions(false, NESTING_OVERRIDE, ...)` then builds a
 * resolver whose only builtin is `vm2`. Sandbox code does
 * `require('vm2')`, constructs an inner `NodeVM({ require: { builtin:
 * ['child_process'] } })` whose config is *not* constrained by the outer VM,
 * and reaches `child_process.execSync` for full host RCE.
 *
 * Same insecure resolver is produced for: `require: false`, `require: undefined`,
 * `require: null`, `require: 0`, `require: ''` — any falsy value, including
 * "field omitted entirely".
 *
 * ## Fix
 * Move the check *after* destructuring and test the computed `requireOpts`
 * with `!requireOpts` so every path that produces a NESTING_OVERRIDE-only
 * resolver is rejected at construction:
 *
 *     const { require: requireOpts = false, nesting = false, ... } = options;
 *     if (nesting === true && !requireOpts) throw VMError(...)
 *
 * This subsumes the GHSA-8hg8-63c5-gwmx fix: explicit `require: false`,
 * omitted `require`, and any other falsy value all collapse to the same
 * rejection. The escape hatch (`nesting: true` + an explicit `require`
 * config object) continues to work — the developer's intent is visible.
 */

'use strict';

const assert = require('assert');
const {NodeVM, VMError} = require('../../../lib/main.js');

describe('GHSA-m4wx-m65x-ghrr — nesting:true without explicit require still RCE', () => {

	it('rejects { nesting: true } alone (require omitted → defaults to false)', () => {
		// The literal PoC config from the advisory.
		assert.throws(
			() => new NodeVM({nesting: true}),
			err => err instanceof VMError
				&& /nesting/.test(err.message)
				&& /require/.test(err.message)
				&& /GHSA-m4wx-m65x-ghrr/.test(err.message),
			'construction must fail with a VMError citing nesting, require, and the advisory'
		);
	});

	it('rejects { nesting: true, require: undefined } (explicit undefined)', () => {
		assert.throws(
			() => new NodeVM({nesting: true, require: undefined}),
			err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message)
		);
	});

	it('rejects { nesting: true, require: null } (null → falsy, same insecure resolver)', () => {
		// makeResolverFromLegacyOptions(null, NESTING_OVERRIDE) hits the
		// `if (!options)` branch the same way `false` does.
		assert.throws(
			() => new NodeVM({nesting: true, require: null}),
			err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message)
		);
	});

	it('rejects { nesting: true, require: 0 } (other falsy values)', () => {
		assert.throws(
			() => new NodeVM({nesting: true, require: 0}),
			err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message)
		);
	});

	it('rejects { nesting: true, require: false } (still covers the original GHSA-8hg8 case)', () => {
		// Regression guard for the prior fix — must continue to throw.
		assert.throws(
			() => new NodeVM({nesting: true, require: false}),
			err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message)
		);
	});

	it('full PoC cannot reach require(\'vm2\') — construction throws before vm.run', () => {
		// Without the fix this prints the host `id` output; with the fix the
		// outer NodeVM never gets to vm.run().
		assert.throws(() => {
			const vm = new NodeVM({nesting: true}); // <-- bare PoC config
			vm.run(`
				const { NodeVM: NVM } = require('vm2');
				const inner = new NVM({ require: { builtin: ['child_process'] } });
				module.exports = inner.run('module.exports = require("child_process").execSync("id").toString()');
			`);
		}, err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message));
	});

	it('accepts { nesting: true, require: { builtin: [] } } (explicit empty allowlist — escape hatch)', () => {
		// Legitimate use: the developer explicitly opted into the documented
		// "nesting is an escape hatch" trade-off by providing a require config.
		assert.doesNotThrow(() => new NodeVM({nesting: true, require: {builtin: []}}));
	});

	it('accepts { nesting: true, require: {} } (empty object is a deliberate config)', () => {
		// `require: {}` is truthy and counts as the developer having made an
		// explicit choice (even if it permits nothing beyond the NESTING_OVERRIDE).
		assert.doesNotThrow(() => new NodeVM({nesting: true, require: {}}));
	});

	it('accepts { require: false } alone (no nesting — deny-all stays valid)', () => {
		// Regression guard: require:false without nesting must continue to work.
		assert.doesNotThrow(() => new NodeVM({require: false}));
	});

	it('accepts { } (default constructor)', () => {
		// The default config has nesting:false, so the new guard does not fire.
		assert.doesNotThrow(() => new NodeVM());
	});

});
