/**
 * GHSA-m4wx-m65x-ghrr — GHSA-8hg8-63c5-gwmx patch bypass: NodeVM `nesting`
 * combined with anything other than a real `require` config object produces
 * a NESTING_OVERRIDE-only resolver → host RCE.
 *
 * ## Vulnerability
 *
 * A truthy `nesting` injects a NESTING_OVERRIDE builtin exposing `vm2` to
 * sandbox code. When `requireOpts` is not a real require-config object,
 * `makeResolverFromLegacyOptions` produces a resolver whose ONLY builtin is
 * `vm2` — a pure escape primitive. Sandbox code does `require('vm2')`,
 * constructs an inner `NodeVM({ require: { builtin: ['child_process'] } })`
 * whose config is *not* constrained by the outer VM, and reaches
 * `child_process.execSync` for full host RCE.
 *
 * Three input-shape classes all collapse to the same insecure resolver:
 *
 *   A. **Falsy / omitted `require`** (`false`, `undefined`, `null`, `0`,
 *      `''`, or field omitted entirely) — `makeResolverFromLegacyOptions`
 *      hits its `if (!options)` branch.
 *
 *   B. **Truthy non-object `require`** (`true`, `1`, `'yes'`, `Symbol()`,
 *      `function(){}`) — destructures to all-`undefined`, then calls
 *      `makeBuiltinsFromLegacyOptions(undefined, …, NESTING_OVERRIDE)` —
 *      the same call shape the falsy branch produces.
 *
 *   C. **Truthy non-`true` `nesting`** (`1`, `'yes'`, `{}`, `[]`,
 *      `function(){}`) — the override gate below is
 *      `nesting && NESTING_OVERRIDE`, which fires for ANY truthy value,
 *      so any "I didn't really mean `true`" assignment still injects
 *      the override.
 *
 * GHSA-8hg8-63c5-gwmx's original check `options.require === false` only
 * caught one syntactic shape from class A. The structural check below
 * matches the actual reachability of the insecure resolver.
 *
 * ## Fix
 *
 *     const hasRealRequireConfig =
 *         requireOpts instanceof Resolver
 *         || (typeof requireOpts === 'object' && requireOpts !== null);
 *     if (nesting && !hasRealRequireConfig) throw VMError(...)
 *
 * - `nesting` checked as truthy — matches the `nesting && NESTING_OVERRIDE`
 *   gate that decides whether `vm2` is exposed.
 * - `requireOpts` must be a non-null object (or a custom `Resolver`).
 *   Primitives and functions all destructure to all-undefined inside
 *   `makeResolverFromLegacyOptions` and produce the insecure resolver.
 * - The documented escape hatch (a truthy `nesting` + an explicit `require`
 *   config object, even `{}` or `Object.create(null)`) keeps working —
 *   non-null object means the developer acknowledged the tradeoff.
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

	// ─── Truthy non-true `nesting` must reject ──────────────────────────────
	//
	// The override gate is `nesting && NESTING_OVERRIDE`, which fires for any
	// truthy value. The guard matches that, so every truthy `nesting` paired
	// with a non-config `require` rejects at construction.

	const TRUTHY_NESTING = [
		['number',  1],
		['string',  'yes'],
		['object',  {}],
		['array',   []],
		['fn',      function(){}]
	];

	for (const [label, value] of TRUTHY_NESTING) {
		it(`rejects { nesting: <${label}>, require: false } (truthy non-true nesting)`, () => {
			assert.throws(
				() => new NodeVM({nesting: value, require: false}),
				err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message),
				`truthy nesting=${label} must reject — override gate is truthy, not ===true`
			);
		});
	}

	it('truthy-nesting PoC (nesting:1) cannot reach require(\'vm2\')', () => {
		// Full chained PoC for the truthy-nesting class — construction throws
		// so vm.run never executes.
		assert.throws(() => {
			const vm = new NodeVM({nesting: 1, require: false});
			vm.run(`
				const { NodeVM: NVM } = require('vm2');
				const inner = new NVM({ require: { builtin: ['child_process'] } });
				module.exports = inner.run('module.exports = require("child_process").execSync("echo PWN").toString().trim()');
			`);
		}, err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message));
	});

	// ─── Truthy non-object `require` must reject ────────────────────────────
	//
	// Primitives and functions destructure to all-undefined inside
	// `makeResolverFromLegacyOptions`, producing the same
	// NESTING_OVERRIDE-only resolver as the falsy branch. The guard requires
	// a non-null object (or a `Resolver` instance) to count as a real config.

	const TRUTHY_NONOBJECT_REQUIRE = [
		['true',     true],
		['number',   1],
		['string',   'truthy'],
		['symbol',   Symbol('x')],
		['function', function(){}]
	];

	for (const [label, value] of TRUTHY_NONOBJECT_REQUIRE) {
		it(`rejects { nesting: true, require: <${label}> } (truthy non-object require)`, () => {
			assert.throws(
				() => new NodeVM({nesting: true, require: value}),
				err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message),
				`require=${label} destructures to all-undefined → same insecure resolver`
			);
		});
	}

	it('truthy-require PoC (require:true) cannot reach require(\'vm2\')', () => {
		// Full chained PoC for the truthy-non-object-require class —
		// construction throws so vm.run never executes.
		assert.throws(() => {
			const vm = new NodeVM({nesting: true, require: true});
			vm.run(`
				const { NodeVM: NVM } = require('vm2');
				const inner = new NVM({ require: { builtin: ['child_process'] } });
				module.exports = inner.run('module.exports = require("child_process").execSync("echo PWN").toString().trim()');
			`);
		}, err => err instanceof VMError && /GHSA-m4wx-m65x-ghrr/.test(err.message));
	});

	// ─── Regression guards: legitimate configs continue to work ─────────────

	it('accepts { nesting: true, require: Object.create(null) } (null-proto config object)', () => {
		// A plain object with a null prototype is still a non-null object
		// — counts as deliberate acknowledgment of the escape hatch.
		assert.doesNotThrow(() => new NodeVM({nesting: true, require: Object.create(null)}));
	});

	it('accepts { nesting: true, require: <Resolver> } (custom resolver path)', () => {
		// `customResolver = requireOpts instanceof Resolver` short-circuits
		// `makeResolverFromLegacyOptions`, so NESTING_OVERRIDE is never even
		// injected into a custom Resolver — the guard must not reject it.
		const { makeResolverFromLegacyOptions } = require('../../../lib/main.js');
		const customResolver = makeResolverFromLegacyOptions({builtin: []});
		assert.doesNotThrow(() => new NodeVM({nesting: true, require: customResolver}));
	});

});
