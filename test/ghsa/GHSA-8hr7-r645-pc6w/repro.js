/**
 * GHSA-8hr7-r645-pc6w — NodeVM nesting guard accepts array-shaped require → host RCE
 *
 * ## Vulnerability class
 *
 * Patch-bypass of the published GHSA-m4wx-m65x-ghrr nesting guard. `nesting: true`
 * is an escape hatch that injects `NESTING_OVERRIDE` (exposes host `vm2` to the
 * sandbox so it can build nested VMs). m4wx added a guard that rejects `nesting`
 * unless the embedder passes an explicit `require` **config object**, so the
 * escape-hatch tradeoff is deliberate and visible.
 *
 * The guard is:
 *     hasRealRequireConfig =
 *         requireOpts instanceof Resolver ||
 *         (typeof requireOpts === 'object' && requireOpts !== null);
 *
 * `typeof x === 'object'` is true for arrays and every exotic object
 * (`Date`, `RegExp`, `Map`, …), none of which are a VMRequire config. Such a
 * value passes the guard, `makeResolverFromLegacyOptions` destructures it to
 * all-`undefined` config fields, merges `NESTING_OVERRIDE`, and returns a
 * resolver that exposes host `vm2` with NO builtin/external restriction. The
 * sandbox then `require('vm2')`, builds an inner `NodeVM` with an
 * attacker-chosen builtin allowlist, and runs `child_process` → host RCE.
 *
 * ## Fix
 *
 * The guard must accept only a genuine require config — a `Resolver` or a plain
 * config object — rejecting arrays and other non-plain-object shapes, so
 * `{nesting:true, require:[]}` throws the m4wx guard error (nesting without an
 * explicit config). Empty/plain configs (`{}`, `{builtin:[]}`) keep working.
 *
 * ## Oracle
 *
 * Attempt the PoC and assert the sandbox never reaches host `child_process`
 * (marker 'PWN'). The fix either throws at construction (malformed nesting
 * config) or denies `require('vm2')` — either way no host command runs.
 */

'use strict';

const assert = require('assert');
const { NodeVM, VMError } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

// Build a NodeVM with the given require option + nesting, run the nested-escape
// payload, and return 'PWN' iff the sandbox reached host child_process. Any
// construction/run throw (the fix's guard) is a safe outcome.
function attemptEscape(requireOpt) {
	const payload =
		"const { NodeVM } = require('vm2');\n" +
		"const inner = new NodeVM({ require: { builtin: ['child_process'] } });\n" +
		"module.exports = inner.run(\"module.exports = require('child_process').execSync('echo PWN').toString().trim()\");";
	try {
		const outer = new NodeVM({ nesting: true, require: requireOpt });
		return outer.run(payload, 'attacker.js');
	} catch (e) {
		return 'BLOCKED:' + (e && e.name) + ':' + String(e && e.message).slice(0, 30);
	}
}

describe('GHSA-8hr7-r645-pc6w (nesting guard accepts non-config require → RCE)', function () {

	it('canonical PoC: {nesting:true, require:[]} must not reach host child_process', function () {
		const out = attemptEscape([]);
		assert.notStrictEqual(out, 'PWN', 'sandbox reached host child_process via array-shaped require');
	});

	it('variant: require = new Array(0) (array subclass-free) must not escape', function () {
		const out = attemptEscape(new Array());
		assert.notStrictEqual(out, 'PWN', 'sandbox escaped via new Array() require');
	});

	it('variant: require = Date instance (exotic object) must not escape', function () {
		const out = attemptEscape(new Date());
		assert.notStrictEqual(out, 'PWN', 'sandbox escaped via Date-shaped require');
	});

	it('variant: require = RegExp (exotic object) must not escape', function () {
		const out = attemptEscape(/x/);
		assert.notStrictEqual(out, 'PWN', 'sandbox escaped via RegExp-shaped require');
	});

	it('variant: require = Map instance (exotic object) must not escape', function () {
		const out = attemptEscape(new Map());
		assert.notStrictEqual(out, 'PWN', 'sandbox escaped via Map-shaped require');
	});

	it('variant: require = a function must not escape (already covered by m4wx, regression guard)', function () {
		const out = attemptEscape(function () {});
		assert.notStrictEqual(out, 'PWN', 'sandbox escaped via function-shaped require');
	});

	// ---- The guard should throw for malformed nesting configs (m4wx contract) ----

	it('{nesting:true, require:[]} throws a VMError at construction (not silently permissive)', function () {
		assert.throws(function () {
			new NodeVM({ nesting: true, require: [] });
		}, function (e) {
			return e instanceof VMError && /nesting/i.test(e.message);
		}, 'array-shaped require under nesting should throw the m4wx guard error');
	});

	// ---- Over-block guards: legitimate nesting configs must still work ----

	it('regression: {nesting:true, require:{builtin:[]}} still allows a nested VM', function () {
		const vm = new NodeVM({ nesting: true, require: { builtin: [] } });
		const nested = vm.run(
			"const { VM } = require('vm2');\n" +
			"const inner = new VM();\n" +
			"module.exports = inner.run('1 + 2');",
			'vm.js'
		);
		assert.strictEqual(nested, 3, 'legitimate nesting (explicit plain-object require) regressed');
	});

	it('regression: {nesting:true, require:{}} (empty plain object) is accepted (deliberate escape-hatch)', function () {
		assert.doesNotThrow(function () {
			new NodeVM({ nesting: true, require: {} });
		}, 'empty plain-object require under nesting must remain the documented opt-in');
	});

	it('regression: a plain-object require without nesting is unaffected', function () {
		const vm = new NodeVM({ require: { builtin: ['assert'] } });
		const ok = vm.run("module.exports = typeof require('assert') === 'function' || typeof require('assert') === 'object';", 'x.js');
		assert.strictEqual(ok, true);
	});

	it('non-nesting guard: {nesting:false, require:[]} does not expose host vm2', function () {
		const vm = new NodeVM({ nesting: false, require: [] });
		const reached = vm.run(
			"var r; try { require('vm2'); r = 'GOT-VM2'; } catch (e) { r = 'denied'; } module.exports = r;",
			'x.js'
		);
		assert.notStrictEqual(reached, 'GOT-VM2', 'array-require without nesting must not expose vm2');
	});
});
