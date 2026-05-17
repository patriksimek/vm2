/**
 * GHSA-q3fm-4wcw-g57x — Defense Invariant #11 violation in stack-trace formatter
 *
 * ## Vulnerability
 * `defaultSandboxPrepareStackTrace` in `lib/setup-sandbox.js` accumulates formatted
 * frames in a sandbox-realm array via `lines[lines.length] = '    at ' + callSites[i]`.
 * That index assignment walks `Array.prototype` when no own slot exists, so a
 * sandbox-installed setter on `Array.prototype[N]` fires during the bridge's safe-
 * default stack-trace formatting. The container is bridge-internal — Invariant #11
 * forbids it from invoking sandbox code. The final `lines.join('\n')` is the same
 * problem on the read side: a sandbox-installed `Array.prototype.join` override
 * would intercept the assembled output.
 *
 * No host-realm reference reaches the setter today (the value is a primitive
 * string sourced from the wrapped sandbox `CallSite.toString()`), so this is a
 * hardening fix rather than an exploit-today escape. The structural concern: a
 * future change that enriches the appended record would regress into the
 * GHSA-9qj6-qjgg-37qq attack shape against this codepath.
 *
 * ## Fix
 * The bridge no longer materialises an array. It folds each frame into a string
 * accumulator with primitive concatenation, eliminating both the prototype-walking
 * index assignment and the prototype-walking `.join` lookup. The bridge-internal
 * container is gone, and Invariant #11 is restored along this codepath.
 *
 * `makeCallSiteGetters` (also in `lib/setup-sandbox.js`) is converted to use
 * `localReflectDefineProperty` for symmetry — it runs at sandbox init before user
 * code can install setters, so it is safe today, but the consistent pattern
 * prevents future regressions.
 *
 * Cross-reference: docs/ATTACKS.md Category 28 Variant B (Defense Invariant #11).
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

function tryEscape(code) {
	const vm = new VM();
	let result;
	let thrown = null;
	try {
		result = vm.run(code);
	} catch (e) {
		thrown = e;
	}
	return { result, thrown };
}

describe('GHSA-q3fm-4wcw-g57x — defaultSandboxPrepareStackTrace setter leak', () => {
	it('Array.prototype[N] setter is not invoked while formatting error.stack', () => {
		// SECURITY: canonical PoC from the advisory. Installs a setter on
		// Array.prototype[1] (the first index the formatter would write to, given
		// the initial `[header]`). After the fix the formatter holds no array, so
		// the setter never fires regardless of the index installed.
		const { result } = tryEscape(`
			const observed = { setterFired: false, capturedValue: null, indexFired: null };
			for (const idx of [0, 1, 2, 3, 4, 5]) {
				Object.defineProperty(Array.prototype, idx, {
					configurable: true,
					set(value) {
						observed.setterFired = true;
						observed.indexFired = idx;
						observed.capturedValue =
							typeof value === 'string' ? value.slice(0, 40) : typeof value;
					},
					get() { return undefined; }
				});
			}
			const e = new Error('x');
			e.stack;
			observed;
		`);

		const out = result || {};
		assert.notStrictEqual(
			out.setterFired,
			true,
			'sandbox setter on Array.prototype[N] fired while formatting error.stack',
		);
	});

	it('Array.prototype.join override does not intercept the assembled stack string', () => {
		// SECURITY: the read-side companion to the index-write fix. Even if the
		// formatter still produced an array, a sandbox-controlled `.join` would
		// observe and rewrite the stack string handed back to sandbox code. The
		// fix removes the array entirely, so no method dispatch through
		// Array.prototype reaches sandbox code.
		const { result } = tryEscape(`
			const observed = { joinFired: false, joinArgs: null };
			const originalJoin = Array.prototype.join;
			Array.prototype.join = function joinHook(sep) {
				observed.joinFired = true;
				observed.joinArgs = { sep, len: this.length };
				return originalJoin.call(this, sep);
			};
			try {
				const e = new Error('x');
				e.stack;
			} finally {
				Array.prototype.join = originalJoin;
			}
			observed;
		`);

		const out = result || {};
		assert.notStrictEqual(
			out.joinFired,
			true,
			'sandbox Array.prototype.join override intercepted stack assembly',
		);
	});

	it('formatter still produces a usable stack string with the structural fix in place', () => {
		// SECURITY: regression guard. The fix must not regress the user-visible
		// shape of error.stack — sandbox developers still see their frames, and
		// the leading header is preserved.
		const { result } = tryEscape(`
			const e = new Error('hello');
			const s = e.stack;
			({ isString: typeof s === 'string', startsWithHeader: s.indexOf('Error: hello') === 0, hasAt: s.indexOf('    at ') !== -1 });
		`);

		const out = result || {};
		assert.strictEqual(out.isString, true, 'error.stack should still be a string');
		assert.strictEqual(out.startsWithHeader, true, 'error.stack should begin with the standard header');
		assert.strictEqual(out.hasAt, true, 'error.stack should still contain frame lines');
	});
});
