/**
 * GHSA-grj5-jjm8-h35p — Array species self-return sandbox escape
 *
 *
 * ## Vulnerability
 * V8's `ArraySpeciesCreate` (invoked internally by `Array.prototype.{map,filter,
 * slice,concat,splice,flat,flatMap}`) reads `this.constructor[Symbol.species]`
 * directly on raw objects, bypassing the bridge proxy's trap handlers. An
 * attacker walked the prototype chain with `({}).__lookupGetter__` + `Buffer.apply`
 * to obtain host `Object`, used `ho.entries({})` to get a host-realm array `r`,
 * installed a sandbox `constructor` whose `[Symbol.species]` returned `r` itself,
 * then called `r.map(f)` — causing V8 to write raw host values directly into the
 * sandbox-visible array and bypass bridge sanitisation entirely. Cross-reference:
 * docs/ATTACKS.md Category 18 (Array Species Self-Return via Constructor
 * Manipulation).
 *
 * ## Fix
 * Two-layer defense in `lib/bridge.js`: (1) the proxy `get` trap for
 * `constructor` on host arrays now returns a cached `Array` constructor captured
 * at module load (prototype-pollution-proof), neutralising any sandbox-side read
 * of the attacker-installed constructor; (2) the `apply`/`construct` traps
 * neutralise every host array reachable as context or argument by shadowing
 * `constructor = undefined` as a data own property before `otherReflectApply`,
 * then restoring the prior descriptor in a `finally`. Non-configurable or
 * non-extensible arrays with attacker state are rejected with `VMError`.
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

// SECURITY: this prelude is common across variant tests. It uses the
// `({}).__lookupGetter__` + `Buffer.apply` trick to walk the prototype chain until
// it obtains a reference to the HOST `Object` constructor. `ho.entries({})` then
// returns a host-realm array -- the primitive surface for the species attack.
const PRELUDE = `
	const g = ({}).__lookupGetter__;
	const a = Buffer.apply;
	const p = a.apply(g, [Buffer, ['__proto__']]);
	const op = p.call(p.call(p.call(p.call(Buffer.of()))));
	const ho = op.constructor; // host Object
`;

function assertBlocked(label, code) {
	const vm = new VM();
	let result;
	let thrown = null;
	try {
		result = vm.run(PRELUDE + code);
	} catch (e) {
		thrown = e;
	}
	// Test code signals the outcome through its own return value:
	//   - 'BLOCKED' means the attack attempt threw inside the sandbox (caught by test code)
	//   - 'NO_ESCAPE' means the attack completed but did NOT escape (fix worked silently)
	// Any other string means the exploit may have succeeded.
	if (thrown) return; // a bridge-level throw also counts as blocked
	assert.ok(
		result === 'BLOCKED' || result === 'NO_ESCAPE',
		`[${label}] expected BLOCKED or NO_ESCAPE, got: ${JSON.stringify(result)}`,
	);
}

describe('GHSA-grj5-jjm8-h35p (array species self-return escape)', () => {
	it('blocks the raw species primitive (r.constructor = x + r.map writes into r)', () => {
		assertBlocked(
			'species-primitive',
			`
			try {
				const r = ho.entries({});
				r.push(1, 2);
				function x() { return r; }
				x[Symbol.species] = x;
				r.constructor = x;
				const mapped = r.map(function (v) { return 'm' + v; });
				// The defense is successful iff V8 does NOT return r as the mapped
				// array (because r.constructor is neutralized to undefined during
				// the map call, so ArraySpeciesCreate falls back to default %Array%).
				if (mapped === r) 'ESCAPE-species-returned-self';
				else if (r[0] !== 1) 'ESCAPE-r-was-mutated';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('blocks the canonical PoC chain (cwu helper + Function extraction)', () => {
		assertBlocked(
			'canonical-poc',
			`
			try {
				function cwu(func, thiz, args) {
					const r = ho.entries({});
					args.unshift(thiz);
					const f = a.apply(a.bind, [func, args]);
					r[0] = 0;
					function x() { return r; }
					x[Symbol.species] = x;
					r.constructor = x;
					r.map(f);
					r.constructor = undefined;
					return r;
				}
				const fp = cwu(p.call, p, [a]);
				const cd = cwu(ho.getOwnPropertyDescriptors, undefined, fp);
				const xx = cwu(ho.entries, undefined, cd);
				xx[1] = [4];
				const ee = cwu(a, xx.at, xx);
				ee[1] = [1];
				const y = cwu(a, ee.at, ee);
				const ey = cwu(ho.entries, 0, y);
				ey[1] = [0];
				const ea = cwu(a, ee.at, ey);
				ea[1] = [1];
				const e = cwu(a, ee.at, ea);
				e.push([undefined,['return process']]);
				const leaked = a.apply(a, e);
				// If we got here, the fix failed and attacker has Function ctor.
				'ESCAPE-canonical:' + typeof leaked;
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('blocks the Object.assign backdoor for installing constructor', () => {
		assertBlocked(
			'object-assign',
			`
			try {
				const r = ho.entries({});
				r.push(1);
				function x() { return r; }
				x[Symbol.species] = x;
				ho.assign(r, { constructor: x });
				const mapped = r.map(function (v) { return 'm' + v; });
				if (mapped === r) 'ESCAPE-assign-species-returned-self';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('rejects non-configurable attacker-installed constructor', () => {
		assertBlocked(
			'non-configurable',
			`
			try {
				const r = ho.entries({});
				r.push(1);
				function x() { return r; }
				x[Symbol.species] = x;
				ho.defineProperty(r, 'constructor', {
					value: x, writable: false, enumerable: false, configurable: false
				});
				// After this, ANY host call that includes r as context/arg must be rejected
				// because we cannot safely neutralize the species channel.
				const mapped = r.map(function (v) { return 'm' + v; });
				if (mapped === r) 'ESCAPE-nonconfig-species';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('blocks prototype-level constructor injection (intermediate proto)', () => {
		assertBlocked(
			'proto-level',
			`
			try {
				const r = ho.entries({});
				r.push(1);
				function x() { return r; }
				x[Symbol.species] = x;
				const fake = ho.create(Array.prototype);
				fake.constructor = x;
				ho.setPrototypeOf(r, fake);
				const mapped = r.map(function (v) { return 'm' + v; });
				if (mapped === r) 'ESCAPE-proto-species';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('rejects preventExtensions-d host arrays with attacker state', () => {
		assertBlocked(
			'prevent-extensions',
			`
			try {
				const r = ho.entries({});
				r.push(1);
				function x() { return r; }
				x[Symbol.species] = x;
				// Install constructor first (as configurable), then preventExtensions.
				// After preventExtensions, existing own properties can be reconfigured
				// (as long as they stay configurable), so the fix still neutralizes.
				r.constructor = x;
				ho.preventExtensions(r);
				const mapped = r.map(function (v) { return 'm' + v; });
				if (mapped === r) 'ESCAPE-preventExt-species';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('blocks species attacks through filter and slice', () => {
		assertBlocked(
			'filter-slice',
			`
			try {
				const r = ho.entries({});
				r.push(1, 2);
				function x() { return r; }
				x[Symbol.species] = x;
				r.constructor = x;
				const filtered = r.filter(function () { return true; });
				const sliced = r.slice(0);
				if (filtered === r || sliced === r) 'ESCAPE-filter-slice-species';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});

	it('blocks species attack on concat result', () => {
		assertBlocked(
			'concat',
			`
			try {
				const r = ho.entries({});
				r.push(1);
				function x() { return r; }
				x[Symbol.species] = x;
				r.constructor = x;
				const concated = r.concat([2]);
				if (concated === r) 'ESCAPE-concat-species';
				else 'NO_ESCAPE';
			} catch (e) { 'BLOCKED' }
		`,
		);
	});
});
