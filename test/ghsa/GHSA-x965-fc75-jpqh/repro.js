/**
 * GHSA-x965-fc75-jpqh — incomplete-fix bypass of GHSA-m283-3h24-438v.
 *
 * handleException() (lib/setup-sandbox.js) memoizes visited carriers as
 * `visited.set(e, true)` and short-circuits a revisit with `return e` — the RAW
 * host carrier. For plain-Error carriers this is safe: sanitizeErrorCause /
 * sanitizeHostOwnProps seal the host object IN PLACE on first visit, so the raw
 * carrier returned on revisit is already neutralized. But sanitizeAggregateError
 * (and sanitizeSuppressedError) do NOT seal in place — they SNAPSHOT-REBUILD the
 * host-wrapped carrier into a fresh sandbox-realm error. So when the same host
 * aggregate is revisited within one traversal (self-cycle `agg.errors=[agg]`,
 * duplicate-in-array `[shared, shared]`, mutual-cycle `a.errors=[b]; b.errors=[a]`),
 * the short-circuit hands back the still-live raw host proxy, which the rebuild
 * re-embeds into the "sanitized" errors[] — a functional host reference reaching
 * sandbox code => host RCE on the caught-exception channel that Defense
 * Invariant #3 promises to sanitize.
 *
 * These tests fail (escape succeeds) on the unpatched tree and pass once the
 * revisit invariant is restored (seal host-wrapped aggregates in place, and/or
 * memoize the sandbox-realm replacement instead of `true`).
 */
'use strict';

const assert = require('assert');
const {VM} = require('../../../lib/main.js');

const HAS_AGGREGATE = typeof AggregateError === 'function';
const HAS_SUPPRESSED = typeof SuppressedError === 'function';

// Marker planted on the REAL host `process`. A sandbox that reaches the live
// host object can read this primitive back through the bridge; a sandbox that
// only ever sees sanitized replacements cannot.
function withMarker(fn) {
	const marker = 'X965_HOST_' + process.pid;
	Object.defineProperty(process, '__x965_marker', {value: marker, configurable: true, enumerable: false});
	try { return fn(marker); } finally { try { delete process.__x965_marker; } catch (_) {} }
}

// Run `hostThrow` inside a VM, catch it sandbox-side, and hunt every reachable
// error/own-property slot for the host marker. Returns the marker string if the
// sandbox reached the live host process, else 'NO-LEAK'.
function probe(hostThrow) {
	return withMarker(marker => {
		const vm = new VM({sandbox: {hostThrow}});
		const out = vm.run(`(function(){
			try { hostThrow(); } catch (e) {
				var seen = [];
				var found = null;
				function visit(x, depth){
					if (found || x === null || x === undefined || depth > 6) return;
					if (typeof x !== 'object' && typeof x !== 'function') return;
					for (var i = 0; i < seen.length; i++) if (seen[i] === x) return;
					seen.push(x);
					try { var m = x.__x965_marker; if (typeof m === 'string' && m.indexOf('X965_HOST_') === 0) { found = m; return; } } catch (_) {}
					try { if (x.errors) { for (var j = 0; j < x.errors.length; j++) visit(x.errors[j], depth+1); } } catch (_) {}
					try { visit(x.error, depth+1); } catch (_) {}       // SuppressedError.error
					try { visit(x.suppressed, depth+1); } catch (_) {}  // SuppressedError.suppressed
					try { visit(x.cause, depth+1); } catch (_) {}
					try { visit(x.leak, depth+1); } catch (_) {}
				}
				visit(e, 0);
				return found || 'NO-LEAK';
			}
			return 'no-throw';
		})()`);
		return out === marker ? 'ESCAPED' : out;
	});
}

(HAS_AGGREGATE ? describe : describe.skip)('GHSA-x965-fc75-jpqh — revisited host AggregateError leaks a live host proxy', function () {

	it('duplicate-in-array [shared, shared] must NOT deliver a live host ref (canonical PoC)', function () {
		const r = probe(function () {
			const shared = new AggregateError([], 'shared');
			shared.leak = process;
			throw new AggregateError([shared, shared], 'all failed');
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via errors[1] on a revisited host aggregate');
	});

	it('self-cycle agg.errors=[agg] must NOT deliver a live host ref', function () {
		const r = probe(function () {
			const agg = new AggregateError([], 'x');
			agg.errors = [agg];
			agg.leak = process;
			throw agg;
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a self-referential host aggregate');
	});

	it('mutual-cycle a.errors=[b]; b.errors=[a] must NOT deliver a live host ref', function () {
		const r = probe(function () {
			const a = new AggregateError([], 'a');
			const b = new AggregateError([], 'b');
			a.errors = [b];
			b.errors = [a];
			b.leak = process;
			throw a;
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a mutually-cyclic host aggregate');
	});

	it('nested duplicated host sub-aggregate must NOT deliver a live host ref', function () {
		const r = probe(function () {
			const inner = new AggregateError([], 'inner');
			inner.leak = process;
			const mid = new AggregateError([inner, inner], 'mid');
			throw new AggregateError([mid], 'outer');
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a nested duplicated host aggregate');
	});

	it('composition: same plain host error with a PROTOTYPE leak listed twice must NOT leak on the revisit', function () {
		// sanitizeHostOwnProps rebuilds a plain host error into a sandbox-realm
		// carrier but the memo pointed at the raw carrier; a second reference to
		// it within one traversal must still resolve to the rebuild, not the raw
		// proxy whose prototype-chain `.leak` is live.
		const r = probe(function () {
			const boom = new Error('boom');
			Object.setPrototypeOf(boom, {leak: process});
			throw new AggregateError([boom, boom], 'twice');
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a duplicated plain host error with a prototype leak');
	});

	// --- Controls: the m283 fix must remain intact (these were already blocked) ---

	it('CONTROL non-cyclic single host sub-error stays blocked', function () {
		const r = probe(function () {
			const sub = new AggregateError([], 'sub');
			sub.leak = process;
			throw new AggregateError([sub], 'outer');
		});
		assert.strictEqual(r, 'NO-LEAK', 'm283 regression: non-cyclic host sub-error leaked');
	});

	it('CONTROL plain Error {cause: process} stays blocked (m283 baseline)', function () {
		const r = probe(function () { throw new Error('boom', {cause: process}); });
		assert.strictEqual(r, 'NO-LEAK', 'm283 regression: Error.cause leaked');
	});

	it('CONTROL plain Error own-prop e.leak=process stays blocked', function () {
		const r = probe(function () { const e = new Error('boom'); e.leak = process; throw e; });
		assert.strictEqual(r, 'NO-LEAK', 'm283 regression: own-property host ref leaked');
	});

	// --- Over-block controls: legitimate aggregates still behave correctly ---

	it('does not over-block: a sandbox-realm AggregateError is caught with its message and errors intact', function () {
		const vm = new VM();
		const out = vm.run(`(function(){
			try { throw new AggregateError([new Error('a'), new TypeError('b')], 'both failed'); }
			catch (e) {
				return [e instanceof AggregateError, e.message, e.errors.length, e.errors[0].message, e.errors[1] instanceof TypeError].join('|');
			}
		})()`);
		assert.strictEqual(out, 'true|both failed|2|a|true');
	});

	it('does not over-block: a host AggregateError with a benign sandbox-safe payload still delivers its errors', function () {
		const out = withMarker(() => {
			const vm = new VM({sandbox: {hostThrow: function () {
				throw new AggregateError([new Error('first'), new Error('second')], 'msg');
			}}});
			return vm.run(`(function(){
				try { hostThrow(); } catch (e) {
					return [e.message, e.errors.length, e.errors[0].message, e.errors[1].message].join('|');
				}
			})()`);
		});
		assert.strictEqual(out, 'msg|2|first|second');
	});
});

(HAS_SUPPRESSED ? describe : describe.skip)('GHSA-x965-fc75-jpqh — revisited host SuppressedError (defensive; excluded by reporter but same shape)', function () {

	it('self-referential SuppressedError must NOT deliver a live host ref', function () {
		const r = probe(function () {
			const se = new SuppressedError(new Error('e'), new Error('s'), 'msg');
			se.error = se;      // revisit trigger
			se.leak = process;
			throw se;
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a self-referential host SuppressedError');
	});

	it('SuppressedError sharing a host sub-error with an aggregate must NOT leak', function () {
		if (!HAS_AGGREGATE) return;
		const r = probe(function () {
			const shared = new Error('shared');
			shared.leak = process;
			const se = new SuppressedError(shared, shared, 'msg');
			throw new AggregateError([se, shared], 'outer');
		});
		assert.strictEqual(r, 'NO-LEAK', 'sandbox reached the live host process via a shared host sub-error across SuppressedError + AggregateError');
	});
});
