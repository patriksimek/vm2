/**
 * GHSA-x965-fc75-jpqh — adversarial / red-team suite (/hacker).
 *
 * Compound bypass attempts against the revisit-memo fix: mixed error-family
 * graphs, TOCTOU / lying accessors, non-array `.errors`, custom own-property
 * names, and isProxy-shadowing. The escape probe scans EVERY own key
 * recursively (not a fixed name list) so a host ref parked on any property is
 * caught. All must report NO-LEAK.
 */
'use strict';

const assert = require('assert');
const {VM} = require('../../../lib/main.js');

const HAS_AGGREGATE = typeof AggregateError === 'function';
const HAS_SUPPRESSED = typeof SuppressedError === 'function';

function withMarker(fn) {
	const marker = 'X965_HOST_' + process.pid;
	Object.defineProperty(process, '__x965_marker', {value: marker, configurable: true, enumerable: false});
	try { return fn(marker); } finally { try { delete process.__x965_marker; } catch (_) {} }
}

// Deep all-own-keys probe: hunt the host marker anywhere reachable from the
// caught exception, following every own property (incl. non-standard names),
// errors[], .error, .suppressed, .cause.
function probe(hostThrow) {
	return withMarker(marker => {
		const vm = new VM({sandbox: {hostThrow}});
		const out = vm.run(`(function(){
			try { hostThrow(); } catch (e) {
				var seen = [];
				var found = null;
				function visit(x, depth){
					if (found || x === null || x === undefined || depth > 8) return;
					var t = typeof x;
					if (t !== 'object' && t !== 'function') return;
					for (var i = 0; i < seen.length; i++) if (seen[i] === x) return;
					seen.push(x);
					try { var m = x.__x965_marker; if (typeof m === 'string' && m.indexOf('X965_HOST_') === 0) { found = m; return; } } catch (_) {}
					var keys;
					try { keys = Object.getOwnPropertyNames(x); } catch (_) { keys = []; }
					for (var k = 0; k < keys.length; k++) {
						var v;
						try { v = x[keys[k]]; } catch (_) { continue; }
						visit(v, depth+1);
						if (found) return;
					}
					try { if (x.errors) { for (var j = 0; j < x.errors.length; j++) visit(x.errors[j], depth+1); } } catch (_) {}
					try { visit(x.cause, depth+1); } catch (_) {}
				}
				visit(e, 0);
				return found || 'NO-LEAK';
			}
			return 'no-throw';
		})()`);
		return out === marker ? 'ESCAPED' : out;
	});
}

(HAS_AGGREGATE ? describe : describe.skip)('GHSA-x965-fc75-jpqh adversarial', function () {

	it('custom own-prop name (.detail) on a self-cyclic host aggregate', function () {
		assert.strictEqual(probe(function () {
			const agg = new AggregateError([], 'x'); agg.errors = [agg]; agg.detail = process; throw agg;
		}), 'NO-LEAK');
	});

	it('non-array .errors accessor returning the host process directly', function () {
		assert.strictEqual(probe(function () {
			const agg = Object.create(AggregateError.prototype);
			Object.defineProperty(agg, 'errors', {get: function () { return process; }, configurable: true});
			agg.message = 'x';
			throw agg;
		}), 'NO-LEAK');
	});

	it('TOCTOU: .errors accessor returns a self-ref array first, a leak array later', function () {
		assert.strictEqual(probe(function () {
			let n = 0;
			const agg = Object.create(AggregateError.prototype);
			const selfArr = [agg];
			Object.defineProperty(agg, 'errors', {get: function () { n++; return n === 1 ? selfArr : [process]; }, configurable: true});
			agg.leak = process;
			throw agg;
		}), 'NO-LEAK');
	});

	it('per-element TOCTOU: errors[i] getter returns process on a later read', function () {
		assert.strictEqual(probe(function () {
			const agg = new AggregateError([], 'x');
			let reads = 0;
			const arr = [];
			Object.defineProperty(arr, '0', {get: function () { reads++; return reads > 1 ? process : agg; }, enumerable: true, configurable: true});
			arr.length = 1;
			agg.errors = arr;
			agg.leak = process;
			throw agg;
		}), 'NO-LEAK');
	});

	it('.message accessor returning a host object (must be treated as non-primitive)', function () {
		let reachedThrow = false;
		assert.strictEqual(probe(function () {
			const a2 = new AggregateError([], 'x'); a2.errors = [a2];
			Object.defineProperty(a2, 'message', {get: function () { return process; }, configurable: true});
			a2.leak = process;
			reachedThrow = true;
			throw a2;
		}), 'NO-LEAK');
		assert.ok(reachedThrow, 'payload never reached its throw - the test is vacuous');
	});

	it('own isProxy=false cannot suppress host-wrapped detection', function () {
		assert.strictEqual(probe(function () {
			const agg = new AggregateError([], 'x');
			agg.errors = [agg];
			Object.defineProperty(agg, 'isProxy', {value: false, configurable: true});
			agg.leak = process;
			throw agg;
		}), 'NO-LEAK');
	});

	it('deep mutual cycle with the leak on the OUTER node', function () {
		assert.strictEqual(probe(function () {
			const a = new AggregateError([], 'a'); a.leak = process;
			const b = new AggregateError([], 'b');
			a.errors = [b]; b.errors = [a];
			throw a;
		}), 'NO-LEAK');
	});

	it('aggregate whose sub-error carries a host ref via .cause, duplicated', function () {
		assert.strictEqual(probe(function () {
			const sub = new Error('sub', {cause: process});
			throw new AggregateError([sub, sub], 'outer');
		}), 'NO-LEAK');
	});

	it('over-block guard: a deep legit sandbox aggregate graph keeps all real messages', function () {
		const vm = new VM();
		const out = vm.run(`(function(){
			try {
				const inner = new AggregateError([new Error('i1'), new RangeError('i2')], 'inner');
				throw new AggregateError([inner, new TypeError('t')], 'outer');
			} catch (e) {
				return [e.message, e.errors.length, e.errors[0].message, e.errors[0].errors[1] instanceof RangeError, e.errors[1] instanceof TypeError].join('|');
			}
		})()`);
		assert.strictEqual(out, 'outer|2|inner|true|true');
	});
});

(HAS_SUPPRESSED ? describe : describe.skip)('GHSA-x965-fc75-jpqh adversarial — SuppressedError family', function () {

	it('mixed graph: AggregateError -> SuppressedError -> Error{cause} sharing a host node', function () {
		if (!HAS_AGGREGATE) return;
		assert.strictEqual(probe(function () {
			const leaky = new Error('leaky'); leaky.leak = process;
			const se = new SuppressedError(leaky, leaky, 'se');
			const agg = new AggregateError([se, leaky], 'outer');
			agg.errors.push(agg); // add a cycle
			throw agg;
		}), 'NO-LEAK');
	});

	it('SuppressedError self-cycle via .suppressed with a custom leak prop', function () {
		assert.strictEqual(probe(function () {
			const se = new SuppressedError(new Error('e'), new Error('s'), 'm');
			se.suppressed = se; se.pwn = process;
			throw se;
		}), 'NO-LEAK');
	});
});
