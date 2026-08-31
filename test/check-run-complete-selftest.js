/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {checkTap} = require('../scripts/check-run-complete');

// Build a TAP document that is internally consistent by construction, so each
// test below can break exactly one thing.
function tap(opts) {
	const o = opts || {};
	const pass = o.pass === undefined ? 2 : o.pass;
	const fail = o.fail === undefined ? 0 : o.fail;
	const skip = o.skip === undefined ? 0 : o.skip;
	const lines = [];
	let n = 0;
	for (let i = 0; i < pass; i++) lines.push('ok ' + ++n + ' passing test ' + i);
	for (let i = 0; i < fail; i++) lines.push('not ok ' + ++n + ' failing test ' + i);
	for (let i = 0; i < skip; i++) lines.push('ok ' + ++n + ' pending test ' + i + ' # SKIP -');
	lines.push('1..' + (o.plan === undefined ? n : o.plan));
	lines.push('# tests ' + (o.tests === undefined ? pass + fail : o.tests));
	lines.push('# pass ' + pass);
	lines.push('# fail ' + fail);
	return lines.join('\n');
}

describe('scripts/check-run-complete', function () {
	it('accepts a complete, self-consistent passing run', function () {
		assert.deepStrictEqual(checkTap(tap({pass: 2}), {minTests: 2}), {ok: true, problems: []});
	});

	it('accepts pending tests, which count toward the plan but not "# tests"', function () {
		// 2 passing + 3 pending => plan 5, "# tests" 2.
		assert.deepStrictEqual(checkTap(tap({pass: 2, skip: 3}), {minTests: 5}), {ok: true, problems: []});
	});

	it('rejects a run with no epilogue (the real crash case)', function () {
		const r = checkTap('ok 1 a\nok 2 b', {minTests: 2});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('epilogue'));
	});

	it('rejects an empty file', function () {
		assert.strictEqual(checkTap('', {minTests: 2}).ok, false);
	});

	it('rejects a summary that contradicts the plan', function () {
		// The exact shape an external review used to defeat the old checker:
		// a single test point, a plan of 1, but a summary claiming 750 tests.
		const forged = ['ok 1 a', '1..1', '# tests 750', '# pass 750', '# fail 0'].join('\n');
		const r = checkTap(forged, {minTests: 750});
		assert.strictEqual(r.ok, false);
		assert.ok(
			r.problems.join(' ').includes('summary disagrees with the plan'),
			'expected the plan/summary disagreement to be caught, got: ' + r.problems.join('; ')
		);
	});

	it('rejects a run that stopped emitting results before the plan', function () {
		// Plan says 10, only 2 points emitted.
		const r = checkTap(tap({pass: 2, plan: 10, tests: 10}), {minTests: 2});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('truncated or inconsistent run'));
	});

	it('rejects a summary whose pass + fail does not equal "# tests"', function () {
		const forged = ['ok 1 a', 'ok 2 b', '1..2', '# tests 2', '# pass 1', '# fail 0'].join('\n');
		const r = checkTap(forged, {minTests: 2});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('internally inconsistent'));
	});

	it('rejects a "# fail" count that disagrees with the not-ok lines', function () {
		const forged = ['not ok 1 a', 'ok 2 b', '1..2', '# tests 2', '# pass 1', '# fail 0'].join('\n');
		const r = checkTap(forged, {minTests: 2});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('failure count disagrees'));
	});

	it('rejects a run with failures', function () {
		const r = checkTap(tap({pass: 1, fail: 3}), {minTests: 4});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('3 failing'));
	});

	it('measures --min-tests against the plan, not the post-skip count', function () {
		// 1 passing + 9 pending: "# tests" is 1, but 10 tests are registered.
		// A floor of 10 must pass, because nothing was lost.
		assert.strictEqual(checkTap(tap({pass: 1, skip: 9}), {minTests: 10}).ok, true);
		assert.strictEqual(checkTap(tap({pass: 1, skip: 9}), {minTests: 11}).ok, false);
	});

	it('rejects a non-zero runner exit even when the TAP output looks clean', function () {
		const r = checkTap(tap({pass: 2}), {minTests: 2, runnerExit: 7});
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('exited 7'));
	});

	it('accepts a zero runner exit', function () {
		assert.strictEqual(checkTap(tap({pass: 2}), {minTests: 2, runnerExit: 0}).ok, true);
	});
});
