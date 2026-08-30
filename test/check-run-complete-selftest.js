/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {checkTap} = require('../scripts/check-run-complete');

const COMPLETE = ['ok 1 a', 'ok 2 b', '1..2', '# tests 2', '# pass 2', '# fail 0'].join('\n');
const TRUNCATED = ['ok 1 a', 'ok 2 b'].join('\n');
const SHORT = ['ok 1 a', '1..1', '# tests 1', '# pass 1', '# fail 0'].join('\n');
const FAILING = ['not ok 1 a', '1..1', '# tests 1', '# pass 0', '# fail 1'].join('\n');

describe('scripts/check-run-complete', function () {
	it('accepts a complete passing run', function () {
		assert.deepStrictEqual(checkTap(COMPLETE, 2), {ok: true, problems: []});
	});

	it('rejects a run with no epilogue (the dishonest-green case)', function () {
		const r = checkTap(TRUNCATED, 2);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('epilogue'));
	});

	it('rejects a run that reports fewer tests than expected', function () {
		const r = checkTap(SHORT, 2);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('expected at least 2'));
	});

	it('rejects a run with failures', function () {
		const r = checkTap(FAILING, 1);
		assert.strictEqual(r.ok, false);
		assert.ok(r.problems.join(' ').includes('1 failing'));
	});
});
