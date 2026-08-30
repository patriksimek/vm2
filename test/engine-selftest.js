/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {IS_BUN, ENGINE, NODE_MAJOR, atLeastNode, nodeOlderThan} = require('./engine');

describe('test/engine.js', function () {
	it('detects the engine without consulting process.versions.node', function () {
		assert.strictEqual(IS_BUN, typeof globalThis.Bun !== 'undefined');
		assert.strictEqual(ENGINE, IS_BUN ? 'jsc' : 'v8');
	});

	it('NODE_MAJOR is null on Bun and a number on Node', function () {
		if (IS_BUN) {
			assert.strictEqual(NODE_MAJOR, null);
		} else {
			assert.ok(typeof NODE_MAJOR === 'number' && NODE_MAJOR > 0);
		}
	});

	it('atLeastNode treats Bun as a modern runtime', function () {
		assert.strictEqual(atLeastNode(8), true);
		assert.strictEqual(atLeastNode(20), true);
	});

	it('nodeOlderThan is always false on Bun (Bun is not old Node)', function () {
		if (IS_BUN) {
			assert.strictEqual(nodeOlderThan(26), false);
			assert.strictEqual(nodeOlderThan(8), false);
		} else {
			assert.strictEqual(nodeOlderThan(NODE_MAJOR + 1), true);
			assert.strictEqual(nodeOlderThan(NODE_MAJOR), false);
		}
	});
});

describe('test/bun-skips.js', function () {
	const {SKIPS, skipReason} = require('./bun-skips');

	it('every entry has a reason and an owning phase', function () {
		assert.ok(SKIPS.length > 0);
		for (const s of SKIPS) {
			assert.ok(typeof s.match === 'string' && s.match.length > 0, 'match required');
			assert.ok(typeof s.reason === 'string' && s.reason.length > 10, 'reason must be substantive: ' + s.match);
			assert.ok(s.phase === 2, 'phase must be 2 - phase 1 fixes nothing behavioural');
			assert.strictEqual(typeof s.security, 'boolean');
		}
	});

	it('matches by substring of the full test title', function () {
		assert.ok(skipReason('GHSA-v27g-jcqj-v8rw (CallSite path leak via prepareStackTrace) getFileName on host frames returns null (no absolute path leaked)'));
		assert.strictEqual(skipReason('some completely unrelated test name'), null);
	});
});
