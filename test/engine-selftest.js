/* eslint-env mocha */

'use strict';

const assert = require('assert');
const {IS_BUN, ENGINE, NODE_MAJOR, atLeastNode, nodeOlderThan} = require('./engine');

describe('test/engine.js', function () {
	it('detects the engine without consulting process.versions.node', function () {
		assert.strictEqual(IS_BUN, typeof process.versions.bun === 'string');
		assert.strictEqual(ENGINE, IS_BUN ? 'jsc' : 'v8');
	});

	// Node only: on Bun `global.Bun` is a readonly property, so the spoof cannot
	// even be attempted there. Node is where a planted global is possible, and
	// therefore where the detection has to be proof against it.
	(IS_BUN ? it.skip : it)('cannot be spoofed by a planted global', function () {
		// A global check would misclassify the runtime here. process.versions is
		// populated by the runtime itself.
		const had = Object.prototype.hasOwnProperty.call(global, 'Bun');
		const prev = global.Bun;
		global.Bun = {};
		try {
			delete require.cache[require.resolve('./engine')];
			const reloaded = require('./engine');
			assert.strictEqual(reloaded.IS_BUN, IS_BUN, 'planting global.Bun changed the detected engine');
			assert.strictEqual(reloaded.ENGINE, ENGINE);
		} finally {
			if (had) global.Bun = prev;
			else delete global.Bun;
			delete require.cache[require.resolve('./engine')];
		}
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

	// Guards against an over-broad `match`: an entry meant for one test that
	// also (accidentally) matches another silently removes coverage for the
	// second test on Bun. GHSA-v27g-jcqj-v8rw is the one deliberate exception
	// -- it quarantines all 7 tests in its file (see its `reason`).
	//
	// Real titles are asked of mocha itself (--dry-run --reporter json) rather
	// than grepped from source: grepping mangles titles with escaped quotes or
	// that span multiple `it(` lines, and mocha's TAP reporter strips leading
	// `#` from titles, so neither is a reliable source here.
	it('every match hits exactly the number of real test titles it declares', function () {
		// Bun-side reliability of this tooling is untested; the SKIPS content
		// this checks is engine-independent, so verifying it under Node suffices.
		if (IS_BUN) return this.skip();

		this.timeout(20000);

		const {execFileSync} = require('child_process');
		const path = require('path');

		const repoRoot = path.join(__dirname, '..');
		const mochaBin = path.join(repoRoot, 'node_modules', 'mocha', 'bin', 'mocha.js');

		const out = execFileSync(
			process.execPath,
			[mochaBin, 'test', '--recursive', '--ignore', 'test/compilers.js', '--dry-run', '--reporter', 'json'],
			{cwd: repoRoot, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024},
		);
		const titles = JSON.parse(out).tests.map(function (t) {
			return t.fullTitle;
		});
		assert.ok(titles.length > 0, 'dry-run produced no titles');

		for (const s of SKIPS) {
			// An entry that deliberately covers a group declares how many tests it
			// owns. Pinning the number is stronger than exempting the entry: if the
			// group grows or shrinks, the guard says so instead of silently
			// absorbing the change.
			const expected = s.expectedMatches === undefined ? 1 : s.expectedMatches;
			const hits = titles.filter(function (title) {
				return title.indexOf(s.match) !== -1;
			});
			assert.ok(
				hits.length === expected,
				'match ' + JSON.stringify(s.match) + ' hits ' + hits.length +
					' real titles but declares ' + expected + ': ' + JSON.stringify(hits),
			);
		}
	});
});

describe('test/engine-messages.js', function () {
	const {msg, MESSAGES} = require('./engine-messages');
	const {ENGINE} = require('./engine');

	it('returns a RegExp for the current engine', function () {
		assert.ok(msg('NOT_A_CONSTRUCTOR') instanceof RegExp);
	});

	it('every key defines a pattern for BOTH engines', function () {
		for (const key of Object.keys(MESSAGES)) {
			assert.ok(MESSAGES[key].v8 instanceof RegExp, key + ' missing v8 pattern');
			assert.ok(MESSAGES[key].jsc instanceof RegExp, key + ' missing jsc pattern');
		}
	});

	it('throws on an unknown key rather than silently matching nothing', function () {
		assert.throws(() => msg('NO_SUCH_KEY'), /unknown message key/);
	});

	it('selects by engine', function () {
		assert.strictEqual(msg('NOT_A_CONSTRUCTOR'), MESSAGES.NOT_A_CONSTRUCTOR[ENGINE]);
	});
});
