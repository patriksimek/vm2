'use strict';

// A minimal mocha work-alike for the Node versions mocha itself no longer
// supports (8 through 18). It has to reproduce mocha's *observable* semantics
// closely enough that a suite written for `npm test` behaves identically here,
// otherwise a security regression test can pass for the wrong reason.
//
// The two semantics that matter most:
//
//  * Suites nest. A parent's `after` hook must run only once every nested suite
//    below it has finished. A flattening runner tears down the parent's fixture
//    (a temp directory, a listening server) before the children run, which turns
//    "this must be denied" assertions vacuously green and "this must still work"
//    assertions red.
//  * Hooks and tests may be synchronous, take a `done` callback, or return a
//    promise, and may call `this.skip()`.

const SKIP = {};

const rootSuites = [];
let currentSuite = null;

function createSuite(name, parent) {
	const suite = {
		name: parent ? parent.name + ' › ' + name : name,
		parent: parent || null,
		tests: [],
		suites: [],
		before: [],
		after: [],
		beforeEach: [],
		afterEach: [],
		// A suite declared inside a skipped suite is itself skipped.
		skip: parent ? parent.skip : false,
		timeoutMs: parent ? parent.timeoutMs : 2000,
	};
	if (parent) {
		parent.suites.push(suite);
	} else {
		rootSuites.push(suite);
	}
	return suite;
}

function defineSuite(name, fn, skip) {
	const parent = currentSuite;
	const suite = createSuite(name, parent);
	if (skip) suite.skip = true;
	currentSuite = suite;
	try {
		// Mocha exposes `this.timeout(ms)` inside describe bodies. We record the
		// value but do not enforce real timeouts in the legacy runner.
		fn.call({
			timeout(ms) {
				suite.timeoutMs = ms;
			},
		});
	} finally {
		currentSuite = parent;
	}
	return suite;
}

global.describe = (name, fn) => defineSuite(name, fn, false);
// Mocha's `describe.skip` marks every test in the suite pending and runs none of
// its hooks. Suites gate on it for runtime capability -- e.g. a builtin this Node
// major does not expose -- so the body is still walked (registering the pending
// tests, keeping counts comparable to mocha) while nothing inside it executes.
global.describe.skip = (name, fn) => defineSuite(name, fn, true);
// `it.only` is registered and then ignored by this runner, so the matching
// `describe.only` is plain `describe` -- same observable behaviour.
global.describe.only = global.describe;

global.it = (name, fn) => {
	currentSuite.tests.push({name, fn});
};
global.it.skip = (name, fn) => {
	currentSuite.tests.push({name, fn, skip: true});
};
global.it.only = global.it;

global.before = fn => {
	currentSuite.before.push(fn);
};
global.after = fn => {
	currentSuite.after.push(fn);
};
global.beforeEach = fn => {
	currentSuite.beforeEach.push(fn);
};
global.afterEach = fn => {
	currentSuite.afterEach.push(fn);
};

require('../test/vm');
require('../test/nodevm');

// Auto-discover GHSA regression suites under test/ghsa/. mocha (Node 20+) does
// this via --recursive; for Node 8-18 the legacy runner has to walk the tree.
const fs = require('fs');
const path = require('path');
const ghsaRoot = path.join(__dirname, '..', 'test', 'ghsa');
if (fs.existsSync(ghsaRoot)) {
	const dirs = fs.readdirSync(ghsaRoot);
	for (let i = 0; i < dirs.length; i++) {
		const dir = path.join(ghsaRoot, dirs[i]);
		if (!fs.statSync(dir).isDirectory()) continue;
		const files = fs.readdirSync(dir);
		for (let j = 0; j < files.length; j++) {
			if (files[j].slice(-3) !== '.js') continue;
			require(path.join(dir, files[j]));
		}
	}
}

currentSuite = null;
let hasError = false;
let counterPassed = 0;
let counterPending = 0;
let counterFailed = 0;
const timeStart = Date.now();

function makeContext(onTimeout) {
	return {
		timeout(ms) {
			if (onTimeout) onTimeout(ms);
		},
		skip() {
			throw SKIP;
		},
	};
}

// Runs `fn` in any of the three shapes mocha accepts -- `done`-callback, promise
// returning, or plain synchronous -- and reports the outcome exactly once.
function invoke(fn, ctx, cb) {
	let settled = false;
	const finish = err => {
		if (settled) return;
		settled = true;
		cb(err || null);
	};
	try {
		if (fn.length) {
			fn.call(ctx, err => finish(err));
		} else {
			const ret = fn.call(ctx);
			if (ret && typeof ret.then === 'function') {
				ret.then(() => finish(null), err => finish(err || new Error('promise rejected')));
			} else {
				finish(null);
			}
		}
	} catch (err) {
		finish(err);
	}
}

function invokeSeries(fns, ctx, cb) {
	let i = 0;
	const step = err => {
		if (err || i >= fns.length) return cb(err || null);
		const fn = fns[i++];
		invoke(fn, ctx, step);
	};
	step(null);
}

function reportPass(name) {
	console.log('    ✔ ' + name);
	counterPassed++;
}

function reportPending(name) {
	console.log('    - ' + name);
	counterPending++;
}

function reportFailure(name, error) {
	console.log('    ✘ ' + name);
	hasError = true;
	counterFailed++;
	console.error(error);
}

// Mark a whole subtree pending -- used for `describe.skip` and for a `before`
// hook that called `this.skip()`.
function markPending(suite, printTitle) {
	if (printTitle) console.log('\n  ' + suite.name);
	for (let i = 0; i < suite.tests.length; i++) reportPending(suite.tests[i].name);
	for (let i = 0; i < suite.suites.length; i++) markPending(suite.suites[i], true);
}

// beforeEach/afterEach are inherited: outermost-first on the way in,
// innermost-first on the way out.
function eachHooks(suite, kind) {
	const chain = [];
	for (let s = suite; s; s = s.parent) chain.unshift(s);
	let hooks = [];
	for (let i = 0; i < chain.length; i++) hooks = hooks.concat(chain[i][kind]);
	return kind === 'afterEach' ? hooks.reverse() : hooks;
}

function runTest(suite, test, cb) {
	if (test.skip) {
		reportPending(test.name);
		return process.nextTick(cb);
	}
	const ctx = makeContext(ms => {
		test.timeoutMs = ms;
	});
	invokeSeries(eachHooks(suite, 'beforeEach'), ctx, err => {
		if (err) {
			if (err === SKIP) reportPending(test.name);
			else reportFailure(test.name, err);
			return process.nextTick(cb);
		}
		invoke(test.fn, ctx, testErr => {
			const afterEach = testErr ? [] : eachHooks(suite, 'afterEach');
			invokeSeries(afterEach, ctx, afterErr => {
				const finalErr = testErr || afterErr;
				if (finalErr === SKIP) reportPending(test.name);
				else if (finalErr) reportFailure(test.name, finalErr);
				else reportPass(test.name);
				process.nextTick(cb);
			});
		});
	});
}

function runSeries(items, run, cb) {
	let i = 0;
	const step = () => {
		if (i >= items.length) return cb();
		run(items[i++], step);
	};
	step();
}

function runSuite(suite, cb) {
	if (suite.skip) {
		markPending(suite, true);
		return cb();
	}
	console.log('\n  ' + suite.name);

	const ctx = makeContext(ms => {
		suite.timeoutMs = ms;
	});
	invokeSeries(suite.before, ctx, err => {
		if (err === SKIP) {
			// `this.skip()` in a `before` hook makes the whole suite pending.
			markPending(suite, false);
			return cb();
		}
		if (err) {
			// Mocha reports the hook itself as the failure and skips the suite's
			// tests. The `after` hook still runs so fixtures get torn down.
			reportFailure('"before all" hook', err);
			return invokeSeries(suite.after, ctx, () => cb());
		}
		// Mocha runs a suite's own tests before descending into nested suites,
		// and only runs `after` once the whole subtree is done.
		runSeries(suite.tests, (test, next) => runTest(suite, test, next), () => {
			runSeries(suite.suites, (child, next) => runSuite(child, next), () => {
				invokeSeries(suite.after, ctx, afterErr => {
					if (afterErr && afterErr !== SKIP) reportFailure('"after all" hook', afterErr);
					cb();
				});
			});
		});
	});
}

runSeries(rootSuites, (suite, next) => runSuite(suite, next), () => {
	console.log('\n\n  ' + counterPassed + ' passing (' + (Date.now() - timeStart) + 'ms)');
	console.log('  ' + counterPending + ' pending');
	if (hasError) {
		console.log('  ' + counterFailed + ' failed');
		process.exit(1);
	}
});
