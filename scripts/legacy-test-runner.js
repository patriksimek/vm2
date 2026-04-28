const stack = [];
let currentGroup;

global.describe = (name, fn) => {
	// Support nested describe by saving/restoring the current group around
	// the inner body. Mocha allows arbitrary nesting; the legacy runner just
	// flattens it — each describe gets its own group in the order they appear.
	const previous = currentGroup;
	const qualifiedName = previous ? previous.name + ' › ' + name : name;
	const group = currentGroup = {
		name: qualifiedName,
		tests: [],
		before: null,
		after: null,
		timeoutMs: 2000,
	};
	stack.push(group);
	// Mocha exposes `this.timeout(ms)` inside describe/it bodies. We honour
	// the value (clamped against an internal default) but do not enforce
	// real timeouts in the legacy runner.
	fn.call({timeout(ms) { group.timeoutMs = ms; }});
	currentGroup = previous;
};
global.it = (name, fn) => {
	const test = {
		name,
		fn,
	};
	currentGroup.tests.push(test);
};
global.it.skip = (name, fn) => {
	const test = {
		name,
		fn,
		skip: true,
	};
	currentGroup.tests.push(test);
};
global.it.only = (name, fn) => {
	const test = {
		name,
		fn,
		only: true,
	};
	currentGroup.tests.push(test);
};
global.before = fn => {
	currentGroup.before = fn;
};
global.after = fn => {
	currentGroup.after = fn;
};
global.beforeEach = fn => {
	(currentGroup.beforeEach = currentGroup.beforeEach || []).push(fn);
};
global.afterEach = fn => {
	(currentGroup.afterEach = currentGroup.afterEach || []).push(fn);
};

require('../test/vm');
require('../test/nodevm');

// Auto-discover GHSA regression suites under test/ghsa/. mocha (Node 16+) does
// this via --recursive; for Node 8-12 the legacy runner has to walk the tree.
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

currentGroup = null;
let hasError = false;
let counterPassed = 0;
let counterPending = 0;
let counterFailed = 0;
let timeStart = Date.now();

function next() {
	while (!currentGroup || currentGroup.tests.length === 0) {
		if (!stack.length) {
			console.log('\n\n  ' + counterPassed + ' passing (' + (Date.now() - timeStart) + 'ms)');
			console.log('  ' + counterPending + ' pending');
			if (hasError) {
				console.log('  ' + counterFailed + ' failed');
				process.exit(1);
			}
			return;
		}

		if (currentGroup && currentGroup.after) {
			currentGroup.after();
		}

		currentGroup = stack.shift();
		console.log('\n  ' + currentGroup.name);

		if (currentGroup.before) {
			currentGroup.before();
		}
	}

	const currentTest = currentGroup.tests.shift();
	if (currentTest.skip) {
		console.log('    - ' + currentTest.name);
		counterPending++;
		process.nextTick(next);
		return;
	}

	const testCompleted = error => {
		if (error) {
			console.log('    ✘ ' + currentTest.name);
			hasError = true;
			counterFailed++;
			console.error(error);
		} else {
			console.log('    ✔ ' + currentTest.name);
			counterPassed++;
		}
		process.nextTick(next);
	};

	// Mocha exposes `this.timeout(ms)` inside it() callbacks too. Provide a
	// stub so tests don't blow up; we don't enforce real timeouts here.
	const ctx = {timeout(ms) { currentTest.timeoutMs = ms; }};
	try {
		if (currentGroup.beforeEach) {
			for (let i = 0; i < currentGroup.beforeEach.length; i++) {
				currentGroup.beforeEach[i].call(ctx);
			}
		}
		if (currentTest.fn.length) {
			// Async test
			currentTest.fn.call(ctx, error => {
				if (!error && currentGroup.afterEach) {
					try {
						for (let i = 0; i < currentGroup.afterEach.length; i++) {
							currentGroup.afterEach[i].call(ctx);
						}
					} catch (e) {
						return testCompleted(e);
					}
				}
				testCompleted(error);
			});
		} else {
			// Sync test
			currentTest.fn.call(ctx);
			if (currentGroup.afterEach) {
				for (let i = 0; i < currentGroup.afterEach.length; i++) {
					currentGroup.afterEach[i].call(ctx);
				}
			}
			testCompleted();
		}
	} catch (error) {
		testCompleted(error);
	}
}

process.nextTick(next);
