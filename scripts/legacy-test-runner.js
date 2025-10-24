const stack = [];
let currentGroup;

global.describe = (name, fn) => {
	const group = currentGroup ={
		name,
		tests: [],
		before: null,
		after: null,
	};
	stack.push(group);
	fn();
	currentGroup = null;
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

require('../test/vm');
require('../test/nodevm');

currentGroup = null;
let hasError = false;
let counterPassed = 0;
let counterPending = 0;
let counterFailed = 0;
let timeStart = Date.now();

function next() {
	if (!currentGroup || currentGroup.tests.length === 0) {
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

	try {
		if (currentTest.fn.length) {
			// Async test
			currentTest.fn(testCompleted);
		} else {
			// Sync test
			currentTest.fn();
			testCompleted();
		}
	} catch (error) {
		testCompleted(error);
	}
}

process.nextTick(next);
