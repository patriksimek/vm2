'use strict';

// Verify that a mocha TAP run actually finished.
//
// A test runner that dies mid-run and still exits 0 is worse than no test
// runner: it reports a success it never verified. That is exactly what mocha
// under Bun did before test/bun-skips.js -- a single file terminated the
// process, 112 tests never ran, and the exit status was 0.
//
// A skip list fixes one such crash. This check fixes the class: any future
// mid-run death becomes a loud failure instead of a quiet pass.

function checkTap(text, minTests) {
	const problems = [];
	const lines = String(text).split('\n');

	let reported = null;
	let failing = null;
	let sawPlan = false;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (/^1\.\.\d+$/.test(line)) sawPlan = true;
		const t = /^# tests (\d+)/.exec(line);
		if (t) reported = parseInt(t[1], 10);
		const f = /^# fail (\d+)/.exec(line);
		if (f) failing = parseInt(f[1], 10);
	}

	if (!sawPlan || reported === null || failing === null) {
		problems.push(
			'run did not finish: TAP epilogue missing (plan=' + sawPlan +
				', "# tests"=' + reported + ', "# fail"=' + failing + '). ' +
				'The process almost certainly died mid-run.'
		);
	}

	if (reported !== null && typeof minTests === 'number' && reported < minTests) {
		problems.push('only ' + reported + ' tests reported, expected at least ' + minTests);
	}

	if (failing !== null && failing > 0) {
		problems.push(failing + ' failing');
	}

	return {ok: problems.length === 0, problems};
}

module.exports = {checkTap};

if (require.main === module) {
	const fs = require('fs');
	const args = process.argv.slice(2);
	const file = args[0];
	const minIdx = args.indexOf('--min-tests');
	const minTests = minIdx === -1 ? null : parseInt(args[minIdx + 1], 10);

	if (!file) {
		console.error('usage: check-run-complete.js <tap-file> [--min-tests <n>]');
		process.exit(2);
	}

	const result = checkTap(fs.readFileSync(file, 'utf8'), minTests);
	if (result.ok) {
		console.log('run complete: ok');
		process.exit(0);
	}
	console.error('RUN NOT TRUSTWORTHY:');
	for (let i = 0; i < result.problems.length; i++) console.error('  - ' + result.problems[i]);
	process.exit(1);
}
