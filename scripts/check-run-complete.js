'use strict';

// Verify that a mocha TAP run actually finished, and that what it reported is
// internally consistent.
//
// A test runner that dies mid-run and still exits 0 is worse than no test
// runner: it reports a success it never verified. That is exactly what mocha
// under Bun did before test/bun-skips.js -- a single file terminated the
// process, 112 tests never ran, and the exit status was 0.
//
// A skip list fixes one such crash. This check fixes the class. It is
// deliberately paranoid about agreement between the four things a TAP run
// tells us, because any one of them alone can be produced by a broken run:
//
//   * the test points actually emitted   (`ok` / `not ok` lines)
//   * the plan                           (`1..N`)
//   * the summary counts                 (`# tests` / `# pass` / `# fail`)
//   * the runner's own exit status       (passed in via --runner-exit)
//
// mocha's TAP reporter counts pending tests as emitted points carrying a
// `# SKIP` directive, but excludes them from `# tests`. So the invariants are
// `points === plan` and `tests + skipped === plan`.

function checkTap(text, opts) {
	const options = opts || {};
	const minTests = typeof options.minTests === 'number' ? options.minTests : null;
	const runnerExit = typeof options.runnerExit === 'number' ? options.runnerExit : null;
	const problems = [];
	const lines = String(text).split('\n');

	let reported = null;
	let passed = null;
	let failing = null;
	let plan = null;
	let points = 0;
	let skipped = 0;
	let notOk = 0;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];

		if (/^ok\b/.test(line) || /^not ok\b/.test(line)) {
			points++;
			if (/^not ok\b/.test(line)) notOk++;
			// A pending test is an `ok` line carrying a SKIP directive.
			if (/#\s*SKIP\b/i.test(line)) skipped++;
			continue;
		}

		const p = /^1\.\.(\d+)\s*$/.exec(line);
		if (p) plan = parseInt(p[1], 10);

		const t = /^# tests (\d+)/.exec(line);
		if (t) reported = parseInt(t[1], 10);

		const ps = /^# pass (\d+)/.exec(line);
		if (ps) passed = parseInt(ps[1], 10);

		const f = /^# fail (\d+)/.exec(line);
		if (f) failing = parseInt(f[1], 10);
	}

	// 1. The run has to have finished at all.
	if (plan === null || reported === null || failing === null) {
		problems.push(
			'run did not finish: TAP epilogue missing (plan=' + plan +
				', "# tests"=' + reported + ', "# fail"=' + failing + '). ' +
				'The process almost certainly died mid-run.'
		);
		// Everything below compares numbers we do not have. Stop here.
		return {ok: false, problems};
	}

	// 2. The emitted test points have to match the plan. Catches a run that
	//    printed a plausible epilogue but stopped emitting results partway.
	if (points !== plan) {
		problems.push(
			'truncated or inconsistent run: ' + points + ' test points emitted but the plan says ' + plan
		);
	}

	// 3. The summary has to agree with the points. `# tests` excludes pending,
	//    so tests + skipped should reconstruct the plan exactly.
	if (reported + skipped !== plan) {
		problems.push(
			'summary disagrees with the plan: "# tests" ' + reported + ' + ' + skipped +
				' skipped = ' + (reported + skipped) + ', but the plan says ' + plan
		);
	}

	if (passed !== null && passed + failing !== reported) {
		problems.push(
			'summary is internally inconsistent: "# pass" ' + passed + ' + "# fail" ' + failing +
				' = ' + (passed + failing) + ', but "# tests" says ' + reported
		);
	}

	if (notOk !== failing) {
		problems.push(
			'failure count disagrees with the results: ' + notOk + ' "not ok" lines but "# fail" says ' + failing
		);
	}

	// 4. Enough tests actually registered. Measured against the PLAN, which is
	//    the registered total and stays stable as tests move in and out of the
	//    skip list -- unlike `# tests`, which shrinks every time one is skipped.
	if (minTests !== null && plan < minTests) {
		problems.push('only ' + plan + ' tests registered, expected at least ' + minTests);
	}

	// 5. No failures.
	if (failing > 0) {
		problems.push(failing + ' failing');
	}

	// 6. The runner's own exit status, when we were given it. A green epilogue
	//    followed by a non-zero exit means something failed during teardown,
	//    which none of the checks above can see. Note the shell must use
	//    `set -o pipefail` for this to be the runner's status rather than
	//    `tee`'s.
	if (runnerExit !== null && runnerExit !== 0) {
		problems.push(
			'the test runner exited ' + runnerExit + ' despite the TAP output above. ' +
				'Something failed outside the reported results (teardown, an uncaught ' +
				'exception after the epilogue, or a crash on exit).'
		);
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

	const exitIdx = args.indexOf('--runner-exit');
	const rawExit = exitIdx === -1 ? null : String(args[exitIdx + 1]).trim();
	const runnerExit = rawExit === null || rawExit === '' ? null : parseInt(rawExit, 10);

	if (!file) {
		console.error('usage: check-run-complete.js <tap-file> [--min-tests <n>] [--runner-exit <status>]');
		process.exit(2);
	}

	if (exitIdx !== -1 && (runnerExit === null || Number.isNaN(runnerExit))) {
		console.error('RUN NOT TRUSTWORTHY:');
		console.error('  - --runner-exit was given but is not a number: ' + JSON.stringify(rawExit));
		console.error('    The runner status was not captured, so a teardown failure would go unnoticed.');
		process.exit(1);
	}

	let text;
	try {
		text = fs.readFileSync(file, 'utf8');
	} catch (e) {
		console.error('RUN NOT TRUSTWORTHY:');
		console.error('  - could not read ' + file + ': ' + e.message);
		process.exit(1);
	}

	const result = checkTap(text, {minTests, runnerExit});
	if (result.ok) {
		console.log('run complete: ok');
		process.exit(0);
	}
	console.error('RUN NOT TRUSTWORTHY:');
	for (let i = 0; i < result.problems.length; i++) console.error('  - ' + result.problems[i]);
	process.exit(1);
}
