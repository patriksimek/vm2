'use strict';

// Portable filesystem helpers for the regression suites.
//
// The suite has to pass on Node 8 through current. Two fs conveniences the
// tests reach for are much newer than that floor:
//
//   fs.mkdirSync(p, {recursive: true})  -- Node 10.12+ (on Node 8 the options
//                                          object is read as a mode, so a
//                                          missing parent fails with ENOENT)
//   fs.rmSync(p, {recursive: true, ...}) -- Node 14.14+
//
// These are fixture plumbing, not the behaviour under test, so the tests should
// keep RUNNING on old runtimes rather than being gated off them. Both helpers
// are feature-detected, never version-detected.

const fs = require('fs');
const path = require('path');

// mkdir -p. Equivalent to fs.mkdirSync(target, {recursive: true}).
function mkdirpSync(target) {
	const parent = path.dirname(target);
	if (parent && parent !== target && !fs.existsSync(parent)) mkdirpSync(parent);
	try {
		fs.mkdirSync(target);
	} catch (e) {
		if (e.code !== 'EEXIST') throw e;
	}
}

// rm -rf. Equivalent to fs.rmSync(target, {recursive: true, force: true}):
// missing paths are not an error.
function rmrfSync(target) {
	if (!target) return;
	if (typeof fs.rmSync === 'function') {
		fs.rmSync(target, {recursive: true, force: true});
		return;
	}
	let stat;
	try {
		stat = fs.lstatSync(target);
	} catch (e) {
		return; // force: absent is success
	}
	if (stat.isDirectory()) {
		const entries = fs.readdirSync(target);
		for (let i = 0; i < entries.length; i++) rmrfSync(path.join(target, entries[i]));
		fs.rmdirSync(target);
	} else {
		fs.unlinkSync(target);
	}
}

module.exports = {mkdirpSync, rmrfSync};
