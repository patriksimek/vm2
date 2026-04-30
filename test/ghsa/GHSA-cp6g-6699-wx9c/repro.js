/**
 * GHSA-cp6g-6699-wx9c — NodeVM require.root symlink bypass
 *
 * Fixed in: commit subject contains GHSA-cp6g-6699-wx9c (git log --grep=GHSA-cp6g-6699-wx9c)
 *
 * ## Vulnerability
 * NodeVM's `require.root` boundary check is a path-prefix string compare on the
 * lexically resolved candidate filename. `path.resolve()` does not dereference
 * symlinks but Node's native `require()` does, so a symlink inside the allowed
 * root that points outside it passes the prefix check while loading code from
 * outside the root. With `context: 'host'`, the attacker reaches host-realm
 * `require()` and trivially escalates to RCE (e.g. by loading vm2 itself and
 * spinning up a privileged inner NodeVM with `child_process`).
 *
 * ## Fix
 * `DefaultFileSystem`/`VMFileSystem` now expose `realpath()` and `isPathAllowed`
 * canonicalises the candidate filename via `fs.realpath()` before performing the
 * prefix check (deny by default if canonicalisation fails). Root paths are also
 * realpath'd at construction time so the prefix bases match the candidate's
 * canonical form. Net result: a symlink target outside `root` is rejected.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {NodeVM, VMError} = require('../../../lib/main.js');

// Each test creates its own scratch tree under tmpdir and tears it down in
// afterEach. We avoid sharing state across cases.
let tmp;

function mkdtemp() {
	return fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'vm2-cp6g-'));
}

function rmrf(p) {
	try { fs.rmSync(p, {recursive: true, force: true}); } catch (e) { /* ignore */ }
}

describe('GHSA-cp6g-6699-wx9c — require.root symlink bypass', () => {

	afterEach(() => {
		if (tmp) {
			rmrf(tmp);
			tmp = undefined;
		}
	});

	it('rejects file-level symlink pointing outside root', () => {
		tmp = mkdtemp();
		const root = path.join(tmp, 'root');
		fs.mkdirSync(root);
		const outside = path.join(tmp, 'outside.js');
		const link = path.join(root, 'link.js');
		// Outside payload writes a sentinel file when executed; if the sandbox
		// boundary holds, the require() must fail and the sentinel must not exist.
		const sentinel = path.join(tmp, 'pwned');
		fs.writeFileSync(outside, `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'pwned'); module.exports = 1;`);
		fs.symlinkSync(outside, link);

		const vm = new NodeVM({require: {external: true, root, context: 'host'}});

		assert.throws(
			() => vm.run("module.exports = require('./link.js')", path.join(root, 'entry.js')),
			err => {
				// Either VMError EDENIED or the resolver's ENOTFOUND is acceptable —
				// what matters is the require() never executed the outside script.
				return err && (err.code === 'EDENIED' || err.code === 'ENOTFOUND' || err instanceof VMError || /not allowed|Cannot find module/.test(err.message));
			}
		);
		assert.strictEqual(fs.existsSync(sentinel), false, 'outside payload must not have executed');
	});

	it('rejects directory-level symlink (pnpm/npm-link layout)', () => {
		tmp = mkdtemp();
		const root = path.join(tmp, 'root');
		fs.mkdirSync(path.join(root, 'node_modules'), {recursive: true});

		// Outside package: name "safe", payload writes a sentinel.
		const outsidePkg = path.join(tmp, 'outside-pkg');
		fs.mkdirSync(outsidePkg);
		fs.writeFileSync(path.join(outsidePkg, 'package.json'), JSON.stringify({name: 'safe', main: 'index.js'}));
		const sentinel = path.join(tmp, 'pwned');
		fs.writeFileSync(
			path.join(outsidePkg, 'index.js'),
			`require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'pwned'); module.exports = 1;`
		);

		// Symlink inside root pointing to the outside package — exactly what
		// pnpm, npm workspaces, and `npm link` create.
		const link = path.join(root, 'node_modules', 'safe');
		fs.symlinkSync(outsidePkg, link, 'dir');

		const vm = new NodeVM({require: {external: ['safe'], root, context: 'host', builtin: []}});

		assert.throws(
			() => vm.run("module.exports = require('safe')", path.join(root, 'entry.js')),
			err => err && (err.code === 'EDENIED' || err.code === 'ENOTFOUND' || err instanceof VMError || /not allowed|Cannot find module/.test(err.message))
		);
		assert.strictEqual(fs.existsSync(sentinel), false, 'outside package must not have executed');
	});

	it('still loads a non-symlinked file inside root (legitimate case)', () => {
		tmp = mkdtemp();
		const root = path.join(tmp, 'root');
		fs.mkdirSync(root);
		fs.writeFileSync(path.join(root, 'inside.js'), "module.exports = 'hello-from-root';");

		const vm = new NodeVM({require: {external: true, root, context: 'host'}});
		const out = vm.run("module.exports = require('./inside.js')", path.join(root, 'entry.js'));
		assert.strictEqual(out, 'hello-from-root');
	});

	it('still loads files when the root path itself contains a symlink', () => {
		// Root configured as a symlinked directory; canonical files inside should
		// continue to load. Verifies that realpath'ing both sides of the prefix
		// check stays consistent.
		tmp = mkdtemp();
		const realRoot = path.join(tmp, 'real-root');
		fs.mkdirSync(realRoot);
		fs.writeFileSync(path.join(realRoot, 'inside.js'), "module.exports = 'via-symlinked-root';");
		const symRoot = path.join(tmp, 'sym-root');
		fs.symlinkSync(realRoot, symRoot, 'dir');

		const vm = new NodeVM({require: {external: true, root: symRoot, context: 'host'}});
		const out = vm.run("module.exports = require('./inside.js')", path.join(symRoot, 'entry.js'));
		assert.strictEqual(out, 'via-symlinked-root');
	});

});
