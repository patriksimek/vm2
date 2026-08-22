/**
 * GHSA-6w8r-xxw2-g3hx — node:sqlite loadExtension native code execution
 *
 * ## Vulnerability
 * A NodeVM allowing only `node:sqlite` exposes the host module read-only. Read-
 * only blocks assignment but forwards calls, so sandbox code can build
 * `new DatabaseSync(':memory:', {allowExtension: true})` and call
 * `loadExtension(pathToBundledLib)`, loading a native SQLite extension into the
 * host process and running its entry point — native RCE. (The report also noted
 * `require('node:sqlite')` resolving via a double-`node:`-prefix resolver
 * quirk.)
 *
 * ## Fix
 * lib/builtin.js wraps the DatabaseSync constructor so `allowExtension` is forced
 * off; Node then throws ERR_INVALID_STATE from loadExtension()/enableLoadExtension(),
 * closing every native-extension path while leaving normal SQL usable.
 * lib/setup-node-sandbox.js rejects repeated `node:` prefixes and resolves the
 * canonical `node:sqlite` spelling.
 *
 * Sound oracle: with allowExtension forced off, loadExtension is *disabled*
 * (ERR_INVALID_STATE), so no native library can be loaded at all.
 */

'use strict';

const assert = require('assert');
const { NodeVM } = require('../../../lib/main.js');

// The member sanitizer only has something to sanitize when vm2 can actually
// expose the module, and vm2's inventory comes from `module.builtinModules` --
// NOT from whether the host can `require('node:sqlite')`. On Node 22 the module
// is requireable host-side (experimental) yet absent from `builtinModules`, so
// vm2 never registers it and the sandbox is denied outright -- a strictly
// stronger outcome than forcing `allowExtension` off. Gating on host
// requireability therefore ran the sanitizer assertions on a runtime where the
// module is unreachable by design. Gate on exposability instead, and assert the
// denial on runtimes that do not list it rather than skipping silently.
const vmCanExposeSqlite = require('module').builtinModules.indexOf('node:sqlite') !== -1;

(vmCanExposeSqlite ? describe : describe.skip)('GHSA-6w8r-xxw2-g3hx — node:sqlite extension loading', function () {
	function run(code, cfg) {
		const vm = new NodeVM(cfg || { require: { builtin: ['node:sqlite'] } });
		return vm.run(code, 'p.js');
	}

	it('allowExtension is forced off, so loadExtension is disabled (ERR_INVALID_STATE)', function () {
		const out = run(`
			const { DatabaseSync } = require('node:sqlite');
			const db = new DatabaseSync(':memory:', { allowExtension: true });
			let code;
			try { db.loadExtension('/any/path/to/lib.so'); code = 'LOADED'; }
			catch (e) { code = e.code || e.message; }
			module.exports = code;
		`, { require: { builtin: ['node:sqlite'] } });
		// ERR_INVALID_STATE => extensions are disabled (allowExtension off).
		// If the fix were absent we'd instead see a load attempt (file error) or LOADED.
		assert.strictEqual(out, 'ERR_INVALID_STATE',
			'loadExtension was reachable — allowExtension was not forced off: ' + out);
	});

	it('a FUNCTION options arg with allowExtension:true cannot re-enable extensions (bypass regression)', function () {
		// Follow-up: Node's DatabaseSync accepts a function as its options argument
		// (functions carry own properties), so `function o(){}; o.allowExtension =
		// true` slipped past an object-only guard and re-enabled loadExtension.
		const out = run(`
			const { DatabaseSync } = require('node:sqlite');
			function options() {}
			options.allowExtension = true;
			const db = new DatabaseSync(':memory:', options);
			let code;
			try { db.loadExtension('/any/path/lib.so'); code = 'LOADED'; }
			catch (e) { code = e.code || e.message; }
			module.exports = code;
		`, { require: { builtin: ['node:sqlite'] } });
		assert.strictEqual(out, 'ERR_INVALID_STATE',
			'loadExtension was reachable via a function-typed options arg: ' + out);
	});

	it('enableLoadExtension(true) is also disabled', function () {
		const out = run(`
			const { DatabaseSync } = require('node:sqlite');
			const db = new DatabaseSync(':memory:', { allowExtension: true });
			let code;
			try { db.enableLoadExtension(true); code = 'ENABLED'; }
			catch (e) { code = e.code || e.message; }
			module.exports = code;
		`, { require: { builtin: ['node:sqlite'] } });
		assert.strictEqual(out, 'ERR_INVALID_STATE',
			'enableLoadExtension re-enabled extension loading: ' + out);
	});

	it('does not over-block: ordinary SQL still works', function () {
		const rows = run(`
			const { DatabaseSync } = require('node:sqlite');
			const db = new DatabaseSync(':memory:');
			db.exec('CREATE TABLE t(a INTEGER, b TEXT)');
			db.prepare('INSERT INTO t VALUES (?, ?)').run(1, 'x');
			module.exports = db.prepare('SELECT a, b FROM t').all();
		`, { require: { builtin: ['node:sqlite'] } });
		assert.strictEqual(rows.length, 1);
		assert.strictEqual(rows[0].a, 1);
		assert.strictEqual(rows[0].b, 'x');
	});

	it('rejects the double-node:-prefix spelling and resolves the canonical one', function () {
		const canonical = run(`module.exports = typeof require('node:sqlite').DatabaseSync;`,
			{ require: { builtin: ['node:sqlite'] } });
		assert.strictEqual(canonical, 'function', 'canonical node:sqlite spelling should resolve');

		let doubleThrew = false;
		try {
			run(`module.exports = typeof require('node:node:sqlite').DatabaseSync;`,
				{ require: { builtin: ['node:sqlite'] } });
		} catch (e) { doubleThrew = true; }
		assert.strictEqual(doubleThrew, true, 'node:node:sqlite double-prefix should be rejected');
	});
});

// Runtimes that do not list `node:sqlite` in `module.builtinModules` (e.g. Node
// 22, where SQLite is experimental) must deny it by every spelling, including
// the double-`node:` alias and the `'*'` wildcard. This is the same guarantee
// the sanitizer provides above, reached by module denial instead.
(vmCanExposeSqlite ? describe.skip : describe)('GHSA-6w8r-xxw2-g3hx — node:sqlite unavailable to the sandbox', function () {
	const spellings = ['node:sqlite', 'sqlite', 'node:node:sqlite'];
	const configs = [
		['explicit node:sqlite', { require: { builtin: ['node:sqlite'] } }],
		['wildcard', { require: { builtin: ['*'] } }]
	];

	configs.forEach(function (entry) {
		spellings.forEach(function (spelling) {
			it(`denies require('${spelling}') under ${entry[0]}`, function () {
				assert.throws(function () {
					new NodeVM(entry[1]).run(
						`module.exports = typeof require('${spelling}').DatabaseSync;`, 'p.js');
				}, /Cannot find module/);
			});
		});
	});
});
