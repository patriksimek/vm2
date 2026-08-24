/**
 * GHSA-6rh5-qq4q-97xh — NodeVM builtin denylist bypass via subpath siblings:
 * `builtin: ['*', '-fs']` still exposes host `fs/promises`, allowing host
 * filesystem writes (`require('fs/promises').writeFile(...)`).
 *
 * ## Vulnerability
 * `makeBuiltinsFromLegacyOptions` expands `builtin: ['*']` and denies a name
 * only on an exact `-${name}` match. `fs` and `fs/promises` are *separate*
 * entries in `require('module').builtinModules`, so `-fs` removes only the
 * `fs` key; `fs/promises` (a full host filesystem API, including `writeFile`)
 * stays registered by `addDefaultBuiltin`. The same gap affects every subpath
 * family: `-path` still exposes `path/posix` / `path/win32`, `-stream` still
 * exposes `stream/promises` / `stream/web`, `-timers` still exposes
 * `timers/promises`, etc.
 *
 * ## Fix
 * `lib/builtin.js`: a negative deny token for a family (`-fs`) also denies its
 * subpath members (`fs/promises`). The `'*'` deny check treats a name of the
 * form `<family>/<sub>` as denied when `-<family>` is present.
 *
 * ## Sound oracle
 * `require('fs/promises')` returning a module with a real `writeFile` is host
 * reach. The test asserts the require is denied — no host file is touched.
 */

'use strict';

const assert = require('assert');
const { NodeVM } = require('../../../lib/main.js');

function loaded(vm, spec) {
	return vm.run(`
		try { const m = require(${JSON.stringify(spec)}); module.exports = { loaded: true, keys: typeof m }; }
		catch (e) { module.exports = { loaded: false, code: e && e.code }; }
	`);
}

// Which subpath builtins Node ships is runtime-dependent, and the assertions
// below are only meaningful where the subpath genuinely exists as a host module:
// on a runtime that never had `fs/promises`, `require('fs/promises')` fails for
// the mundane reason that there is no such module, which would make a denial
// assertion pass without exercising the fix at all. Gate on the observable
// capability (`module.builtinModules`), never on a version number.
//
//   Node  8/10 -- no subpath builtins beyond `v8/tools/*` internals
//   Node    12 -- no subpath builtins at all
//   Node    14 -- `fs/promises` only
//   Node   16+ -- `path/posix`, `path/win32`, `stream/*`, `timers/promises`, ...
const BUILTINS = require('module').builtinModules || [];
const has = name => BUILTINS.indexOf(name) >= 0;
const HAS_FS_SUBPATH = has('fs/promises');
const HAS_PATH_SUBPATH = has('path/posix') && has('path/win32');

// For the over-deny direction we need a subpath builtin belonging to a family
// OTHER than the one being denied. Which pair is available differs per runtime,
// so pick a real one rather than hardcoding a name a given major may not ship.
// it.cond is set up by test/vm.js when the main suite runs first; if this GHSA
// regression file is loaded standalone (mocha file-order is undefined), fall
// back to a local shim so the cond gating still works.
if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const OVER_DENY =
	HAS_PATH_SUBPATH ? {token: '-fs', family: 'path', subpath: 'path/posix'} :
		HAS_FS_SUBPATH ? {token: '-path', family: 'fs', subpath: 'fs/promises'} :
			null;

describe('GHSA-6rh5-qq4q-97xh (builtin denylist bypass via subpath siblings)', function () {
	it('`-fs` denies the host `fs` family (both spellings)', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-fs', '-child_process'] } });
		assert.strictEqual(loaded(vm, 'fs').loaded, false, 'require("fs") was exposed despite -fs');
		assert.strictEqual(loaded(vm, 'node:fs').loaded, false, 'require("node:fs") was exposed despite -fs');
	});

	it.cond('`-fs` denies the host `fs/promises` subpath', HAS_FS_SUBPATH, function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-fs', '-child_process'] } });
		assert.strictEqual(loaded(vm, 'fs/promises').loaded, false, 'require("fs/promises") reached host fs despite -fs');
		assert.strictEqual(loaded(vm, 'node:fs/promises').loaded, false, 'require("node:fs/promises") reached host fs despite -fs');
	});

	it('`-path` denies the `path` family', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-path'] } });
		assert.strictEqual(loaded(vm, 'path').loaded, false, 'require("path") exposed despite -path');
	});

	it.cond('`-path` denies the `path/posix` and `path/win32` subpaths', HAS_PATH_SUBPATH, function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-path'] } });
		assert.strictEqual(loaded(vm, 'path/posix').loaded, false, 'require("path/posix") exposed despite -path');
		assert.strictEqual(loaded(vm, 'path/win32').loaded, false, 'require("path/win32") exposed despite -path');
	});

	// Composition with GHSA-8686-vhfx-7r3j: that advisory normalized the `node:`
	// prefix on deny tokens, this one extended tokens to cover subpaths. Both
	// run through the shared `isBuiltinDenied` chokepoint, so a `node:`-spelled
	// token must also reach the family's subpaths — the case neither advisory
	// exercised on its own.
	it('`-node:fs` denies both un-prefixed spellings of the fs family', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-node:fs'] } });
		for (const spec of ['fs', 'node:fs']) {
			assert.strictEqual(loaded(vm, spec).loaded, false, `require(${JSON.stringify(spec)}) exposed despite -node:fs`);
		}
	});

	it.cond('`-node:fs` also reaches the fs family subpaths', HAS_FS_SUBPATH, function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-node:fs'] } });
		for (const spec of ['fs/promises', 'node:fs/promises']) {
			assert.strictEqual(loaded(vm, spec).loaded, false, `require(${JSON.stringify(spec)}) exposed despite -node:fs`);
		}
	});

	it('does not over-deny: an undenied family stays available', function () {
		// `-fs` must not affect the unrelated `path` family.
		const vm = new NodeVM({ require: { builtin: ['*', '-fs'] } });
		assert.strictEqual(loaded(vm, 'path').loaded, true, 'require("path") wrongly denied');
	});

	it.cond('does not over-deny: an undenied family keeps its subpath', OVER_DENY !== null, function () {
		const vm = new NodeVM({ require: { builtin: ['*', OVER_DENY.token] } });
		assert.strictEqual(loaded(vm, OVER_DENY.family).loaded, true, `require("${OVER_DENY.family}") wrongly denied by ${OVER_DENY.token}`);
		assert.strictEqual(loaded(vm, OVER_DENY.subpath).loaded, true, `require("${OVER_DENY.subpath}") wrongly denied by ${OVER_DENY.token}`);
	});
});
