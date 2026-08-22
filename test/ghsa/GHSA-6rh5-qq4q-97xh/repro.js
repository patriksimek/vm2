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

describe('GHSA-6rh5-qq4q-97xh (builtin denylist bypass via subpath siblings)', function () {
	it('`-fs` denies the host `fs/promises` subpath (and `fs`)', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-fs', '-child_process'] } });
		assert.strictEqual(loaded(vm, 'fs').loaded, false, 'require("fs") was exposed despite -fs');
		assert.strictEqual(loaded(vm, 'fs/promises').loaded, false, 'require("fs/promises") reached host fs despite -fs');
		assert.strictEqual(loaded(vm, 'node:fs/promises').loaded, false, 'require("node:fs/promises") reached host fs despite -fs');
	});

	it('`-path` denies the `path/posix` and `path/win32` subpaths', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-path'] } });
		assert.strictEqual(loaded(vm, 'path').loaded, false, 'require("path") exposed despite -path');
		assert.strictEqual(loaded(vm, 'path/posix').loaded, false, 'require("path/posix") exposed despite -path');
		assert.strictEqual(loaded(vm, 'path/win32').loaded, false, 'require("path/win32") exposed despite -path');
	});

	// Composition with GHSA-8686-vhfx-7r3j: that advisory normalized the `node:`
	// prefix on deny tokens, this one extended tokens to cover subpaths. Both
	// run through the shared `isBuiltinDenied` chokepoint, so a `node:`-spelled
	// token must also reach the family's subpaths — the case neither advisory
	// exercised on its own.
	it('`-node:fs` denies every spelling of the fs family, including subpaths', function () {
		const vm = new NodeVM({ require: { builtin: ['*', '-node:fs'] } });
		for (const spec of ['fs', 'node:fs', 'fs/promises', 'node:fs/promises']) {
			assert.strictEqual(loaded(vm, spec).loaded, false, `require(${JSON.stringify(spec)}) exposed despite -node:fs`);
		}
	});

	it('does not over-deny: a family that is NOT denied keeps its subpath', function () {
		// `-fs` must not affect the unrelated `path` family.
		const vm = new NodeVM({ require: { builtin: ['*', '-fs'] } });
		assert.strictEqual(loaded(vm, 'path').loaded, true, 'require("path") wrongly denied');
		assert.strictEqual(loaded(vm, 'path/posix').loaded, true, 'require("path/posix") wrongly denied');
	});
});
