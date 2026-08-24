/**
 * GHSA-7q3f-wx44-378m — NodeVM external allowlist bypass: a prefix-sharing
 * sibling package is treated as allowlisted.
 *
 * ## Vulnerability
 * `LegacyResolver.isPathAllowedForModule(path, mod)` authorizes a require
 * originating from an allowlisted module `mod` with a raw
 * `path.startsWith(mod.path)` test and no path-boundary check. For an
 * allowlisted module at `.../node_modules/foo`, a sibling
 * `.../node_modules/foo2/index.js` passes `startsWith` (the remainder
 * `2/index.js` contains no `node_modules` segment), so the unrelated sibling
 * `foo2` loads as if it were the allowlisted `foo`.
 *
 * ## Fix
 * `lib/resolver-compat.js`: require a path boundary after `mod.path` — an exact
 * match, `mod.path` already ending in a separator, or the next character being
 * a separator — mirroring the boundary check already used by the base
 * `CustomResolver.isPathAllowed`. `foo2` no longer matches `foo`.
 *
 * ## Test
 * Drives `isPathAllowedForModule` directly through a resolver built by
 * `makeResolverFromLegacyOptions` (no `require.root`, so the base boundary check
 * is a no-op and this test isolates the module-prefix boundary).
 */

'use strict';

const assert = require('assert');
const { makeResolverFromLegacyOptions } = require('../../../lib/resolver-compat.js');

describe('GHSA-7q3f-wx44-378m (external allowlist sibling-prefix bypass)', function () {
	const resolver = makeResolverFromLegacyOptions({ external: ['foo'] });
	const mod = { path: '/app/node_modules/foo', allowTransitive: false };

	it('denies a prefix-sharing sibling package (foo2 vs allowlisted foo)', function () {
		assert.strictEqual(
			resolver.isPathAllowedForModule('/app/node_modules/foo2/index.js', mod),
			false,
			'sibling node_modules/foo2 was authorized as if it were the allowlisted foo',
		);
		assert.strictEqual(
			resolver.isPathAllowedForModule('/app/node_modules/foobar/index.js', mod),
			false,
			'sibling node_modules/foobar was authorized as if it were foo',
		);
	});

	it('still allows the allowlisted module itself and its own subpaths', function () {
		assert.strictEqual(resolver.isPathAllowedForModule('/app/node_modules/foo', mod), true, 'the module dir itself was denied');
		assert.strictEqual(resolver.isPathAllowedForModule('/app/node_modules/foo/index.js', mod), true, 'a file directly under the module was denied');
		assert.strictEqual(resolver.isPathAllowedForModule('/app/node_modules/foo/lib/util.js', mod), true, 'a nested file under the module was denied');
	});

	it('still denies a nested node_modules dependency under the allowlisted module', function () {
		// Pre-existing invariant (transitive:false): a nested node_modules must
		// not be reachable even from the allowlisted module.
		assert.strictEqual(
			resolver.isPathAllowedForModule('/app/node_modules/foo/node_modules/bar/index.js', mod),
			false,
			'a nested node_modules dependency was authorized under transitive:false',
		);
	});
});

/**
 * End-to-end coverage through the real NodeVM require path.
 *
 * The block above drives `isPathAllowedForModule` directly. These tests exercise
 * the attack as it actually presents: an allowlisted package performing a
 * relative require to a prefix-sharing sibling, with `transitive: false`. Without
 * the boundary check every `sibling` case below loads the un-allowlisted package.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { NodeVM } = require('../../../lib/main.js');
const {mkdirpSync, rmrfSync} = require('../../fs-compat.js');

describe('GHSA-7q3f-wx44-378m (sibling-prefix bypass through the NodeVM require path)', function () {
	let root;

	function pkg(name, body) {
		const dir = path.join(root, 'node_modules', name);
		mkdirpSync(dir);
		fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({name, version: '1.0.0', main: 'index.js'}));
		fs.writeFileSync(path.join(dir, 'index.js'), body);
		return dir;
	}

	before(function () {
		// realpath: on macOS os.tmpdir() is itself a symlink, and require.root
		// canonicalizes its roots at construction (GHSA-cp6g-6699-wx9c).
		root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-7q3f-')));
		// The allowlisted package, with a sandbox-reachable relative require.
		pkg('foo', 'module.exports = {who: "foo", reach: n => require("../" + n)};');
		mkdirpSync(path.join(root, 'node_modules', 'foo', 'lib'));
		fs.writeFileSync(path.join(root, 'node_modules', 'foo', 'lib', 'x.js'), 'module.exports = "foo-lib-x";');
		// Prefix-sharing siblings that must stay unreachable.
		for (const name of ['foo2', 'foo-evil', 'foobar']) pkg(name, `module.exports = {who: ${JSON.stringify(name)}};`);
		// Scoped pair — same bug shape, no special boundary semantics.
		pkg('@scope/pkg', 'module.exports = {who: "@scope/pkg", reach: n => require("../" + n)};');
		pkg('@scope/pkg-evil', 'module.exports = {who: "@scope/pkg-evil"};');
	});

	after(function () {
		if (root) rmrfSync(root);
	});

	function run(code, modules, transitive) {
		const vm = new NodeVM({require: {external: {modules, transitive}, context: 'sandbox', root}});
		return vm.run(code, path.join(root, 'main.js'));
	}

	describe('transitive: false (the advisory configuration)', function () {
		for (const sibling of ['foo2', 'foo-evil', 'foobar']) {
			it(`denies prefix-sharing sibling ${sibling} reached by relative require from foo`, function () {
				assert.throws(
					() => run(`module.exports = require("foo").reach(${JSON.stringify(sibling)})`, ['foo'], false),
					/Cannot find module/,
					`un-allowlisted sibling ${sibling} was loaded through the allowlisted package foo`,
				);
			});
		}

		it('denies a non-prefix-sharing sibling too (unchanged pre-existing behaviour)', function () {
			assert.throws(() => run('module.exports = require("foo").reach("foobar/../foo2")', ['foo'], false), /Cannot find module/);
		});
	});

	describe('transitive: true', function () {
		// NOT a bypass, and deliberately unchanged by this fix. `transitive: true`
		// sets `mod.allowTransitive`, which short-circuits `isPathAllowedForModule`
		// BEFORE the prefix check — that is what the option means: an allowlisted
		// package may pull in its dependencies. npm flattens `node_modules`, so a
		// genuine transitive dependency IS a sibling directory. Asserted here so a
		// future change to the boundary check cannot silently alter this branch.
		it('still permits sibling loading from an allowlisted package', function () {
			assert.strictEqual(run('module.exports = require("foo").reach("foo2").who', ['foo'], true), 'foo2');
		});
	});

	for (const transitive of [false, true]) {
		describe(`no over-block, transitive: ${transitive}`, function () {
			it('still loads the allowlisted package itself', function () {
				assert.strictEqual(run('module.exports = require("foo").who', ['foo'], transitive), 'foo');
			});

			it('still loads a legitimate subpath inside the allowlisted package', function () {
				assert.strictEqual(run('module.exports = require("foo/lib/x.js")', ['foo'], transitive), 'foo-lib-x');
			});
		});
	}

	it('denies a prefix-sharing sibling of a SCOPED allowlisted package', function () {
		assert.throws(
			() => run('module.exports = require("@scope/pkg").reach("pkg-evil")', ['@scope/pkg'], false),
			/Cannot find module/,
			'@scope/pkg-evil was loaded through the allowlisted @scope/pkg',
		);
	});

	it('still loads the allowlisted scoped package itself', function () {
		assert.strictEqual(run('module.exports = require("@scope/pkg").who', ['@scope/pkg'], false), '@scope/pkg');
	});
});
