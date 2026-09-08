/**
 * GHSA-5h3f-q97h-ccvc — NodeVM custom-resolver authorization admits
 * prefix-sharing siblings.
 *
 * ## Vulnerability
 * After the embedder's `require.resolve` returns, `LegacyResolver.customResolve`
 * appended a raw path prefix to its authorization record:
 *
 *     this.externals.push(new RegExp('^' + escapeRegExp(resolved)));
 *
 * `isPathAllowedForModule` falls back to `this.externals.some(re => re.test(path))`,
 * and that regex has no path boundary. Once `foo` resolved to
 * `.../node_modules/foo`, a later absolute `require('.../node_modules/foo2/index.js')`
 * matched `^.../node_modules/foo` and was authorized. With the default
 * `context: 'host'` the sibling is loaded by the host `require()`, so its
 * top-level code runs with host authority.
 *
 * The object return shape (`{module, path}`) is the same bug one level wider:
 * `path` is a node_modules SEARCH directory, so authorizing it authorized every
 * package inside it.
 *
 * ## Fix
 * `lib/resolver-compat.js`: custom-resolver authorizations are stored as
 * resolved base paths in `this.externalPaths` and matched with the shared
 * `isPathWithin` boundary predicate (exact match, or a separator at the
 * boundary, via `this.fs.isSeparator`) — the same idiom the GHSA-7q3f-wx44-378m
 * check uses for `mod.path`. The object shape authorizes only the resolved
 * package directory inside the search directory, never the search directory.
 * The `<path><ext>` candidates the loader probes are authorized individually in
 * `this.externalExact` by full equality, so an extension-less resolver answer
 * still resolves while no sibling of it does, and an authorization is taken back
 * when the load it was recorded for produces no module.
 *
 * ## Test
 * Drives the real NodeVM require path with `context: 'host'`. The oracle is a
 * marker file each sibling writes with the HOST `fs` at its top level: if the
 * marker exists, un-allowlisted code ran in the host. Every sibling has its own
 * module file and its own marker, because host `require()` caches modules
 * process-wide and a module loaded once would not re-run its top level.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { NodeVM } = require('../../../lib/main.js');
const { mkdirpSync, rmrfSync } = require('../../fs-compat.js');

describe('GHSA-5h3f-q97h-ccvc (custom-resolver prefix-sharing sibling authorization)', function () {
	let base;
	let root;
	let nodeModules;
	let pkgs;
	let files;
	let entry;

	// A module whose top-level code writes a host marker file. Loading it at all
	// is the escape; the marker proves the top level ran in the host realm.
	function attacker(file, name) {
		mkdirpSync(path.dirname(file));
		fs.writeFileSync(file,
			'require("fs").writeFileSync(' + JSON.stringify(markerOf(name)) + ', "PWNED");\n' +
			'module.exports = ' + JSON.stringify('PWN:' + name) + ';');
	}

	function benign(file, value) {
		mkdirpSync(path.dirname(file));
		fs.writeFileSync(file, 'module.exports = ' + JSON.stringify(value) + ';');
	}

	function markerOf(name) {
		return path.join(root, name + '.marker');
	}

	before(function () {
		// realpath: on macOS os.tmpdir() is itself a symlink, and require.root
		// canonicalizes its roots at construction (GHSA-cp6g-6699-wx9c).
		base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-5h3f-')));
		root = path.join(base, 'root');
		nodeModules = path.join(root, 'node_modules');
		pkgs = path.join(root, 'pkgs');
		files = path.join(root, 'files');
		// The entry module lives OUTSIDE root, so the ordinary lookup paths never
		// find `foo` and the custom resolver is consulted — the advisory's shape.
		// Its directory is also disjoint from root: the main module's own directory
		// tree is authorized for it by `isPathAllowedForModule`'s `mod.path` branch,
		// which would otherwise mask the authorization under test.
		entry = path.join(base, 'entry', 'entry.js');
		mkdirpSync(path.dirname(entry));

		// The allowlisted package, in a node_modules directory.
		benign(path.join(nodeModules, 'foo', 'index.js'), 'FOO_OK');
		benign(path.join(nodeModules, 'foo', 'lib', 'inner.js'), 'INNER_OK');
		// The same package outside any node_modules directory. `external: ['foo']`
		// builds a static matcher anchored on `node_modules/foo`, so a package here
		// is authorized ONLY by what customResolve appends — these cases isolate the
		// authorization under test.
		benign(path.join(pkgs, 'foo', 'index.js'), 'PKG_FOO_OK');
		benign(path.join(pkgs, 'foo', 'lib', 'inner.js'), 'PKG_INNER_OK');

		// Prefix-sharing siblings. One module file and one marker per case.
		attacker(path.join(nodeModules, 'foo2', 'index.js'), 'nm-foo2');
		attacker(path.join(nodeModules, 'foo3', 'index.js'), 'nm-foo3');
		attacker(path.join(nodeModules, 'foo4', 'index.js'), 'nm-foo4');
		attacker(path.join(nodeModules, 'foo5', 'index.js'), 'nm-foo5');
		attacker(path.join(nodeModules, 'foo6', 'index.js'), 'nm-foo6');
		attacker(path.join(pkgs, 'foo2', 'index.js'), 'pkgs-foo2');
		attacker(path.join(pkgs, 'foo3', 'index.js'), 'pkgs-foo3');
		// Siblings of a resolved FILE path (`.../pkgs/foo/index.js`).
		attacker(path.join(pkgs, 'foo', 'index.jsx'), 'jsx');
		attacker(path.join(pkgs, 'foo', 'index.js.evil.js'), 'evil');

		// An extension-less resolver answer (`.../pkgs/ext/index` -> `index.js`),
		// which the loader finds by probing extensions, plus siblings that the
		// probe must not reach.
		benign(path.join(pkgs, 'ext', 'index.js'), 'EXTLESS_OK');
		attacker(path.join(pkgs, 'ext', 'index.jsx'), 'ext-jsx');
		attacker(path.join(pkgs, 'ext', 'index2.js'), 'ext-index2');

		// The same for the {module, path} shape, where the module IS the file
		// `<dir>/bar.js` (LOAD_AS_FILE(DIR/X)).
		benign(path.join(files, 'bar.js'), 'BAR_OK');
		attacker(path.join(files, 'bar.jsx'), 'bar-jsx');
		attacker(path.join(files, 'bar2.js'), 'bar2');

		// Scoped package resolved through the {module, path} shape.
		benign(path.join(pkgs, '@sc', 'pkg', 'index.js'), 'SCOPED_OK');
		attacker(path.join(pkgs, '@sc', 'pkg2', 'index.js'), 'sc-pkg2');

		// Directories a resolver answer points at but that resolve to no module:
		// nothing loadable at the top level, only a file a later require could aim
		// at if the failed resolution left its authorization behind.
		attacker(path.join(pkgs, 'ghost', 'evil.js'), 'ghost-evil');
		attacker(path.join(files, 'nope', 'evil.js'), 'nope-evil');
	});

	after(function () {
		if (base) rmrfSync(base);
	});

	function run(resolve, code, modules) {
		const vm = new NodeVM({
			require: {
				external: {modules: modules || ['foo'], transitive: false},
				root: root,
				context: 'host',
				resolve: resolve
			}
		});
		return vm.run(code, entry);
	}

	function attempt(resolve, code, modules) {
		try {
			return {loaded: true, value: run(resolve, code, modules)};
		} catch (e) {
			return {loaded: false, error: e};
		}
	}

	// The escape condition: the sibling's top-level code must not have run in the
	// host, and its exports must not have reached the sandbox.
	function assertDenied(res, name, what) {
		assert.strictEqual(fs.existsSync(markerOf(name)), false,
			what + ': the un-allowlisted sibling ran its top-level code in the HOST realm');
		assert.notStrictEqual(res.value, 'PWN:' + name,
			what + ': the un-allowlisted sibling\'s exports reached the sandbox');
		assert.strictEqual(res.loaded, false, what + ': the un-allowlisted sibling loaded');
	}

	const dirResolver = function (name) {
		return name === 'foo' ? path.join(nodeModules, 'foo') : undefined;
	};
	const pkgDirResolver = function (name) {
		return name === 'foo' ? path.join(pkgs, 'foo') : undefined;
	};
	const fileResolver = function (name) {
		return name === 'foo' ? path.join(pkgs, 'foo', 'index.js') : undefined;
	};
	const searchDirResolver = function (name) {
		return name === 'foo' ? {module: 'foo', path: nodeModules} : undefined;
	};
	const pkgSearchDirResolver = function (name) {
		return name === 'foo' ? {module: 'foo', path: pkgs} : undefined;
	};
	// An extension-less answer: the file is `<pkgs>/ext/index.js`.
	const extlessResolver = function (name) {
		return name === 'foo' ? path.join(pkgs, 'ext', 'index') : undefined;
	};
	// The {module, path} shape where the module IS the file `<files>/bar.js`.
	const fileSearchDirResolver = function (name) {
		return name === 'bar' ? {module: 'bar', path: files} : undefined;
	};
	const scopedSearchDirResolver = function (name) {
		return name === '@sc/pkg' ? {module: '@sc/pkg', path: pkgs} : undefined;
	};
	// Answers that resolve to no module at all.
	const ghostResolver = function (name) {
		return name === 'foo' ? path.join(pkgs, 'ghost') : undefined;
	};
	const ghostSearchDirResolver = function (name) {
		return name === 'bar' ? {module: 'nope', path: files} : undefined;
	};

	function requireAbs(file) {
		return 'module.exports = require(' + JSON.stringify(file) + ');';
	}

	function requireFooThen(file) {
		return 'require("foo"); ' + requireAbs(file);
	}

	describe('string-return resolver naming the package directory', function () {
		it('denies a prefix-sharing sibling package after the allowlisted module resolved', function () {
			const res = attempt(dirResolver, requireFooThen(path.join(nodeModules, 'foo2', 'index.js')));
			assertDenied(res, 'nm-foo2', 'sibling node_modules/foo2');
		});

		it('denies the sibling reached through a `..` segment in the absolute path', function () {
			const traversal = path.join(nodeModules, 'foo') + path.sep + '..' + path.sep + 'foo3' + path.sep + 'index.js';
			const res = attempt(dirResolver, requireFooThen(traversal));
			assertDenied(res, 'nm-foo3', 'sibling reached as foo/../foo3/index.js');
		});

		it('denies the sibling reached with a trailing separator on the authorized directory', function () {
			const traversal = path.join(nodeModules, 'foo') + path.sep + path.sep + '..' + path.sep + 'foo4' + path.sep + 'index.js';
			const res = attempt(dirResolver, requireFooThen(traversal));
			assertDenied(res, 'nm-foo4', 'sibling reached as foo//../foo4/index.js');
		});

		it('denies the sibling package directory itself', function () {
			const res = attempt(dirResolver, requireFooThen(path.join(nodeModules, 'foo5')));
			assertDenied(res, 'nm-foo5', 'sibling directory node_modules/foo5');
		});

		it('denies a prefix-sharing sibling outside node_modules (only the appended authorization applies)', function () {
			const res = attempt(pkgDirResolver, requireFooThen(path.join(pkgs, 'foo2', 'index.js')));
			assertDenied(res, 'pkgs-foo2', 'sibling pkgs/foo2');
		});

		it('still loads the allowlisted module and its own subpaths (no over-block)', function () {
			assert.strictEqual(run(dirResolver, 'module.exports = require("foo");'), 'FOO_OK');
			assert.strictEqual(
				run(dirResolver, requireFooThen(path.join(nodeModules, 'foo', 'lib', 'inner.js'))),
				'INNER_OK');
			assert.strictEqual(run(pkgDirResolver, 'module.exports = require("foo");'), 'PKG_FOO_OK');
			assert.strictEqual(
				run(pkgDirResolver, requireFooThen(path.join(pkgs, 'foo', 'lib', 'inner.js'))),
				'PKG_INNER_OK');
		});
	});

	describe('string-return resolver naming a FILE', function () {
		it('denies a sibling file sharing the resolved filename as a prefix', function () {
			const res = attempt(fileResolver, requireFooThen(path.join(pkgs, 'foo', 'index.jsx')));
			assertDenied(res, 'jsx', 'sibling index.jsx of resolved index.js');
		});

		it('denies a sibling file whose name extends the resolved filename', function () {
			const res = attempt(fileResolver, requireFooThen(path.join(pkgs, 'foo', 'index.js.evil.js')));
			assertDenied(res, 'evil', 'sibling index.js.evil.js of resolved index.js');
		});

		it('still loads the resolved file itself (no over-block)', function () {
			assert.strictEqual(run(fileResolver, 'module.exports = require("foo");'), 'PKG_FOO_OK');
		});
	});

	describe('object-return resolver ({module, path})', function () {
		it('denies a sibling package inside the search directory', function () {
			const res = attempt(searchDirResolver, requireFooThen(path.join(nodeModules, 'foo6', 'index.js')));
			assertDenied(res, 'nm-foo6', 'sibling node_modules/foo6 inside the authorized search directory');
		});

		it('denies a sibling package inside a search directory outside node_modules', function () {
			const res = attempt(pkgSearchDirResolver, requireFooThen(path.join(pkgs, 'foo3', 'index.js')));
			assertDenied(res, 'pkgs-foo3', 'sibling pkgs/foo3 inside the authorized search directory');
		});

		it('denies a prefix-sharing sibling of a SCOPED package resolved this way', function () {
			const res = attempt(scopedSearchDirResolver,
				'require("@sc/pkg"); ' + requireAbs(path.join(pkgs, '@sc', 'pkg2', 'index.js')),
				['@sc/pkg']);
			assertDenied(res, 'sc-pkg2', 'sibling pkgs/@sc/pkg2 of the resolved @sc/pkg');
		});

		it('still resolves the module through the search directory (no over-block)', function () {
			assert.strictEqual(run(searchDirResolver, 'module.exports = require("foo");'), 'FOO_OK');
			assert.strictEqual(run(pkgSearchDirResolver, 'module.exports = require("foo");'), 'PKG_FOO_OK');
			assert.strictEqual(
				run(pkgSearchDirResolver, requireFooThen(path.join(pkgs, 'foo', 'lib', 'inner.js'))),
				'PKG_INNER_OK');
			assert.strictEqual(
				run(scopedSearchDirResolver, 'module.exports = require("@sc/pkg");', ['@sc/pkg']),
				'SCOPED_OK');
		});
	});

	// A `{module, path}` answer can only authorize a package INSIDE the search
	// directory, so a `module` that is relative, absolute or walks out with `..`
	// is refused before anything is recorded. Each case drives the resolver, then
	// reaches for the sibling by absolute path in the SAME VM, so a refusal that
	// still left an authorization behind would show up as a load.
	describe('object-return resolver with a refused `module` value', function () {
		// The fixture paths are only known once `before` has run, so each case
		// carries a thunk rather than a value.
		const cases = [
			['./foo', function () { return './foo'; }],
			['../pkgs/foo2', function () { return '../pkgs/foo2'; }],
			['an absolute path to the sibling', function () { return sibling(); }],
			['foo/..', function () { return 'foo/..'; }],
			['foo/../foo2', function () { return 'foo/../foo2'; }],
			['.', function () { return '.'; }],
			['bar/', function () { return 'bar/'; }]
		];

		function sibling() {
			return path.join(pkgs, 'foo2', 'index.js');
		}

		for (let i = 0; i < cases.length; i++) {
			const label = cases[i][0];
			const valueOf = cases[i][1];
			it('refuses module ' + JSON.stringify(label) + ' and leaves no authorization', function () {
				const value = valueOf();
				const resolver = function (name) {
					return name === 'foo' ? {module: value, path: pkgs} : undefined;
				};
				// The resolver answer must not resolve...
				const resolution = attempt(resolver, 'module.exports = require("foo");');
				assert.strictEqual(resolution.loaded, false,
					'module ' + JSON.stringify(label) + ' resolved through the object shape');
				// ...and must not leave the sibling authorized for a later require in
				// the same VM (the same resolver instance holds the record).
				const res = attempt(resolver,
					'try { require("foo"); } catch (e) {} ' + requireAbs(sibling()));
				assertDenied(res, 'pkgs-foo2', 'sibling pkgs/foo2 after a refused module ' + JSON.stringify(label));
			});
		}
	});

	// The loader finds an extension-less answer by probing `<path><ext>`
	// (LOAD_AS_FILE / LOAD_AS_FILE(DIR/X)). Those candidates are authorized as
	// EXACT paths, so they keep resolving while nothing beside them is reachable.
	describe('resolver answers found by extension probing', function () {
		it('still resolves an extension-less string return (no over-block)', function () {
			assert.strictEqual(run(extlessResolver, 'module.exports = require("foo");'), 'EXTLESS_OK');
		});

		it('denies siblings of the probed candidate (string return)', function () {
			const jsx = attempt(extlessResolver, requireFooThen(path.join(pkgs, 'ext', 'index.jsx')));
			assertDenied(jsx, 'ext-jsx', 'sibling index.jsx of the probed index.js');
			const index2 = attempt(extlessResolver, requireFooThen(path.join(pkgs, 'ext', 'index2.js')));
			assertDenied(index2, 'ext-index2', 'sibling index2.js of the probed index.js');
		});

		it('still resolves {module, path} where the module is the file <dir>/bar.js (no over-block)', function () {
			assert.strictEqual(
				run(fileSearchDirResolver, 'module.exports = require("bar");', ['bar']),
				'BAR_OK');
		});

		it('denies siblings of the probed candidate (object return)', function () {
			const jsx = attempt(fileSearchDirResolver,
				'require("bar"); ' + requireAbs(path.join(files, 'bar.jsx')), ['bar']);
			assertDenied(jsx, 'bar-jsx', 'sibling bar.jsx of the probed bar.js');
			const bar2 = attempt(fileSearchDirResolver,
				'require("bar"); ' + requireAbs(path.join(files, 'bar2.js')), ['bar']);
			assertDenied(bar2, 'bar2', 'sibling bar2.js of the probed bar.js');
		});
	});

	// An authorization is recorded before the load, because the load itself is
	// what checks it. A load that finds no module must take it back again.
	describe('a resolver answer that resolves to nothing leaves no authorization', function () {
		it('string return pointing at a directory with no loadable module', function () {
			const res = attempt(ghostResolver,
				'try { require("foo"); } catch (e) {} ' + requireAbs(path.join(pkgs, 'ghost', 'evil.js')));
			assertDenied(res, 'ghost-evil', 'file under the failed resolver answer pkgs/ghost');
		});

		it('object return pointing at a package with no loadable module', function () {
			const res = attempt(ghostSearchDirResolver,
				'try { require("bar"); } catch (e) {} ' + requireAbs(path.join(files, 'nope', 'evil.js')),
				['bar']);
			assertDenied(res, 'nope-evil', 'file under the failed resolver answer files/nope');
		});
	});

	describe('controls', function () {
		it('denies the siblings without the preceding allowlisted resolution', function () {
			// Nothing has been authorized yet in these VMs, so the siblings are
			// denied for the ordinary reason. Asserted so the attack cases above
			// cannot pass for the wrong reason.
			const cases = [
				[dirResolver, path.join(nodeModules, 'foo2', 'index.js')],
				[pkgDirResolver, path.join(pkgs, 'foo2', 'index.js')],
				[searchDirResolver, path.join(nodeModules, 'foo6', 'index.js')],
				[fileResolver, path.join(pkgs, 'foo', 'index.jsx')]
			];
			for (let i = 0; i < cases.length; i++) {
				const res = attempt(cases[i][0], requireAbs(cases[i][1]));
				assert.strictEqual(res.loaded, false, 'sibling ' + cases[i][1] + ' loaded with no prior resolution');
			}
		});

		it('denies the sibling as a bare specifier (not on the external allowlist)', function () {
			const res = attempt(dirResolver, 'require("foo"); module.exports = require("foo2");');
			assert.strictEqual(res.loaded, false, 'un-allowlisted bare specifier foo2 loaded');
		});
	});
});
