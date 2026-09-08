'use strict';

// Translate the old options to the new Resolver functionality.
const {
	Resolver,
	DefaultResolver
} = require('./resolver');
const {VMError} = require('./bridge');
const {DefaultFileSystem} = require('./filesystem');
const {makeBuiltinsFromLegacyOptions} = require('./builtin');
const {jsCompiler} = require('./compiler');

const nodePath = require('path');

// SECURITY (defense-in-depth for GHSA-j3hm-6rg5-mchv, which remains OPEN): deny a
// sandbox require() of vm2 itself (which returns the real VM/NodeVM classes and
// lets sandbox code build a nested unrestricted sandbox). This removes one
// escalation route only. We block vm2's IMPORTABLE surface specifically — its
// `lib/` directory and its package main entry — NOT the whole package root, since
// in the source tree that root also holds test fixtures (test/node_modules/*) an
// embedder's `require.root` may legitimately point at. Paths are realpath'd once
// so a symlinked candidate can't dodge the boundary check.
function realpathOr(p) {
	try {
		return require('fs').realpathSync(p);
	} catch (e) {
		return p;
	}
}
const VM2_LIB_DIR = realpathOr(__dirname);
let VM2_MAIN_ENTRY = null;
try {
	VM2_MAIN_ENTRY = realpathOr(require.resolve(nodePath.dirname(__dirname)));
} catch (e) {
	// package main not resolvable in this layout — lib/ block still applies
}

function isVm2SelfRequire(fs, filename) {
	let real = filename;
	try {
		real = fs.realpath(filename);
	} catch (e) {
		// fall back to the lexical filename
	}
	if (typeof real !== 'string') return false;
	if (VM2_MAIN_ENTRY !== null && real === VM2_MAIN_ENTRY) return true;
	return real === VM2_LIB_DIR || real.startsWith(VM2_LIB_DIR + nodePath.sep);
}

// SECURITY (GHSA-j3hm-6rg5-mchv — STILL OPEN): bare `require.external:true` with
// no `require.root` and a host context lets sandbox code host-require ANY path,
// which then executes in the host realm. That primitive is NOT closed here:
// isPathAllowed still returns true unconditionally when rootPaths is undefined.
// All this does is WARN (once) so existing embedders are not broken but are
// steered toward require.root / context:'sandbox'. Two adjacent, narrower routes
// ARE hard-blocked: the vm2-self-require denial in isPathAllowed below, and the
// CLI's own configuration (GHSA-jxxv-8r27-vm4p, fixed in lib/cli.js).
let externalWithoutRootWarned = false;
function warnExternalWithoutRoot() {
	if (externalWithoutRootWarned) return;
	externalWithoutRootWarned = true;
	console.warn('vm2 security warning: `require.external` without `require.root` lets sandboxed code host-require arbitrary paths (a sandbox escape). Set `require.root` to a directory boundary, or use `context: "sandbox"`. See GHSA-jxxv-8r27-vm4p / GHSA-j3hm-6rg5-mchv.');
}

/**
 * Require wrapper to be able to annotate require with webpackIgnore.
 *
 * @private
 * @param {string} moduleName - Name of module to load.
 * @return {*} Module exports.
 */
function defaultRequire(moduleName) {
	// Set module.parser.javascript.commonjsMagicComments=true in your webpack config.
	 
	return require(/* webpackIgnore: true */ moduleName);
}

// source: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#Escaping
function escapeRegExp(string) {
	return string.replace(/[.*+\-?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

function makeExternalMatcherRegex(obj) {
	return escapeRegExp(obj).replace(/\\\\|\//g, '[\\\\/]')
		.replace(/\\\*\\\*/g, '.*').replace(/\\\*/g, '[^\\\\/]*').replace(/\\\?/g, '[^\\\\/]');
}

function makeExternalMatcher(obj) {
	const regexString = makeExternalMatcherRegex(obj);
	return new RegExp(`[\\\\/]node_modules[\\\\/]${regexString}(?:[\\\\/](?!(?:.*[\\\\/])?node_modules[\\\\/]).*)?$`);
}

/**
 * SECURITY (GHSA-5h3f-q97h-ccvc): the package directory a module specifier
 * names — `foo` for `foo/lib/x.js`, `@scope/pkg` for `@scope/pkg/lib/x.js`.
 * Used to authorize ONLY the resolved package's own directory inside a custom
 * resolver's search directory. A specifier that is absolute, relative, or
 * `..`-bearing yields a first segment (``, `.`, `..`) that joins back to the
 * search directory or above it; the caller rejects those by requiring the
 * result to be strictly inside the search directory.
 *
 * @private
 * @param {string} spec - Module specifier.
 * @return {string} First path segment, or the first two for a scoped name.
 */
function packageDirName(spec) {
	const parts = spec.split(/[\\/]/);
	if (parts.length > 1 && parts[0][0] === '@') return parts[0] + '/' + parts[1];
	return parts[0];
}

class CustomResolver extends DefaultResolver {

	constructor(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict) {
		super(fileSystem, globalPaths, builtinModules);
		this.rootPaths = rootPaths;
		this.pathContext = pathContext;
		this.customResolver = customResolver;
		this.hostRequire = hostRequire;
		this.compiler = compiler;
		this.strict = strict;
	}

	/**
	 * SECURITY (GHSA-7q3f-wx44-378m, GHSA-5h3f-q97h-ccvc): the single
	 * path-containment primitive of this resolver. A raw `startsWith` is string
	 * containment, not directory containment: `/x/foo2/index.js` starts with
	 * `/x/foo`, so every prefix-sharing sibling of an authorized path passed.
	 * Containment requires a boundary — the path either equals `base`, or `base`
	 * already ends in a separator, or a separator follows it. Separators go
	 * through `this.fs.isSeparator` so the FileSystem adapter in force decides,
	 * not a hardcoded character. Both operands must be in the same (lexically
	 * resolved) path space; canonicalizing only one side re-introduces a
	 * mismatch.
	 *
	 * @private
	 * @param {string} base - Authorized base path.
	 * @param {string} path - Candidate path.
	 * @return {boolean} True if `path` is `base` or lies inside it.
	 */
	isPathWithin(base, path) {
		if (!path.startsWith(base)) return false;
		const len = base.length;
		if (path.length === len) return true;
		if (len > 0 && this.fs.isSeparator(base[len - 1])) return true;
		return this.fs.isSeparator(path[len]);
	}

	isPathAllowed(filename) {
		// SECURITY (defense-in-depth for GHSA-j3hm-6rg5-mchv, which remains OPEN):
		// never let the sandbox host-require vm2's own package — that returns the real
		// VM/NodeVM classes and lets sandbox code build a nested unrestricted sandbox
		// (full escape), even when require.root is set to a directory that contains
		// node_modules/vm2 (e.g. the README's root:'./'). This denies ONE escalation
		// route; it does NOT close the underlying primitive — see the `rootPaths ===
		// undefined` early return immediately below, which still admits every other
		// attacker-named path. Legitimate nesting uses the builtin-override mechanism,
		// not an external file require, so this does not affect nesting:true.
		if (isVm2SelfRequire(this.fs, filename)) return false;
		if (this.rootPaths === undefined) return true;
		// SECURITY: Dereference symlinks before the prefix check. The lexical
		// resolve() does not follow symlinks but Node's native require() does,
		// so a symlink inside the root pointing outside it would otherwise
		// bypass the boundary. Deny by default if the path can't be canonicalized
		// (missing file, broken link, or fs without realpath). GHSA-cp6g-6699-wx9c.
		let realFilename;
		try {
			realFilename = this.fs.realpath(filename);
		} catch (e) {
			return false;
		}
		return this.rootPaths.some(path => this.isPathWithin(path, realFilename));
	}

	loadJS(vm, mod, filename) {
		if (this.pathContext(filename, 'js') !== 'host') return super.loadJS(vm, mod, filename);
		const m = this.hostRequire(filename);
		mod.exports = vm.readonly(m);
	}

	loadNode(vm, mod, filename) {
		if (this.pathContext(filename, 'node') !== 'host') return super.loadNode(vm, mod, filename);
		const m = this.hostRequire(filename);
		mod.exports = vm.readonly(m);
	}

	customResolve(x, path, extList) {
		if (this.customResolver === undefined) return undefined;
		const resolved = this.customResolver(x, path);
		if (!resolved) return undefined;
		if (typeof resolved === 'string') {
			return this.loadAsFileOrDirectory(resolved, extList);
		}
		const {module=x, path: resolvedPath} = resolved;
		return this.loadNodeModules(module, [resolvedPath], extList);
	}

	getCompiler(filename) {
		return this.compiler;
	}

	isStrict(filename) {
		return this.strict;
	}

}

class LegacyResolver extends CustomResolver {

	constructor(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict, externals, allowTransitive) {
		super(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict);
		this.externals = externals.map(makeExternalMatcher);
		// SECURITY (GHSA-c48m-32m9-vx93): the bare-specifier allowlist pre-check in
		// `customResolve` must match the WHOLE specifier (the package name,
		// optionally followed by a subpath), NOT a substring. The previous
		// unanchored `new RegExp(makeExternalMatcherRegex(pattern))` matched
		// `left-pad` inside `evil-left-pad` / `left-pad-evil` / `xleft-padx`, so a
		// colliding host package was handed to the custom resolver and its
		// top-level code ran in host context. Anchor both ends: `^<pattern>` and
		// either end-of-string or a path separator introducing a subpath. Wildcard
		// semantics inside the pattern (`*` -> `[^/]*`, `**` -> `.*`) are preserved.
		this.externalCache = externals.map(pattern => new RegExp('^(?:' + makeExternalMatcherRegex(pattern) + ')(?:[\\\\/].*)?$'));
		// SECURITY (GHSA-5h3f-q97h-ccvc): authorizations granted by the embedder's
		// custom resolver are recorded here as resolved base PATHS, matched with
		// the `isPathWithin` directory boundary. They used to be appended to
		// `this.externals` as `new RegExp('^' + escapeRegExp(resolved))` — a raw
		// string prefix that also authorized every prefix-sharing sibling of the
		// resolved path (`.../node_modules/foo` authorized
		// `.../node_modules/foo2/index.js`), which `context: 'host'` then executed
		// in the host realm. `this.externals` stays exactly what
		// `makeExternalMatcher` builds: static, `node_modules`-anchored allowlist
		// matchers.
		this.externalPaths = [];
		// SECURITY (GHSA-5h3f-q97h-ccvc): the companion EXACT-match list. The
		// loader finds an extension-less resolver answer by probing `<path><ext>`
		// (`DefaultResolver.tryWithExtension`), which a boundary-matched base does
		// not cover, so the probed candidates are authorized individually and by
		// full equality. Exact entries authorize no descendants and no siblings:
		// `/x/foo/index.js` is authorized, `/x/foo/index.jsx` and
		// `/x/foo/index.js.evil.js` are not.
		this.externalExact = [];
		this.currMod = undefined;
		this.trustedMods = new WeakMap();
		this.allowTransitive = allowTransitive;
	}

	isPathAllowed(path) {
		return this.isPathAllowedForModule(path, this.currMod);
	}

	/**
	 * SECURITY (GHSA-5h3f-q97h-ccvc): true if `filename` is a path the embedder's
	 * custom resolver authorized — the resolved path itself, something inside it,
	 * or one of the exact extension candidates the loader probes for it. Never a
	 * prefix-sharing sibling.
	 *
	 * @private
	 * @param {string} filename - Resolved absolute filename.
	 * @return {boolean} True if a custom-resolver authorization covers it.
	 */
	isCustomResolved(filename) {
		if (this.externalExact.indexOf(filename) !== -1) return true;
		return this.externalPaths.some(base => this.isPathWithin(base, filename));
	}

	/**
	 * SECURITY (GHSA-5h3f-q97h-ccvc): record ONE custom-resolver authorization —
	 * `base` (itself and its descendants) plus the exact `<target><ext>`
	 * candidates `DefaultResolver.tryWithExtension` probes, so an extension-less
	 * resolver answer keeps resolving without any prefix ever being matched.
	 * Extensions that are not their own basename are skipped, exactly as the
	 * loader skips them, so a separator inside an extension cannot widen the
	 * authorization.
	 *
	 * The authorization has to be in place BEFORE the load runs (the load itself
	 * calls `isPathAllowed` on every candidate), so the returned function undoes
	 * it when the load does not produce a module — otherwise a resolver answer
	 * that resolves to nothing would leave a permanent authorization behind. The
	 * load cannot re-enter `customResolve`, so removing this call's own entries
	 * by index is exact.
	 *
	 * @private
	 * @param {string} base - Resolved directory or file to authorize.
	 * @param {string} target - Path whose extension candidates to authorize.
	 * @param {Array<string>} extList - Extensions the loader will probe.
	 * @return {Function} Undoes the authorization.
	 */
	addCustomAuthorization(base, target, extList) {
		const paths = this.externalPaths;
		const exact = this.externalExact;
		const pathIndex = paths.length;
		const exactIndex = exact.length;
		paths.push(base);
		if (Array.isArray(extList)) {
			for (let i = 0; i < extList.length; i++) {
				const ext = extList[i];
				if (typeof ext !== 'string' || ext === '' || ext !== this.fs.basename(ext)) continue;
				exact.push(target + ext);
			}
		}
		const exactCount = exact.length - exactIndex;
		return () => {
			paths.splice(pathIndex, 1);
			exact.splice(exactIndex, exactCount);
		};
	}

	isPathAllowedForModule(path, mod) {
		if (!super.isPathAllowed(path)) return false;
		if (mod) {
			if (mod.allowTransitive) return true;
			// SECURITY (GHSA-7q3f-wx44-378m): require a path boundary after
			// `mod.path`, not a raw prefix. Without it a prefix-sharing sibling
			// (`.../node_modules/foo2/index.js` vs allowlisted
			// `.../node_modules/foo`) passed `startsWith` — the remainder
			// `2/index.js` has no `node_modules` segment — and loaded as if it
			// were `foo`. Mirror the boundary check in the base
			// `CustomResolver.isPathAllowed`: exact match, `mod.path` already
			// ending in a separator, or the next character being a separator.
			// Shared with that check and with `isCustomResolved` as `isPathWithin`.
			if (this.isPathWithin(mod.path, path)) {
				const rem = path.slice(mod.path.length);
				if (!/(?:^|[\\\\/])node_modules(?:$|[\\\\/])/.test(rem)) return true;
			}
		}
		if (this.externals.some(regex => regex.test(path))) return true;
		// SECURITY (GHSA-5h3f-q97h-ccvc): paths the custom resolver authorized are
		// matched with a directory boundary, not a raw string prefix.
		return this.isCustomResolved(path);
	}

	registerModule(mod, filename, path, parent, direct) {
		const trustedParent = this.trustedMods.get(parent);
		this.trustedMods.set(mod, {
			filename,
			path,
			paths: this.genLookupPaths(path),
			// SECURITY (GHSA-5h3f-q97h-ccvc): `isCustomResolved` keeps the
			// pre-existing behaviour that a custom-resolved module counts as
			// external here (it used to be one of the `this.externals` entries),
			// now with the directory boundary applied.
			allowTransitive: this.allowTransitive &&
				((direct && trustedParent && trustedParent.allowTransitive) ||
					this.externals.some(regex => regex.test(filename)) || this.isCustomResolved(filename))
		});
	}

	resolveFull(mod, x, options, extList, direct) {
		this.currMod = undefined;
		if (!direct) return super.resolveFull(mod, x, options, extList, false);
		const trustedMod = this.trustedMods.get(mod);
		if (!trustedMod || mod.path !== trustedMod.path) return super.resolveFull(mod, x, options, extList, false);
		const paths = [...mod.paths];
		if (paths.length !== trustedMod.paths.length) return super.resolveFull(mod, x, options, extList, false);
		for (let i = 0; i < paths.length; i++) {
			if (paths[i] !== trustedMod.paths[i]) {
				return super.resolveFull(mod, x, options, extList, false);
			}
		}
		try {
			this.currMod = trustedMod;
			return super.resolveFull(trustedMod, x, options, extList, true);
		} finally {
			this.currMod = undefined;
		}
	}

	checkAccess(mod, filename) {
		const trustedMod = this.trustedMods.get(mod);
		if ((!trustedMod || trustedMod.filename !== filename) && !this.isPathAllowedForModule(filename, undefined)) {
			throw new VMError(`Module '${filename}' is not allowed to be required. The path is outside the border!`, 'EDENIED');
		}
	}

	loadJS(vm, mod, filename) {
		if (this.pathContext(filename, 'js') !== 'host') {
			const trustedMod = this.trustedMods.get(mod);
			const script = this.readScript(filename);
			vm.run(script, {filename, strict: this.isStrict(filename), module: mod, wrapper: 'none', dirname: trustedMod ? trustedMod.path : mod.path});
		} else {
			const m = this.hostRequire(filename);
			mod.exports = vm.readonly(m);
		}
	}

	customResolve(x, path, extList) {
		if (this.customResolver === undefined) return undefined;
		// `DefaultResolver.resolveFull` only reaches customResolve with a bare
		// specifier (absolute and relative forms return or throw earlier), so this
		// branch is always taken today; it is kept as a guard for future callers.
		if (!(this.pathIsAbsolute(x) || this.pathIsRelative(x))) {
			if (!this.externalCache.some(regex => regex.test(x))) return undefined;
			// SECURITY (GHSA-c48m-32m9-vx93): the anchored allowlist matcher permits a
			// subpath after the package name (`left-pad/utils`), but that subpath may
			// contain `..` traversal segments — `left-pad/../evil-package`,
			// `left-pad/sub/../../evil-package` — which pass the regex yet resolve via
			// normal path semantics to an UN-allowlisted package, running its top-level
			// code in host context (same impact as the original bypass). A regex-only
			// guard is insufficient: a negative lookahead only catches `..` right after
			// the first separator, not deeper (`left-pad/sub/../evil`). Reject any
			// specifier with a `..` path segment before calling the resolver. It then
			// falls back to the standard loader whose resolved path is never added to
			// `this.externalPaths`, so `isPathAllowed` denies it ("module not found").
			if (x.split(/[\\/]/).indexOf('..') !== -1) return undefined;
		}
		const resolved = this.customResolver(x, path);
		if (!resolved) return undefined;
		if (typeof resolved === 'string') {
			// SECURITY (GHSA-5h3f-q97h-ccvc): authorize the resolved path, its
			// descendants and its exact extension candidates, nothing else. The path
			// is normalized first so the stored base lives in the same space as the
			// candidates `isPathAllowed` sees (they arrive through `this.fs.resolve`
			// in `tryFile`/`readPackage`), so a `..` segment in a later absolute
			// require cannot re-enter the base by spelling — it is normalized away
			// before the boundary test.
			const base = this.fs.resolve(resolved);
			return this.loadAuthorized(base, base, extList, () => this.loadAsFileOrDirectory(base, extList));
		}
		const {module=x, path: resolvedPath} = resolved;
		// SECURITY (GHSA-5h3f-q97h-ccvc): an unexpected return shape must DENY, not
		// throw out of the resolver or fall through to a wider authorization.
		if (typeof module !== 'string' || typeof resolvedPath !== 'string') return undefined;
		// SECURITY (GHSA-5h3f-q97h-ccvc): `resolvedPath` is a node_modules SEARCH
		// directory, not the module — authorizing it authorized every package
		// inside it. Authorize only the directory of the package being resolved
		// (`searchDir/<package name>`), plus the exact extension candidates the
		// loader probes for `searchDir/<specifier>` (LOAD_AS_FILE(DIR/X), which is
		// how `{module: 'bar', path: dir}` resolves the file `dir/bar.js`).
		// A `module` that is absolute, relative or `..`-bearing would widen the
		// base back to the search directory or above it, or aim the extension
		// candidates outside the package; such a resolution is refused outright
		// (`undefined` falls back to the standard loader, which finds nothing
		// authorized and reports module-not-found).
		const searchDir = this.fs.resolve(resolvedPath);
		const base = this.fs.resolve(this.fs.join(searchDir, packageDirName(module)));
		if (base === searchDir || !this.isPathWithin(searchDir, base)) return undefined;
		const target = this.fs.resolve(this.fs.join(searchDir, module));
		if (!this.isPathWithin(base, target)) return undefined;
		return this.loadAuthorized(base, target, extList, () => this.loadNodeModules(module, [searchDir], extList));
	}

	/**
	 * SECURITY (GHSA-5h3f-q97h-ccvc): run one custom-resolver load with its
	 * authorization in place, and take the authorization back when the load does
	 * not produce a module. A resolver answer that resolves to nothing must not
	 * leave a permanently authorized directory behind for later requires.
	 *
	 * @private
	 * @param {string} base - Resolved directory or file to authorize.
	 * @param {string} target - Path whose extension candidates to authorize.
	 * @param {Array<string>} extList - Extensions the loader will probe.
	 * @param {Function} load - Performs the load.
	 * @return {string|undefined} The resolved filename, if any.
	 */
	loadAuthorized(base, target, extList, load) {
		const undo = this.addCustomAuthorization(base, target, extList);
		let found = false;
		try {
			const filename = load();
			found = filename !== undefined;
			return filename;
		} finally {
			if (!found) undo();
		}
	}

}

const DEFAULT_FS = new DefaultFileSystem();

const DENY_RESOLVER = new Resolver(DEFAULT_FS, [], new Map());

// Host intrinsics cached at module load (runs in the embedder's Node realm).
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const arrayIsArray = Array.isArray;

/**
 * SECURITY (GHSA-8hr7-r645-pc6w): "plain config object" test. Returns true only
 * for `Object.prototype`- or null-prototyped objects. Rejects arrays
 * (`Array.prototype`), exotic builtin instances (`Date`/`RegExp`/`Map`/…), and
 * boxed primitives (`new String`/`new Number`/`new Boolean`, whose prototypes
 * are not `Object.prototype`). Those non-config shapes are `typeof 'object'` and
 * non-null — so the old `typeof x === 'object' && x !== null` gate accepted them
 * — yet they carry no require-config fields and destructure to all-`undefined`,
 * i.e. the same insecure shape as a bare primitive.
 *
 * @private
 * @param {*} value - Value to classify.
 * @return {boolean} True if `value` is a genuine plain require-config object.
 */
function isPlainConfigObject(value) {
	if (value === null || typeof value !== 'object') return false;
	// SECURITY (GHSA-8hr7-r645-pc6w): reject arrays before the prototype compare.
	// A normal array is already rejected below (its proto is Array.prototype),
	// but Array.isArray also sees through a Proxy-around-array whose
	// `getPrototypeOf` trap spoofs `Object.prototype` — closing that shape too.
	// (`requireOpts` is embedder-supplied, not attacker-controlled, so this is
	// robustness rather than an attacker-reachable gap.)
	if (arrayIsArray(value)) return false;
	const proto = objectGetPrototypeOf(value);
	return proto === objectPrototype || proto === null;
}

function makeResolverFromLegacyOptions(options, override, compiler) {
	// SECURITY (GHSA-8hr7-r645-pc6w): defense in depth beneath the nodevm.js
	// guard. NESTING_OVERRIDE exposes host `vm2` to the sandbox; only inject it
	// when `options` is a genuine require config. A truthy non-plain-object shape
	// (array, exotic instance, boxed primitive) destructures to all-`undefined`
	// and, with the override merged, would produce a resolver whose ONLY builtin
	// is `vm2` — a pure escape primitive. Strip the override for such shapes so
	// no alternate call path (bypassing the nodevm.js gate) can re-open the
	// class. `nesting` gates the override upstream, so a falsy override (the
	// `{nesting:false, require:[]}` case) is a no-op here.
	if (override && options && !isPlainConfigObject(options)) {
		override = undefined;
	}
	if (!options) {
		if (!override) return DENY_RESOLVER;
		const builtins = makeBuiltinsFromLegacyOptions(undefined, defaultRequire, undefined, override);
		return new Resolver(DEFAULT_FS, [], builtins);
	}

	const {
		builtin: builtinOpt,
		mock: mockOpt,
		external: externalOpt,
		root: rootPaths,
		resolve: customResolver,
		customRequire: hostRequire = defaultRequire,
		context = 'host',
		strict = true,
		fs: fsOpt = DEFAULT_FS,
	} = options;

	const builtins = makeBuiltinsFromLegacyOptions(builtinOpt, hostRequire, mockOpt, override);

	if (!externalOpt) return new Resolver(fsOpt, [], builtins);

	if (!compiler) compiler = jsCompiler;

	// SECURITY: Canonicalize root paths so the prefix comparison in isPathAllowed
	// matches the realpath of candidate filenames. GHSA-cp6g-6699-wx9c.
	//
	// Eager FileSystem contract probe: if `require.root` is set the adapter
	// MUST be able to dereference symlinks, otherwise the boundary degrades to
	// a lexical prefix check (the exact CWE-59 condition the fix closes). Fail
	// loudly at construction so users can fix their adapter, instead of silently
	// denying every require() later.
	let checkedRootPaths;
	if (rootPaths !== undefined) {
		if (typeof fsOpt.realpath !== 'function') {
			throw new VMError('NodeVM `require.root` requires the FileSystem adapter to implement realpath(path). See lib/filesystem.js for the contract. Context: GHSA-cp6g-6699-wx9c.');
		}
		checkedRootPaths = (Array.isArray(rootPaths) ? rootPaths : [rootPaths]).map(f => {
			const resolved = fsOpt.resolve(f);
			try {
				return fsOpt.realpath(resolved);
			} catch (e) {
				// TypeError = adapter wired up realpath() but its underlying
				// implementation (e.g. VMFileSystem's `fs.realpathSync`) is
				// missing. Contract violation — surface it now instead of
				// deny-by-default at every later require().
				if (e instanceof TypeError) {
					throw new VMError('NodeVM `require.root` realpath probe failed: ' + e.message + '. If using VMFileSystem with a custom fs module, the underlying fs must provide realpathSync. Context: GHSA-cp6g-6699-wx9c.');
				}
				// Other errors (ENOENT, EACCES) may legitimately occur if the
				// root doesn't exist yet at construction. Fall back to lexical;
				// isPathAllowed() still realpaths candidates at require() time.
				return resolved;
			}
		});
	}

	const pathContext = typeof context === 'function' ? context : (() => context);

	if (typeof externalOpt !== 'object') {
		// SECURITY (GHSA-j3hm-6rg5-mchv — STILL OPEN): bare `require.external: true`
		// builds a CustomResolver whose isPathAllowed is a no-op when require.root is
		// unset — every absolute/relative path the sandbox names is host-require()'d,
		// a full host escape (not merely "external modules are allowed"). This is NOT
		// refused at construction: doing so would reverse the shipped
		// GHSA-cp6g-6699-wx9c invariant that construction succeeds when root is unset.
		// The combination is only WARNED, so the escape primitive remains reachable;
		// require.root / context:'sandbox' are the recommended embedder-side fixes
		// until a structural fix for GHSA-j3hm-6rg5-mchv lands.
		if (rootPaths === undefined && (typeof context === 'function' || context === 'host')) {
			warnExternalWithoutRoot();
		}
		return new CustomResolver(fsOpt, [], builtins, checkedRootPaths, pathContext, customResolver, hostRequire, compiler, strict);
	}

	let transitive = false;
	let external = undefined;
	if (Array.isArray(externalOpt)) {
		external = externalOpt;
	} else {
		external = externalOpt.modules;
		transitive = context !== 'host' && externalOpt.transitive;
	}
	return new LegacyResolver(fsOpt, [], builtins, checkedRootPaths, pathContext, customResolver, hostRequire, compiler, strict, external, transitive);
}

exports.makeResolverFromLegacyOptions = makeResolverFromLegacyOptions;
exports.isPlainConfigObject = isPlainConfigObject;
