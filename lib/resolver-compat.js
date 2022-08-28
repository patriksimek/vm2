'use strict';

// Translate the old options to the new Resolver functionality.

const fs = require('fs');
const pa = require('path');
const nmod = require('module');
const {EventEmitter} = require('events');
const util = require('util');

const {
	Resolver,
	DefaultResolver
} = require('./resolver');
const {VMScript} = require('./script');
const {VM} = require('./vm');
const {VMError} = require('./bridge');

/**
 * Require wrapper to be able to annotate require with webpackIgnore.
 *
 * @private
 * @param {string} moduleName - Name of module to load.
 * @return {*} Module exports.
 */
function defaultRequire(moduleName) {
	// Set module.parser.javascript.commonjsMagicComments=true in your webpack config.
	// eslint-disable-next-line global-require
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

class LegacyResolver extends DefaultResolver {

	constructor(builtinModules, checkPath, globalPaths, pathContext, customResolver, hostRequire, compiler, strict, externals, allowTransitive) {
		super(builtinModules, checkPath, globalPaths, pathContext, customResolver, hostRequire, compiler, strict);
		this.externals = externals;
		this.currMod = undefined;
		this.trustedMods = new WeakMap();
		this.allowTransitive = allowTransitive;
	}

	isPathAllowed(path) {
		return this.isPathAllowedForModule(path, this.currMod);
	}

	isPathAllowedForModule(path, mod) {
		if (!super.isPathAllowed(path)) return false;
		if (mod) {
			if (mod.allowTransitive) return true;
			if (path.startsWith(mod.path)) {
				const rem = path.slice(mod.path.length);
				if (!/(?:^|[\\\\/])node_modules(?:$|[\\\\/])/.test(rem)) return true;
			}
		}
		return this.externals.some(regex => regex.test(path));
	}

	registerModule(mod, filename, path, parent, direct) {
		const trustedParent = this.trustedMods.get(parent);
		this.trustedMods.set(mod, {
			filename,
			path,
			paths: this.genLookupPaths(path),
			allowTransitive: this.allowTransitive &&
				((direct && trustedParent && trustedParent.allowTransitive) || this.externals.some(regex => regex.test(filename)))
		});
	}

	resolveFull(mod, x, options, ext, direct) {
		this.currMod = undefined;
		if (!direct) return super.resolveFull(mod, x, options, ext, false);
		const trustedMod = this.trustedMods.get(mod);
		if (!trustedMod || mod.path !== trustedMod.path) return super.resolveFull(mod, x, options, ext, false);
		const paths = [...mod.paths];
		if (paths.length === trustedMod.length) {
			for (let i = 0; i < paths.length; i++) {
				if (paths[i] !== trustedMod.paths[i]) {
					return super.resolveFull(mod, x, options, ext, false);
				}
			}
		}
		const extCopy = Object.assign({__proto__: null}, ext);
		try {
			this.currMod = trustedMod;
			return super.resolveFull(trustedMod, x, undefined, extCopy, true);
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
		filename = this.pathResolve(filename);
		this.checkAccess(mod, filename);
		if (this.pathContext(filename, 'js') === 'sandbox') {
			const trustedMod = this.trustedMods.get(mod);
			const script = this.readScript(filename);
			vm.run(script, {filename, strict: true, module: mod, wrapper: 'none', dirname: trustedMod ? trustedMod.path : mod.path});
		} else {
			const m = this.hostRequire(filename);
			mod.exports = vm.readonly(m);
		}
	}

}

function defaultBuiltinLoader(resolver, vm, id) {
	const mod = resolver.hostRequire(id);
	return vm.readonly(mod);
}

const eventsModules = new WeakMap();

function defaultBuiltinLoaderEvents(resolver, vm, id) {
	return eventsModules.get(vm);
}

let cacheBufferScript;

function defaultBuiltinLoaderBuffer(resolver, vm, id) {
	if (!cacheBufferScript) {
		cacheBufferScript = new VMScript('return buffer=>({Buffer: buffer});', {__proto__: null, filename: 'buffer.js'});
	}
	const makeBuffer = vm.run(cacheBufferScript, {__proto__: null, strict: true, wrapper: 'none'});
	return makeBuffer(Buffer);
}

let cacheUtilScript;

function defaultBuiltinLoaderUtil(resolver, vm, id) {
	if (!cacheUtilScript) {
		cacheUtilScript = new VMScript(`return function inherits(ctor, superCtor) {
			ctor.super_ = superCtor;
			Object.setPrototypeOf(ctor.prototype, superCtor.prototype);
		}`, {__proto__: null, filename: 'util.js'});
	}
	const inherits = vm.run(cacheUtilScript, {__proto__: null, strict: true, wrapper: 'none'});
	const copy = Object.assign({}, util);
	copy.inherits = inherits;
	return vm.readonly(copy);
}

const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding('natives'))).filter(s=>!s.startsWith('internal/'));

let EventEmitterReferencingAsyncResourceClass = null;
if (EventEmitter.EventEmitterAsyncResource) {
	// eslint-disable-next-line global-require
	const {AsyncResource} = require('async_hooks');
	const kEventEmitter = Symbol('kEventEmitter');
	class EventEmitterReferencingAsyncResource extends AsyncResource {
		constructor(ee, type, options) {
			super(type, options);
			this[kEventEmitter] = ee;
		}
		get eventEmitter() {
			return this[kEventEmitter];
		}
	}
	EventEmitterReferencingAsyncResourceClass = EventEmitterReferencingAsyncResource;
}

let cacheEventsScript;

const SPECIAL_MODULES = {
	events(vm) {
		if (!cacheEventsScript) {
			const eventsSource = fs.readFileSync(`${__dirname}/events.js`, 'utf8');
			cacheEventsScript = new VMScript(`(function (fromhost) { const module = {}; module.exports={};{ ${eventsSource}
} return module.exports;})`, {filename: 'events.js'});
		}
		const closure = VM.prototype.run.call(vm, cacheEventsScript);
		const eventsInstance = closure(vm.readonly({
			kErrorMonitor: EventEmitter.errorMonitor,
			once: EventEmitter.once,
			on: EventEmitter.on,
			getEventListeners: EventEmitter.getEventListeners,
			EventEmitterReferencingAsyncResource: EventEmitterReferencingAsyncResourceClass
		}));
		eventsModules.set(vm, eventsInstance);
		vm._addProtoMapping(EventEmitter.prototype, eventsInstance.EventEmitter.prototype);
		return defaultBuiltinLoaderEvents;
	},
	buffer(vm) {
		return defaultBuiltinLoaderBuffer;
	},
	util(vm) {
		return defaultBuiltinLoaderUtil;
	}
};

function addDefaultBuiltin(builtins, key, vm) {
	if (builtins[key]) return;
	const special = SPECIAL_MODULES[key];
	builtins[key] = special ? special(vm) : defaultBuiltinLoader;
}


function genBuiltinsFromOptions(vm, builtinOpt, mockOpt, override) {
	const builtins = {__proto__: null};
	if (mockOpt) {
		const keys = Object.getOwnPropertyNames(mockOpt);
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			builtins[key] = (resolver, tvm, id) => tvm.readonly(mockOpt[key]);
		}
	}
	if (override) {
		const keys = Object.getOwnPropertyNames(override);
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			builtins[key] = override[key];
		}
	}
	if (Array.isArray(builtinOpt)) {
		const def = builtinOpt.indexOf('*') >= 0;
		if (def) {
			for (let i = 0; i < BUILTIN_MODULES.length; i++) {
				const name = BUILTIN_MODULES[i];
				if (builtinOpt.indexOf(`-${name}`) === -1) {
					addDefaultBuiltin(builtins, name, vm);
				}
			}
		} else {
			for (let i = 0; i < BUILTIN_MODULES.length; i++) {
				const name = BUILTIN_MODULES[i];
				if (builtinOpt.indexOf(name) !== -1) {
					addDefaultBuiltin(builtins, name, vm);
				}
			}
		}
	} else if (builtinOpt) {
		for (let i = 0; i < BUILTIN_MODULES.length; i++) {
			const name = BUILTIN_MODULES[i];
			if (builtinOpt[name]) {
				addDefaultBuiltin(builtins, name, vm);
			}
		}
	}
	return builtins;
}

function defaultCustomResolver() {
	return undefined;
}

const DENY_RESOLVER = new Resolver({__proto__: null}, [], id => {
	throw new VMError(`Access denied to require '${id}'`, 'EDENIED');
});

function resolverFromOptions(vm, options, override, compiler) {
	if (!options) {
		if (!override) return DENY_RESOLVER;
		const builtins = genBuiltinsFromOptions(vm, undefined, undefined, override);
		return new Resolver(builtins, [], defaultRequire);
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
	} = options;

	const builtins = genBuiltinsFromOptions(vm, builtinOpt, mockOpt, override);

	if (!externalOpt) return new Resolver(builtins, [], hostRequire);

	let checkPath;
	if (rootPaths) {
		const checkedRootPaths = (Array.isArray(rootPaths) ? rootPaths : [rootPaths]).map(f => pa.resolve(f));
		checkPath = (filename) => {
			return checkedRootPaths.some(path => {
				if (!filename.startsWith(path)) return false;
				const len = path.length;
				if (filename.length === len || (len > 0 && path[len-1] === pa.sep)) return true;
				const sep = filename[len];
				return sep === '/' || sep === pa.sep;
			});
		};
	} else {
		checkPath = () => true;
	}

	let newCustomResolver = defaultCustomResolver;
	let externals = undefined;
	let external = undefined;
	if (customResolver) {
		let externalCache;
		newCustomResolver = (resolver, x, path, extList) => {
			if (external && !(resolver.pathIsAbsolute(x) || resolver.pathIsRelative(x))) {
				if (!externalCache) {
					externalCache = external.map(ext => new RegExp(makeExternalMatcherRegex(ext)));
				}
				if (!externalCache.some(regex => regex.test(x))) return undefined;
			}
			const resolved = customResolver(x, path);
			if (!resolved) return undefined;
			if (externals) externals.push(new RegExp('^' + escapeRegExp(resolved)));
			return resolver.loadAsFileOrDirecotry(resolved, extList);
		};
	}

	if (typeof externalOpt !== 'object') {
		return new DefaultResolver(builtins, checkPath, [], () => context, newCustomResolver, hostRequire, compiler, strict);
	}

	let transitive = false;
	if (Array.isArray(externalOpt)) {
		external = externalOpt;
	} else {
		external = externalOpt.modules;
		transitive = context === 'sandbox' && externalOpt.transitive;
	}
	externals = external.map(makeExternalMatcher);
	return new LegacyResolver(builtins, checkPath, [], () => context, newCustomResolver, hostRequire, compiler, strict, externals, transitive);
}

exports.resolverFromOptions = resolverFromOptions;
