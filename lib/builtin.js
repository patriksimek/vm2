
const fs = require('fs');
const nmod = require('module');
const {EventEmitter} = require('events');
const util = require('util');
const {VMScript} = require('./script');
const {VM} = require('./vm');

const eventsModules = new WeakMap();

function defaultBuiltinLoaderEvents(vm) {
	return eventsModules.get(vm);
}

let cacheBufferScript;

function defaultBuiltinLoaderBuffer(vm) {
	if (!cacheBufferScript) {
		cacheBufferScript = new VMScript('return buffer=>({Buffer: buffer});', {__proto__: null, filename: 'buffer.js'});
	}
	const makeBuffer = vm.run(cacheBufferScript, {__proto__: null, strict: true, wrapper: 'none'});
	return makeBuffer(Buffer);
}

let cacheUtilScript;

function defaultBuiltinLoaderUtil(vm) {
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

// SECURITY (GHSA-947f-4v7f-x2v8): Some Node builtins are sandbox-bypass primitives
// by design -- their primary capability is to reach host code regardless of the
// vm2 builtin allowlist. They must NEVER be reachable from the sandbox, even when
// the user requests `'*'` or explicitly names them in `builtin`.
//
//   - module          : exposes `Module._load`, `Module._resolveFilename`,
//                       `Module._cache`, `createRequire` -- loads ANY host
//                       builtin or external module bypassing the allowlist.
//   - worker_threads  : `new Worker(code, {eval: true})` runs arbitrary JS in
//                       a fresh thread that has no vm2 sandbox at all.
//   - cluster         : `cluster.fork()` spawns a host child process running
//                       attacker-controlled code.
//   - vm              : `vm.runInThisContext` evaluates code in the host realm,
//                       bypassing every bridge proxy.
//   - repl            : `repl.start()` constructs an interactive evaluator
//                       attached to host streams; low utility for sandboxed
//                       code, high host-RCE potential.
//   - inspector       : the inspector protocol can attach a debugger to the
//                       host process, exposing arbitrary host state.
//
// This denylist is enforced at the `BUILTIN_MODULES` source (so the `'*'`
// wildcard never expands to them) AND inside `addDefaultBuiltin` (so explicit
// `builtin: ['module']` / `makeBuiltins(['module'])` requests are rejected).
// `SPECIAL_MODULES` and `overrides` can still register safe replacements under
// these names if a user genuinely needs one.
const DANGEROUS_BUILTINS = new Set([
	'module',
	'worker_threads',
	'cluster',
	'vm',
	'repl',
	'inspector',
	// Host-process abort DoS: `trace_events.createTracing({categories: [...]})`
	// asserts `args[0]->IsArray()` in C++; the array crosses the bridge as a
	// Proxy, which fails the assertion and aborts the entire host process.
	// Reachable as ~150 bytes from sandbox under `builtin: ['*']`.
	'trace_events',
	// `wasi` exposes the WebAssembly System Interface preview1 syscall
	// surface (filesystem `preopens`, host clock/random, network if
	// preopened). API is experimental and broad; even a misconfigured
	// `preopens: {}` exposes the host CWD when sandbox code constructs
	// a WASI module. Embedders who genuinely need WASI can register a
	// controlled wrapper via `mock`/`override`.
	'wasi'
]);

const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding('natives')))
	.filter(s=>!s.startsWith('internal/') && !DANGEROUS_BUILTINS.has(s));

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
	events: {
		init(vm) {
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
		},
		load: defaultBuiltinLoaderEvents
	},
	buffer: defaultBuiltinLoaderBuffer,
	util: defaultBuiltinLoaderUtil
};

function addDefaultBuiltin(builtins, key, hostRequire) {
	if (builtins.has(key)) return;
	const special = SPECIAL_MODULES[key];
	// SECURITY (GHSA-947f-4v7f-x2v8): Defense-in-depth. Reject sandbox-bypass
	// primitives even when the caller explicitly names them (e.g.
	// `builtin: ['module']` or `makeBuiltins(['worker_threads'])`). A non-special
	// dangerous builtin would otherwise be wrapped in a readonly proxy whose
	// `apply` trap forwards every method call to the host realm -- handing the
	// sandbox a primitive that loads ANY other builtin (`Module._load`),
	// spawns processes (`cluster.fork`), runs unsandboxed code
	// (`new Worker(src, {eval:true})`), or evaluates host-realm code
	// (`vm.runInThisContext`). The `SPECIAL_MODULES` escape hatch above is
	// still honoured -- a future safe wrapper can be registered there.
	if (!special && DANGEROUS_BUILTINS.has(key)) return;
	builtins.set(key, special ? special : vm => vm.readonly(hostRequire(key)));
}


function makeBuiltinsFromLegacyOptions(builtins, hostRequire, mocks, overrides) {
	const res = new Map();
	if (mocks) {
		const keys = Object.getOwnPropertyNames(mocks);
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			res.set(key, (tvm) => tvm.readonly(mocks[key]));
		}
	}
	if (overrides) {
		const keys = Object.getOwnPropertyNames(overrides);
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			res.set(key, overrides[key]);
		}
	}
	if (Array.isArray(builtins)) {
		const def = builtins.indexOf('*') >= 0;
		if (def) {
			for (let i = 0; i < BUILTIN_MODULES.length; i++) {
				const name = BUILTIN_MODULES[i];
				if (builtins.indexOf(`-${name}`) === -1) {
					addDefaultBuiltin(res, name, hostRequire);
				}
			}
		} else {
			for (let i = 0; i < BUILTIN_MODULES.length; i++) {
				const name = BUILTIN_MODULES[i];
				if (builtins.indexOf(name) !== -1) {
					addDefaultBuiltin(res, name, hostRequire);
				}
			}
		}
	} else if (builtins) {
		for (let i = 0; i < BUILTIN_MODULES.length; i++) {
			const name = BUILTIN_MODULES[i];
			if (builtins[name]) {
				addDefaultBuiltin(res, name, hostRequire);
			}
		}
	}
	return res;
}

function makeBuiltins(builtins, hostRequire) {
	const res = new Map();
	for (let i = 0; i < builtins.length; i++) {
		const name = builtins[i];
		addDefaultBuiltin(res, name, hostRequire);
	}
	return res;
}

exports.makeBuiltinsFromLegacyOptions = makeBuiltinsFromLegacyOptions;
exports.makeBuiltins = makeBuiltins;
