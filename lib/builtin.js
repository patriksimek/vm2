
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

// SECURITY (GHSA-947f-4v7f-x2v8, GHSA-rp36-8xq3-r6c4): Some Node builtins are
// sandbox-bypass primitives by design -- their primary capability is to reach
// host code regardless of the vm2 builtin allowlist. They must NEVER be
// reachable from the sandbox, even when the user requests `'*'` or explicitly
// names them in `builtin`.
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
//                       host process, exposing arbitrary host state. Covers
//                       the subpath family `inspector/promises` as well.
//   - process         : `process.getBuiltinModule(name)` (Node 22+) reloads
//                       ANY core module regardless of the embedder's
//                       allow/deny configuration. `process.binding`,
//                       `process.dlopen`, `process._linkedBinding`, and the
//                       raw host `process.env` are equally fatal. The
//                       sandbox global `process` is a sanitized shim defined
//                       in `setup-node-sandbox.js`; `require('process')`
//                       returns the raw host module and is never safe.
//
// This denylist is enforced at the `BUILTIN_MODULES` source (so the `'*'`
// wildcard never expands to them) AND inside `addDefaultBuiltin` (so explicit
// `builtin: ['module']` / `makeBuiltins(['module'])` requests are rejected).
// `SPECIAL_MODULES` and `overrides` can still register safe replacements under
// these names if a user genuinely needs one.
//
// Matching is family-based: any builtin whose path is `<family>/...` where
// `<family>` is listed below is also blocked. This covers
// `inspector/promises` today and any future subpath such as
// `inspector/foo`, `process/foo`, `module/foo`. The `node:` URL-style
// prefix is stripped before matching so neither `require('node:process')`
// nor `require('node:inspector/promises')` can bypass via the alternative
// spelling.
const DANGEROUS_BUILTINS = new Set([
	'module',
	'worker_threads',
	'cluster',
	'vm',
	'repl',
	'inspector',
	'process',
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
	'wasi',
	// SECURITY (GHSA-9g8x-92q2-p28f): Process-wide observability builtins.
	// Unlike most Node builtins, these expose state of the *entire host
	// process* rather than sandbox-local state -- the vm2 boundary cannot
	// usefully contain them because the data they surface (HTTP requests,
	// async-context, perf marks, heap contents) belongs to the embedder.
	// Even a readonly proxy that forwards every call to the host module is
	// a working host-data exfiltration primitive:
	//
	//   - diagnostics_channel : `dc.channel('http.server.request.start').subscribe(cb)`
	//                           hands the sandbox raw host IncomingMessage
	//                           objects -- including Authorization /
	//                           session-token headers -- for every request the
	//                           embedder receives.
	//   - async_hooks         : `executionAsyncResource()` returns the host's
	//                           current AsyncResource; embedders routinely
	//                           pin per-request user/auth state on it via
	//                           AsyncLocalStorage.
	//   - perf_hooks          : `performance.getEntriesByType('mark')` reads
	//                           every host-side `performance.mark(name)`,
	//                           which embedders often label with request IDs,
	//                           user IDs, or query strings.
	//   - v8                  : `v8.getHeapSnapshot()` / `v8.writeHeapSnapshot()`
	//                           serialize the *entire* host V8 heap (every
	//                           string, every Buffer, every closure capture)
	//                           and `v8.queryObjects(Ctor)` (Node 20+) returns
	//                           every host-realm instance of a constructor.
	//                           Strictly worse than perf_hooks for the same
	//                           reason -- host process state, not sandbox state.
	//
	// Embedders who genuinely need a sandbox-local replacement can register a
	// controlled wrapper under the same name via `mock` / `override`; the
	// denylist only rejects the default host-passthrough loader.
	'diagnostics_channel',
	'async_hooks',
	'perf_hooks',
	'v8'
]);

// SECURITY (GHSA-rp36-8xq3-r6c4): Family-prefix denylist check. `inspector` and
// `inspector/promises` must share fate; same for any future subpath under a
// dangerous family. Also strips the `node:` URL-style prefix so
// `node:process` and `node:inspector/promises` cannot bypass via spelling.
function isDangerousBuiltin(key) {
	if (typeof key !== 'string') return false;
	if (key.startsWith('node:')) key = key.slice(5);
	if (DANGEROUS_BUILTINS.has(key)) return true;
	const slash = key.indexOf('/');
	if (slash > 0 && DANGEROUS_BUILTINS.has(key.slice(0, slash))) return true;
	return false;
}

// SECURITY (GHSA-r9pm-gxmw-wv6p): Underscored builtins (_http_client,
// _http_server, _http_agent, _http_common, _http_incoming, _http_outgoing,
// _tls_common, _tls_wrap, _stream_*) are Node's private implementation
// modules backing http/https/tls/streams. They are listed by
// `require('module').builtinModules` but are not documented public API and
// expose network primitives directly (`_http_client.ClientRequest`,
// `_http_server.Server`). Filtering them at the `BUILTIN_MODULES` source
// removes them from `'*'` wildcard expansion, so the documented
// `builtin: ['*', '-http', '-https', '-net', '-tls', ...]` pattern is
// once again coherent. Explicit opt-in (`builtin: ['_http_client']`) and
// `mock`/`override` registrations remain functional via `addDefaultBuiltin`
// -- power users who genuinely need an internal sibling can still name it.
const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding('natives')))
	.filter(s=>!s.startsWith('internal/') && !s.startsWith('_') && !isDangerousBuiltin(s));

let EventEmitterReferencingAsyncResourceClass = null;
if (EventEmitter.EventEmitterAsyncResource) {
	 
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
	// SECURITY (GHSA-947f-4v7f-x2v8, GHSA-rp36-8xq3-r6c4): Defense-in-depth.
	// Reject sandbox-bypass primitives even when the caller explicitly names
	// them (e.g. `builtin: ['module']`, `builtin: ['process']`,
	// `makeBuiltins(['inspector/promises'])`). A non-special dangerous builtin
	// would otherwise be wrapped in a readonly proxy whose `apply` trap
	// forwards every method call to the host realm -- handing the sandbox a
	// primitive that loads ANY other builtin (`Module._load`,
	// `process.getBuiltinModule`), spawns processes (`cluster.fork`), runs
	// unsandboxed code (`new Worker(src, {eval:true})`,
	// `inspector/promises Session.post('Runtime.evaluate')`), or evaluates
	// host-realm code (`vm.runInThisContext`). The `SPECIAL_MODULES` escape
	// hatch above is still honoured -- a future safe wrapper can be
	// registered there.
	if (!special && isDangerousBuiltin(key)) return;
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
