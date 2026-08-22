
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
	'v8',
	// SECURITY (GHSA-m5w8-4gq2-6f8x): Same process-wide class as the GHSA-9g8x
	// four above, extended with the two builtins that also expose host-process
	// state the `vm.readonly()` proxy cannot localise -- and, worse, carry
	// *write* APIs that mutate global host state from one line of sandbox code:
	//
	//   - os   : `os.userInfo()` leaks the host process owner (uid/gid/username/
	//            homedir/shell); `os.networkInterfaces()` leaks the full host
	//            network topology (container/VM veth pairs, IPs, MACs);
	//            `os.hostname()` / `os.loadavg()` / `os.uptime()` / `os.freemem()`
	//            are host-wide telemetry. `os.setPriority([pid,] prio)` is a
	//            *write* -- `setpriority(2)` on the host process (pid 0 = host),
	//            strictly worse than the read-only v8/perf_hooks family.
	//   - dns  : `dns.setServers(['attacker:53'])` replaces the host's
	//            process-wide DNS resolver list, hijacking every subsequent
	//            lookup the host makes (outbound HTTP, telemetry, npm registry,
	//            fetch, URL-based fs paths) -- a one-line DNS-hijack primitive
	//            with no rate limit, audit trail, or embedder notification.
	//            `dns.setDefaultResultOrder()` is a second process-wide write
	//            knob. `dns.getServers()` / `dns.lookup()` / `dns.resolve()`
	//            read and act from the host network identity. Covers the
	//            `dns/promises` subpath via the family-prefix matcher below.
	//
	// Embedders who genuinely need a sandbox-local subset (typically
	// `os.platform()`, `os.EOL`, `os.constants`) can register a controlled
	// wrapper under the same name via `mock` / `override`.
	'os',
	'dns',
	// SECURITY (GHSA-qhwx-74w5-xhxq): `node:test` is a host-process-SPAWNING
	// primitive, the same class as `worker_threads` / `cluster` above.
	// `test.run({ files, execArgv: ['--eval=<js>'] })` starts a SEPARATE host
	// Node process that executes attacker-supplied code with full host
	// authority — a host RCE even from a sandbox with no fs/child_process. On
	// Node 18+ `require('module').builtinModules` lists `node:test` /
	// `node:test/reporters` WITH the `node:` prefix, so `builtin: ['node:test']`
	// (and `['*']`) previously admitted it. Deny the whole `test` family (the
	// `node:` prefix is stripped and the subpath `test/reporters` is covered by
	// the family-prefix match in `isDangerousBuiltin`). Embedders who need an
	// in-sandbox test runner can register a controlled wrapper via `mock` /
	// `override`.
	'test'
]);

// SECURITY (GHSA-rp36-8xq3-r6c4): Family-prefix denylist check. `inspector` and
// `inspector/promises` must share fate; same for any future subpath under a
// dangerous family. Also strips the `node:` URL-style prefix so
// `node:process` and `node:inspector/promises` cannot bypass via spelling.
function isDangerousBuiltin(key) {
	if (typeof key !== 'string') return false;
	// SECURITY (GHSA-qhwx-74w5-xhxq): strip ALL leading `node:` prefixes, not
	// just one, so a double-prefixed spelling (`node:node:test`) normalizes to
	// the same base name and cannot slip past the denylist.
	while (key.startsWith('node:')) key = key.slice(5);
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

// SECURITY (GHSA-46pr-c5wc-xffx): Some builtins are safe to expose EXCEPT for a
// handful of members that reach host-process authority the `vm.readonly()` wrap
// cannot contain. readonly() blocks property *assignment* through the sandbox
// proxy, but it forwards every *call* to the host member with full host
// authority -- so a callable that loads native code, mutates a process-wide
// security setting, or hands back a shared host singleton is a sandbox-escape
// primitive even behind the read-only proxy. Rather than deny these
// otherwise-useful modules wholesale (hashing/signing is a legitimate sandbox
// use of `crypto`), expose a sanitized shallow copy with just the dangerous
// member neutralized.
//
//   - crypto.setEngine(path[, flags]) : hands `path` to OpenSSL's ENGINE loader,
//     which asks the OS dynamic loader to load the named shared library. The
//     library's constructor runs as arbitrary native code BEFORE OpenSSL decides
//     whether the file is a usable engine -- so even the expected
//     ERR_CRYPTO_ENGINE_UNKNOWN rejection happens only after host-native code has
//     already executed. A sandbox with only `crypto` allowed and a native file in
//     its own package directory therefore has a native-RCE primitive.
//
// The stub throws instead of forwarding to host OpenSSL, so no library is ever
// loaded. Matching strips the `node:` prefix so `node:crypto` shares fate.
function sanitizeCryptoModule(mod) {
	const copy = Object.assign({}, mod);
	copy.setEngine = function setEngine() {
		throw new Error('crypto.setEngine is disabled in vm2 sandboxes: it asks OpenSSL to dynamically load a native library into the host process, executing arbitrary native code (GHSA-46pr-c5wc-xffx).');
	};
	return copy;
}

// SECURITY (GHSA-6w8r-xxw2-g3hx): `node:sqlite`'s DatabaseSync can load a native
// SQLite extension (`loadExtension(path)` / the `loadExtension` SQL function) —
// arbitrary native code in the host process. Node gates this entirely on the
// constructor's `allowExtension` option: with it off (the default), both
// `loadExtension()` and `enableLoadExtension()` throw `ERR_INVALID_STATE`.
// Wrap the DatabaseSync constructor so `allowExtension` is forced off, which
// closes every extension-loading path while leaving normal SQL usable.
function sanitizeSqliteModule(mod) {
	const HostDatabaseSync = mod.DatabaseSync;
	if (typeof HostDatabaseSync !== 'function') return mod;
	const copy = Object.assign({}, mod);
	class DatabaseSync extends HostDatabaseSync {
		constructor(location, ...rest) {
			// Preserve call arity (native DatabaseSync rejects an explicit
			// `undefined` options arg). Force `allowExtension` off only when an
			// options value is actually supplied; otherwise the native default
			// (off) already applies. SECURITY (GHSA-6w8r-xxw2-g3hx follow-up): the
			// native DatabaseSync also accepts a FUNCTION as its options argument
			// (functions carry own properties), so `function o(){}; o.allowExtension
			// = true` bypassed an `object`-only check. Treat functions as options
			// too — Object.assign copies their own enumerable props and forces
			// allowExtension off.
			if (rest.length > 0 && rest[0] !== null &&
				(typeof rest[0] === 'object' || typeof rest[0] === 'function')) {
				rest[0] = Object.assign({}, rest[0], {allowExtension: false});
			}
			super(location, ...rest);
		}
	}
	copy.DatabaseSync = DatabaseSync;
	return copy;
}

// SECURITY (GHSA-98xx-8mx4-x7cm): `tls.setDefaultCACertificates(list)` replaces
// the calling thread's process-wide default CA trust store, so every subsequent
// host TLS client that doesn't supply its own `ca` accepts attacker-signed
// certificates. This is the same process-wide-mutation class as the already-
// denied `dns.setServers`; unlike dns the rest of `tls` is legitimately useful
// to sandboxed code, so neutralize just this member. (The native function
// requires a real host array, which the sandbox can forge via `url`'s
// `URLSearchParams.getAll()` — the bridge unwraps it back to a host array — so
// argument-side defenses are insufficient; the member itself must be removed.)
function sanitizeTlsModule(mod) {
	if (typeof mod.setDefaultCACertificates !== 'function') return mod;
	const copy = Object.assign({}, mod);
	copy.setDefaultCACertificates = function setDefaultCACertificates() {
		throw new Error('tls.setDefaultCACertificates is disabled in vm2 sandboxes: it replaces the host process default CA trust store (GHSA-98xx-8mx4-x7cm).');
	};
	return copy;
}

// SECURITY (GHSA-h85j-hv3c-qfgq): `http.globalAgent` / `https.globalAgent` are
// the real process-wide host singletons. The read-only wrap hands them straight
// to the sandbox, and `.on('free'|'keylog'|...)` is a *read*+subscribe, not a
// property assignment, so it is forwarded to the host object. A sandbox listener
// then receives live host request options (Authorization tokens, private
// host/port) and the released host TLSSocket whenever an unrelated host request
// completes — credential/traffic exfiltration. Replace the exposed `globalAgent`
// with a fresh sandbox-dedicated Agent so the sandbox can never reach the host
// singleton. The module's own `request()`/`get()` keep working (they close over
// the module-internal agent, not this exposed property), so the sandbox can
// still make its own requests; it simply cannot observe the host's shared agent.
// Inject a default `agent` into an http/https request-args list without
// disturbing a caller-supplied agent, mirroring `request(url?, options?, cb?)`.
function requestArgsWithDefaultAgent(args, agent) {
	let i = 0;
	if (typeof args[i] === 'string' || (typeof URL !== 'undefined' && args[i] instanceof URL)) i++;
	const opts = args[i];
	if (opts !== null && typeof opts === 'object') {
		if (opts.agent === undefined) {
			const clone = Object.assign({}, opts);
			clone.agent = agent;
			args[i] = clone;
		}
	} else {
		// No options object (a callback or nothing sits here) — insert one.
		args.splice(i, 0, {agent});
	}
	return args;
}

function makeHttpAgentSanitizer(agentKey) {
	return function sanitizeHttpModule(mod) {
		if (typeof mod.Agent !== 'function' || !mod[agentKey]) return mod;
		const copy = Object.assign({}, mod);
		const sandboxAgent = new mod.Agent();
		// The exposed globalAgent is the sandbox-dedicated one — a direct read +
		// `.on('free')` reaches only this empty agent, never the host singleton.
		copy[agentKey] = sandboxAgent;
		// SECURITY (GHSA-h85j-hv3c-qfgq, hardening): the module's own request()/get()
		// close over the *real* host globalAgent, so a no-agent request would set
		// `req.agent` to the host singleton and re-expose it (`https.request().agent
		// .on('free', …)`). Route those helpers through the sandbox agent by default
		// so `req.agent` and connection pooling never touch the host singleton. A
		// caller-supplied `agent` (e.g. a sandbox-created Agent, or `agent:false`)
		// is preserved.
		const hostRequest = mod.request;
		const hostGet = mod.get;
		if (typeof hostRequest === 'function') {
			copy.request = function request(...args) {
				return hostRequest.apply(this, requestArgsWithDefaultAgent(args, sandboxAgent));
			};
		}
		if (typeof hostGet === 'function') {
			copy.get = function get(...args) {
				return hostGet.apply(this, requestArgsWithDefaultAgent(args, sandboxAgent));
			};
		}
		return copy;
	};
}

const BUILTIN_MEMBER_SANITIZERS = {
	__proto__: null,
	crypto: sanitizeCryptoModule,
	sqlite: sanitizeSqliteModule,
	tls: sanitizeTlsModule,
	http: makeHttpAgentSanitizer('globalAgent'),
	https: makeHttpAgentSanitizer('globalAgent')
};

function sanitizeBuiltinMembers(key, mod) {
	if (typeof key === 'string' && key.startsWith('node:')) key = key.slice(5);
	const sanitizer = BUILTIN_MEMBER_SANITIZERS[key];
	if (!sanitizer || !mod || (typeof mod !== 'object' && typeof mod !== 'function')) return mod;
	return sanitizer(mod);
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
	// SECURITY (GHSA-46pr-c5wc-xffx): sanitize dangerous host members before the
	// read-only wrap forwards their calls to the host realm.
	builtins.set(key, special ? special : vm => vm.readonly(sanitizeBuiltinMembers(key, hostRequire(key))));
}


// Single chokepoint for "is this wildcard-expanded builtin denied by a negative
// token?". It composes two INDEPENDENT properties; both must hold.
//
// SECURITY (GHSA-8686-vhfx-7r3j) -- spelling normalization. A negative deny
// token may be written with or without the `node:` URL prefix (`-fs` /
// `-node:fs`), matching how `require()` accepts `node:`-prefixed specifiers.
// The original exact-string match recognized only one spelling, so the other
// was a silent no-op that left the real host module exposed under
// `builtin: ['*']`. Compare on the `node:`-stripped form of BOTH the module
// name and the token, so every spelling of a token denies every spelling of
// the module.
//
// SECURITY (GHSA-6rh5-qq4q-97xh) -- family coverage. `fs` and `fs/promises`
// are SEPARATE entries in `builtinModules`, so a deny token matching only the
// exact name removed `fs` yet left the full host `fs/promises` API (including
// `writeFile`) registered. Treat `<family>/<sub>` as denied whenever
// `-<family>` is present, so `-fs` blocks `fs/promises`, `-path` blocks
// `path/posix` / `path/win32`, `-stream` blocks `stream/promises` /
// `stream/web`. A family that is not denied keeps its subpaths (no
// over-denial), and the explicit (non-wildcard) allowlist branch is untouched.
//
// The two compose: `-node:fs` denies `fs`, `node:fs`, `fs/promises` AND
// `node:fs/promises`, because the family split runs on the normalized name and
// each candidate is looked up in both spellings.
function stripNodePrefix(name) {
	return name.startsWith('node:') ? name.slice(5) : name;
}

function isBuiltinDenied(builtins, name) {
	const bare = stripNodePrefix(name);
	// Exact name, either spelling of the token.
	if (builtins.indexOf(`-${bare}`) !== -1 || builtins.indexOf(`-node:${bare}`) !== -1) return true;
	// Subpath member -- inherit the family's deny token, either spelling.
	const slash = bare.indexOf('/');
	if (slash > 0) {
		const family = bare.slice(0, slash);
		if (builtins.indexOf(`-${family}`) !== -1 || builtins.indexOf(`-node:${family}`) !== -1) return true;
	}
	return false;
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
				// SECURITY (GHSA-8686-vhfx-7r3j, GHSA-6rh5-qq4q-97xh): both the
				// `node:` spelling of a deny token and the subpath family it
				// covers are handled inside `isBuiltinDenied`.
				if (!isBuiltinDenied(builtins, name)) {
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
