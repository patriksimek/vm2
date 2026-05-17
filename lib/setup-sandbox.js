/* global host, bridge, data, context */

'use strict';

const {
	Object: localObject,
	Array: localArray,
	Error: LocalError,
	Reflect: localReflect,
	Proxy: LocalProxy,
	WeakMap: LocalWeakMap,
	Function: localFunction,
	eval: localEval,
} = global;

const { freeze: localObjectFreeze } = localObject;

const {
	getPrototypeOf: localReflectGetPrototypeOf,
	apply,
	construct: localReflectConstruct,
	deleteProperty: localReflectDeleteProperty,
	has: localReflectHas,
	defineProperty: localReflectDefineProperty,
	setPrototypeOf: localReflectSetPrototypeOf,
	getOwnPropertyDescriptor: localReflectGetOwnPropertyDescriptor,
	ownKeys: localReflectOwnKeys,
} = localReflect;

const localObjectGetOwnPropertySymbols = localObject.getOwnPropertySymbols;
const localObjectGetOwnPropertyDescriptors = localObject.getOwnPropertyDescriptors;
const localObjectAssign = localObject.assign;
// SECURITY (GHSA-m5q2-4fm3-vfqp): captured at module load before sandbox code
// can run, so prefix-matching `Symbol.for` keys against the `nodejs.` namespace
// (see below) cannot be subverted by an attacker who later monkey-patches
// `String.prototype.startsWith` from inside the sandbox.
const localStringStartsWith = global.String.prototype.startsWith;

const speciesSymbol = Symbol.species;
const globalPromise = global.Promise;
// SECURITY (GHSA-hw58-p9xv-2mjh): cache the host then() before the
// `globalPromise.prototype.then` override below replaces it. The internal
// swallow tail attached in the localPromise constructor must use the
// unmodified host then() so it doesn't recurse through our own override
// (which calls resetPromiseSpecies and could throw on hostile prototypes).
const globalPromisePrototypeThen = globalPromise.prototype.then;
function localPromiseSwallow() {
	/* no-op consumer to silence unhandledRejection */
}
// SECURITY (GHSA-hw58-p9xv-2mjh): re-entrancy guard. Attaching the swallow
// tail invokes the native then() which constructs a downstream promise via
// the species protocol — that downstream construction would recurse back
// into this constructor. We only need a tail on the *outermost* user-
// visible promise; internal species constructions are left bare.
let localPromiseInSwallowTail = false;
class localPromise extends globalPromise {
	// SECURITY (GHSA-hw58-p9xv-2mjh): wrap the user-supplied executor so any
	// synchronous throw — including V8-internal throws produced while the
	// engine is *inside* the executor (e.g. `e.name = Symbol(); e.stack`
	// triggers FormatStackTrace -> host TypeError) — is funnelled through
	// handleException and surfaces as a sandbox-realm rejection rather than
	// a raw host-realm error. The swallow tail below additionally consumes
	// the rejection if no sandbox `.catch()` is attached, so the host's
	// `unhandledRejection` event never fires and Node 15+'s default-throw
	// behaviour cannot be used to crash the host process.
	constructor(executor) {
		// Preserve native semantics: a non-callable executor must cause the
		// Promise constructor to throw a TypeError synchronously. Calling
		// super(executor) directly delegates that check to the native
		// Promise constructor.
		if (typeof executor !== 'function') {
			super(executor);
			return;
		}
		super(function wrappedExecutor(resolve, reject) {
			try {
				return apply(executor, this, [resolve, reject]);
			} catch (e) {
				// SECURITY: handleException walks SuppressedError /
				// AggregateError sub-error chains and routes the value
				// through ensureThis, so a sandbox `.catch()` handler sees
				// a sandbox-realm value rather than a raw host TypeError.
				reject(handleException(e));
			}
		});
		// SECURITY: even after the rejection has been sanitised, if no
		// sandbox code attaches a `.catch()` the host fires its
		// unhandledRejection hook and (Node 15+ default) terminates the
		// process. Attach a benign tail handler that consumes the rejection
		// silently. The tail uses the *original* host then() (cached above)
		// so it bypasses our own then() override and doesn't recurse.
		if (!localPromiseInSwallowTail) {
			localPromiseInSwallowTail = true;
			try {
				// SECURITY (GHSA-76w7-j9cq-rx2j): the cached host then()
				// resolves the downstream child via the species protocol
				// (`this.constructor[Symbol.species]`). Without this reset
				// a sandbox subclass — `class F extends Promise { static
				// get [Symbol.species](){ return ct } }` — hijacks species
				// to a user function `ct` which is then `Construct`ed with
				// V8's internal `(resolve, reject)` executor. The user can
				// reassign V8's resolve/reject, redirect rejection to a
				// sandbox collector, and receive a raw host-realm Error
				// (e.g. RangeError from `e.stack` after deep recursion)
				// whose `.constructor.constructor` is the host `Function`
				// constructor → RCE. Pinning the species back to
				// `localPromise` forces the downstream child through our
				// own wrapped executor where the species cannot be
				// hijacked. The sandbox-side `then`/`catch`/`Reflect.apply`
				// overrides already call this; the swallow-tail call here
				// was the missed site.
				resetPromiseSpecies(this);
				apply(globalPromisePrototypeThen, this, [undefined, localPromiseSwallow]);
			} catch (e) {
				// best effort — never let the swallow itself crash the executor
			} finally {
				localPromiseInSwallowTail = false;
			}
		}
	}
}

// V8 creates async function promises using the realm's intrinsic Promise
// (globalPromise), not localPromise. Since localPromise.prototype is not
// in globalPromise instances' prototype chain, `p instanceof Promise`
// would return false without this. Delegate to globalPromise's instanceof
// which is safe because globalPromise is frozen later (line 826).
localReflectDefineProperty(localPromise, Symbol.hasInstance, {
	__proto__: null,
	value: function (instance) {
		return instance instanceof globalPromise;
	},
});

/*
 * Symbol.for protection
 *
 * Certain Node.js cross-realm symbols can be exploited for sandbox escapes:
 *
 * - 'nodejs.util.inspect.custom': Called by util.inspect with host's inspect function as argument.
 *   If sandbox defines this on an object passed to host APIs (e.g., WebAssembly.compileStreaming),
 *   Node's error handling calls the custom function with host context, enabling escape.
 *
 * - 'nodejs.rejection': Called by EventEmitter on promise rejection with captureRejections enabled.
 *   The handler receives error objects that could potentially leak host context.
 *
 * - 'nodejs.util.promisify.custom': Hook util.promisify(fn) calls when present on `fn`. If a
 *   sandbox-installed function is invoked here, host code that relies on promisified behavior
 *   gets sandbox-controlled return values. (GHSA-m5q2-4fm3-vfqp)
 *
 * - 'nodejs.stream.{readable,writable,duplex,transform}': Brand symbols Node's stream subsystem
 *   uses for duck typing. Sandbox-installed brands confuse host-side `Stream.is{Readable,Writable}`
 *   checks. (GHSA-m5q2-4fm3-vfqp)
 *
 * - 'nodejs.webstream.{isClosedPromise,controllerErrorFunction}': WebStream internals — a
 *   sandbox-installed handler executes in host realm with host arguments. (GHSA-m5q2-4fm3-vfqp)
 *
 * Fix: Override Symbol.for to return a sandbox-local symbol for any key in the `nodejs.` namespace
 * instead of the real cross-realm symbol. The `nodejs.` prefix is reserved by Node for internal
 * cross-realm hooks; sandbox code has no legitimate reason to register symbols under it. Each
 * unique `nodejs.*` key is mapped to a stable sandbox-local symbol so that repeated `Symbol.for`
 * calls inside the sandbox preserve identity (matching the spec's registry semantics for the
 * sandbox's own consumption), while never crossing the realm boundary.
 */
const originalSymbolFor = Symbol.for;
const blockedSymbolCustomInspect = Symbol('nodejs.util.inspect.custom');
const blockedSymbolRejection = Symbol('nodejs.rejection');

// Per-key cache for unknown `nodejs.*` symbols so `Symbol.for(k) === Symbol.for(k)` still holds
// inside the sandbox. Built via the cached Reflect primitives so a sandbox-side override of
// `Object.prototype` / proxies cannot intercept reads or writes here.
const blockedNodejsSymbolCache = { __proto__: null };
localReflectDefineProperty(blockedNodejsSymbolCache, 'nodejs.util.inspect.custom', {
	__proto__: null, value: blockedSymbolCustomInspect, writable: true, enumerable: false, configurable: false,
});
localReflectDefineProperty(blockedNodejsSymbolCache, 'nodejs.rejection', {
	__proto__: null, value: blockedSymbolRejection, writable: true, enumerable: false, configurable: false,
});

Symbol.for = function (key) {
	// Convert to string once to prevent toString/toPrimitive bypass and TOCTOU attacks
	const keyStr = '' + key;
	// SECURITY (GHSA-m5q2-4fm3-vfqp): deny the entire `nodejs.` namespace. The prior allowlist
	// of two specific keys missed seven other dangerous Node-internal symbols and would miss any
	// future addition. The `nodejs.` prefix is owned by Node for internal cross-realm hooks.
	if (apply(localStringStartsWith, keyStr, ['nodejs.'])) {
		const cached = blockedNodejsSymbolCache[keyStr];
		if (typeof cached === 'symbol') return cached;
		const fresh = Symbol(keyStr);
		localReflectDefineProperty(blockedNodejsSymbolCache, keyStr, {
			__proto__: null, value: fresh, writable: true, enumerable: false, configurable: false,
		});
		return fresh;
	}
	return originalSymbolFor(keyStr);
};

/*
 * Cross-realm symbol extraction protection
 *
 * Even with Symbol.for overridden, cross-realm symbols can be extracted from
 * host objects exposed to the sandbox (e.g., Buffer.prototype) via:
 *   Object.getOwnPropertySymbols(Buffer.prototype).find(s => s.description === 'nodejs.util.inspect.custom')
 *
 * Fix: Override Object.getOwnPropertySymbols and Reflect.ownKeys to replace
 * dangerous cross-realm symbols with sandbox-local equivalents in results.
 */
const realSymbolCustomInspect = originalSymbolFor('nodejs.util.inspect.custom');
const realSymbolRejection = originalSymbolFor('nodejs.rejection');
// SECURITY (GHSA-m5q2-4fm3-vfqp): pre-cache every known dangerous `nodejs.*` cross-realm symbol so
// `isDangerousSymbol` can identify them in extraction paths (Reflect.ownKeys, Object.assign, ...).
// Identity check against these references is the structural test — `description`-string matching
// is forgeable from sandbox code. Adding new entries here automatically extends every filter.
const realDangerousSymbols = [
	realSymbolCustomInspect,
	realSymbolRejection,
	originalSymbolFor('nodejs.util.promisify.custom'),
	originalSymbolFor('nodejs.stream.readable'),
	originalSymbolFor('nodejs.stream.writable'),
	originalSymbolFor('nodejs.stream.duplex'),
	originalSymbolFor('nodejs.stream.transform'),
	originalSymbolFor('nodejs.webstream.isClosedPromise'),
	originalSymbolFor('nodejs.webstream.controllerErrorFunction'),
];

function isDangerousSymbol(sym) {
	for (let i = 0; i < realDangerousSymbols.length; i++) {
		if (sym === realDangerousSymbols[i]) return true;
	}
	return false;
}

localObject.getOwnPropertySymbols = function getOwnPropertySymbols(obj) {
	const symbols = apply(localObjectGetOwnPropertySymbols, localObject, [obj]);
	const result = [];
	let j = 0;
	for (let i = 0; i < symbols.length; i++) {
		if (typeof symbols[i] !== 'symbol' || !isDangerousSymbol(symbols[i])) {
			localReflectDefineProperty(result, j++, {
				__proto__: null,
				value: symbols[i],
				writable: true,
				enumerable: true,
				configurable: true,
			});
		}
	}
	return result;
};

localReflect.ownKeys = function ownKeys(obj) {
	const keys = apply(localReflectOwnKeys, localReflect, [obj]);
	const result = [];
	let j = 0;
	for (let i = 0; i < keys.length; i++) {
		if (typeof keys[i] !== 'symbol' || !isDangerousSymbol(keys[i])) {
			localReflectDefineProperty(result, j++, {
				__proto__: null,
				value: keys[i],
				writable: true,
				enumerable: true,
				configurable: true,
			});
		}
	}
	return result;
};

/*
 * Object.getOwnPropertyDescriptors uses the internal [[OwnPropertyKeys]] which
 * bypasses our Reflect.ownKeys override. The result object has dangerous symbols
 * as property keys, which can then be leaked via Object.assign/Object.defineProperties
 * to a Proxy whose set/defineProperty trap captures the key.
 */
localObject.getOwnPropertyDescriptors = function getOwnPropertyDescriptors(obj) {
	const descs = apply(localObjectGetOwnPropertyDescriptors, localObject, [obj]);
	// SECURITY (GHSA-m5q2-4fm3-vfqp): drop every known dangerous cross-realm symbol slot,
	// not just the original two. Iterates `realDangerousSymbols` so additions stay in sync.
	for (let i = 0; i < realDangerousSymbols.length; i++) {
		localReflectDeleteProperty(descs, realDangerousSymbols[i]);
	}
	return descs;
};

/*
 * Object.assign uses internal [[OwnPropertyKeys]] on source objects, bypassing our
 * Reflect.ownKeys override. If a source (bridge proxy) has an enumerable dangerous-symbol
 * property, the symbol is passed to the target's [[Set]] which could be a user Proxy trap.
 */
localObject.assign = function assign(target) {
	if (target === null || target === undefined) {
		throw new LocalError('Cannot convert undefined or null to object');
	}
	const to = localObject(target);
	for (let s = 1; s < arguments.length; s++) {
		const source = arguments[s];
		if (source === null || source === undefined) continue;
		const from = localObject(source);
		const keys = apply(localReflectOwnKeys, localReflect, [from]);
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			if (typeof key === 'symbol' && isDangerousSymbol(key)) continue;
			const desc = apply(localReflectGetOwnPropertyDescriptor, localReflect, [from, key]);
			if (desc && desc.enumerable === true) {
				to[key] = from[key];
			}
		}
	}
	return to;
};

const resetPromiseSpecies = p => {
	// Note: We do not use instanceof to check if p is a Promise because
	// Reflect.construct(Promise, [...], FakeNewTarget) can create a real Promise
	// (with internal slots) whose prototype does not include globalPromise.prototype,
	// bypassing the instanceof check entirely.
	//
	// Instead, we unconditionally set the constructor property on any object.
	// This ensures species resolution always uses localPromise, regardless of
	// how the promise was constructed.
	if (p !== null && (typeof p === 'object' || typeof p === 'function')) {
		// Always define an own data property for 'constructor' to eliminate
		// any TOCTOU vulnerability. Accessor properties (getters) on either the
		// instance or anywhere in the prototype chain can return different values
		// on each access, allowing an attacker to pass our check on the first read
		// while V8 internally sees a malicious species on subsequent reads.
		let success;
		try {
			success = localReflectDefineProperty(p, 'constructor', {
				__proto__: null,
				value: localPromise,
				writable: true,
				configurable: true,
			});
		} catch (e) {
			// If defineProperty throws (e.g., Proxy with throwing trap), treat as failure
			success = false;
		}
		if (!success) {
			throw new LocalError('Unsafe Promise species cannot be reset');
		}
	}
};

const globalPromiseThen = globalPromise.prototype.then;
const globalPromiseCatch = globalPromise.prototype.catch;

globalPromise.prototype.then = function then(onFulfilled, onRejected) {
	resetPromiseSpecies(this);
	if (typeof onFulfilled === 'function') {
		const origOnFulfilled = onFulfilled;
		onFulfilled = function onFulfilled(value) {
			// SECURITY (GHSA-9vg3-4rfj-wgcm): use `ensureThis`, NOT `from`.
			// Reverts the b57ac2d "GHSA-mpf8 symmetry" change. This wrapper
			// runs for every sandbox-realm Promise (including async-function-
			// returned globalPromise instances). The resolution value is
			// sandbox-realm by construction; host-realm values reach sandbox
			// callbacks through a separate path — the bridge's apply-trap
			// interception of host `Promise.prototype.then`, which sanitises
			// via `wrapHostPromiseThenArgs` (see bridge.js). Calling `from`
			// on a SANDBOX null-proto value built a bridge proxy whose `set`
			// trap unwraps incoming sandbox proxies of host (e.g. raw
			// Buffer.prototype.inspect) onto the underlying sandbox object;
			// reading the property back via the original sandbox reference
			// returned the raw host fn → host Function constructor → RCE.
			value = ensureThis(value);
			return apply(origOnFulfilled, this, [value]);
		};
	}
	if (typeof onRejected === 'function') {
		const origOnRejected = onRejected;
		onRejected = function onRejected(error) {
			error = handleException(error);
			return apply(origOnRejected, this, [error]);
		};
	}
	return apply(globalPromiseThen, this, [onFulfilled, onRejected]);
};

globalPromise.prototype.catch = function _catch(onRejected) {
	resetPromiseSpecies(this);
	if (typeof onRejected === 'function') {
		const origOnRejected = onRejected;
		onRejected = function onRejected(error) {
			error = handleException(error);
			return apply(origOnRejected, this, [error]);
		};
	}
	return apply(globalPromiseCatch, this, [onRejected]);
};

const localReflectApply = (target, thisArg, args) => {
	resetPromiseSpecies(thisArg);
	return apply(target, thisArg, args);
};

const { isArray: localArrayIsArray } = localArray;

const {
	ensureThis,
	ReadOnlyHandler,
	from,
	fromWithFactory,
	readonlyFactory,
	connect,
	addProtoMapping,
	VMError,
	// SECURITY (GHSA-v37h-5mfm-c47c): token-bound handler factories. The
	// bridge no longer exposes ReadOnlyMockHandler as a direct constructor;
	// setup-sandbox must go through these helpers so the construction token
	// (closure-scoped inside bridge.js) stays out of reach of sandbox code.
	createReadOnlyMockHandler,
	newBufferHandler,
	rebindHandlerConstructor,
} = bridge;

const { allowAsync, GeneratorFunction, AsyncFunction, AsyncGeneratorFunction, bufferAllocLimit } = data;

// SECURITY (GHSA-6785-pvv7-mvg7): Buffer.alloc / allocUnsafe / allocUnsafeSlow
// (and the deprecated Buffer(N) / new Buffer(N) forms) execute as a single
// synchronous host C++ allocation. V8's `timeout` cannot interrupt them, so
// an attacker controlling the size argument can amplify a small payload into
// hundreds of megabytes of host RSS, crashing the host process in
// memory-constrained environments (Docker/K8s/Lambda). Cap every allocation
// size before it reaches the host implementation. Cached in a const so a
// sandbox-side prototype-pollution attempt cannot mutate it post-init.
const localBufferAllocLimit = bufferAllocLimit;
function checkBufferAllocLimit(size) {
	// Match host Buffer.alloc semantics: it expects a number. Non-numeric
	// values are passed through to host validation (it throws TypeError).
	// Only enforce the cap on numbers actually large enough to trip it.
	if (typeof size === 'number' && size > localBufferAllocLimit) {
		throw new RangeError('Buffer allocation size ' + size + ' exceeds bufferAllocLimit ' + localBufferAllocLimit);
	}
}

const { get: localWeakMapGet, set: localWeakMapSet } = LocalWeakMap.prototype;

function localUnexpected() {
	return new VMError('Should not happen');
}

// global is originally prototype of host.Object so it can be used to climb up from the sandbox.
if (!localReflectSetPrototypeOf(context, localObject.prototype)) throw localUnexpected();

Object.defineProperties(global, {
	global: { value: global, writable: true, configurable: true, enumerable: true },
	globalThis: { value: global, writable: true, configurable: true },
	GLOBAL: { value: global, writable: true, configurable: true },
	root: { value: global, writable: true, configurable: true },
	Error: { value: LocalError },
	Promise: { value: localPromise },
	Proxy: { value: undefined },
});

/*
 * WebAssembly.JSTag protection
 *
 * WebAssembly.JSTag (Node 25+) allows wasm exception handling to catch JavaScript
 * exceptions via try_table/catch with JSTag. This completely bypasses the transformer's
 * catch block instrumentation, which only wraps JavaScript catch clauses with
 * handleException(). An attacker can:
 *   1. Create a wasm module that imports JSTag and catches JS exceptions
 *   2. Import a function that triggers a host TypeError (e.g., via Symbol() name trick)
 *   3. Catch the host error in wasm, returning it as an externref
 *   4. Use the raw host error's constructor chain to escape
 *
 * Fix: Remove WebAssembly.JSTag from the sandbox. Without it, wasm code cannot
 * catch JavaScript exceptions — catch_all provides no value access, and catch_all_ref
 * requires JSTag for exn.extract. The tag is a V8 internal and cannot be reconstructed.
 */
if (typeof WebAssembly !== 'undefined' && WebAssembly.JSTag !== undefined) {
	localReflectDeleteProperty(WebAssembly, 'JSTag');
}

/*
 * WebAssembly JSPI protection (GHSA-6j2x-vhqr-qr7q)
 *
 * The WebAssembly JavaScript Promise Integration (JSPI) API — `WebAssembly.promising`
 * and `WebAssembly.Suspending` (Node 24+ behind --experimental-wasm-jspi, Node 26+
 * by default) — produces Promise objects whose prototype chain points DIRECTLY at
 * the host realm's `Promise.prototype` without going through any bridge proxy.
 * Sandbox property access on a JSPI promise (e.g. `p.then`, `p.finally`) walks the
 * cross-realm prototype chain and resolves to host-realm native methods, completely
 * bypassing:
 *   - the sandbox-side `globalPromise.prototype.then|catch` overrides (different
 *     prototype object, so the overrides are never reached),
 *   - `resetPromiseSpecies` (only called from those overrides),
 *   - the bridge `apply`-trap callback wrapping for host Promise methods (only
 *     fires for *bridge-proxied* host promises; JSPI promises aren't proxied).
 *
 * Consequences:
 *   1. An attacker can install `Object.defineProperty(p, 'constructor', { get(){return F}})`
 *      directly on the JSPI promise (no proxy intercepts it).
 *   2. Host's `Promise.prototype.finally` reads `p.constructor` for SpeciesConstructor,
 *      gets the attacker's F (sandbox class), builds a result capability whose
 *      `[[Resolve]]` / `[[Reject]]` are the *raw* sandbox closures F supplied in its
 *      executor — with no bridge wrapping.
 *   3. When the JSPI promise rejects (e.g. with a host-realm TypeError thrown by
 *      `WebAssembly.compileStreaming` on a non-Response input), V8 dispatches the
 *      rejection through F's reject closure, delivering the raw host error into
 *      sandbox code. `e.constructor.constructor('return process')()` then evaluates
 *      in the host realm because `Function.[[Realm]]` is host.
 *
 * Fix: remove `WebAssembly.promising` and `WebAssembly.Suspending` from the sandbox.
 * Without `Suspending`, wasm modules cannot import a JS function as a suspending
 * import; without `promising`, sandbox cannot promote a wasm function into a JSPI
 * export. JSPI is the only known path that produces a sandbox-visible Promise whose
 * prototype crosses realms without bridge interposition — mirrors the existing
 * `WebAssembly.JSTag` removal (GHSA-9qj6-qjgg-37qq) in spirit.
 */
if (typeof WebAssembly !== 'undefined') {
	// SECURITY (GHSA-6j2x-vhqr-qr7q): WebAssembly.promising returns Promises with
	// host-realm Promise.prototype in their [[Prototype]] chain. No sandbox-side
	// override and no bridge proxy can intercept method dispatch on such objects.
	if (typeof WebAssembly.promising !== 'undefined') {
		localReflectDeleteProperty(WebAssembly, 'promising');
	}
	// SECURITY (GHSA-6j2x-vhqr-qr7q): WebAssembly.Suspending is required to satisfy
	// the suspending-import slot in any JSPI module. Removing it alone closes the
	// instantiation half of the chain; removing `.promising` closes the export half.
	if (typeof WebAssembly.Suspending !== 'undefined') {
		localReflectDeleteProperty(WebAssembly, 'Suspending');
	}
}

if (
	!localReflectDefineProperty(global, 'VMError', {
		__proto__: null,
		value: VMError,
		writable: true,
		enumerable: false,
		configurable: true,
	})
)
	throw localUnexpected();

// Fixes buffer unsafe allocation

class BufferHandler extends ReadOnlyHandler {
	// SECURITY (GHSA-v37h-5mfm-c47c): forward every arg (token + object)
	// to super() so BaseHandler's token check succeeds. Without this
	// forward, or if the constructor is reached by sandbox code without
	// the token, the super() call throws and no BufferHandler instance
	// is produced.
	constructor(...args) {
		super(...args);
	}

	apply(target, thiz, args) {
		if (args.length > 0 && typeof args[0] === 'number') {
			// SECURITY (GHSA-6785-pvv7-mvg7): deprecated Buffer(N) form. Cap before delegating to host.
			checkBufferAllocLimit(args[0]);
			return LocalBuffer.alloc(args[0]);
		}
		return apply(LocalBuffer.from, LocalBuffer, args);
	}

	construct(target, args, newTarget) {
		if (args.length > 0 && typeof args[0] === 'number') {
			// SECURITY (GHSA-6785-pvv7-mvg7): deprecated new Buffer(N) form. Cap before delegating.
			checkBufferAllocLimit(args[0]);
			return LocalBuffer.alloc(args[0]);
		}
		return apply(LocalBuffer.from, LocalBuffer, args);
	}
}

// SECURITY (post-GHSA-v37h hardening): rebind BufferHandler.prototype.constructor
// to the throw-always sentinel so `Object.getPrototypeOf(handler).constructor`
// on a leaked BufferHandler returns the sentinel rather than the real subclass.
// Layer 1 (token check via super(...args)) already blocks the actual construction,
// but Layer 3 was advertised as "every handler prototype" while only covering the
// four core classes — this closes the gap for handler subclasses defined outside
// bridge.js.
rebindHandlerConstructor(BufferHandler);

// SECURITY (GHSA-v37h-5mfm-c47c): construction goes through
// newBufferHandler, which injects the closure-scoped construction token.
const LocalBuffer = fromWithFactory(obj => newBufferHandler(BufferHandler, obj), host.Buffer);

if (
	!localReflectDefineProperty(global, 'Buffer', {
		__proto__: null,
		value: LocalBuffer,
		writable: true,
		enumerable: false,
		configurable: true,
	})
)
	throw localUnexpected();

addProtoMapping(LocalBuffer.prototype, host.Buffer.prototype, 'Uint8Array');

// SECURITY (GHSA-6785-pvv7-mvg7): cap Buffer.alloc before delegating to host.
// The captured `localBufferAllocOriginal` is the bridge proxy of host.Buffer.alloc;
// `connect()` then registers our wrapper as the canonical sandbox-side alloc, so
// future sandbox lookups of `Buffer.alloc` route through the cap.
const localBufferAllocOriginal = LocalBuffer.alloc;
function alloc(size, fill, encoding) {
	checkBufferAllocLimit(size);
	// Use raw Reflect.apply (`apply`) here — LocalBuffer is a frozen bridge proxy.
	return apply(localBufferAllocOriginal, LocalBuffer, arguments);
}

connect(alloc, host.Buffer.alloc);

/**
 *
 * @param {*} size Size of new buffer
 * @this LocalBuffer
 * @return {LocalBuffer}
 */
function allocUnsafe(size) {
	// SECURITY (GHSA-6785-pvv7-mvg7): cap before delegating. LocalBuffer.alloc
	// is already capped via connect() above, but we check here too so a future
	// refactor cannot silently re-open this path.
	checkBufferAllocLimit(size);
	return LocalBuffer.alloc(size);
}

connect(allocUnsafe, host.Buffer.allocUnsafe);

/**
 *
 * @param {*} size Size of new buffer
 * @this LocalBuffer
 * @return {LocalBuffer}
 */
function allocUnsafeSlow(size) {
	// SECURITY (GHSA-6785-pvv7-mvg7): cap before delegating (see allocUnsafe).
	checkBufferAllocLimit(size);
	return LocalBuffer.alloc(size);
}

connect(allocUnsafeSlow, host.Buffer.allocUnsafeSlow);

/**
 * Replacement for Buffer inspect
 *
 * @param {*} recurseTimes
 * @param {*} ctx
 * @this LocalBuffer
 * @return {string}
 */
function inspect(recurseTimes, ctx) {
	// Mimic old behavior, could throw but didn't pass a test.
	const max = host.INSPECT_MAX_BYTES;
	const actualMax = Math.min(max, this.length);
	const remaining = this.length - max;
	let str = this.hexSlice(0, actualMax)
		.replace(/(.{2})/g, '$1 ')
		.trim();
	if (remaining > 0) str += ` ... ${remaining} more byte${remaining > 1 ? 's' : ''}`;
	return `<${this.constructor.name} ${str}>`;
}

connect(inspect, host.Buffer.prototype.inspect);

connect(localFunction.prototype.bind, host.Function.prototype.bind);

connect(localObject.prototype.__defineGetter__, host.Object.prototype.__defineGetter__);
connect(localObject.prototype.__defineSetter__, host.Object.prototype.__defineSetter__);
connect(localObject.prototype.__lookupGetter__, host.Object.prototype.__lookupGetter__);
connect(localObject.prototype.__lookupSetter__, host.Object.prototype.__lookupSetter__);

/*
 * PrepareStackTrace sanitization
 */

const oldPrepareStackTraceDesc = localReflectGetOwnPropertyDescriptor(LocalError, 'prepareStackTrace');

/*
 * Safe default prepareStackTrace function.
 *
 * When Error.prepareStackTrace is undefined in the sandbox, V8 falls back to
 * Node.js's host-side prepareStackTraceCallback (from node:internal/errors).
 * If that host code throws (e.g., when error.name is a Symbol), the TypeError
 * is a host-realm error, which can be used for sandbox escape.
 *
 * This function ensures V8 never falls back to the host formatter. It safely
 * handles Symbol names, Proxy objects, and other exotic types without throwing.
 */
function defaultSandboxPrepareStackTrace(error, callSites) {
	// Safely convert error to a header string, handling Symbol names,
	// Proxy objects, and other exotic types that would throw during coercion.
	let header;
	try {
		let name;
		try {
			name = error.name;
		} catch (e) {
			name = 'Error';
		}
		// If name is a Symbol or other non-string, safely coerce it
		if (typeof name === 'symbol') {
			try {
				name = name.toString();
			} catch (e) {
				name = 'Error';
			}
		} else if (typeof name !== 'string') {
			try {
				name = '' + name;
			} catch (e) {
				name = 'Error';
			}
		}
		let message;
		try {
			message = error.message;
		} catch (e) {
			message = '';
		}
		if (typeof message !== 'string') {
			try {
				message = '' + message;
			} catch (e) {
				message = '';
			}
		}
		header = message ? name + ': ' + message : name;
	} catch (e) {
		header = 'Error';
	}

	// SECURITY (GHSA-q3fm-4wcw-g57x): build the result via primitive string
	// concatenation rather than `lines[lines.length] = X` + `lines.join('\n')`.
	// The former is the GHSA-9qj6-qjgg-37qq pattern in a different file: an index
	// assignment on a fresh sandbox-realm array walks the prototype chain when
	// no own slot exists, so a sandbox-installed setter on `Array.prototype[N]`
	// would observe each appended frame. The latter dispatches `Array.prototype.join`
	// through the prototype chain, so a sandbox override would intercept the
	// assembled stack string on the way out. Both violate Defense Invariant #11
	// ("bridge-internal containers must not invoke sandbox code"). Folding the
	// frames straight into a string accumulator removes the container entirely,
	// so no `Array.prototype` slot — getter, setter, or method — is reachable
	// from this codepath.
	let result = header;
	for (let i = 0; i < callSites.length; i++) {
		let frame;
		try {
			frame = '    at ' + callSites[i];
		} catch (e) {
			frame = '    at <error formatting frame>';
		}
		result += '\n' + frame;
	}
	return result;
}

let currentPrepareStackTrace = LocalError.prepareStackTrace;
const wrappedPrepareStackTrace = new LocalWeakMap();
if (typeof currentPrepareStackTrace === 'function') {
	wrappedPrepareStackTrace.set(currentPrepareStackTrace, currentPrepareStackTrace);
}
// HARDENING (post-#563): the original PR pre-registered defaultSandboxPrepareStackTrace
// in the WeakMap as identity (mapping itself to itself), which would have caused the
// setter to bypass the call-site wrapping path. Removed — the setter now wraps the
// default through the same `newWrapped` logic as user-provided functions, so callsite
// `toString()` invocations go through the sandbox `CallSite` wrapper class and don't
// leak host paths.

let OriginalCallSite;
LocalError.prepareStackTrace = (e, sst) => {
	OriginalCallSite = sst[0].constructor;
};
new LocalError().stack;
if (typeof OriginalCallSite === 'function') {
	// SECURITY (GHSA-v27g-jcqj-v8rw): if we leave prepareStackTrace as
	// `undefined`, V8 falls through to its native default formatter, which
	// emits absolute host paths and host function names into `error.stack`.
	// Defer the install of our sandbox default until OriginalCallSite-based
	// frame classification is available below; for now, set to undefined so
	// the setter installed later can take over.
	LocalError.prepareStackTrace = undefined;

	function makeCallSiteGetters(list) {
		// SECURITY (GHSA-q3fm-4wcw-g57x): install each entry as an own data
		// property via localReflectDefineProperty rather than `callSiteGetters[N] = …`.
		// This loop runs at sandbox init before user code can install a setter
		// on `Array.prototype[N]`, so the prototype-walking index assignment is
		// safe today — the change is for symmetry with the defaultSandboxPrepareStackTrace
		// fix and to keep Defense Invariant #11 ("bridge-internal containers must
		// not invoke sandbox code") uniform across this file. Indexed reads at
		// the consumers (applyCallSiteGetters, the prototype-population loop
		// below) then land on own data slots and cannot be intercepted by a
		// later sandbox-installed getter on `Array.prototype[N]`.
		const callSiteGetters = [];
		let callSiteGettersLen = 0;
		for (let i = 0; i < list.length; i++) {
			const name = list[i];
			const func = OriginalCallSite.prototype[name];
			// Older Node versions (e.g. v10) don't ship every getter we list
			// (isAsync / isPromiseAll / getPromiseIndex landed in Node 12).
			// Skip missing entries so applyCallSiteGetters doesn't apply
			// `undefined` and throw "Function.prototype.apply was called on undefined".
			if (typeof func !== 'function') continue;
			localReflectDefineProperty(callSiteGetters, callSiteGettersLen, {
				__proto__: null,
				value: {
					__proto__: null,
					name,
					propName: '_' + name,
					func: thiz => {
						return localReflectApply(func, thiz, []);
					},
				},
				writable: true,
				enumerable: true,
				configurable: true,
			});
			callSiteGettersLen++;
		}
		return callSiteGetters;
	}

	// SECURITY (GHSA-v27g-jcqj-v8rw): a "host frame" is any frame whose source
	// filename indicates host-realm code: an absolute path (starts with `/`),
	// a Windows-style absolute path (matches `<letter>:\`), a Node internals
	// pseudo-path (starts with `node:` or `internal/`), or a relative path
	// containing `..` (host modules sometimes appear with relative paths).
	// Clean sandbox filenames (e.g. the default `vm.js`, or user-provided
	// VMScript filenames without separators) do NOT match — sandbox
	// developers can still see their own line numbers and function names.
	function isHostFrameFileName(name) {
		if (typeof name !== 'string' || name.length === 0) return false;
		if (name.charCodeAt(0) === 0x2f /* '/' */) return true;
		if (name.length >= 2 && name.charCodeAt(1) === 0x3a /* ':' */) return true;
		if (name.length >= 5 && name.slice(0, 5) === 'node:') return true;
		if (name.length >= 9 && name.slice(0, 9) === 'internal/') return true;
		return false;
	}

	function applyCallSiteGetters(thiz, callSite, getters) {
		// SECURITY (GHSA-v27g-jcqj-v8rw): classify the frame once (host vs sandbox)
		// by inspecting the underlying CallSite's getFileName. Host frames return
		// null for every getter — closes the path/line/function-name leak via
		// custom `Error.prepareStackTrace`.
		let fileName;
		try {
			fileName = localReflectApply(OriginalCallSite.prototype.getFileName, callSite, []);
		} catch (e) {
			fileName = null;
		}
		const isHostFrame = isHostFrameFileName(fileName);
		for (let i = 0; i < getters.length; i++) {
			const getter = getters[i];
			let value;
			if (isHostFrame) {
				value = null;
			} else if (getter.name === 'getEvalOrigin') {
				// SECURITY (post-GHSA-v27g hardening): a sandbox frame's
				// `getEvalOrigin()` returns a string of the form
				// `"eval at FUNC (FILENAME:LINE:COL)"` whose embedded
				// FILENAME may be a host-realm path (e.g. eval triggered
				// from `lib/setup-sandbox.js`). The frame-level host
				// classifier above does not inspect that nested path.
				// Sandbox developers don't need eval-origin info for
				// debugging their own code, so always redact.
				value = null;
			} else {
				value = getter.func(callSite);
			}
			localReflectDefineProperty(thiz, getter.propName, {
				__proto__: null,
				value,
			});
		}
	}

	const callSiteGetters = makeCallSiteGetters([
		'getTypeName',
		'getFunctionName',
		'getMethodName',
		'getFileName',
		'getLineNumber',
		'getColumnNumber',
		'getEvalOrigin',
		'isToplevel',
		'isEval',
		'isNative',
		'isConstructor',
		'isAsync',
		'isPromiseAll',
		'getPromiseIndex',
	]);

	class CallSite {
		constructor(callSite) {
			applyCallSiteGetters(this, callSite, callSiteGetters);
		}
		getThis() {
			return undefined;
		}
		getFunction() {
			return undefined;
		}
		toString() {
			return 'CallSite {}';
		}
	}

	for (let i = 0; i < callSiteGetters.length; i++) {
		const name = callSiteGetters[i].name;
		const funcProp = localReflectGetOwnPropertyDescriptor(OriginalCallSite.prototype, name);
		if (!funcProp) continue;
		const propertyName = callSiteGetters[i].propName;
		const func = {
			func() {
				return this[propertyName];
			},
		}.func;
		const nameProp = localReflectGetOwnPropertyDescriptor(func, 'name');
		if (!nameProp) throw localUnexpected();
		nameProp.value = name;
		if (!localReflectDefineProperty(func, 'name', nameProp)) throw localUnexpected();
		funcProp.value = func;
		if (!localReflectDefineProperty(CallSite.prototype, name, funcProp)) throw localUnexpected();
	}

	if (
		!localReflectDefineProperty(LocalError, 'prepareStackTrace', {
			configurable: false,
			enumerable: false,
			get() {
				return currentPrepareStackTrace;
			},
			set(value) {
				// HARDENING (post-#563): when user sets prepareStackTrace to a
				// non-function (undefined / null / etc.), substitute the safe
				// default so V8 never falls back to Node's host-side formatter
				// (which throws host-realm TypeError on Symbol-named errors).
				// Crucially, route the default through the SAME wrapping path
				// as user-provided functions below — that wraps each CallSite
				// in the sandbox-realm `CallSite` class so `'    at ' + cs`
				// uses our wrapper's safe `toString()` ('CallSite {}') instead
				// of V8's native CallSite toString (which leaks absolute host
				// paths and host function names into the formatted string).
				if (typeof value !== 'function') {
					value = defaultSandboxPrepareStackTrace;
				}
				const wrapped = localReflectApply(localWeakMapGet, wrappedPrepareStackTrace, [value]);
				if (wrapped) {
					currentPrepareStackTrace = wrapped;
					return;
				}
				const newWrapped = (error, sst) => {
					const sandboxSst = ensureThis(sst);
					if (localArrayIsArray(sst)) {
						if (sst === sandboxSst) {
							for (let i = 0; i < sst.length; i++) {
								const cs = sst[i];
								if (
									typeof cs === 'object' &&
									localReflectGetPrototypeOf(cs) === OriginalCallSite.prototype
								) {
									sst[i] = new CallSite(cs);
								}
							}
						} else {
							sst = [];
							for (let i = 0; i < sandboxSst.length; i++) {
								const cs = sandboxSst[i];
								localReflectDefineProperty(sst, i, {
									__proto__: null,
									value: new CallSite(cs),
									enumerable: true,
									configurable: true,
									writable: true,
								});
							}
						}
					} else {
						sst = sandboxSst;
					}
					return value(error, sst);
				};
				localReflectApply(localWeakMapSet, wrappedPrepareStackTrace, [value, newWrapped]);
				localReflectApply(localWeakMapSet, wrappedPrepareStackTrace, [newWrapped, newWrapped]);
				currentPrepareStackTrace = newWrapped;
			},
		})
	)
		throw localUnexpected();

	// SECURITY (post-GHSA-v27g Path A residual): assign the safe default
	// through the setter so `currentPrepareStackTrace` is the wrapped
	// default (not `undefined`). Without this, V8 falls back to Node's
	// host-side `defaultPrepareStackTrace` until sandbox code first
	// assigns to `Error.prepareStackTrace` — emitting absolute host paths
	// in `error.stack` and throwing host-realm TypeError on Symbol-named
	// errors.
	LocalError.prepareStackTrace = defaultSandboxPrepareStackTrace;
} else if (oldPrepareStackTraceDesc) {
	localReflectDefineProperty(LocalError, 'prepareStackTrace', oldPrepareStackTraceDesc);
} else {
	localReflectDeleteProperty(LocalError, 'prepareStackTrace');
}

/*
 * Exception sanitization
 */

/*
 * SuppressedError / AggregateError sanitization
 *
 * When V8 internally creates SuppressedError during DisposableStack.dispose()
 * or 'using' declarations, the .error and .suppressed properties may contain
 * host-realm errors (e.g., TypeError from Symbol() name trick). Since the
 * SuppressedError is created in the sandbox context, ensureThis returns it
 * as-is, leaving its sub-error properties unsanitized.
 *
 * The same sub-error-sanitization gap applies to AggregateError, which
 * Promise.any produces when every contributing promise rejects. If any
 * contributing promise was host-realm (GHSA-55hx-c926-fr95 / -35vh-489p-v7cx
 * class — host-Promise rejection delivery), its rejection value ends up as
 * an element of AggregateError.errors[] and reaches sandbox code unsanitized.
 *
 * Fix: handleException detects SuppressedError / AggregateError instances
 * and recursively sanitizes .error / .suppressed / .errors[] via ensureThis.
 */
const localSuppressedErrorProto = typeof SuppressedError === 'function' ? SuppressedError.prototype : null;
const localAggregateErrorProto = typeof AggregateError === 'function' ? AggregateError.prototype : null;

function handleException(e, visited) {
	// SECURITY (GHSA-9vg3-4rfj-wgcm): use `ensureThis`, NOT `from`. Reverts
	// the b57ac2d "GHSA-mpf8 symmetry" hardening. The values reaching this
	// function from sandbox-side callsites — transformer-instrumented JS
	// catch (`catch(e){e=handleException(e);}`), the localPromise executor
	// catch wrapper, and the sandbox-side `Promise.prototype.then|catch`
	// onRejected wrappers — are sandbox-realm by construction (host-side
	// errors are pre-converted at the bridge boundary by
	// `thisFromOtherForThrow`). Wrapping a sandbox-realm null-proto value
	// with `from` builds a bridge proxy whose `set` trap unwraps incoming
	// sandbox proxies of host references (e.g., `Buffer.prototype.inspect`)
	// to their raw host originals and stores them on the underlying
	// sandbox object — readable directly via the sandbox reference and
	// trivially pivoted to host Function via `.constructor` → RCE. The
	// genuinely-host-realm path (host-Promise rejections through
	// `setHostPromiseSanitizers`) wraps with `from()` *before* calling
	// handleException; see the install site below.
	e = ensureThis(e);
	if (e === null || (typeof e !== 'object' && typeof e !== 'function')) return e;
	if (localSuppressedErrorProto === null && localAggregateErrorProto === null) return e;
	if (!visited) visited = new LocalWeakMap();
	// Cycle detection: if we've already visited this object, stop recursing
	if (apply(localWeakMapGet, visited, [e])) return e;
	apply(localWeakMapSet, visited, [e, true]);
	let proto;
	try {
		proto = localReflectGetPrototypeOf(e);
	} catch (ex) {
		return e;
	}
	while (proto !== null) {
		if (localSuppressedErrorProto !== null && proto === localSuppressedErrorProto) {
			// SECURITY: SuppressedError.error / .suppressed frequently carry
			// host-realm errors produced by V8 internals (DisposableStack,
			// `using` declarations). Recursively sanitize both branches.
			try {
				e.error = handleException(e.error, visited);
			} catch (ex) {
				/* best effort */
			}
			try {
				e.suppressed = handleException(e.suppressed, visited);
			} catch (ex) {
				/* best effort */
			}
			return e;
		}
		if (localAggregateErrorProto !== null && proto === localAggregateErrorProto) {
			// SECURITY (GHSA-55hx-c926-fr95): AggregateError.errors[] can carry
			// host-realm rejection values when contributing promises in a
			// Promise.any call are host-realm. Sanitize each entry.
			let arr;
			try {
				arr = e.errors;
			} catch (ex) {
				return e;
			}
			if (localArrayIsArray(arr)) {
				let len;
				try {
					len = arr.length >>> 0;
				} catch (ex) {
					return e;
				}
				for (let i = 0; i < len; i++) {
					let item;
					try {
						item = arr[i];
					} catch (ex) {
						continue;
					}
					const sanitized = handleException(item, visited);
					if (sanitized !== item) {
						try {
							arr[i] = sanitized;
						} catch (ex) {
							/* best effort */
						}
					}
				}
			}
			return e;
		}
		try {
			proto = localReflectGetPrototypeOf(proto);
		} catch (ex) {
			return e;
		}
	}
	return e;
}

// SECURITY (GHSA-55hx): install sanitizers for sandbox callbacks bound to
// host-realm Promise.prototype.then|catch|finally. Without this, when sandbox
// code calls .then/.catch on a host Promise (returned e.g. by an embedder-
// exposed `async () => {}`), the host Promise machinery (PromiseReactionJob)
// runs the sandbox callback against the RAW host fulfillment/rejection value,
// bypassing the sandbox-side Promise.prototype override above. The bridge
// apply-trap interception on those methods now wraps callbacks through these
// sanitizers, closing the invariant: every sandbox callback bound to a host
// Promise receives its argument(s) bridge-wrapped.
//
// Both arguments wrap with `from()` because at this site the value is host-
// realm by construction (delivered from host Promise machinery).
//
// SECURITY (GHSA-9vg3-4rfj-wgcm): the rejection sanitizer composes `from` ON
// THE OUTSIDE of `handleException`. handleException itself now uses
// `ensureThis` internally (sandbox-realm-safe) — see its body above for why.
// We must still wrap host-realm rejection values to preserve the GHSA-mpf8
// invariant (unmapped-proto host values reach sandbox callbacks bridge-
// wrapped, not raw), so do the wrap explicitly here before calling
// handleException, which then performs its SuppressedError / AggregateError
// recursive sanitization on the wrapped value.
if (typeof bridge.setHostPromiseSanitizers === 'function') {
	bridge.setHostPromiseSanitizers(e => handleException(from(e)), from);
}

// SECURITY (GHSA-248r-7h7q-cr24): Async generator yield*-return thenable
// exception capture. When sandbox code calls `i.return(thenable)` on an
// async generator that delegates via `yield*` to an inner async iterator
// without a `return` method, V8's PromiseResolveThenableJob captures any
// synchronous throw from the thenable's `.then` callback and the yield*
// machinery delivers it to sandbox code as an iterator result
// (`{ value: thrown, done: false }`). This bypasses (a) the transformer's
// `catch`-block instrumentation (the catch is implicit in V8 internals)
// and (b) the `globalPromise.prototype.then` rejection sanitizer above,
// because internal `Await` uses `PerformPromiseThen` directly and never
// invokes the user-visible `.then` override. Wrap
// `%AsyncGeneratorPrototype%.next` / `.return` / `.throw` so every value
// flowing out of an async generator into sandbox code is routed through
// `handleException` — restoring the invariant that no host-realm value
// can reach sandbox code without sanitization.
let localAsyncGeneratorPrototype = null;
try {
	// %AsyncGeneratorPrototype% is two prototype levels up from an instance:
	//   instance.[[Prototype]]                    → per-function prototype
	//   per-function-prototype.[[Prototype]]      → %AsyncGeneratorPrototype%
	// Each async generator function gets its own per-function prototype, so
	// wrapping that level is ineffective for any other async generator
	// (like helpers defined inside sandbox code). Walk up one more step to
	// reach the shared intrinsic prototype that owns next/return/throw.
	const localAsyncGenInstance = localEval('(async function*(){})()');
	localAsyncGeneratorPrototype = localReflectGetPrototypeOf(localReflectGetPrototypeOf(localAsyncGenInstance));
} catch (e) {
	// AsyncGenerators not available (Node < 10) — nothing to wrap.
}

if (localAsyncGeneratorPrototype) {
	const origAsyncGenNext = localAsyncGeneratorPrototype.next;
	const origAsyncGenReturn = localAsyncGeneratorPrototype.return;
	const origAsyncGenThrow = localAsyncGeneratorPrototype.throw;

	// SECURITY: chain through the *cached* native then() so this sanitization
	// step does not itself recurse through the `globalPromise.prototype.then`
	// override (which would double-handle and could observe attacker-supplied
	// species manipulation on intermediate promises).
	function sanitizeAsyncIteratorResultPromise(promise) {
		return apply(globalPromisePrototypeThen, promise, [
			function sanitizeFulfilledIterResult(result) {
				if (result === null || (typeof result !== 'object' && typeof result !== 'function')) return result;
				let value;
				try {
					value = result.value;
				} catch (ex) {
					return result;
				}
				const sanitized = safeSanitize(value);
				if (sanitized === value) return result;
				let done;
				try {
					done = !!result.done;
				} catch (ex) {
					done = false;
				}
				// New object — never mutate an attacker-controlled result shape.
				return { value: sanitized, done };
			},
			function sanitizeRejectedIterResult(error) {
				throw safeSanitize(error);
			},
		]);
	}

	// SECURITY: when sandbox passes a thenable to AsyncGeneratorPrototype.return
	// (or .next / .throw), V8 awaits the thenable as part of yield* abrupt-
	// completion processing. PromiseResolveThenableJob calls the thenable's
	// .then(resolve, reject); a synchronous throw from .then is captured by
	// V8's host-side try/catch and propagated INTO the inner iterator as the
	// resumption value — i.e., V8 calls inner.next(captured) on the next loop
	// turn. The inner iterator (sandbox-defined) can package that value
	// however it wants — including hiding it inside a closure
	// (`{value: ()=>v, done: false}`) so the wrapper above sees only the
	// closure and the iterator-result `value` sanitization is a no-op.
	//
	// Three sub-attacks, all closed below:
	//
	//   (1) Direct sync throw — wrap user .then in try/catch, convert to
	//       reject(handleException(e)).
	//   (2) Nested-thenable resolve — `{ then(r){ r({ then(r){ f(); r(); }}) }}`.
	//       Outer .then resolves with another thenable; V8 recursively
	//       unwraps via PromiseResolveThenableJob, the inner .then runs
	//       unwrapped. Fix: wrap the resolve callback so any thenable
	//       handed to it is recursively re-sanitised before V8 sees it.
	//   (3) Getter TOCTOU on .then — a getter returns undefined to our
	//       pre-read and a real function to V8's read. Fix: never pre-read.
	//       Always substitute a sandbox-realm wrapper whose .then is a
	//       fixed function. Inside that function read user.then exactly
	//       once and use the captured ref. For the non-thenable branch,
	//       resolve with a fresh shadow object that has no .then own or
	//       inherited property, so V8 cannot re-detect a thenable when
	//       PromiseResolve runs again on the resolution value.
	//
	// Together these collapse the attack surface to: V8 only ever calls
	// safeThen, and safeThen routes every value flowing across the boundary
	// through handleException or another safeThen wrapper.
	// SECURITY (v5 — review feedback): the previous makeNonThenableShadow
	// always built a `{__proto__:null}` copy of value's own descriptors.
	// That preserved the "V8 cannot re-detect a thenable on PromiseResolve"
	// invariant, but corrupted any value with meaningful prototype-defined
	// behaviour: passing a function, Map, Set, Date, or any class instance
	// to `i.return(x)` would surface to sandbox code as an empty object
	// stripped of its constructor methods (`fn(2,3)`, `m.get('a')`,
	// `d.toISOString()` all break).
	//
	// Use a hybrid strategy: walk value's prototype chain for a `then`
	// accessor (getter/setter). If none, V8's re-read of `value.then` will
	// see the same `undefined` we did — safe to pass `value` straight to
	// resolve, preserving identity and prototype methods. If an accessor
	// IS present (attacker scenario or `Object.prototype.then` poisoning),
	// fall back to the stripped shadow — the data corruption is acceptable
	// because the value is already attacker-crafted in that case.

	// SECURITY (v7 — GHSA-248r-7h7q-cr24): the v6 fix used a descriptor
	// walk + double-read to decide whether `value` could be passed
	// directly to `resolve()` (preserving identity for benign non-thenable
	// inputs). The reviewer demonstrated a structural bypass: a getter on
	// `.then` that counts reads, returns non-function on each pre-read,
	// then self-replaces with a data property holding a malicious function
	// before V8's `[[Get]]` in `PromiseResolveThenableJob` runs. The
	// descriptor walk afterwards sees the data property (not an accessor)
	// and concludes "safe to pass value". V8 then reads the malicious
	// function and schedules another `PromiseResolveThenableJob` that
	// invokes it OUTSIDE our wrapper, with V8 internal capability
	// resolvers — defeating every layer above.
	//
	// The same flaw applies to Proxies: `getOwnPropertyDescriptor` traps
	// can lie about descriptors while `get` traps return arbitrary values
	// across reads. Detection-based heuristics on attacker-controlled
	// `.then` slots are fundamentally bypassable.
	//
	// `thenIsAccessorInChain` is therefore removed in v7. The non-function
	// branch ALWAYS shadows; see `safeThen` below for rationale.
	function makeNonThenableShadow(value) {
		const shadow = { __proto__: null };
		let keys;
		try {
			keys = localReflectOwnKeys(value);
		} catch (ex) {
			return shadow;
		}
		if (!localArrayIsArray(keys)) return shadow;
		for (let i = 0; i < keys.length; i++) {
			const k = keys[i];
			if (k === 'then') continue;
			let desc;
			try {
				desc = localReflectGetOwnPropertyDescriptor(value, k);
			} catch (ex) {
				continue;
			}
			if (!desc) continue;
			try {
				localReflectDefineProperty(shadow, k, desc);
			} catch (ex) {
				// best effort — non-configurable / non-writable conflicts
			}
		}
		return shadow;
	}

	// SECURITY (v5 — review feedback): handleException(e) itself can throw
	// (e.g., bridge.from on a hostile prototype, or a getter on .error /
	// .suppressed that escapes its inner try/catch). If the throw escapes
	// uncaught from a place where we then re-throw or hand the value to V8,
	// the original raw value reaches sandbox code via the rejection path —
	// defeating the entire sanitisation chain. Wrap every call with a
	// fallback that returns a sandbox-realm VMError.
	function safeSanitize(e) {
		let result;
		try {
			result = handleException(e);
		} catch (sanEx) {
			try {
				result = new VMError('Exception sanitization failed');
			} catch (vmEx) {
				try {
					result = new LocalError('Exception sanitization failed');
				} catch (errEx) {
					result = undefined;
				}
			}
		}
		return result;
	}

	function sanitizeThenableArg(value) {
		if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return value;
		// ALWAYS wrap. Do not pre-read value.then — a getter could behave
		// differently on the second call and bypass the wrap (sub-attack 3).
		return {
			then: function safeThen(resolve, reject) {
				// Read user.then exactly once; V8 will not re-read because it
				// already captured `safeThen` (a fixed function) at PromiseResolve
				// time and uses that captured ref for the resolver job.
				let userThen;
				try {
					userThen = value.then;
				} catch (e) {
					if (typeof reject === 'function') {
						try {
							reject(safeSanitize(e));
						} catch (rejectEx) {
							/* best effort */
						}
						return undefined;
					}
					throw safeSanitize(e);
				}
				if (typeof userThen !== 'function') {
					// SECURITY (v7 — GHSA-248r-7h7q-cr24): the v6 fix tried
					// to preserve identity for benign non-thenable inputs by
					// passing `value` to `resolve()` after a descriptor walk
					// confirmed no `.then` accessor in the chain. The
					// external review demonstrated a counter: a getter
					// that counts reads, returns non-function on each
					// pre-read, then self-replaces with a data property
					// holding a malicious function before V8's `[[Get]]` in
					// PromiseResolveThenableJob. By the time the descriptor
					// walk runs, the getter has already mutated to a data
					// property, so the walk reports "no accessor" and the
					// code passes `value` to `resolve()`. V8 then reads the
					// malicious function via [[Get]] and schedules another
					// PromiseResolveThenableJob that calls it OUTSIDE our
					// wrapper — proven by the V8-supplied resolver having
					// `.name === ""` instead of `safeResolveCallback`.
					//
					// Doubling, tripling, or N-reading does not help: the
					// getter (or a Proxy) can count to any N before
					// switching, and Proxies can lie about descriptors.
					// Detection-based heuristics on an attacker-controlled
					// `.then` slot are fundamentally bypassable.
					//
					// Structural fix: when `userThen` is non-function on
					// our read, ALWAYS resolve with a sandbox-realm shadow
					// that has no `.then` anywhere in its chain. V8 cannot
					// re-read the user's `value`; it only sees the shadow,
					// which we fully control. Trade-off: identity is not
					// preserved for non-thenable values passed to
					// `i.return(x)` (the resolved iterator value will not
					// be `===` to the input). Identity preservation in this
					// codepath is incompatible with safety against TOCTOU
					// attacks on `.then`; the shadow option is the only
					// invariant we can hold against an adversarial input.
					if (typeof resolve === 'function') {
						let shadow;
						try {
							shadow = makeNonThenableShadow(value);
						} catch (shadowEx) {
							shadow = { __proto__: null };
						}
						try {
							resolve(shadow);
						} catch (resolveEx) {
							/* best effort */
						}
					}
					return undefined;
				}
				// Wrap resolve so any nested thenable handed to it is itself
				// sanitised before V8 schedules the next PromiseResolveThenableJob
				// (sub-attack 2 — `{ then(r){ r(innerThenable) }}` chains).
				const safeResolve =
					typeof resolve === 'function'
						? function safeResolveCallback(v) {
								let safe;
								try {
									safe = sanitizeThenableArg(v);
								} catch (wrapEx) {
									safe = v;
								}
								return resolve(safe);
							}
						: resolve;
				const safeReject =
					typeof reject === 'function'
						? function safeRejectCallback(r) {
								return reject(safeSanitize(r));
							}
						: reject;
				try {
					return apply(userThen, value, [safeResolve, safeReject]);
				} catch (e) {
					const sanitized = safeSanitize(e);
					if (typeof reject === 'function') {
						try {
							reject(sanitized);
						} catch (rejectEx) {
							/* best effort */
						}
						return undefined;
					}
					throw sanitized;
				}
			},
		};
	}

	function wrapAsyncGenMethod(orig) {
		return function asyncGenSanitizedWrapper() {
			// SECURITY: sanitize the first argument (the only one V8 awaits in
			// yield* abrupt-completion paths) BEFORE delegating to the native
			// method. Build the argsList as a `{ __proto__: null }` array-like
			// so writes to `args[i]` cannot walk the prototype chain and fire
			// sandbox-installed setters on `Array.prototype` / `Object.prototype`.
			// Using `[]` would inherit Array.prototype, and an attacker setter
			// on `Array.prototype['0']` would intercept the user value before
			// sanitizeThenableArg ever runs (or could feed a different value
			// to the native method via a paired getter).
			const len = arguments.length;
			const args = { __proto__: null, length: len };
			for (let i = 0; i < len; i++) {
				args[i] = arguments[i];
			}
			if (len > 0) {
				args[0] = sanitizeThenableArg(args[0]);
			}
			let res;
			try {
				res = apply(orig, this, args);
			} catch (e) {
				// Synchronous throw from the native method (e.g. wrong receiver) —
				// sanitize the throw value before it reaches sandbox catch blocks.
				throw safeSanitize(e);
			}
			if (res === null || (typeof res !== 'object' && typeof res !== 'function')) return res;
			return sanitizeAsyncIteratorResultPromise(res);
		};
	}

	// SECURITY: install with writable:false, configurable:false so sandbox
	// code cannot delete or replace the wrappers (defense-in-depth — even
	// without a reference to the original native, replacing the wrapper
	// would let sandbox interpose its own logic on V8's yield* protocol
	// invocations).
	if (typeof origAsyncGenNext === 'function') {
		if (
			!localReflectDefineProperty(localAsyncGeneratorPrototype, 'next', {
				__proto__: null,
				value: wrapAsyncGenMethod(origAsyncGenNext),
				writable: false,
				enumerable: false,
				configurable: false,
			})
		)
			throw localUnexpected();
	}
	if (typeof origAsyncGenReturn === 'function') {
		if (
			!localReflectDefineProperty(localAsyncGeneratorPrototype, 'return', {
				__proto__: null,
				value: wrapAsyncGenMethod(origAsyncGenReturn),
				writable: false,
				enumerable: false,
				configurable: false,
			})
		)
			throw localUnexpected();
	}
	if (typeof origAsyncGenThrow === 'function') {
		if (
			!localReflectDefineProperty(localAsyncGeneratorPrototype, 'throw', {
				__proto__: null,
				value: wrapAsyncGenMethod(origAsyncGenThrow),
				writable: false,
				enumerable: false,
				configurable: false,
			})
		)
			throw localUnexpected();
	}
}

const withProxy = localObjectFreeze({
	__proto__: null,
	has(target, key) {
		if (key === host.INTERNAL_STATE_NAME) return false;
		return localReflectHas(target, key);
	},
});

const interanState = localObjectFreeze({
	__proto__: null,
	wrapWith(x) {
		if (x === null || x === undefined) return x;
		return new LocalProxy(localObject(x), withProxy);
	},
	handleException,
	import(what) {
		throw new VMError('Dynamic Import not supported');
	},
});

// SECURITY (GHSA-2cm2-m3w5-gp2f): the internal state used to be installed
// as a permanent non-enumerable property on `globalThis`. The previous fix
// (GHSA-wp5r-2gw5-m7q7) closed the bare-identifier read path through the
// transformer, but any computed-key probe — `globalThis['VM2_…']`,
// `Reflect.get(globalThis, '…')`, `Object.getOwnPropertyDescriptor`, or
// just enumerating `Object.getOwnPropertyNames(globalThis)` — could still
// reach it, because the transformer is a syntactic gate and cannot see
// through dynamic property keys.
//
// The structural fix is to bind the canonical identifier in the context's
// GlobalLexicalEnvironment instead of as a property of the global object.
// The bootstrap script (compiled in `vm.js`) declares the canonical
// identifier as a top-level `let` BEFORE the IIFE that contains the rest
// of the bootstrap; the assignment below populates it. The resulting
// binding has three properties that the original global-property design
// lacked simultaneously:
//
//   - It IS reachable as a bare identifier from every script that runs
//     in this context (user scripts, eval'd source, Function constructor
//     bodies, the NodeVM module wrapper) — bare-identifier resolution
//     walks GlobalLexicalEnvironment after the script's own lex chain.
//
//   - It is NOT reachable from `globalThis[name]`, `Reflect.get`,
//     `Object.getOwnPropertyDescriptor`, `Object.getOwnPropertyNames`,
//     `Reflect.ownKeys`, or any other probe of the global object —
//     GlobalLexicalEnvironment is a separate record from the global
//     object's own-property table.
//
//   - It persists across every `runInContext` call in the same context,
//     so user-script `let x = …` is unaffected (other top-level `let`
//     declarations from user scripts continue to land in the same env
//     record exactly as they did before).
//
// The transformer rejects user source containing the canonical identifier
// (and its unicode-escape variants), so user code cannot redeclare it,
// cannot shadow it, and cannot reference it by name. The only reference
// path that resolves is the transformer's own injected emissions.
if (typeof host.INTERNAL_STATE_NAME !== 'string') throw localUnexpected();
// The IIFE wrapping the bootstrap shadows none of its enclosing script's
// `let` bindings, so the assignment below resolves up the lex chain to
// the top-level `let` declared in `vm.js`'s setupSandboxScript.
// eslint-disable-next-line no-undef
VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL = interanState;

/*
 * Eval sanitization
 */

function throwAsync() {
	return new VMError('Async not available');
}

function makeFunction(inputArgs, isAsync, isGenerator) {
	const lastArgs = inputArgs.length - 1;
	let code = lastArgs >= 0 ? `${inputArgs[lastArgs]}` : '';
	let args = lastArgs > 0 ? `${inputArgs[0]}` : '';
	for (let i = 1; i < lastArgs; i++) {
		args += `,${inputArgs[i]}`;
	}
	try {
		code = host.transformAndCheck(args, code, isAsync, isGenerator, allowAsync);
	} catch (e) {
		throw bridge.from(e);
	}
	return localEval(code);
}

const FunctionHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		return makeFunction(args, this.isAsync, this.isGenerator);
	},
	construct(target, args, newTarget) {
		return makeFunction(args, this.isAsync, this.isGenerator);
	},
};

const EvalHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		if (args.length === 0) return undefined;
		let code = `${args[0]}`;
		try {
			code = host.transformAndCheck(null, code, false, false, allowAsync);
		} catch (e) {
			throw bridge.from(e);
		}
		return localEval(code);
	},
};

const AsyncErrorHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		throw throwAsync();
	},
	construct(target, args, newTarget) {
		throw throwAsync();
	},
};

function makeCheckFunction(isAsync, isGenerator) {
	if (isAsync && !allowAsync) return AsyncErrorHandler;
	return {
		__proto__: FunctionHandler,
		isAsync,
		isGenerator,
	};
}

function overrideWithProxy(obj, prop, value, handler) {
	const proxy = new LocalProxy(value, handler);
	if (!localReflectDefineProperty(obj, prop, { __proto__: null, value: proxy })) throw localUnexpected();
	return proxy;
}

const proxiedFunction = overrideWithProxy(
	localFunction.prototype,
	'constructor',
	localFunction,
	makeCheckFunction(false, false),
);
if (GeneratorFunction) {
	if (!localReflectSetPrototypeOf(GeneratorFunction, proxiedFunction)) throw localUnexpected();
	overrideWithProxy(GeneratorFunction.prototype, 'constructor', GeneratorFunction, makeCheckFunction(false, true));
}
if (AsyncFunction) {
	if (!localReflectSetPrototypeOf(AsyncFunction, proxiedFunction)) throw localUnexpected();
	overrideWithProxy(AsyncFunction.prototype, 'constructor', AsyncFunction, makeCheckFunction(true, false));
}
if (AsyncGeneratorFunction) {
	if (!localReflectSetPrototypeOf(AsyncGeneratorFunction, proxiedFunction)) throw localUnexpected();
	overrideWithProxy(
		AsyncGeneratorFunction.prototype,
		'constructor',
		AsyncGeneratorFunction,
		makeCheckFunction(true, true),
	);
}

function makeSafeHandlerArgs(args) {
	const sArgs = ensureThis(args);
	if (sArgs === args) return args;
	const a = [];
	for (let i = 0; i < sArgs.length; i++) {
		localReflectDefineProperty(a, i, {
			__proto__: null,
			value: sArgs[i],
			enumerable: true,
			configurable: true,
			writable: true,
		});
	}
	return a;
}

const makeSafeArgs = Object.freeze({
	__proto__: null,
	apply(target, thiz, args) {
		return localReflectApply(target, thiz, makeSafeHandlerArgs(args));
	},
	construct(target, args, newTarget) {
		return localReflectConstruct(target, makeSafeHandlerArgs(args), newTarget);
	},
});

const proxyHandlerHandler = Object.freeze({
	__proto__: null,
	get(target, name, receiver) {
		if (name === 'isProxy') return true;
		const value = target.handler[name];
		if (typeof value !== 'function') return value;
		return new LocalProxy(value, makeSafeArgs);
	},
});

function wrapProxyHandler(args) {
	if (args.length < 2) return args;
	const handler = args[1];
	args[1] = new LocalProxy({ __proto__: null, handler }, proxyHandlerHandler);
	return args;
}

const proxyHandler = Object.freeze({
	__proto__: null,
	apply(target, thiz, args) {
		return localReflectApply(target, thiz, wrapProxyHandler(args));
	},
	construct(target, args, newTarget) {
		return localReflectConstruct(target, wrapProxyHandler(args), newTarget);
	},
});

const proxiedProxy = new LocalProxy(LocalProxy, proxyHandler);

overrideWithProxy(LocalProxy, 'revocable', LocalProxy.revocable, proxyHandler);

global.Proxy = proxiedProxy;
global.Function = proxiedFunction;
global.eval = new LocalProxy(localEval, EvalHandler);

/*
 * Promise sanitization
 */

if (localPromise) {
	const PromisePrototype = localPromise.prototype;

	if (!allowAsync) {
		overrideWithProxy(PromisePrototype, 'then', PromisePrototype.then, AsyncErrorHandler);
		// This seems not to work, and will produce
		// UnhandledPromiseRejectionWarning: TypeError: Method Promise.prototype.then called on incompatible receiver [object Object].
		// This is likely caused since the host.Promise.prototype.then cannot use the VM Proxy object.
		// Contextify.connect(host.Promise.prototype.then, Promise.prototype.then);
	} else {
		overrideWithProxy(PromisePrototype, 'then', PromisePrototype.then, {
			__proto__: null,
			apply(target, thiz, args) {
				if (args.length > 0) {
					const onFulfilled = args[0];
					if (typeof onFulfilled === 'function') {
						args[0] = function sanitizedOnFulfilled(value) {
							value = ensureThis(value);
							return localReflectApply(onFulfilled, this, [value]);
						};
					}
				}
				if (args.length > 1) {
					const onRejected = args[1];
					if (typeof onRejected === 'function') {
						args[1] = function sanitizedOnRejected(error) {
							error = handleException(error);
							return localReflectApply(onRejected, this, [error]);
						};
					}
				}
				return localReflectApply(target, thiz, args);
			},
		});

		overrideWithProxy(PromisePrototype, 'catch', PromisePrototype.catch, {
			__proto__: null,
			apply(target, thiz, args) {
				if (args.length > 0) {
					const onRejected = args[0];
					if (typeof onRejected === 'function') {
						args[0] = function sanitizedOnRejected(error) {
							error = handleException(error);
							return localReflectApply(onRejected, this, [error]);
						};
					}
				}
				return localReflectApply(target, thiz, args);
			},
		});
	}

	// Secure Promise static methods to prevent species attacks via static method stealing.
	//
	// Several methods are vulnerable because they catch errors during iteration/resolution
	// and pass them directly to the result promise's reject handler. If the attacker does:
	//   FakePromise.all = Promise.all; FakePromise.all(iterable);
	// Then `this` inside Promise.all is FakePromise, so it creates the result promise using
	// `new FakePromise(executor)`. When iteration throws a host error (e.g., from accessing
	// error.stack with error.name = Symbol()), Promise.all catches it and passes it to
	// FakePromise's reject handler, which receives the unsanitized host error.
	//
	// The fix wraps ALL Promise static methods to always use localPromise as the constructor,
	// ignoring `this`. This provides defense in depth even for methods like reject/withResolvers
	// that aren't currently known to be exploitable.
	//
	const globalPromiseTry = globalPromise.try;
	if (typeof globalPromiseTry === 'function') {
		globalPromise.try = function _try() {
			return apply(globalPromiseTry, localPromise, arguments);
		};
	}

	const globalPromiseAll = globalPromise.all;
	globalPromise.all = function all(iterable) {
		return apply(globalPromiseAll, localPromise, [iterable]);
	};

	const globalPromiseRace = globalPromise.race;
	globalPromise.race = function race(iterable) {
		return apply(globalPromiseRace, localPromise, [iterable]);
	};

	const globalPromiseAllSettled = globalPromise.allSettled;
	if (typeof globalPromiseAllSettled === 'function') {
		globalPromise.allSettled = function allSettled(iterable) {
			return apply(globalPromiseAllSettled, localPromise, [iterable]);
		};
	}

	const globalPromiseAny = globalPromise.any;
	if (typeof globalPromiseAny === 'function') {
		globalPromise.any = function any(iterable) {
			return apply(globalPromiseAny, localPromise, [iterable]);
		};
	}

	const globalPromiseResolve = globalPromise.resolve;
	globalPromise.resolve = function resolve(value) {
		return apply(globalPromiseResolve, localPromise, [value]);
	};

	const globalPromiseReject = globalPromise.reject;
	globalPromise.reject = function reject(reason) {
		return apply(globalPromiseReject, localPromise, [reason]);
	};

	const globalPromiseWithResolvers = globalPromise.withResolvers;
	if (typeof globalPromiseWithResolvers === 'function') {
		globalPromise.withResolvers = function withResolvers() {
			return apply(globalPromiseWithResolvers, localPromise, []);
		};
	}

	// Freeze globalPromise to prevent Symbol.hasInstance override
	// (which would bypass the instanceof check in resetPromiseSpecies).
	// Freeze globalPromise.prototype to prevent defining accessor properties
	// on 'constructor' that could be used for TOCTOU attacks via the prototype chain.
	Object.freeze(globalPromise);
	Object.freeze(globalPromise.prototype);
	Object.freeze(localPromise);
	Object.freeze(PromisePrototype);
}

function readonly(other, mock) {
	// Note: other@other(unsafe) mock@other(unsafe) returns@this(unsafe) throws@this(unsafe)
	if (!mock) return fromWithFactory(readonlyFactory, other);
	const tmock = from(mock);
	// SECURITY (GHSA-v37h-5mfm-c47c): use the token-bound helper instead of
	// `new ReadOnlyMockHandler(...)`. The handler class is no longer
	// directly constructible from sandbox code.
	return fromWithFactory(obj => createReadOnlyMockHandler(obj, tmock), other);
}

return {
	__proto__: null,
	readonly,
	global,
};
