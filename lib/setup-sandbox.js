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
// SECURITY (GHSA-x6m4-chr9-cg97): captured at module load, before sandbox code
// runs, for the host-frame stack redactor below. Used when a host Error's
// `.stack` is carried onto a sandbox-realm rebuild in sanitizeHostOwnProps —
// a path that never crosses the bridge `get` trap, so the bridge-side redactor
// (lib/bridge.js) cannot cover it.
const localStringSplit = global.String.prototype.split; // SECURITY (GHSA-x6m4-chr9-cg97)
const localStringSlice = global.String.prototype.slice; // SECURITY (GHSA-x6m4-chr9-cg97)
const localStringCharCodeAt = global.String.prototype.charCodeAt; // SECURITY (GHSA-x6m4-chr9-cg97)
const localStringLastIndexOf = global.String.prototype.lastIndexOf; // SECURITY (GHSA-x6m4-chr9-cg97)

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
// SECURITY (GHSA-f8gf-w286-fmq2): registry of localPromise's OWN wrapped
// executors. Under allowAsync:false, localPromise's [[Prototype]] is replaced
// by a construct-guard Proxy (see the Promise sanitization section) that
// refuses every construction of the native base intrinsic EXCEPT localPromise's
// genuine super() call. Membership in this set is how the guard tells the two
// apart. Keyed on the ephemeral wrapped-executor function, which sandbox code
// can never obtain a reference to.
const trustedPromiseExecutors = new LocalWeakMap();
// SECURITY (GHSA-f8gf-w286-fmq2): build a resolve capability that refuses any
// object/function value when async is disabled. Thenable assimilation is the
// only way sandbox code can schedule a callback that runs AFTER run() returns
// (no timers/queueMicrotask are exposed under allowAsync:false), and V8's
// PromiseResolveThenableJob reads the resolved value's own `.then` directly —
// never through our blocked Promise.prototype.then. The check is TOCTOU-safe
// BY CONSTRUCTION: it never reads `.then`. (Probing `.then` and then forwarding
// the original value to the native resolve would let a `.then` getter flip
// callability between our probe and V8's own read, re-opening the hole.) It
// also makes nested thenables moot — `res({then(r){r({then(){evil()}}})}` is
// refused at the OUTER object before any inner unwrap can be scheduled.
// Primitives are harmless — they cannot carry a `.then`.
function makeAsyncGuardedResolve(resolve) {
	if (allowAsync) return resolve;
	return function guardedResolve(value) {
		if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
			throw throwAsync();
		}
		return apply(resolve, this, [value]);
	};
}
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
		// SECURITY (GHSA-f8gf-w286-fmq2): when async execution is disabled, the
		// resolve capability is the engine-level vector for thenable
		// assimilation. Guard the user executor's resolve argument so
		// `new Promise(r => r(thenable))` cannot schedule a microtask after
		// run() returns. Because V8 builds promise capabilities by Constructing
		// this class via NewPromiseCapability, the same guard also covers
		// `Promise.withResolvers().resolve` and the internal capabilities used
		// by the static combinators. See makeAsyncGuardedResolve for the
		// TOCTOU-safety rationale. No-op under allowAsync:true (hot path).
		const wrappedExecutor = function wrappedExecutor(resolve, reject) {
			const guardedResolve = makeAsyncGuardedResolve(resolve);
			try {
				return apply(executor, this, [guardedResolve, reject]);
			} catch (e) {
				// SECURITY: handleException walks SuppressedError /
				// AggregateError sub-error chains and routes the value
				// through ensureThis, so a sandbox `.catch()` handler sees
				// a sandbox-realm value rather than a raw host TypeError.
				reject(handleException(e));
			}
		};
		// SECURITY (GHSA-f8gf-w286-fmq2): mark this executor as trusted BEFORE
		// super() so the construct-guard Proxy on our [[Prototype]] forwards the
		// genuine super() call to the native base. Statements before super() are
		// legal as long as they don't touch `this`/`new.target`. No-op (and no
		// Proxy) under allowAsync:true, so the hot path is unaffected.
		if (!allowAsync) apply(localWeakMapSet, trustedPromiseExecutors, [wrappedExecutor, true]);
		super(wrappedExecutor);
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
 * - 'nodejs.stream.{disturbed,errored}': State symbols Node reads directly off a raw stream object
 *   in `stream.Readable.isDisturbed(s)` / `isErrored(s)`. Sandbox code writing them onto a host
 *   stream flips its consumed/errored state host-side (e.g. isDisturbed true -> false). (GHSA-jf8q-945g-9q4c)
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
// SECURITY (GHSA-jf8q-945g-9q4c): cache the pristine `Symbol.keyFor` for the
// namespace-based dangerous-symbol check in `isDangerousSymbol`. Captured at
// bootstrap, before sandbox code can tamper with it.
const originalSymbolKeyFor = Symbol.keyFor;
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
	// SECURITY (GHSA-jf8q-945g-9q4c):
	originalSymbolFor('nodejs.stream.disturbed'),
	originalSymbolFor('nodejs.stream.errored'),
];

function isDangerousSymbol(sym) {
	if (typeof sym !== 'symbol') return false;
	for (let i = 0; i < realDangerousSymbols.length; i++) {
		if (sym === realDangerousSymbols[i]) return true;
	}
	// SECURITY (GHSA-jf8q-945g-9q4c): namespace-based catch-all. The `Symbol.for`
	// override above already denies the entire `nodejs.` namespace at the source;
	// mirror that here so EXTRACTION of real host `nodejs.*` symbols (via
	// getOwnPropertySymbols / Reflect.ownKeys / getOwnPropertyDescriptors /
	// Object.assign) is filtered for the whole namespace, not just the explicit
	// list. `Symbol.keyFor` returns a string only for REGISTERED symbols, so
	// well-known symbols (Symbol.iterator, …) and the sandbox-local
	// `Symbol('nodejs.*')` surrogates (unregistered → keyFor undefined) are
	// unaffected. This ends the list-goes-stale recurrence (jf8q is the second
	// such gap after GHSA-m5q2); the explicit list is kept as a fast path and
	// regression documentation.
	const key = originalSymbolKeyFor(sym);
	if (typeof key === 'string' && apply(localStringStartsWith, key, ['nodejs.'])) return true;
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
	// SECURITY (GHSA-m5q2-4fm3-vfqp / GHSA-jf8q-945g-9q4c): drop every dangerous
	// cross-realm symbol slot. Enumerate the result's own symbols with the raw
	// (captured) getOwnPropertySymbols and delete any that `isDangerousSymbol`
	// flags — this is the whole `nodejs.` namespace, so a symbol not in the
	// explicit list (a newer Node `nodejs.*` symbol) is still scrubbed.
	const descSymbols = apply(localObjectGetOwnPropertySymbols, localObject, [descs]);
	for (let i = 0; i < descSymbols.length; i++) {
		if (isDangerousSymbol(descSymbols[i])) localReflectDeleteProperty(descs, descSymbols[i]);
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
// SECURITY (GHSA-27g9-p43v-cw3v): cache the native `finally` for the wrapper
// installed below.
const globalPromiseFinally = globalPromise.prototype.finally;

const wrappedPromiseThen = function then(onFulfilled, onRejected) {
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
			// via `normalizeHostPromiseCallbacks` (see bridge.js). Calling `from`
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

const wrappedPromiseCatch = function _catch(onRejected) {
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

// SECURITY (GHSA-27g9-p43v-cw3v): wrap `finally` to run `resetPromiseSpecies`
// before delegating to the native implementation. `Promise.prototype.finally`
// internally performs a `SpeciesConstructor(this, Promise)` read; without this
// wrapper an attacker `constructor[Symbol.species]` installed on the promise
// gains control of the native reaction's resolve/reject. Neutralizing the
// species here closes the `finally` path independently of the protector fix
// below.
const wrappedPromiseFinally = typeof globalPromiseFinally === 'function'
	? function _finally(onFinally) {
		resetPromiseSpecies(this);
		return apply(globalPromiseFinally, this, [onFinally]);
	}
	: undefined;

// SECURITY (GHSA-27g9-p43v-cw3v): install the wrappers via `defineProperty`
// rather than plain assignment. On Node 26 / V8 14.6 the `SetPrototypeProperties`
// path taken by a direct `Promise.prototype.then = fn` assignment updates the
// existing data property WITHOUT invalidating the `PromiseThenLookupChain`
// protector. `Promise.prototype.finally` then trusted the stale protector and
// took an internal `InvokeThen` fast path that called the ORIGINAL native
// `then`, bypassing the wrapper above and its `resetPromiseSpecies`. Installing
// through `[[DefineOwnProperty]]` invalidates the protector, so `finally` (and
// any other native consumer of `then`) dispatches through the wrapper again.
localReflectDefineProperty(globalPromise.prototype, 'then', {
	__proto__: null,
	value: wrappedPromiseThen,
	writable: true,
	enumerable: false,
	configurable: true,
});
localReflectDefineProperty(globalPromise.prototype, 'catch', {
	__proto__: null,
	value: wrappedPromiseCatch,
	writable: true,
	enumerable: false,
	configurable: true,
});
if (wrappedPromiseFinally) {
	localReflectDefineProperty(globalPromise.prototype, 'finally', {
		__proto__: null,
		value: wrappedPromiseFinally,
		writable: true,
		enumerable: false,
		configurable: true,
	});
}

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
	// The omitted attributes matter — do NOT "clarify" these by spelling out
	// `writable: false, configurable: false`. They are the spec defaults, so the
	// two forms are equivalent on a current V8, but NOT on the Node 8 global
	// proxy: there the omitted form leaves the slot writable (which is what lets
	// the `Proxy` install further down take effect) while the explicit form
	// genuinely seals it. Making them explicit silently removed `Proxy` from
	// Node 8 sandboxes once already.
	// `Error` in particular backs the `prepareStackTrace` defence (issue #467).
	Error: { value: LocalError },
	Promise: { value: localPromise },
	Proxy: { value: undefined },
});

/*
 * WebAssembly.JSTag protection
 *
 * WebAssembly.JSTag (Node 22+) allows wasm exception handling to catch JavaScript
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
 *   - the sandbox-side `globalPromise.prototype.then|catch|finally` overrides
 *     (different prototype object, so the overrides are never reached),
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
 * export. Mirrors the existing `WebAssembly.JSTag` removal (Category 17 in
 * docs/attacks/error-sanitization.md, commit 1fbdeff) in spirit.
 *
 * JSPI was ORIGINALLY believed to be the only path producing a sandbox-visible
 * Promise with a cross-realm prototype. GHSA-wjwh-qqvp-g4p4 disproved that: the
 * streaming-compile APIs are a second source, removed in the same block below.
 *
 * Scope of this block. It removes SOURCES of cross-realm-prototype Promises; it
 * does NOT itself harden the species channel. The species channel on the SANDBOX
 * `Promise.prototype` is closed separately, above: `then` / `catch` / `finally`
 * are all overridden with wrappers that run `resetPromiseSpecies(this)`, and the
 * overrides are installed with `localReflectDefineProperty` so V8 cannot serve a
 * stale `PromiseThenLookupChain` protector and route around them
 * (GHSA-27g9-p43v-cw3v). That defense only helps a Promise whose `[[Prototype]]`
 * chain actually reaches the sandbox `Promise.prototype`. A Promise with a
 * HOST-realm prototype dispatches to the host `finally`, which no sandbox-side
 * override can intercept — so any future intrinsic that hands the sandbox such a
 * Promise re-opens the same flow and still needs its own removal here.
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
	// SECURITY (GHSA-wjwh-qqvp-g4p4, dup GHSA-m3pp-qgq7-gwm6): the streaming
	// compile APIs are a second source (besides JSPI) of a sandbox-visible
	// Promise whose [[Prototype]] chain reaches the HOST `Promise.prototype`.
	// The sandbox-side `globalPromise.prototype.then/catch/finally` overrides and
	// `resetPromiseSpecies` never run on such a promise, so installing an
	// attacker `constructor[Symbol.species]` and calling `p.finally()` routes
	// the raw host-realm rejection into an attacker capability
	// (`e.constructor.constructor("return globalThis")()` → host `process`).
	// `compileStreaming`/`instantiateStreaming` consume a `Response`/streaming
	// source the sandbox has no way to obtain, so removing them has no
	// legitimate-use cost; the non-streaming `WebAssembly.compile` /
	// `WebAssembly.instantiate` (whose Promises are sandbox-realm and pass
	// through the bridge/override path) remain available.
	if (typeof WebAssembly.compileStreaming !== 'undefined') {
		localReflectDeleteProperty(WebAssembly, 'compileStreaming');
	}
	if (typeof WebAssembly.instantiateStreaming !== 'undefined') {
		localReflectDeleteProperty(WebAssembly, 'instantiateStreaming');
	}
}

/*
 * FinalizationRegistry / WeakRef removal (GHSA-r4fx-v8hh-22mv)
 *
 * The `timeout` option only bounds the synchronous body of `run()` — it is
 * implemented with V8's TerminateExecution, which unblocks the running call and
 * nothing else. A `FinalizationRegistry` cleanup callback, by contrast, is
 * invoked by the garbage collector at an unpredictable later time, AFTER `run()`
 * has already returned, so it executes sandbox code entirely outside any timeout
 * accounting. Untrusted code can register a callback that busy-loops and block
 * the host event loop for an arbitrary duration with no relationship to the
 * configured timeout (`registry.register(obj, x)` then drop the reference).
 *
 * This is the last out-of-band execution scheduler reachable in the default
 * configuration. The others are already handled: timers
 * (setTimeout/setInterval/setImmediate) and queueMicrotask are not exposed to
 * the VM sandbox at all, and Promise continuations — the same class of
 * after-run() execution — are closed by `allowAsync: false`. Crucially,
 * `allowAsync: false` does NOT close the FinalizationRegistry vector (the GC
 * still fires the callback), so it must be withheld outright.
 *
 * `WeakRef` cannot itself schedule a callback (`deref` is synchronous) and is
 * harmless on its own, but it is removed alongside `FinalizationRegistry`: the
 * two are a pair, untrusted code rarely needs either, and a WeakRef without a
 * registry serves little purpose. Neither constructor has literal syntax, so
 * once its global binding is deleted it cannot be reconstructed from within the
 * sandbox. NodeVM inherits this removal (it extends VM and shares this
 * bootstrap). Embedders who genuinely need these for trusted code can expose
 * them explicitly via the `sandbox` option.
 */
if (typeof global.FinalizationRegistry !== 'undefined') {
	localReflectDeleteProperty(global, 'FinalizationRegistry');
}
if (typeof global.WeakRef !== 'undefined') {
	localReflectDeleteProperty(global, 'WeakRef');
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
		// SECURITY (GHSA-fcqc-726x-5wfc): deprecated Buffer(array|string|arrayBuffer)
		// form aliases Buffer.from. Route through `bufferFrom` so the result is
		// depooled (exact-size backing store) — a raw `LocalBuffer.from` here would
		// return a pool-backed buffer whose `.buffer` exposes the shared 64 KiB pool.
		return apply(bufferFrom, LocalBuffer, args);
	}

	construct(target, args, newTarget) {
		if (args.length > 0 && typeof args[0] === 'number') {
			// SECURITY (GHSA-6785-pvv7-mvg7): deprecated new Buffer(N) form. Cap before delegating.
			checkBufferAllocLimit(args[0]);
			return LocalBuffer.alloc(args[0]);
		}
		// SECURITY (GHSA-fcqc-726x-5wfc): deprecated new Buffer(array|string|arrayBuffer)
		// form aliases Buffer.from — route through `bufferFrom` for the depool guarantee.
		return apply(bufferFrom, LocalBuffer, args);
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

// SECURITY (GHSA-fcqc-726x-5wfc): isolate sandbox Buffer allocations from Node's
// shared small-buffer pool.
//
// ## Vulnerability
// Node serves small `Buffer.from(...)` / `Buffer.allocUnsafe(...)` allocations out
// of ONE shared backing ArrayBuffer of `Buffer.poolSize` bytes (64 KiB on modern
// Node). A pooled buffer's `.buffer` getter (Uint8Array.prototype.buffer) therefore
// exposes that WHOLE shared pool, including bytes owned by *other* host-realm buffers
// that happened to land in the same pool (`Buffer.from(secret)`, DB rows, tokens).
// From inside the sandbox:
//   const ab = Buffer.from([0]).buffer;              // the whole 64 KiB pool AB
//   Buffer.from(ab, 0, ab.byteLength);               // read/write every pooled byte
// This discloses AND corrupts host-realm memory — a full sandbox escape of
// confidentiality and integrity.
//
// ## Invariant
// A buffer handed to sandbox code must OWN its entire backing store: byteOffset 0 and
// `buffer.byteLength === length`. Then `.buffer` can never reveal a byte the buffer
// does not itself contain. Pool-backed results (byteOffset !== 0 OR
// buffer.byteLength !== length) are copied into a standalone exact-size buffer via the
// already-non-pooled `LocalBuffer.alloc(n)` before crossing into the sandbox.

// Spoof-proof ArrayBuffer / SharedArrayBuffer brand test. The `byteLength` getter
// performs an internal-slot ([[ArrayBufferData]]) brand check that sandbox code cannot
// fake (a plain object, a TypedArray, or a Proxy all make it throw). Captured here at
// init, before the GHSA-v836 allocation caps replace the global constructors — the
// prototypes (and thus these getters) are untouched by that later step.
const localArrayBufferByteLengthGetterDesc = localReflectGetOwnPropertyDescriptor(global.ArrayBuffer.prototype, 'byteLength');
const localArrayBufferByteLengthGetter = localArrayBufferByteLengthGetterDesc && localArrayBufferByteLengthGetterDesc.get;
let localSharedArrayBufferByteLengthGetter = null;
if (typeof global.SharedArrayBuffer === 'function') {
	const sabDesc = localReflectGetOwnPropertyDescriptor(global.SharedArrayBuffer.prototype, 'byteLength');
	if (sabDesc) localSharedArrayBufferByteLengthGetter = sabDesc.get;
}

// SECURITY (GHSA-fcqc-726x-5wfc): raw copy primitive captured off the bridge-proxied
// prototype. Used to move bytes out of a pooled buffer into a standalone one without
// going through any sandbox-overridable method.
const localBufferProtoCopy = LocalBuffer.prototype.copy;

// SECURITY (GHSA-fcqc-726x-5wfc): true only for a genuine ArrayBuffer/SharedArrayBuffer,
// which identifies the `Buffer.from(arrayBuffer, byteOffset, length)` overload that
// legitimately SHARES the caller's buffer (must not be copied). Once small allocations
// no longer pool, the only ArrayBuffer a sandbox can pass here is one it already owns,
// and that buffer's backing store is exact-size, so sharing exposes nothing extra.
function isArrayBufferOrShared(value) {
	if (value === null || typeof value !== 'object') return false;
	if (localArrayBufferByteLengthGetter) {
		try {
			apply(localArrayBufferByteLengthGetter, value, []);
			return true;
		} catch (e) {
			// not a plain ArrayBuffer
		}
	}
	if (localSharedArrayBufferByteLengthGetter !== null) {
		try {
			apply(localSharedArrayBufferByteLengthGetter, value, []);
			return true;
		} catch (e) {
			// not a SharedArrayBuffer
		}
	}
	return false;
}

// SECURITY (GHSA-fcqc-726x-5wfc): true only when `buf` owns its entire backing store.
function bufferOwnsExactBackingStore(buf) {
	let len, off, abLen;
	try {
		len = buf.length;
		off = buf.byteOffset;
		abLen = buf.buffer.byteLength;
	} catch (e) {
		return false;
	}
	return typeof len === 'number' && off === 0 && abLen === len;
}

// SECURITY (GHSA-fcqc-726x-5wfc): return `buf` if it already owns its backing store,
// otherwise a standalone exact-size copy. `LocalBuffer.alloc(n)` is non-pooled
// (byteOffset 0, buffer.byteLength === n) and zero-filled, so even a short copy can
// never leave host-pool bytes exposed.
function depoolBuffer(buf) {
	if (buf === null || typeof buf !== 'object') return buf;
	if (bufferOwnsExactBackingStore(buf)) return buf;
	const len = buf.length;
	const copy = LocalBuffer.alloc(len);
	if (typeof len === 'number' && len > 0) {
		apply(localBufferProtoCopy, buf, [copy, 0, 0, len]);
	}
	return copy;
}

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

// SECURITY (GHSA-gmc2-2x9w-cgh9): bufferAllocLimit bypass via Buffer.concat
// and Buffer.from(arrayLike).
//
// ## Invariant
// Every host-Buffer factory reachable from sandbox code by a sandbox-controlled
// size must consult `checkBufferAllocLimit` before the host C++ allocator runs.
// The 3.11.0 cap (GHSA-6785-pvv7-mvg7) enforced this only at four entry points
// (`alloc`, `allocUnsafe`, `allocUnsafeSlow`, deprecated `Buffer(N)`); the
// reporter found two more (`concat` total-length, `from` array-like length).
// There will be more in future Node versions.
//
// ## Chokepoint
// Two complementary layers:
//
//   Layer A — `connect()` a sandbox wrapper for *every* size-bearing host
//   factory. Sandbox `Buffer.X` is the bridge proxy of `host.Buffer.X`; with
//   the wrapper installed via `connect()`, any sandbox lookup of `Buffer.X`,
//   `buf.constructor.X` (LocalBuffer.prototype.constructor === LocalBuffer
//   and cannot be reassigned because the prototype is a ReadOnly bridge
//   proxy), or `host.Buffer.X` round-tripped through the bridge resolves to
//   the capped wrapper. This closes the *known* bypass set: alloc trio
//   (existing), deprecated `Buffer(N)` (BufferHandler), `concat`, `from`,
//   `copyBytesFrom` (Node 22+).
//
//   Layer B — fail-closed key enumeration. We classify every own key of
//   `host.Buffer` at sandbox-init time into one of three buckets:
//     SAFE — does not allocate by sandbox-controlled size (`isBuffer`,
//       `byteLength`, `compare`, `isEncoding`, `poolSize`, `name`,
//       `length`, `prototype`).
//     CAPPED — wrapped above via `connect()`.
//     UNKNOWN — anything else.
//   For any UNKNOWN function-valued key we `connect()` a throwing stub.
//   A future Node version that ships `host.Buffer.allocBig(N)` cannot
//   reach the host allocator from sandbox code: the new method is UNKNOWN,
//   gets the throwing stub, and a maintainer must classify it explicitly
//   before vm2 will let sandbox code call it. This is the structural
//   guarantee: the invariant survives "the maintainer forgot to add a
//   wrapper", because the default failure mode is now "throws" rather
//   than "uncapped host allocation".
//
// ## What is NOT covered (residual risks documented in NOTES.md)
//   - Allocation by a host *non-Buffer* API that returns a Buffer (e.g.,
//     `fs.readFileSync` returning a buffer of attacker-controlled file
//     size). Out of scope: `fs.*` is gated by NodeVM's module-loader
//     policy, not by this cap.
//   - Memory pressure from a *very large set* of small, individually-OK
//     allocations. The cap is per-call; combine with `timeout` and host
//     RSS limits for total memory bounds.

// SECURITY (GHSA-gmc2-2x9w-cgh9): Buffer.concat(list, totalLength).
// Node internally calls `Buffer.allocUnsafe(totalLength)` before iterating
// the list. The sandbox `Buffer.concat` is the bridge proxy of the host
// method, so the host allocator was reached without consulting our
// `allocUnsafe` wrapper. We must cap either the supplied totalLength (if
// numeric) or the summed list lengths (if omitted) before calling host.
const localBufferConcatOriginal = LocalBuffer.concat;
function concat(list, totalLength) {
	// Match host argument-validation order: if `list` is not array-like,
	// fall through to host to throw its native TypeError. We only enforce
	// the cap on the size argument or the summed lengths.
	if (arguments.length >= 2 && typeof totalLength === 'number') {
		// SECURITY (GHSA-gmc2-2x9w-cgh9): explicit totalLength path —
		// host allocates exactly `totalLength` bytes regardless of the
		// list contents. Cap before delegating.
		checkBufferAllocLimit(totalLength);
	} else if (list != null && typeof list === 'object' && typeof list.length === 'number') {
		// SECURITY (GHSA-gmc2-2x9w-cgh9): implicit totalLength path —
		// host sums `list[i].length` and allocates the sum. Replicate
		// that sum here so we cap the same value host would have used.
		// We deliberately read `list[i]` and `list[i].length` directly
		// without coercion: any throw (hostile getter) propagates to the
		// caller as it would from host's own iteration, and any non-
		// numeric length skips the cap (host will reject with TypeError).
		let sum = 0;
		const n = list.length;
		for (let i = 0; i < n; i++) {
			const item = list[i];
			if (item == null) continue;
			const len = item.length;
			if (typeof len === 'number' && len > 0) sum += len;
		}
		checkBufferAllocLimit(sum);
	}
	// Delegate to host concat. `apply` is raw Reflect.apply.
	// SECURITY (GHSA-fcqc-726x-5wfc): Buffer.concat allocates its result out of the
	// shared pool for small totals; depool so its `.buffer` is exact-size and cannot
	// expose neighbouring host-realm pool bytes.
	return depoolBuffer(apply(localBufferConcatOriginal, LocalBuffer, arguments));
}

connect(concat, host.Buffer.concat);

// SECURITY (GHSA-gmc2-2x9w-cgh9): Buffer.from(arg, ...).
// `Buffer.from({length: N})` triggers host's `fromArrayLike`, which calls
// `Buffer.allocUnsafe(N)` *before* iterating indices 0..N — so a fake
// array-like with a numeric `.length` materializes N host bytes from a
// tiny sandbox payload. Cap before delegating.
//
// We must NOT cap legitimate forms:
//   - `Buffer.from(string [, encoding])` — first arg is a string. Result
//     bytelength is bounded by the string (which is itself sandbox memory).
//   - `Buffer.from(buffer)` / `Buffer.from(Uint8Array)` / typedarray —
//     result is a copy of an existing object; bounded by source.
//   - `Buffer.from(arrayBuffer, byteOffset, length)` — `length` is sandbox
//     controlled, but the ArrayBuffer itself bounds it and host throws
//     on out-of-bounds. Still, we cap `length` if provided as a number,
//     since an ArrayBuffer of size M permits `length <= M` and M can be
//     large.
//   - `Buffer.from(arrayLike)` with real array contents — but a real array
//     of length N has *already* been allocated in sandbox memory, so the
//     cap should still apply: the attacker pays sandbox cost to amplify
//     to host cost, but the amplification is exactly 1x; nevertheless
//     consistent capping closes the "small sandbox heap, large host
//     allocation per call" amplification when the caller can recycle the
//     sandbox-side array.
//
// Decision rule: read `.length` from the first argument only when it is a
// non-null, non-string, object-typed value. Treat the result as the
// requested allocation size if it is a finite non-negative number.
const localBufferFromOriginal = LocalBuffer.from;
function bufferFrom(value, encodingOrOffset, length) {
	// SECURITY (GHSA-gmc2-2x9w-cgh9): explicit `length` cap for the
	// ArrayBuffer overload — host will allocate up to `length` bytes (or
	// up to the ArrayBuffer's remaining bytes, whichever is smaller).
	// Capping the requested length covers the worst case.
	if (typeof length === 'number') {
		checkBufferAllocLimit(length);
	}
	// SECURITY (GHSA-gmc2-2x9w-cgh9): array-like / iterable form. Strings
	// and primitives are exempt because their byte length is bounded by
	// the sandbox-side value itself. For everything else, the host's
	// allocation size is `value.length` (fromArrayLike) — cap it.
	if (
		value != null &&
		typeof value === 'object' &&
		typeof value.length === 'number'
	) {
		// `.length` may be a getter; reading it here mirrors what host's
		// `fromArrayLike` does internally and surfaces any thrown error
		// to the caller exactly as host would. We pass the read value
		// straight to `checkBufferAllocLimit`, which short-circuits on
		// non-positive numbers.
		checkBufferAllocLimit(value.length);
	}
	const result = apply(localBufferFromOriginal, LocalBuffer, arguments);
	// SECURITY (GHSA-fcqc-726x-5wfc): the (arrayBuffer|sharedArrayBuffer, byteOffset,
	// length) overload legitimately SHARES the caller-supplied buffer — preserve that
	// documented contract (mutations reflect both ways). Every other overload
	// (string / array / typedarray / buffer / array-like) returns a possibly
	// POOL-BACKED buffer whose `.buffer` would expose Node's shared allocation pool;
	// depool it so `.buffer.byteLength === length` and byteOffset === 0.
	if (isArrayBufferOrShared(value)) return result;
	return depoolBuffer(result);
}

connect(bufferFrom, host.Buffer.from);

// SECURITY (GHSA-gmc2-2x9w-cgh9): structural fail-closed enumeration of
// host.Buffer's own keys. Every function-valued key that is NOT on the
// classified allowlist below gets a sandbox-side throwing stub installed
// via connect(). A future host method that allocates by sandbox-controlled
// size therefore cannot reach the host allocator from sandbox code unless
// a maintainer explicitly classifies it as either SAFE (leave alone) or
// CAPPED (add a wrapper above).
//
// Classification rules:
//   SAFE      — does not allocate by sandbox-controlled size, or allocation
//               is bounded by an already-allocated sandbox-side input.
//   CAPPED    — wrapped via connect() above; reaches host through a
//               checkBufferAllocLimit chokepoint.
//   METADATA  — non-function properties (length, name, prototype, poolSize).

// Allowlist. Keep alphabetical for review.
//   SAFE: shape-only / inspector / metadata that does not allocate by
//   sandbox-controlled byte size.
//   CAPPED: connected above via a sandbox-side wrapper.
//   Any future addition not on this list will hit the throwing stub.
const BUFFER_STATIC_CLASSIFIED = {
	__proto__: null,
	// CAPPED
	alloc: true,
	allocUnsafe: true,
	allocUnsafeSlow: true,
	concat: true,
	from: true,
	// SAFE — non-allocating inspectors and helpers.
	byteLength: true,
	compare: true,
	isBuffer: true,
	isEncoding: true,
	of: true, // Buffer.of(...args) — bounded by arg count (V8 call-stack limit).
	// METADATA (handled separately, but classified here for completeness).
	length: true,
	name: true,
	poolSize: true,
	prototype: true,
};

// SECURITY (GHSA-gmc2-2x9w-cgh9): explicitly classify `copyBytesFrom`
// (Node 22+) as CAPPED. It takes (view, offset, length) and allocates
// `length` bytes (or view.length - offset if length omitted). Sandbox
// controls `length`. Without a wrapper this is a direct bypass parallel
// to Buffer.concat/totalLength.
if (typeof host.Buffer.copyBytesFrom === 'function') {
	const localBufferCopyBytesFromOriginal = host.Buffer.copyBytesFrom;
	function copyBytesFrom(view, offset, length) {
		// length may be undefined — host then defaults to view byteLength
		// minus offset. Cap that derived value too.
		if (typeof length === 'number') {
			checkBufferAllocLimit(length);
		} else if (view != null && typeof view === 'object' && typeof view.byteLength === 'number') {
			const off = typeof offset === 'number' && offset > 0 ? offset : 0;
			const derived = view.byteLength - off;
			if (derived > 0) checkBufferAllocLimit(derived);
		}
		// SECURITY (GHSA-fcqc-726x-5wfc): copyBytesFrom copies into a fresh,
		// pool-backed buffer for small views; depool so its `.buffer` is exact-size.
		return depoolBuffer(apply(localBufferCopyBytesFromOriginal, LocalBuffer, arguments));
	}
	connect(copyBytesFrom, host.Buffer.copyBytesFrom);
	BUFFER_STATIC_CLASSIFIED.copyBytesFrom = true;
}

// SECURITY (GHSA-fcqc-726x-5wfc): Buffer.of(...items) delegates to Buffer.from and can
// return a pool-backed buffer on some Node versions. Depool so its `.buffer` is
// exact-size. No alloc cap needed — the result size is bounded by the argument count
// (V8 call-stack limit), so `of` stays SAFE for bufferAllocLimit purposes. `of` is
// already classified SAFE below, so the fail-closed gate leaves this wrapper in place.
if (typeof host.Buffer.of === 'function') {
	const localBufferOfOriginal = LocalBuffer.of;
	function bufferOf() {
		return depoolBuffer(apply(localBufferOfOriginal, LocalBuffer, arguments));
	}
	connect(bufferOf, host.Buffer.of);
}

// SECURITY (GHSA-gmc2-2x9w-cgh9): fail-closed gate. Iterate the host
// Buffer's own keys (read via host bridge) and install a throwing stub
// for any function-valued key not in the classified allowlist. We read
// via `host.Buffer` directly (host bridge proxy) to enumerate from the
// host realm rather than from the sandbox view (which may have been
// affected by the connect() calls above).
{
	// Read keys via a host-realm enumeration. `host.Buffer` is the bridge
	// proxy of host's Buffer constructor; iterating its own property names
	// gives us the sandbox's view of host's static surface.
	const bufferOwnKeys = localObject.getOwnPropertyNames(host.Buffer);
	for (let i = 0; i < bufferOwnKeys.length; i++) {
		const key = bufferOwnKeys[i];
		if (BUFFER_STATIC_CLASSIFIED[key]) continue;
		// Unknown key. Inspect its value through host.Buffer; if it's a
		// function, install a throwing stub. We do NOT throw at init time
		// because that would break vm2 on any Node version that adds a
		// new property — instead we let property *access* succeed and
		// fail at the *call* site, with a clear error message naming
		// the advisory.
		let value;
		try {
			value = host.Buffer[key];
		} catch (e) {
			// Hostile getter (very unlikely on host.Buffer) — skip.
			continue;
		}
		if (typeof value === 'function') {
			// Install a unique stub per key so the error message can name
			// the method, aiding the maintainer triaging a future Node
			// upgrade.
			(function (name) {
				function bufferStaticUnknownNamed() {
					throw new VMError(
						"Buffer." +
							name +
							" has not been classified for bufferAllocLimit safety in this vm2 version (GHSA-gmc2-2x9w-cgh9). " +
							'See lib/setup-sandbox.js to classify it as SAFE or CAPPED.',
					);
				}
				localObjectFreeze(bufferStaticUnknownNamed);
				connect(bufferStaticUnknownNamed, value);
			})(key);
		}
	}
}

// SECURITY (GHSA-v836-6xw4-9cx3): close the bufferAllocLimit bypass class.
//
// The GHSA-6785 cap above only wraps the `Buffer.*` family, but `ArrayBuffer`,
// `SharedArrayBuffer`, and every TypedArray constructor allocate host
// backing-store memory through the SAME synchronous, timeout-immune V8 C++ path
// (`ArrayBuffer::NewBackingStore` -> `ArrayBufferAllocator::Allocate` ->
// `calloc`). `WebAssembly.Memory` is the same primitive in 64 KiB pages. None of
// these are intercepted by `checkBufferAllocLimit`, so a single ~200-byte
// sandbox payload (`new ArrayBuffer(1<<30)`) amplifies into gigabytes of host
// RSS in one uninterruptible allocation — identical to the Buffer.alloc DoS.
//
// Fix: when a finite cap is configured, replace each sandbox-realm allocation
// constructor with a `construct`-trapping Proxy that runs `checkBufferAllocLimit`
// on the requested byte count BEFORE the native allocation, and pin every
// `prototype.constructor` back-reference to the wrapper so the original uncapped
// intrinsic cannot be recovered via a constructor walk such as
// `new Uint8Array(0).buffer.constructor`. The Proxy forwards `prototype`,
// `[Symbol.species]`, and `[[Prototype]]` to the original, so `instanceof`,
// species-derived construction (slice/map/subarray), and subclassing keep working.
//
// Gated on a finite limit: with the default `bufferAllocLimit: Infinity` the
// native intrinsics are left completely untouched — zero behavioural or identity
// change for embedders who have not opted into the cap (matches GHSA-6785's
// non-breaking, opt-in semantics).
if (localBufferAllocLimit !== Infinity) {
	installAllocationCaps();
}

function installAllocationCaps() {
	// SECURITY (GHSA-v836-6xw4-9cx3): the native constructors size their
	// allocation with ToIndex(arg), i.e. ToNumber first — so a length supplied
	// as a string ("209715200"), an object with `valueOf` / `Symbol.toPrimitive`,
	// etc. is coerced to a large number by V8. A `typeof === 'number'` guard
	// would wave all of those through. `coerceAllocMagnitude` mirrors the
	// ToNumber step so the cap measures the SAME magnitude V8 will allocate.
	// Values that cannot yield a large positive allocation collapse to 0 (the
	// native constructor still applies its own validation/throws); Symbols and
	// BigInts throw under unary `+` and are caught — for those the native call
	// throws before allocating, so 0 is safe.
	function coerceAllocMagnitude(value) {
		let n;
		try {
			n = +value;
		} catch (e) {
			return 0;
		}
		// NaN (n !== n) or negative => no large allocation to cap here.
		if (n !== n || n < 0) return 0;
		return n;
	}

	function isObjectLike(value) {
		return value !== null && (typeof value === 'object' || typeof value === 'function');
	}

	// SECURITY (GHSA-v836-6xw4-9cx3): the magnitude must be read EXACTLY ONCE.
	// `checkBufferAllocLimit(computeBytes(args))` followed by
	// `Reflect.construct(target, args)` reads any `valueOf` / accessor twice —
	// a getter returning small-then-large slips the real (large) value past the
	// cap (TOCTOU). The construct traps below therefore canonicalize every
	// object-valued size input to the primitive number the cap checked, and hand
	// the native constructor THAT primitive, so check-time and alloc-time observe
	// identical values. Pure-primitive inputs are immutable (no TOCTOU) and pass
	// through untouched, preserving exact native semantics (e.g. BigInt throws).

	// Install `value` as the sandbox global `name`, matching the native global
	// property attributes { writable, !enumerable, configurable }.
	function defineGlobalCtor(name, value) {
		localReflectDefineProperty(global, name, {
			__proto__: null,
			value: value,
			writable: true,
			enumerable: false,
			configurable: true,
		});
	}

	// SECURITY (GHSA-v836-6xw4-9cx3): pin the prototype back-reference to the
	// capped proxy so the original uncapped intrinsic cannot be recovered via a
	// constructor walk (`new Uint8Array(0).buffer.constructor`). Native
	// attributes are { writable, !enumerable, configurable }.
	function pinConstructor(prototype, capProxy) {
		localReflectDefineProperty(prototype, 'constructor', {
			__proto__: null,
			value: capProxy,
			writable: true,
			enumerable: false,
			configurable: true,
		});
	}

	// ArrayBuffer / SharedArrayBuffer. The allocated bytes are the larger of the
	// committed `length` (arg0) and the reserved `maxByteLength` (resizable /
	// growable forms reserve max up front). Both are canonicalized to primitives
	// so a `maxByteLength` accessor cannot read small here and large inside V8 —
	// which would otherwise leave the buffer resizable past the cap and let a
	// later `.resize()` / `.grow()` commit the full (uncapped) maximum.
	function capArrayBuffer(OriginalCtor) {
		const capProxy = new LocalProxy(OriginalCtor, {
			__proto__: null,
			construct(target, args, newTarget) {
				const rawLen = args.length > 0 ? args[0] : 0;
				const lenMag = coerceAllocMagnitude(rawLen);
				let capBytes = lenMag;
				let maxPresent = false;
				let maxMag = 0;
				const options = args.length > 1 ? args[1] : undefined;
				if (options !== null && typeof options === 'object') {
					const rawMax = options.maxByteLength; // read accessor exactly once
					if (rawMax !== undefined) {
						maxPresent = true;
						maxMag = coerceAllocMagnitude(rawMax);
						if (maxMag > capBytes) capBytes = maxMag;
					}
				}
				checkBufferAllocLimit(capBytes);
				// Rebuild args from the canonical magnitudes when an object-valued
				// length or any maxByteLength option was involved (the TOCTOU-capable
				// shapes); pure-primitive non-resizable calls pass through untouched.
				if (isObjectLike(rawLen) || maxPresent) {
					const finalLen = isObjectLike(rawLen) ? lenMag : rawLen;
					args = maxPresent
						? [finalLen, { __proto__: null, maxByteLength: maxMag }]
						: [finalLen];
				}
				return localReflectConstruct(target, args, newTarget === capProxy ? OriginalCtor : newTarget);
			},
		});
		pinConstructor(OriginalCtor.prototype, capProxy);
		return capProxy;
	}

	// TypedArray. Two allocating shapes carry an attacker-controlled size:
	//   (1) `new TA(N)` — primitive length, ToIndex(N) * BYTES_PER_ELEMENT bytes.
	//   (2) `new TA(arrayLike)` — object with a `length` property; V8 reads
	//       LengthOfArrayLike and allocates that many elements in one shot
	//       (`new Uint8Array({length: 1<<30})`).
	// The (buffer[, offset[, len]]) view form views an existing buffer and the
	// iterable form is bounded by interruptible JS iteration — neither is a
	// single-shot amplifier. We do NOT classify the object (a spoofed
	// `Symbol.toStringTag` could lie): instead we simply cap `arg0.length`. A real
	// ArrayBuffer/SharedArrayBuffer has no `length` own/inherited property
	// (coerces to 0 → no false positive); an array-like exposes its element count;
	// an existing TypedArray source reports a length already ≤ the cap. The
	// primitive path (1) is immutable (no TOCTOU). A hostile `length` *accessor*
	// on an array-like remains a documented residual; the common data-property
	// amplifier is fully capped.
	function capTypedArray(OriginalCtor, bytesPerElement) {
		const capProxy = new LocalProxy(OriginalCtor, {
			__proto__: null,
			construct(target, args, newTarget) {
				const rawLen = args.length > 0 ? args[0] : 0;
				const sizeSource = isObjectLike(rawLen) ? rawLen.length : rawLen;
				checkBufferAllocLimit(coerceAllocMagnitude(sizeSource) * bytesPerElement);
				return localReflectConstruct(target, args, newTarget === capProxy ? OriginalCtor : newTarget);
			},
		});
		pinConstructor(OriginalCtor.prototype, capProxy);
		return capProxy;
	}

	defineGlobalCtor('ArrayBuffer', capArrayBuffer(global.ArrayBuffer));
	if (typeof global.SharedArrayBuffer === 'function') {
		defineGlobalCtor('SharedArrayBuffer', capArrayBuffer(global.SharedArrayBuffer));
	}

	const typedArrayNames = [
		'Int8Array', 'Uint8Array', 'Uint8ClampedArray',
		'Int16Array', 'Uint16Array', 'Float16Array',
		'Int32Array', 'Uint32Array', 'Float32Array',
		'Float64Array', 'BigInt64Array', 'BigUint64Array',
	];
	for (let i = 0; i < typedArrayNames.length; i++) {
		const name = typedArrayNames[i];
		const Ctor = global[name];
		// Feature-gated: Float16Array (Node 22+), BigInt64Array/BigUint64Array
		// (Node 10+) may be absent on older runtimes.
		if (typeof Ctor !== 'function') continue;
		defineGlobalCtor(name, capTypedArray(Ctor, Ctor.BYTES_PER_ELEMENT));
	}

	// SECURITY (GHSA-v836-6xw4-9cx3, defense-in-depth): WebAssembly.Memory commits
	// host pages (64 KiB each) through the same backing-store path; `initial` is
	// attacker-controlled and `grow()` extends the commitment incrementally. Cap
	// the initial reservation at construction and bound cumulative growth in
	// `grow()`. `maximum` only reserves virtual address space (not RSS), so it is
	// not capped here. WebAssembly.Memory exists regardless of the `wasm` option.
	if (typeof WebAssembly !== 'undefined' && typeof WebAssembly.Memory === 'function') {
		const WASM_PAGE_BYTES = 65536;
		const OriginalMemory = WebAssembly.Memory;
		const memoryProto = OriginalMemory.prototype;
		const originalGrow = memoryProto.grow;
		const memoryBufferDescriptor = localReflectGetOwnPropertyDescriptor(memoryProto, 'buffer');

		const memoryCapProxy = new LocalProxy(OriginalMemory, {
			__proto__: null,
			construct(target, args, newTarget) {
				const descriptor = args.length > 0 ? args[0] : undefined;
				let pages = 0;
				let initialPresent = false;
				if (descriptor !== null && typeof descriptor === 'object') {
					const rawInitial = descriptor.initial; // read accessor exactly once
					if (rawInitial !== undefined) {
						initialPresent = true;
						pages = coerceAllocMagnitude(rawInitial);
					}
				}
				// SECURITY (GHSA-v836-6xw4-9cx3): cap the initial committed bytes.
				// `initial` is coerced via ToNumber by V8 (string / valueOf / accessor),
				// so measure the coerced magnitude, then hand V8 a descriptor whose
				// `initial` is that exact primitive — a toggling `initial` accessor
				// cannot read small here and large inside V8 (TOCTOU). `maximum`
				// only reserves virtual address space (not RSS) and incremental
				// commitment via `grow()` is separately bounded below, so it is
				// preserved verbatim.
				checkBufferAllocLimit(pages * WASM_PAGE_BYTES);
				if (initialPresent) {
					const rebuilt = { __proto__: null, initial: pages };
					// COMPAT: forward `maximum` / `shared` only when the caller
					// actually supplied them. Node 8's V8 does not treat an explicit
					// `maximum: undefined` as an absent key -- it coerces it to 0 and
					// then rejects the descriptor for having `maximum` below
					// `initial`, which would break every capped Memory construction
					// on that runtime. Each is still read exactly once, so the
					// TOCTOU canonicalization above is preserved.
					const rawMaximum = descriptor.maximum;
					if (rawMaximum !== undefined) rebuilt.maximum = rawMaximum;
					const rawShared = descriptor.shared;
					if (rawShared !== undefined) rebuilt.shared = rawShared;
					args = [rebuilt];
				}
				return localReflectConstruct(target, args, newTarget === memoryCapProxy ? OriginalMemory : newTarget);
			},
		});

		if (typeof originalGrow === 'function' && memoryBufferDescriptor && typeof memoryBufferDescriptor.get === 'function') {
			const memoryBufferGetter = memoryBufferDescriptor.get;
			const cappedGrow = function grow(delta) {
				// SECURITY (GHSA-v836-6xw4-9cx3): bound the post-grow total. Read
				// current size off the live backing buffer; a non-Memory `this`
				// makes the getter throw, preserving native semantics. `delta` is
				// coerced once and the canonical primitive is forwarded to the native
				// grow so a `valueOf`/accessor cannot read small here and large in V8.
				const currentBuffer = apply(memoryBufferGetter, this, []);
				const currentBytes = currentBuffer ? currentBuffer.byteLength : 0;
				const addedPages = coerceAllocMagnitude(delta);
				checkBufferAllocLimit(currentBytes + addedPages * WASM_PAGE_BYTES);
				return apply(originalGrow, this, [addedPages]);
			};
			localReflectDefineProperty(memoryProto, 'grow', {
				__proto__: null,
				value: cappedGrow,
				writable: true,
				enumerable: false,
				configurable: true,
			});
		}

		localReflectDefineProperty(memoryProto, 'constructor', {
			__proto__: null,
			value: memoryCapProxy,
			writable: true,
			enumerable: false,
			configurable: true,
		});
		localReflectDefineProperty(WebAssembly, 'Memory', {
			__proto__: null,
			value: memoryCapProxy,
			writable: true,
			enumerable: false,
			configurable: true,
		});
	}
}

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
const LocalSuppressedError = typeof SuppressedError === 'function' ? SuppressedError : null;
const LocalAggregateError = typeof AggregateError === 'function' ? AggregateError : null;

// SECURITY (GHSA-m283-3h24-438v): the standard Error subclasses are captured
// HERE, at module load, before any sandbox code has run -- the same reason
// `localStringStartsWith` is captured above for GHSA-m5q2-4fm3-vfqp. The
// carrier rebuild in `sanitizeHostOwnProps` runs at exception-handling time,
// long after guest code has executed; reading the mutable sandbox globals
// (`RangeError`, `TypeError`, ...) at that point would let `RangeError = fn`
// from inside the sandbox place attacker code in the middle of the sanitizer
// and choose the value it returns.
const LocalTypeError = global.TypeError;
const LocalRangeError = global.RangeError;
const LocalReferenceError = global.ReferenceError;
const LocalSyntaxError = global.SyntaxError;
const LocalEvalError = global.EvalError;
const LocalURIError = global.URIError;

// SECURITY (GHSA-m283-3h24-438v): resolve a carrier's error subclass from its
// `name` STRING rather than `instanceof`. A host-wrapped carrier's prototype
// chain reaches the *host* `RangeError.prototype`, never the sandbox's, so
// `instanceof` against a sandbox constructor is false for every host error and
// the subclass would always collapse to plain Error. Matching on the name also
// avoids running attacker-reachable prototype walks (and any `Symbol.hasInstance`
// trap) inside the sanitizer. `name` is attacker-controllable, but the only
// thing it can influence is which of these six benign sandbox-realm
// constructors is used -- every one of them is captured above.
function localErrorCtorForName(name) {
	if (typeof name !== 'string') return LocalError;
	// Node <= 11 reports its internal errors with the legacy composite name
	// "RangeError [ERR_INVALID_OPT_VALUE]", so match the leading token rather
	// than the whole string -- an exact comparison silently degrades every such
	// error to plain Error on those runtimes. `localStringStartsWith` is the
	// module-load capture (see GHSA-m5q2-4fm3-vfqp), so a sandbox that
	// monkey-patches String.prototype.startsWith cannot influence this.
	if (apply(localStringStartsWith, name, ['TypeError'])) return LocalTypeError;
	if (apply(localStringStartsWith, name, ['RangeError'])) return LocalRangeError;
	if (apply(localStringStartsWith, name, ['ReferenceError'])) return LocalReferenceError;
	if (apply(localStringStartsWith, name, ['SyntaxError'])) return LocalSyntaxError;
	if (apply(localStringStartsWith, name, ['EvalError'])) return LocalEvalError;
	if (apply(localStringStartsWith, name, ['URIError'])) return LocalURIError;
	return LocalError;
}

// SECURITY (GHSA-m283-3h24-438v): see comment at the call site in
// handleException. Splits the host-wrapped vs sandbox-realm branches so the
// behavior is auditable independent of the caller. Returns the (possibly
// replaced) carrier — the host-wrapped branch may substitute a fresh
// sandbox-realm Error when `.cause` cannot be overwritten in place (frozen
// / non-configurable host property), because in that scenario the proxy
// `get` trap would otherwise re-deliver the host reference on every read.
function sanitizeErrorCause(e, visited) {
	let isWrappedHost = false;
	try {
		isWrappedHost = e.isProxy === true;
	} catch (_) {
		/* sandbox-side object with an `isProxy` accessor throwing —
		 * treat as sandbox-realm. */
	}
	if (isWrappedHost) {
		// SECURITY (GHSA-m283-3h24-438v second follow-up): strip `.cause` with
		// a SEALED descriptor (`writable: false, configurable: false`). The
		// previous configurable strip could be bypassed two ways:
		//   1. Lying Proxy host-carrier: `throw new Proxy(realErr, {
		//      defineProperty: () => true })` returned `true` without modifying
		//      the target; the strip's success boolean was a lie, and
		//      subsequent `.cause` reads went through the proxy's `get` trap
		//      back to the underlying `process`.
		//   2. TOCTOU on the recheck: any value-based fallback can be defeated
		//      by an accessor that returns benign-now / process-later.
		// Non-configurable + non-writable forces two ECMA-262 Proxy invariants:
		//   * §10.5.6 ProxyDefineOwnProperty: if Desc.[[Configurable]] is
		//     false and the target's current descriptor is configurable, the
		//     engine throws regardless of the trap's return value. So a lying
		//     `defineProperty` trap that doesn't actually modify the target
		//     cannot succeed — the engine catches the invariant violation.
		//   * §10.5.8 ProxyGet: once the property is non-configurable and
		//     non-writable, the trap MUST return SameValue(target.value). A
		//     get trap that lies about the value triggers TypeError. So
		//     subsequent sandbox reads of `.cause` either return undefined or
		//     throw — both safe.
		// We accept the cost that primitive `.cause` values on host errors are
		// reset to `undefined` and the property is sealed — primitives carry
		// no pivot, and mutating a thrown error's `.cause` post-strip has no
		// legitimate use case.
		let stripped = false;
		try {
			stripped =
				localReflectDefineProperty(e, 'cause', {
					__proto__: null,
					value: undefined,
					writable: false,
					enumerable: false,
					configurable: false,
				}) === true;
		} catch (_) {
			/* engine threw on invariant violation (proxy trap lied, or target
			 * has non-configurable accessor we can't redefine compatibly).
			 * Fall through to substitution. */
		}
		if (!stripped) {
			// Strip did not seal the property. The carrier itself is unsafe;
			// substitute a sandbox-realm Error preserving only `.message`.
			let safeMsg = '';
			try {
				const m = e.message;
				if (typeof m === 'string') safeMsg = m;
			} catch (_) {}
			return new LocalError(safeMsg);
		}
	} else {
		// Sandbox-realm carrier. Read `.cause` once, recurse if non-primitive
		// so nested host-wrapped sub-errors get their own `.cause` stripped,
		// then re-install the sanitized value as a data property. Re-installing
		// as a data property also defeats sandbox-side accessor `.cause`
		// definitions that could return different values on subsequent reads.
		let causeVal;
		try {
			causeVal = e.cause;
		} catch (_) {
			return e;
		}
		let sanitized = causeVal;
		if (causeVal !== undefined && causeVal !== null) {
			const t = typeof causeVal;
			if (t === 'object' || t === 'function') {
				sanitized = handleException(causeVal, visited);
			}
		}
		// Always re-install as a data property — eliminates any sandbox-side
		// accessor on `.cause`, locking the value to what we just sanitized.
		try {
			localReflectDefineProperty(e, 'cause', {
				__proto__: null,
				value: sanitized,
				writable: true,
				enumerable: false,
				configurable: true,
			});
		} catch (_) {
			/* best effort — sandbox-realm frozen carriers cannot be rewritten,
			 * but a sandbox-realm carrier with a host-wrapped `.cause` requires
			 * sandbox code to already hold the host reference, so no new
			 * escape primitive is introduced. */
			try {
				e.cause = sanitized;
			} catch (_) {}
		}
	}
	return e;
}

// SECURITY (GHSA-cfcw-xp6x-25gj): captured at module load, before any sandbox
// code runs, so the foreign-realm detector below cannot be subverted by later
// mutation of `Object.prototype` from inside the sandbox.
const localObjectPrototype = localObject.prototype;
// SECURITY (GHSA-cfcw-xp6x-25gj): hard cap on the proto-chain walk. A genuine
// sandbox object reaches `Object.prototype` in a handful of hops; the cap only
// bounds pathological / adversarial chains.
const FOREIGN_PROTO_WALK_LIMIT = 100;

// SECURITY (GHSA-cfcw-xp6x-25gj): mechanism-independent payoff defense for the
// host-prototype-severance escape family (GHSA-v6mx-mf47-r5wg and its
// composition follow-up GHSA-cfcw-xp6x-25gj). Second, independent layer to the
// `thisEnsureThis` proto-walk guard in lib/bridge.js.
//
// Those attacks sever a host error's prototype chain (`host.NodeError.prototype
// .__proto__ = null`) so the bridge's proto-mapping lookups miss and a RAW host
// error could surface in a sandbox `catch`. The sandbox then pivots
// `e.constructor.constructor` to host `Function` → RCE. The cfcw follow-up
// launders that severance entirely host-side (`apply.bind(call,call)` composed
// over a genuine host array's `.map`), so a defense that only inspects values
// *crossing* the bridge apply trap can be composed past.
//
// This layer sits at `handleException`, the sole sanitizer the transformer
// routes every caught value through (`catch(e){e=handleException(e);}`), plus
// the promise rejection wrappers. It is mechanism-independent — it does not
// care HOW the chain was severed; it only asks whether the caught value is a
// host-realm object that reached here unwrapped. Invariant: every legitimate
// sandbox-realm object's prototype chain terminates at the sandbox
// `Object.prototype` (or is a deliberately primordial `Object.create(null)`
// value with NO prototype at all). A host-realm object whose chain was severed
// has a non-null immediate prototype (the still-intact host intrinsic
// prototype) yet its chain reaches `null` WITHOUT ever passing through the
// sandbox `Object.prototype`. That exact signature is what we refuse here.
function isForeignSeveredHostValue(e) {
	// Note: e@unknown. Returns true only for the attacker-corrupted host
	// signature; never for sandbox-native values.
	let proto;
	try {
		proto = localReflectGetPrototypeOf(e);
	} catch (ex) {
		// A throwing [[GetPrototypeOf]] is itself foreign/hostile; treat as
		// suspect rather than trusting the value.
		return true;
	}
	// Primordial null-proto sandbox object (`Object.create(null)`): legitimate,
	// not host-realm. The early `!proto` shape is explicitly exercised by the
	// GHSA-v6mx regression suite and MUST pass through untouched.
	if (proto === null) return false;
	for (let i = 0; i < FOREIGN_PROTO_WALK_LIMIT; i++) {
		// Reached the sandbox Object.prototype anywhere on the chain → this is a
		// sandbox-realm value (every sandbox intrinsic's chain terminates here).
		if (proto === localObjectPrototype) return false;
		let next;
		try {
			next = localReflectGetPrototypeOf(proto);
		} catch (ex) {
			return true;
		}
		// Chain ended at null without ever hitting the sandbox Object.prototype:
		// foreign (host-realm) object whose chain was severed — the v6mx / cfcw
		// escape signature.
		if (next === null) return true;
		proto = next;
	}
	// Pathologically long chain that never reached Object.prototype: refuse.
	return true;
}

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
	// SECURITY (GHSA-cfcw-xp6x-25gj): second, mechanism-independent layer for
	// the host-prototype-severance escape family. If a RAW host-realm object
	// (whose severed prototype chain defeated the bridge's proto-mapping and so
	// reached here unwrapped) surfaces in a sandbox catch, refuse to hand it to
	// user code: replace it with a benign sandbox-realm Error. This neutralizes
	// the universal payoff step `e.constructor.constructor === host.Function`
	// regardless of how the severance was performed (direct bridge call OR fully
	// host-side laundering via `apply.bind`/`map`). Sandbox-realm values —
	// including `Object.create(null)` throws and every normal Error subclass —
	// are unaffected (see isForeignSeveredHostValue). Complements the
	// thisEnsureThis proto-walk guard in lib/bridge.js; either layer alone
	// blocks the escape, but they sit at independent chokepoints.
	if (isForeignSeveredHostValue(e)) {
		return new LocalError('Foreign exception blocked by vm2 sandbox');
	}
	// SECURITY (GHSA-m283-3h24-438v): there is deliberately no
	// `if (localSuppressedErrorProto === null && localAggregateErrorProto === null) return e;`
	// short-circuit here. That early return predated .cause / own-property
	// sanitization and would skip both on any runtime without SuppressedError
	// and AggregateError (Node < 15), leaving the host-reference leak open
	// precisely on the oldest supported versions.
	if (!visited) visited = new LocalWeakMap();
	// SECURITY (GHSA-x965-fc75-jpqh): the value memoized for a carrier is
	// EXACTLY what a revisit must return — the carrier itself when it is sealed
	// in place (plain Error, sandbox-realm), or its sandbox-realm REPLACEMENT
	// when a rebuild-style sanitizer (host-wrapped AggregateError /
	// SuppressedError) swaps it for a fresh object. All stored values are truthy
	// objects, so a `get` returning undefined means "absent" and any truthy
	// value means "present — return this". The prior code stored `true` and the
	// revisit short-circuit did `return e` (the RAW host carrier); for a
	// rebuild sanitizer the raw carrier and its sanitized replacement are
	// DIFFERENT objects, so a revisited host aggregate handed its live host
	// proxy straight back into errors[] — the m283 bypass this advisory closes.
	const memoized = apply(localWeakMapGet, visited, [e]);
	if (memoized) return memoized;
	// Default memo: seal-in-place carriers resolve a revisit to themselves.
	// Rebuild sanitizers OVERWRITE this with their replacement BEFORE recursing
	// into sub-errors (see sanitizeAggregateError / sanitizeSuppressedError).
	apply(localWeakMapSet, visited, [e, e]);
	// SECURITY (GHSA-m283-3h24-438v): Error.cause is a free-form ES2022
	// property that can carry an arbitrary host reference. When an embedder-
	// exposed host function throws `new Error('msg', { cause: process })`,
	// the host Error reaches the sandbox catch as a bridge proxy. The
	// proxy's `get` trap automatically wraps `.cause` on read — but the
	// resulting bridge proxy of `process` is FULLY FUNCTIONAL: sandbox can
	// chain `e.cause.mainModule.require('child_process').execSync(...)`
	// through proxy `apply` traps and reach host RCE. The bridge wraps for
	// realm isolation, not for capability restriction — so re-wrapping is
	// not enough; we must remove `.cause` from sandbox reach entirely.
	//
	// Two carriers, two strategies:
	//   * host-wrapped carrier (`e.isProxy === true`) — overwrite the host-
	//     side `.cause` with `undefined` via `localReflectDefineProperty`,
	//     which routes through the proxy `defineProperty` trap and lands on
	//     the underlying host object. `defineProperty` (not `delete`) is
	//     used so accessor-shaped `.cause` definitions are flattened to a
	//     data property rather than leaving the getter in place.
	//   * sandbox-realm carrier — recurse: `e.cause = handleException(...)`
	//     replaces the property on the sandbox object so a sandbox-thrown
	//     `new Error('x', { cause: hostErr })` still gets its sub-error
	//     processed by the same chokepoint (which then strips its own
	//     `.cause` because that sub-error IS host-wrapped).
	const beforeCause = e;
	e = sanitizeErrorCause(e, visited);
	// SECURITY (GHSA-x965-fc75-jpqh): if .cause sanitization substituted a fresh
	// sandbox-realm carrier (strip-failed host carrier → new LocalError), keep
	// the memo pointing at what a revisit of the original must now return.
	if (e !== beforeCause) apply(localWeakMapSet, visited, [beforeCause, e]);
	// SECURITY (GHSA-m283-3h24-438v): skipping the SuppressedError /
	// AggregateError prototype walk when neither intrinsic exists on this
	// runtime is a valid optimization, but execution MUST still fall through to
	// the own-property sanitizer below. Returning early here left every
	// arbitrary host reference (`err.detail = process`,
	// `err.originalError = require('child_process')`) fully exploitable on any
	// runtime without AggregateError -- i.e. Node < 15, the oldest supported
	// versions -- while appearing fixed on newer ones.
	if (localSuppressedErrorProto !== null || localAggregateErrorProto !== null) {
		let proto;
		try {
			proto = localReflectGetPrototypeOf(e);
		} catch (ex) {
			return e;
		}
		while (proto !== null) {
			if (localSuppressedErrorProto !== null && proto === localSuppressedErrorProto) {
				return sanitizeSuppressedError(e, visited);
			}
			if (localAggregateErrorProto !== null && proto === localAggregateErrorProto) {
				return sanitizeAggregateError(e, visited);
			}
			try {
				proto = localReflectGetPrototypeOf(proto);
			} catch (ex) {
				return e;
			}
		}
	}
	// SECURITY (GHSA-m283-3h24-438v third follow-up): close arbitrary own-
	// property leak class on host-wrapped error carriers. The .cause /
	// SuppressedError / AggregateError chokepoints only sanitize known
	// spec-defined sub-error slots, but Node libraries routinely attach host
	// references via custom property names (`err.detail = process`,
	// `err.originalError = require('child_process')`, etc.) — same proxy-
	// wrapped-but-functional escape primitive as the original .cause channel.
	// sanitizeHostOwnProps enumerates own keys on host-wrapped carriers and
	// seals every non-primitive property to undefined (non-configurable,
	// non-writable), preserving primitive diagnostic values (`message`,
	// `stack`, `name`, `code`, etc.). SuppressedError / AggregateError do not
	// reach here — their handlers above return sandbox-realm replacements.
	if (_isHostWrapped(e)) {
		const rebuilt = sanitizeHostOwnProps(e);
		// SECURITY (GHSA-x965-fc75-jpqh): sanitizeHostOwnProps rebuilds the
		// host-wrapped carrier into a sandbox-realm error (to drop host-realm
		// prototype-chain references its own-key sealing cannot reach). The memo
		// still points at the RAW carrier `e`, so without this update a second
		// reference to the same carrier within one traversal (e.g. the same host
		// error listed twice in an aggregate's errors[]) would hit the revisit
		// short-circuit and return the raw carrier — whose prototype-chain host
		// refs are still live. Point the memo at the rebuild.
		if (rebuilt !== e) apply(localWeakMapSet, visited, [e, rebuilt]);
		return rebuilt;
	}
	return e;
}

// SECURITY (GHSA-m283-3h24-438v second follow-up): the original recursive
// sanitization for SuppressedError / AggregateError used a read-then-recurse-
// then-assign pattern (`e.error = handleException(e.error, visited)`). On a
// host-wrapped carrier with a getter-only accessor `.error`, the right-hand-
// side read invokes the host getter once (returning a benign value that
// recurses harmlessly), and the assignment back is a SET — silently no-op
// against a getter-only accessor. The accessor remains live, and any later
// sandbox read invokes it again, returning a host reference (e.g., process).
// Same TOCTOU class as the original `.cause` advisory.
//
// Structural fix: when the carrier is host-wrapped, snapshot the sub-errors
// via a SINGLE read each, sanitize them, and construct a fresh sandbox-realm
// replacement of the same type. The original carrier — which may have any
// number of attacker-controlled accessors — is dropped entirely. Sandbox
// receives a stable sandbox-realm carrier whose sub-error slots are plain
// data properties.
// SECURITY (GHSA-x965-fc75-jpqh): defense-in-depth backstop for the rebuild
// sanitizers. A rebuilt sandbox-realm error MUST contain only sandbox-realm
// sub-errors. handleException() is EXPECTED to return a sandbox-realm value for
// every element, but this helper re-checks at the embed site, AFTER the
// recursive call and BEFORE installation, and is agnostic to WHY an element is
// still host-wrapped — so it independently blocks the revisit-short-circuit leak
// this advisory closes AND any future rebuild path that forgets to sanitize an
// element. A legitimately sanitized sub-error is sandbox-realm (isProxy
// undefined), so it passes through untouched — no over-block.
function _blockHostWrapped(v) {
	if (_isHostWrapped(v)) {
		return new LocalError('Foreign exception blocked by vm2 sandbox');
	}
	return v;
}

function _isHostWrapped(e) {
	try { return e.isProxy === true; } catch (_) { return false; }
}

function sanitizeSuppressedError(e, visited) {
	if (!_isHostWrapped(e) || LocalSuppressedError === null) {
		// Sandbox-realm carrier (or no SuppressedError available): recurse and
		// assign back. Sandbox-realm objects with attacker-controlled accessors
		// were already constructed by sandbox code holding the references, so
		// no new escape primitive is introduced.
		try { e.error = handleException(e.error, visited); } catch (_) {}
		try { e.suppressed = handleException(e.suppressed, visited); } catch (_) {}
		return e;
	}
	// SECURITY (GHSA-x965-fc75-jpqh): TWO-PHASE build so cycles terminate on a
	// sandbox-realm object. (1) construct the empty sandbox-realm replacement,
	// (2) register it in `visited` BEFORE recursing into .error/.suppressed so a
	// self-reference (`se.error = se`) or a sub-error shared with another carrier
	// resolves to the replacement, not the raw host proxy, (3) populate its
	// slots with the sanitized children. Attacker-controlled own properties on
	// the host carrier (e.g. `.leak = process`) are dropped by construction.
	let msg = '';
	try { const m = e.message; if (typeof m === 'string') msg = m; } catch (_) {}
	let replacement;
	try {
		replacement = new LocalSuppressedError(undefined, undefined, msg);
	} catch (_) {
		replacement = new LocalError(msg);
	}
	apply(localWeakMapSet, visited, [e, replacement]); // SECURITY (GHSA-x965-fc75-jpqh): register before recursion
	let errVal, suppVal;
	try { errVal = e.error; } catch (_) {}
	try { suppVal = e.suppressed; } catch (_) {}
	// SECURITY (GHSA-x965-fc75-jpqh): backstop each rebuilt slot — never embed a
	// still-host-wrapped element (see _blockHostWrapped). Primary defence is the
	// two-phase memo above; this is the independent second layer.
	const sanitizedErr = _blockHostWrapped(handleException(errVal, visited));
	const sanitizedSupp = _blockHostWrapped(handleException(suppVal, visited));
	// SECURITY (GHSA-x965-fc75-jpqh): install sanitized children as plain
	// sandbox-realm own data properties on the replacement.
	try {
		localReflectDefineProperty(replacement, 'error', {
			__proto__: null, value: sanitizedErr, writable: true, enumerable: false, configurable: true,
		});
	} catch (_) { try { replacement.error = sanitizedErr; } catch (_) {} }
	try {
		localReflectDefineProperty(replacement, 'suppressed', {
			__proto__: null, value: sanitizedSupp, writable: true, enumerable: false, configurable: true,
		});
	} catch (_) { try { replacement.suppressed = sanitizedSupp; } catch (_) {} }
	return replacement;
}

function sanitizeAggregateError(e, visited) {
	if (!_isHostWrapped(e) || LocalAggregateError === null) {
		// Sandbox-realm carrier: existing in-place sanitization.
		let arr;
		try { arr = e.errors; } catch (_) { return e; }
		if (localArrayIsArray(arr)) {
			let len;
			try { len = arr.length >>> 0; } catch (_) { return e; }
			for (let i = 0; i < len; i++) {
				let item;
				try { item = arr[i]; } catch (_) { continue; }
				const sanitized = handleException(item, visited);
				if (sanitized !== item) {
					try { arr[i] = sanitized; } catch (_) {}
				}
			}
		}
		return e;
	}
	// Host-wrapped carrier: snapshot, sanitize, rebuild as sandbox-realm.
	// SECURITY (GHSA-x965-fc75-jpqh): TWO-PHASE build so cycles terminate on a
	// sandbox-realm object. (1) construct the empty sandbox-realm replacement,
	// (2) register it in `visited` BEFORE recursing into `.errors` so any cycle
	// back to this carrier — self-cycle `agg.errors=[agg]`, duplicate
	// `[shared, shared]`, mutual `a↔b`, or a nested duplicate — short-circuits to
	// the replacement (a sandbox-realm object) instead of the raw host proxy the
	// prior memo handed back, (3) populate `.errors` with the sanitized elements.
	let msg = '';
	try { const m = e.message; if (typeof m === 'string') msg = m; } catch (_) {}
	let replacement;
	try {
		replacement = new LocalAggregateError([], msg);
	} catch (_) {
		replacement = new LocalError(msg);
	}
	apply(localWeakMapSet, visited, [e, replacement]); // SECURITY (GHSA-x965-fc75-jpqh): register before recursion
	let arrRead;
	try { arrRead = e.errors; } catch (_) {}
	const sanitizedArr = [];
	if (localArrayIsArray(arrRead)) {
		let len = 0;
		try { len = arrRead.length >>> 0; } catch (_) {}
		for (let i = 0; i < len; i++) {
			let item;
			try { item = arrRead[i]; } catch (_) { continue; }
			// SECURITY (GHSA-x965-fc75-jpqh): backstop every element — never embed
			// a still-host-wrapped element (see _blockHostWrapped). Primary defence
			// is the two-phase memo above; this is the independent second layer.
			sanitizedArr[sanitizedArr.length] = _blockHostWrapped(handleException(item, visited));
		}
	}
	// SECURITY (GHSA-x965-fc75-jpqh): install the sanitized array as a plain
	// sandbox-realm own data property (AggregateError.prototype.errors is a
	// writable/configurable own data prop, so this replaces the constructor's
	// empty array with the fully-sanitized one).
	try {
		localReflectDefineProperty(replacement, 'errors', {
			__proto__: null, value: sanitizedArr, writable: true, enumerable: false, configurable: true,
		});
	} catch (_) { try { replacement.errors = sanitizedArr; } catch (_) {} }
	return replacement;
}

// SECURITY (GHSA-m283-3h24-438v third follow-up): close arbitrary own-
// property channel on host-wrapped error carriers. Enumerates own keys via
// the bridge's ownKeys trap (single call) and, for each key, seals the
// property to a fixed value via non-configurable + non-writable
// defineProperty. The chosen value:
//   * primitive (string/number/boolean/bigint/null/undefined): captured first
//     read — locks the property to that primitive so subsequent reads cannot
//     deliver a different value (defeats TOCTOU accessors that return primitive
//     now / process later).
//   * non-primitive (object/function): replaced with `undefined` — closes the
//     leak channel entirely. The bridge's `get` invariant (§10.5.8) then
//     forces sandbox reads to return undefined or throw.
// Both descriptor shapes are non-configurable + non-writable so the ECMA-262
// §10.5.6 ProxyDefineOwnProperty invariant catches lying-Proxy host-carriers
// (cannot pretend success without modifying a configurable target). On any
// seal failure, the carrier itself is unsafe — substitute a fresh sandbox-
// realm Error preserving the message captured during the enumeration.
// SECURITY (GHSA-x6m4-chr9-cg97): host-frame classifier, mirror of the
// nested `isHostFrameFileName` (GHSA-v27g) and of bridge.js. A source filename
// denotes host-realm code when it is an absolute POSIX path ('/'), a Windows
// drive ('X:'), or a Node pseudo-path ('node:' / 'internal/'). Clean sandbox
// filenames (bare `vm.js`, user VMScript names without separators) never match.
function x6m4IsHostFrameFile(name) {
	if (typeof name !== 'string' || name.length === 0) return false; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (localReflectApply(localStringCharCodeAt, name, [0]) === 0x2f /* '/' */) return true; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (name.length >= 2 && localReflectApply(localStringCharCodeAt, name, [1]) === 0x3a /* ':' */) return true; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (name.length >= 5 && localReflectApply(localStringSlice, name, [0, 5]) === 'node:') return true; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (name.length >= 9 && localReflectApply(localStringSlice, name, [0, 9]) === 'internal/') return true; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (name.length >= 5 && localReflectApply(localStringSlice, name, [0, 5]) === 'file:') return true; // SECURITY (GHSA-x6m4-chr9-cg97): ESM host frames as file:// URLs
	if (name.length >= 5 && localReflectApply(localStringSlice, name, [0, 5]) === 'wasm:') return true; // SECURITY (GHSA-x6m4-chr9-cg97): WASM frames
	if (localReflectApply(localStringLastIndexOf, name, ['..']) !== -1) return true; // SECURITY (GHSA-x6m4-chr9-cg97): relative `..` traversal = host module path
	return false; // SECURITY (GHSA-x6m4-chr9-cg97)
}

// SECURITY (GHSA-x6m4-chr9-cg97): true if a single `.stack` line is a host
// frame. Frame lines are `    at NAME (FILE:L:C)` or `    at FILE:L:C`; extract
// FILE and classify by prefix. Non-frame lines (the message header) return
// false so the message is preserved.
function x6m4StackLineIsHostFrame(line) {
	if (typeof line !== 'string') return false; // SECURITY (GHSA-x6m4-chr9-cg97)
	const len = line.length; // SECURITY (GHSA-x6m4-chr9-cg97)
	let i = 0; // SECURITY (GHSA-x6m4-chr9-cg97): skip leading indentation
	while (i < len && localReflectApply(localStringCharCodeAt, line, [i]) === 0x20 /* ' ' */) i++; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (localReflectApply(localStringCharCodeAt, line, [i]) !== 0x61 /* 'a' */) return false; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (localReflectApply(localStringCharCodeAt, line, [i + 1]) !== 0x74 /* 't' */) return false; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (localReflectApply(localStringCharCodeAt, line, [i + 2]) !== 0x20 /* ' ' */) return false; // SECURITY (GHSA-x6m4-chr9-cg97)
	let file; // SECURITY (GHSA-x6m4-chr9-cg97)
	if (len > 0 && localReflectApply(localStringCharCodeAt, line, [len - 1]) === 0x29 /* ')' */) { // SECURITY (GHSA-x6m4-chr9-cg97)
		const open = localReflectApply(localStringLastIndexOf, line, ['(']); // SECURITY (GHSA-x6m4-chr9-cg97)
		if (open === -1) return false; // SECURITY (GHSA-x6m4-chr9-cg97)
		file = localReflectApply(localStringSlice, line, [open + 1, len - 1]); // SECURITY (GHSA-x6m4-chr9-cg97)
	} else { // SECURITY (GHSA-x6m4-chr9-cg97)
		file = localReflectApply(localStringSlice, line, [i + 3, len]); // SECURITY (GHSA-x6m4-chr9-cg97)
		if (file.length >= 6 && localReflectApply(localStringSlice, file, [0, 6]) === 'async ') { // SECURITY (GHSA-x6m4-chr9-cg97)
			file = localReflectApply(localStringSlice, file, [6, file.length]); // SECURITY (GHSA-x6m4-chr9-cg97)
		}
	}
	return x6m4IsHostFrameFile(file); // SECURITY (GHSA-x6m4-chr9-cg97)
}

// SECURITY (GHSA-x6m4-chr9-cg97): drop host-realm frame lines from a host
// Error's `.stack` before it is carried onto a sandbox-realm error rebuild.
// Preserves the message header and any clean sandbox frames. Primitive string
// accumulation only (no Array container) — same rationale as
// defaultSandboxPrepareStackTrace (Defense Invariant #11).
function x6m4RedactHostFramesFromStack(stack) {
	if (typeof stack !== 'string') return stack; // SECURITY (GHSA-x6m4-chr9-cg97)
	let lines; // SECURITY (GHSA-x6m4-chr9-cg97)
	try {
		lines = localReflectApply(localStringSplit, stack, ['\n']); // SECURITY (GHSA-x6m4-chr9-cg97)
	} catch (_) {
		return stack; // SECURITY (GHSA-x6m4-chr9-cg97): fail closed to original on error
	}
	if (!localArrayIsArray(lines)) return stack; // SECURITY (GHSA-x6m4-chr9-cg97)
	let result = ''; // SECURITY (GHSA-x6m4-chr9-cg97)
	let first = true; // SECURITY (GHSA-x6m4-chr9-cg97)
	for (let i = 0; i < lines.length; i++) { // SECURITY (GHSA-x6m4-chr9-cg97)
		const line = lines[i]; // SECURITY (GHSA-x6m4-chr9-cg97)
		if (x6m4StackLineIsHostFrame(line)) continue; // SECURITY (GHSA-x6m4-chr9-cg97)
		result += first ? line : ('\n' + line); // SECURITY (GHSA-x6m4-chr9-cg97)
		first = false; // SECURITY (GHSA-x6m4-chr9-cg97)
	}
	return result; // SECURITY (GHSA-x6m4-chr9-cg97)
}

function sanitizeHostOwnProps(e) {
	let keys;
	try {
		keys = apply(localReflectOwnKeys, localReflect, [e]);
	} catch (_) {
		return new LocalError('');
	}
	if (!localArrayIsArray(keys)) return new LocalError('');
	let keysLen;
	try {
		keysLen = keys.length >>> 0;
	} catch (_) {
		return new LocalError('');
	}
	let safeMsg = '';
	// Primitive own properties survive the rebuild below; collected as we seal.
	const carryKeys = [];
	const carryVals = [];
	for (let i = 0; i < keysLen; i++) {
		let k;
		try { k = keys[i]; } catch (_) { return new LocalError(safeMsg); }
		let v;
		try { v = e[k]; } catch (_) { v = undefined; }
		// SECURITY (GHSA-x6m4-chr9-cg97): a host Error's `.stack` is a primitive
		// string V8 formatted with absolute host paths. It is carried verbatim
		// onto the sandbox-realm rebuild below (and this read does NOT cross the
		// bridge `get` trap, so the bridge-side redactor cannot reach it). Redact
		// host frames here so no host path is ever handed to sandbox code.
		if (k === 'stack' && typeof v === 'string') { // SECURITY (GHSA-x6m4-chr9-cg97)
			v = x6m4RedactHostFramesFromStack(v); // SECURITY (GHSA-x6m4-chr9-cg97)
		}
		const t = typeof v;
		const isPrim = v === null || v === undefined || (t !== 'object' && t !== 'function');
		if (isPrim && k === 'message' && t === 'string') safeMsg = v;
		let sealed = false;
		try {
			sealed = localReflectDefineProperty(e, k, {
				__proto__: null,
				value: isPrim ? v : undefined,
				writable: false,
				enumerable: false,
				configurable: false,
			}) === true;
		} catch (_) {
			/* engine invariant violation — lying proxy or incompatible non-
			 * configurable target descriptor. Substitute carrier below. */
		}
		if (!sealed) {
			return new LocalError(safeMsg);
		}
		if (isPrim && k !== 'message' && v !== undefined) {
			carryKeys[carryKeys.length] = k;
			carryVals[carryVals.length] = v;
		}
	}
	// SECURITY (GHSA-m283-3h24-438v fourth follow-up): sealing OWN keys cannot
	// reach a host reference installed on a PROTOTYPE in the carrier's chain --
	// `Object.setPrototypeOf(hostErr, { leak: process })` -- because
	// Reflect.ownKeys does not report inherited properties. Returning the
	// host-wrapped carrier therefore still handed sandbox code a live bridge
	// proxy of the host object through `e.leak`, reachable as
	// `e.leak.mainModule.require('child_process')`.
	//
	// Own-key enumeration cannot be extended to cover this: the chain is
	// attacker-shaped and each link may itself be a lying Proxy. Instead drop
	// the host prototype chain entirely by rebuilding the carrier in the
	// sandbox realm, carrying across only the primitive own properties sealed
	// above (message via the constructor, plus name/stack/code/errno/syscall/
	// path and any other primitive the host attached). This mirrors the
	// snapshot-and-rebuild already applied to SuppressedError / AggregateError
	// carriers, and makes the returned object structurally incapable of
	// referencing the host realm.
	let safeName = '';
	try {
		const n = e.name;
		if (typeof n === 'string') safeName = n;
	} catch (_) { /* hostile accessor — fall back to plain Error */ }
	const Ctor = localErrorCtorForName(safeName);
	let out;
	try {
		out = new Ctor(safeMsg);
	} catch (_) {
		out = new LocalError(safeMsg);
	}
	for (let i = 0; i < carryKeys.length; i++) {
		try {
			localReflectDefineProperty(out, carryKeys[i], {
				__proto__: null,
				value: carryVals[i],
				writable: true,
				enumerable: false,
				configurable: true,
			});
		} catch (_) { /* best effort: a diagnostic property is not worth failing on */ }
	}
	return out;
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

// This write looks dead on a current runtime. It is not, and it must not be
// removed or "simplified" again without testing the FULL supported Node range.
//
// The `Object.defineProperties(global, ...)` block near the top of this file
// installs `Proxy` as `undefined` with the attributes omitted, i.e. sealed by
// the spec defaults. Whether that seal actually takes on a vm context's global
// proxy is engine-dependent. Measured on real interpreters, not inferred:
//
//   Node >= 10  the slot really is non-writable. This write is a silent no-op
//               and the sandbox has no `Proxy` at all.
//   Node 8      the slot stays writable AND configurable, and that old V8
//               global proxy honours [[Set]] while silently ignoring
//               [[DefineOwnProperty]] — `Reflect.defineProperty` returns true
//               and stores nothing. So a plain assignment is the only form that
//               works, and it is what gives that sandbox its handler-
//               sanitising `Proxy`.
//   JSC (Bun)   implements the strict-mode write to a sealed slot correctly and
//               THROWS, which would abort sandbox setup before the first run().
//
// Hence: a plain assignment (the only form Node 8 respects) inside a try/catch
// (because JSC throws). Swallowing the throw is safe — the failure outcome is
// "no `Proxy` in the sandbox", which is strictly more restrictive, never less.
//
// Removing this once already changed behaviour on Node 8, where `new Proxy(...)`
// inside the sandbox began throwing: not a security regression, but a real
// compatibility break on a runtime `engines` still admits. `test/vm.js` has an
// AST-based guard that fails if this write is ever left unguarded.
try {
	global.Proxy = proxiedProxy;
} catch (e) {
	// Sealed slot on this engine. Sandbox keeps no `Proxy`; nothing to do.
}
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
	// SECURITY (GHSA-f8gf-w286-fmq2): the assimilating static methods
	// (`resolve`, `all`, `race`, `any`, `allSettled`, `try`) each invoke an
	// attacker thenable's `.then` in a microtask AFTER run() returns, bypassing
	// the blocked Promise.prototype.then. When async execution is disabled, no
	// sandbox-reachable operation may enqueue a job that calls back into the
	// sandbox once run() has returned. The constructor-level resolve guard
	// already neutralizes the capability these methods build internally, but we
	// ALSO refuse them synchronously here. That is both clearer and more
	// version-robust: on Node versions where the combinators call an internal
	// resolve (rather than `Get(C, "resolve")`), the constructor guard alone
	// would surface the failure as a late rejection instead of a synchronous
	// throw. `reject` does NOT assimilate (a thenable reason is delivered as-is)
	// and `withResolvers` only hands back a (constructor-guarded) resolve
	// capability, so both stay available.
	const globalPromiseTry = globalPromise.try;
	if (typeof globalPromiseTry === 'function') {
		globalPromise.try = function _try() {
			if (!allowAsync) throw throwAsync();
			return apply(globalPromiseTry, localPromise, arguments);
		};
	}

	const globalPromiseAll = globalPromise.all;
	globalPromise.all = function all(iterable) {
		if (!allowAsync) throw throwAsync();
		return apply(globalPromiseAll, localPromise, [iterable]);
	};

	const globalPromiseRace = globalPromise.race;
	globalPromise.race = function race(iterable) {
		if (!allowAsync) throw throwAsync();
		return apply(globalPromiseRace, localPromise, [iterable]);
	};

	const globalPromiseAllSettled = globalPromise.allSettled;
	if (typeof globalPromiseAllSettled === 'function') {
		globalPromise.allSettled = function allSettled(iterable) {
			if (!allowAsync) throw throwAsync();
			return apply(globalPromiseAllSettled, localPromise, [iterable]);
		};
	}

	const globalPromiseAny = globalPromise.any;
	if (typeof globalPromiseAny === 'function') {
		globalPromise.any = function any(iterable) {
			if (!allowAsync) throw throwAsync();
			return apply(globalPromiseAny, localPromise, [iterable]);
		};
	}

	const globalPromiseResolve = globalPromise.resolve;
	globalPromise.resolve = function resolve(value) {
		if (!allowAsync) throw throwAsync();
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

	// SECURITY (GHSA-f8gf-w286-fmq2): close the realm-intrinsic base path.
	// Everything above guards the *user-facing* Promise (localPromise) and its
	// static methods, but the native base constructor (globalPromise) stays
	// reachable from the sandbox: `localPromise extends globalPromise`, so
	// `Object.getPrototypeOf(Promise)` and `Object.getPrototypeOf(
	// Promise.prototype).constructor` both reach it. Constructing it directly —
	// `new (Object.getPrototypeOf(Promise))(r => r(thenable))` or
	// `Reflect.construct(base, [exec], target)` (with any forged newTarget) —
	// yields an UNGUARDED native resolve and re-opens thenable assimilation. The
	// base cannot be made non-constructable (it is a native intrinsic), and it
	// cannot be removed from localPromise's chain (the chain provides the
	// [[PromiseState]] internal slot via super()). So we interpose a
	// construct-guard:
	//
	//   1. Replace localPromise's [[Prototype]] with a Proxy over globalPromise
	//      whose `construct` trap forwards ONLY localPromise's own genuine
	//      super() call (identified by a trusted wrapped executor) and refuses
	//      every other base construction — direct `new base()` and
	//      `Reflect.construct(base, [exec], anyTarget)` alike, regardless of the
	//      newTarget — with a synchronous throw. The Proxy forwards property
	//      reads to globalPromise, so inherited statics still resolve; its target
	//      is NOT exposed by `getPrototypeOf` (that returns Function.prototype).
	//   2. Repoint globalPromise.prototype.constructor at localPromise so the
	//      deep `getPrototypeOf(Promise.prototype).constructor` walk lands on the
	//      guarded constructor instead of the raw base. (resetPromiseSpecies
	//      already pins instance `.constructor` to localPromise, so this only
	//      makes the prototype consistent with existing behaviour.)
	//
	// This is gated to allowAsync:false, so the battle-tested allowAsync:true
	// Promise shape — and every prior advisory defense built on it — is
	// untouched. The freezes below then lock localPromise (and its prototype)
	// non-extensible, so the guard cannot be stripped via setPrototypeOf or
	// constructor redefinition.
	if (!allowAsync) {
		const promiseConstructGuard = new LocalProxy(globalPromise, {
			__proto__: null,
			construct(target, args, newTarget) {
				// The ONLY legitimate construction through the native base is
				// localPromise's own super() call, which passes a wrapped
				// executor we registered in trustedPromiseExecutors. Forward that
				// transparently (the wrapped executor already guards resolve and
				// swallows rejections). Every other construction — direct
				// `new (Object.getPrototypeOf(Promise))(...)`, `Reflect.construct(
				// base, [exec], target)` with any newTarget, etc. — is sandbox
				// code reaching the raw intrinsic to obtain an UNGUARDED native
				// resolve capability. Refuse it with a synchronous throw (no
				// promise is created, so this cannot become an unhandled
				// rejection).
				const executor = args.length > 0 ? args[0] : undefined;
				if (typeof executor === 'function' &&
					apply(localWeakMapGet, trustedPromiseExecutors, [executor]) === true) {
					return localReflectConstruct(target, args, newTarget);
				}
				throw throwAsync();
			},
		});
		if (!localReflectSetPrototypeOf(localPromise, promiseConstructGuard)) throw localUnexpected();
		if (!localReflectDefineProperty(globalPromise.prototype, 'constructor', {
			__proto__: null,
			value: localPromise,
			writable: true,
			configurable: true,
		})) throw localUnexpected();
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

// SECURITY (GHSA-f8gf-w286-fmq2): `Array.fromAsync` (Node 22+) is an Array
// static — not a Promise method — but it belongs to the same vulnerability
// class. It asynchronously iterates its argument and `await`s each element,
// assimilating any thenable element: the element's `.then` runs in a microtask
// AFTER run() returns, bypassing the blocked Promise.prototype.then exactly like
// the Promise combinators. (It also always returns a pending promise, which is
// meaningless when async is disabled.) When async is disabled, neutralize it. We
// install a throwing replacement as a NON-configurable, NON-writable own data
// property so sandbox code cannot restore the original via assignment OR
// `Object.defineProperty` (redefining a non-configurable property throws).
// `localArray` is the sandbox context's own `Array` intrinsic, so this does not
// touch the host realm's `Array`.
if (!allowAsync && localArray && typeof localArray.fromAsync === 'function') {
	if (!localReflectDefineProperty(localArray, 'fromAsync', {
		__proto__: null,
		value: function fromAsync() {
			throw throwAsync();
		},
		writable: false,
		enumerable: false,
		configurable: false,
	})) throw localUnexpected();
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
