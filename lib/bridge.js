'use strict';

/**
 * __        ___    ____  _   _ ___ _   _  ____
 * \ \      / / \  |  _ \| \ | |_ _| \ | |/ ___|
 *  \ \ /\ / / _ \ | |_) |  \| || ||  \| | |  _
 *   \ V  V / ___ \|  _ <| |\  || || |\  | |_| |
 *    \_/\_/_/   \_\_| \_\_| \_|___|_| \_|\____|
 *
 * This file is critical for vm2. It implements the bridge between the host and the sandbox.
 * If you do not know exactly what you are doing, you should NOT edit this file.
 *
 * The file is loaded in the host and sandbox to handle objects in both directions.
 * This is done to ensure that RangeErrors are from the correct context.
 * The boundary between the sandbox and host might throw RangeErrors from both contexts.
 * Therefore, thisFromOther and friends can handle objects from both domains.
 *
 * Method parameters have comments to tell from which context they came.
 *
 */

const globalsList = [
	'Number',
	'String',
	'Boolean',
	'Date',
	'RegExp',
	'Map',
	'WeakMap',
	'Set',
	'WeakSet',
	'Promise',
	'Function'
];

const errorsList = [
	'RangeError',
	'ReferenceError',
	'SyntaxError',
	'TypeError',
	'EvalError',
	'URIError',
	'SuppressedError',
	'Error'
];

const OPNA = 'Operation not allowed on contextified object.';

const thisGlobalPrototypes = {
	__proto__: null,
	Object: Object.prototype,
	Array: Array.prototype
};

for (let i = 0; i < globalsList.length; i++) {
	const key = globalsList[i];
	const g = global[key];
	if (g) thisGlobalPrototypes[key] = g.prototype;
}

for (let i = 0; i < errorsList.length; i++) {
	const key = errorsList[i];
	const g = global[key];
	if (g) thisGlobalPrototypes[key] = g.prototype;
}

// Add non-global function constructor prototypes for cross-realm blocking.
// These are not on `global` but are needed to block sandbox escape via
// AsyncFunction('code'), GeneratorFunction('code'), etc.
try {
	thisGlobalPrototypes['AsyncFunction'] = (async function() {}).constructor.prototype;
} catch (e) {}
try {
	thisGlobalPrototypes['GeneratorFunction'] = (function*() {}).constructor.prototype;
} catch (e) {}
try {
	// Use eval to avoid syntax error on Node < 10 where async generators don't exist
	thisGlobalPrototypes['AsyncGeneratorFunction'] = eval('(async function*() {})').constructor.prototype;
} catch (e) {}

// Cache this-realm dangerous function constructors.
// Used to block raw host Function constructors from leaking when handler
// methods are called directly (e.g., via showProxy handler exposure).
// This complements isDangerousFunctionConstructor which checks OTHER-realm constructors.
let thisAsyncFunctionCtor;
let thisGeneratorFunctionCtor;
let thisAsyncGeneratorFunctionCtor;
try {
	if (thisGlobalPrototypes.AsyncFunction) {
		const desc = thisReflectGetOwnPropertyDescriptor(thisGlobalPrototypes.AsyncFunction, 'constructor');
		if (desc) thisAsyncFunctionCtor = desc.value;
	}
} catch (e) {}
try {
	if (thisGlobalPrototypes.GeneratorFunction) {
		const desc = thisReflectGetOwnPropertyDescriptor(thisGlobalPrototypes.GeneratorFunction, 'constructor');
		if (desc) thisGeneratorFunctionCtor = desc.value;
	}
} catch (e) {}
try {
	if (thisGlobalPrototypes.AsyncGeneratorFunction) {
		const desc = thisReflectGetOwnPropertyDescriptor(thisGlobalPrototypes.AsyncGeneratorFunction, 'constructor');
		if (desc) thisAsyncGeneratorFunctionCtor = desc.value;
	}
} catch (e) {}

function isThisDangerousFunctionConstructor(value) {
	return value === thisFunction ||
		(thisAsyncFunctionCtor && value === thisAsyncFunctionCtor) ||
		(thisGeneratorFunctionCtor && value === thisGeneratorFunctionCtor) ||
		(thisAsyncGeneratorFunctionCtor && value === thisAsyncGeneratorFunctionCtor);
}

const {
	getPrototypeOf: thisReflectGetPrototypeOf,
	setPrototypeOf: thisReflectSetPrototypeOf,
	defineProperty: thisReflectDefineProperty,
	deleteProperty: thisReflectDeleteProperty,
	getOwnPropertyDescriptor: thisReflectGetOwnPropertyDescriptor,
	isExtensible: thisReflectIsExtensible,
	preventExtensions: thisReflectPreventExtensions,
	apply: thisReflectApply,
	construct: thisReflectConstruct,
	set: thisReflectSet,
	get: thisReflectGet,
	has: thisReflectHas,
	ownKeys: thisReflectOwnKeys,
	enumerate: thisReflectEnumerate,
} = Reflect;

const thisObject = Object;
const {
	freeze: thisObjectFreeze,
	prototype: thisObjectPrototype
} = thisObject;
const thisObjectHasOwnProperty = thisObjectPrototype.hasOwnProperty;
const ThisProxy = Proxy;
const ThisWeakMap = WeakMap;
const thisWeakMapProto = ThisWeakMap.prototype;
const thisWeakMapGet = thisWeakMapProto.get;
const thisWeakMapSet = thisWeakMapProto.set;
// SECURITY (GHSA-v37h, GHSA-qcp4, GHSA-vwrp): cached so the trap-this guards,
// validateHandlerTarget, and the protected-host-object check cannot be
// subverted by attacker mutation of WeakMap.prototype.has.
const thisWeakMapHas = thisWeakMapProto.has;
const ThisMap = Map;
const thisMapGet = ThisMap.prototype.get;
const thisMapSet = ThisMap.prototype.set;
const thisFunction = Function;
const thisFunctionBind = thisFunction.prototype.bind;
const thisArrayIsArray = Array.isArray;
// SECURITY (GHSA-grj5-jjm8-h35p): Cache the this-realm Array constructor at module
// load time, BEFORE any sandbox code runs. Used as the safe species-neutralized
// return value from proxy.get 'constructor' on host arrays. We cache this directly
// from `global.Array` so that prototype pollution attacks
// (e.g., `Array.prototype.constructor = attackerFn` via cross-realm proto injection)
// cannot redirect our defense to an attacker-controlled value.
const thisArrayCtor = Array;
const thisErrorCaptureStackTrace = Error.captureStackTrace;

const thisSymbolToString = Symbol.prototype.toString;
const thisSymbolToStringTag = Symbol.toStringTag;
const thisSymbolIterator = Symbol.iterator;
const thisSymbolNodeJSUtilInspectCustom = Symbol.for('nodejs.util.inspect.custom');
const thisSymbolNodeJSRejection = Symbol.for('nodejs.rejection');

function isDangerousCrossRealmSymbol(key) {
	return key === thisSymbolNodeJSUtilInspectCustom || key === thisSymbolNodeJSRejection;
}

/**
 * VMError.
 *
 * @public
 * @extends {Error}
 */
class VMError extends Error {

	/**
	 * Create VMError instance.
	 *
	 * @public
	 * @param {string} message - Error message.
	 * @param {string} code - Error code.
	 */
	constructor(message, code) {
		super(message);

		this.name = 'VMError';
		this.code = code;

		thisErrorCaptureStackTrace(this, this.constructor);
	}
}

thisGlobalPrototypes['VMError'] = VMError.prototype;

function thisUnexpected() {
	return new VMError('Unexpected');
}

if (!thisReflectSetPrototypeOf(exports, null)) throw thisUnexpected();

function thisSafeGetOwnPropertyDescriptor(obj, key) {
	const desc = thisReflectGetOwnPropertyDescriptor(obj, key);
	if (!desc) return desc;
	if (!thisReflectSetPrototypeOf(desc, null)) throw thisUnexpected();
	return desc;
}

function thisThrowCallerCalleeArgumentsAccess(key) {
	'use strict';
	thisThrowCallerCalleeArgumentsAccess[key];
	return thisUnexpected();
}

function thisIdMapping(factory, other) {
	return other;
}

const thisThrowOnKeyAccessHandler = thisObjectFreeze({
	__proto__: null,
	get(target, key, receiver) {
		if (key === 'isProxy') return true;
		if (typeof key === 'symbol') {
			key = thisReflectApply(thisSymbolToString, key, []);
		} else if (key === 'href') {
			// Fixes util.inspect in Node.js 22 that performs checks for URL by accessing the href property.
			return undefined;
		}
		throw new VMError(`Unexpected access to key '${key}'`);
	}
});

const emptyFrozenObject = thisObjectFreeze({
	__proto__: null
});

const thisThrowOnKeyAccess = new ThisProxy(emptyFrozenObject, thisThrowOnKeyAccessHandler);

function SafeBase() {}

if (!thisReflectDefineProperty(SafeBase, 'prototype', {
	__proto__: null,
	value: thisThrowOnKeyAccess
})) throw thisUnexpected();

function SHARED_FUNCTION() {}

const TEST_PROXY_HANDLER = thisObjectFreeze({
	__proto__: thisThrowOnKeyAccess,
	construct() {
		return this;
	}
});

function thisIsConstructor(obj) {
	// Note: obj@any(unsafe)
	const Func = new ThisProxy(obj, TEST_PROXY_HANDLER);
	try {
		// eslint-disable-next-line no-new
		new Func();
		return true;
	} catch (e) {
		return false;
	}
}

function thisCreateTargetObject(obj, proto) {
	// Note: obj@any(unsafe) proto@any(unsafe) returns@this(unsafe) throws@this(unsafe)
	let base;
	if (typeof obj === 'function') {
		if (thisIsConstructor(obj)) {
			// Bind the function since bound functions do not have a prototype property.
			base = thisReflectApply(thisFunctionBind, SHARED_FUNCTION, [null]);
		} else {
			base = () => {};
		}
	} else if (thisArrayIsArray(obj)) {
		base = [];
	} else {
		return {__proto__: proto};
	}
	if (!thisReflectSetPrototypeOf(base, proto)) throw thisUnexpected();
	return base;
}

function createBridge(otherInit, registerProxy) {

	const mappingOtherToThis = new ThisWeakMap();
	const protoMappings = new ThisMap();
	const protoName = new ThisMap();
	// SECURITY (GHSA-v37h-5mfm-c47c): Module-local, unforgeable construction
	// token. Every legitimate construction of a handler class must pass this
	// Symbol as the first argument to the constructor. Sandbox code that
	// leaks a handler via util.inspect+showProxy cannot read the token — it
	// is closure-scoped and never assigned to any object reachable from a
	// handler, a prototype, or the exported `result` bag. Any
	// `new pp.constructor(...)`, `Reflect.construct(Handler, ...)`, or
	// subclass instantiation from sandbox code will therefore fail the
	// token check and throw `VMError(OPNA)`.
	const constructionToken = Symbol('vm2 bridge handler construction');
	// Store wrapped objects in a WeakMap keyed by handler instance.
	// This prevents exposure of raw objects via util.inspect with showProxy:true,
	// which can leak the handler's internal state.
	const handlerToObject = new ThisWeakMap();
	// Store factory functions in a WeakMap keyed by handler instance.
	// This prevents exposure of factory functions via util.inspect with showProxy:true,
	// which would allow attackers to create new handlers wrapping attacker-controlled objects.
	const handlerToFactory = new ThisWeakMap();
	// SECURITY (GHSA-qcp4-v2jj-fjx8): canonical proxy target keyed by handler.
	// util.inspect(showProxy:true) leaks handlers to sandbox code; without this
	// map a leaked handler can be invoked as a plain function with a forged
	// `target` (e.g. handler.getPrototypeOf(Buffer)) to walk arbitrary host
	// prototype chains. Trap methods that read `target` validate it against
	// this map at entry; the Proxy machinery always supplies the canonical
	// target so legitimate dispatch is unaffected.
	const handlerToTarget = new ThisWeakMap();

	// Closure-scoped function to retrieve the wrapped object from a handler.
	// This is NOT a method on BaseHandler, so it cannot be called by attackers
	// even if they obtain a reference to the handler via showProxy.
	//
	// SECURITY (GHSA-v37h-5mfm-c47c): If `handler` has no WeakMap entry it
	// is not a real handler -- it may be a sandbox-forged object whose
	// prototype is `BaseHandler.prototype` (e.g., via
	// `Object.setPrototypeOf({}, pp)`) or a forged receiver passed via
	// `pp.set.call(forged, ...)`. In that case every trap must refuse to
	// operate, so we throw VMError immediately rather than returning
	// `undefined` (which subtly causes `getOwnPropertyDescriptor(undefined, ...)`
	// to blow up deeper inside a trap, with an unpredictable error type).
	function getHandlerObject(handler) {
		if (!thisReflectApply(thisWeakMapHas, handlerToObject, [handler])) {
			throw new VMError(OPNA);
		}
		return thisReflectApply(thisWeakMapGet, handlerToObject, [handler]);
	}

	// SECURITY (GHSA-qcp4-v2jj-fjx8): enforce the invariant that a handler trap
	// only operates on the proxy target it was paired with at construction time.
	// Two distinct failure modes are caught:
	//   - Forged `this` (handler not registered): WeakMap.has returns false.
	//   - Forged `target` (registered handler, attacker-supplied target): the
	//     stored target does not strict-equal the supplied one.
	// Throws VMError(OPNA) on either, the same error used elsewhere for
	// boundary violations, so attackers learn nothing about internal state.
	function validateHandlerTarget(handler, target) {
		if (!thisReflectApply(thisWeakMapHas, handlerToTarget, [handler])) throw new VMError(OPNA);
		if (thisReflectApply(thisWeakMapGet, handlerToTarget, [handler]) !== target) throw new VMError(OPNA);
	}

	// Closure-scoped function to retrieve the factory from a handler.
	// This is NOT a method on BaseHandler, so it cannot be called by attackers
	// even if they obtain a reference to the handler via showProxy.
	function getHandlerFactory(handler) {
		return thisReflectApply(thisWeakMapGet, handlerToFactory, [handler]);
	}

	// Closure-scoped function to convert other-realm objects to this-realm with factory.
	// This is NOT a method on BaseHandler, so it cannot be called by attackers
	// even if they obtain a reference to the handler via showProxy.
	function handlerFromOtherWithContext(handler, other) {
		return thisFromOtherWithFactory(getHandlerFactory(handler), other);
	}

	// Closure-scoped function to prevent extensions on a proxy target.
	// This is NOT a method on BaseHandler, so it cannot be called by attackers
	// even if they obtain a reference to the handler via showProxy.
	// Unlike other handler methods which use getHandlerObject(this), the old
	// doPreventExtensions accepted `object` as a direct parameter, allowing
	// attackers to pass crafted objects. Now it retrieves `object` from the WeakMap.
	function doPreventExtensions(handler, target) {
		// Note: handler@this(unsafe) target@this(unsafe) throws@this(unsafe)
		const object = getHandlerObject(handler); // @other(unsafe)
		let keys; // @other(safe-array-of-prim)
		try {
			keys = otherReflectOwnKeys(object);
		} catch (e) { // @other(unsafe)
			throw thisFromOtherForThrow(e);
		}
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i]; // @prim
			// Skip dangerous cross-realm symbols
			if (isDangerousCrossRealmSymbol(key)) continue;
			let desc;
			try {
				desc = otherSafeGetOwnPropertyDescriptor(object, key);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			if (!desc) continue;
			if (!desc.configurable) {
				const current = thisSafeGetOwnPropertyDescriptor(target, key);
				if (current && !current.configurable) continue;
				if (desc.get || desc.set) {
					desc.get = handlerFromOtherWithContext(handler, desc.get);
					desc.set = handlerFromOtherWithContext(handler, desc.set);
				} else if (typeof object === 'function' && (key === 'caller' || key === 'callee' || key === 'arguments')) {
					desc.value = null;
				} else {
					desc.value = handlerFromOtherWithContext(handler, desc.value);
				}
			} else {
				if (desc.get || desc.set) {
					desc = {
						__proto__: null,
						configurable: true,
						enumerable: desc.enumerable,
						writable: true,
						value: null
					};
				} else {
					desc.value = null;
				}
			}
			if (!thisReflectDefineProperty(target, key, desc)) throw thisUnexpected();
		}
		if (!thisReflectPreventExtensions(target)) throw thisUnexpected();
	}

	// (Removed PR #563's `neutralizeArraySpecies` / `neutralizeArraySpeciesArgs`
	// helpers — superseded by `neutralizeArraySpeciesOn` / `neutralizeArraySpeciesBatch`
	// + `restoreArraySpeciesOn` / `restoreArraySpeciesBatch` defined below, which
	// add restore-on-exit so host arrays' `constructor` isn't permanently mutated.
	// The PR's set/defineProperty trap interception of `constructor` writes is
	// preserved as a complementary defense layer.)

	function thisAddProtoMapping(proto, other, name) {
		// Note: proto@this(unsafe) other@other(unsafe) name@this(unsafe) throws@this(unsafe)
		thisReflectApply(thisMapSet, protoMappings, [proto, thisIdMapping]);
		thisReflectApply(thisMapSet, protoMappings, [other,
			(factory, object, preventUnwrap) => thisProxyOther(factory, object, proto, preventUnwrap)]);
		if (name) thisReflectApply(thisMapSet, protoName, [proto, name]);
	}

	function thisAddProtoMappingFactory(protoFactory, other, name) {
		// Note: protoFactory@this(unsafe) other@other(unsafe) name@this(unsafe) throws@this(unsafe)
		let proto;
		thisReflectApply(thisMapSet, protoMappings, [other,
			(factory, object, preventUnwrap) => {
				if (!proto) {
					proto = protoFactory();
					thisReflectApply(thisMapSet, protoMappings, [proto, thisIdMapping]);
					if (name) thisReflectApply(thisMapSet, protoName, [proto, name]);
				}
				return thisProxyOther(factory, object, proto, preventUnwrap);
			}]);
	}

	const result = {
		__proto__: null,
		globalPrototypes: thisGlobalPrototypes,
		safeGetOwnPropertyDescriptor: thisSafeGetOwnPropertyDescriptor,
		fromArguments: thisFromOtherArguments,
		from: thisFromOther,
		fromWithFactory: thisFromOtherWithFactory,
		ensureThis: thisEnsureThis,
		mapping: mappingOtherToThis,
		connect: thisConnect,
		reflectSet: thisReflectSet,
		reflectGet: thisReflectGet,
		reflectDefineProperty: thisReflectDefineProperty,
		reflectDeleteProperty: thisReflectDeleteProperty,
		reflectApply: thisReflectApply,
		reflectConstruct: thisReflectConstruct,
		reflectHas: thisReflectHas,
		reflectOwnKeys: thisReflectOwnKeys,
		reflectEnumerate: thisReflectEnumerate,
		reflectGetPrototypeOf: thisReflectGetPrototypeOf,
		reflectIsExtensible: thisReflectIsExtensible,
		reflectPreventExtensions: thisReflectPreventExtensions,
		objectHasOwnProperty: thisObjectHasOwnProperty,
		weakMapSet: thisWeakMapSet,
		addProtoMapping: thisAddProtoMapping,
		addProtoMappingFactory: thisAddProtoMappingFactory,
		defaultFactory,
		protectedFactory,
		readonlyFactory,
		VMError
	};

	const isHost = typeof otherInit !== 'object';

	if (isHost) {
		otherInit = otherInit(result, registerProxy);
	}

	result.other = otherInit;

	const {
		globalPrototypes: otherGlobalPrototypes,
		safeGetOwnPropertyDescriptor: otherSafeGetOwnPropertyDescriptor,
		fromArguments: otherFromThisArguments,
		from: otherFromThis,
		mapping: mappingThisToOther,
		reflectSet: otherReflectSet,
		reflectGet: otherReflectGet,
		reflectDefineProperty: otherReflectDefineProperty,
		reflectDeleteProperty: otherReflectDeleteProperty,
		reflectApply: otherReflectApply,
		reflectConstruct: otherReflectConstruct,
		reflectHas: otherReflectHas,
		reflectOwnKeys: otherReflectOwnKeys,
		reflectEnumerate: otherReflectEnumerate,
		reflectGetPrototypeOf: otherReflectGetPrototypeOf,
		reflectIsExtensible: otherReflectIsExtensible,
		reflectPreventExtensions: otherReflectPreventExtensions,
		objectHasOwnProperty: otherObjectHasOwnProperty,
		weakMapSet: otherWeakMapSet
	} = otherInit;

	// Cache the other realm's Function constructors to block them from crossing the bridge.
	// This prevents sandbox escape via indirect access paths like
	// Object.getOwnPropertyDescriptor(Function.prototype, 'constructor').value
	// We block all code-executing constructors: Function, AsyncFunction, GeneratorFunction, AsyncGeneratorFunction
	// IMPORTANT: We must get these from otherGlobalPrototypes (the OTHER realm), not from
	// local function instances which would give us THIS realm's constructors.
	let otherFunctionCtor;
	let otherAsyncFunctionCtor;
	let otherGeneratorFunctionCtor;
	let otherAsyncGeneratorFunctionCtor;
	try {
		const desc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Function, 'constructor');
		if (desc) otherFunctionCtor = desc.value;
	} catch (e) {
		// If we can't get it, the get trap's constructor case still provides protection
	}
	// Get AsyncFunction, GeneratorFunction, AsyncGeneratorFunction constructors from OTHER realm
	try {
		if (otherGlobalPrototypes.AsyncFunction) {
			const desc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.AsyncFunction, 'constructor');
			if (desc) otherAsyncFunctionCtor = desc.value;
		}
	} catch (e) {}
	try {
		if (otherGlobalPrototypes.GeneratorFunction) {
			const desc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.GeneratorFunction, 'constructor');
			if (desc) otherGeneratorFunctionCtor = desc.value;
		}
	} catch (e) {}
	try {
		if (otherGlobalPrototypes.AsyncGeneratorFunction) {
			const desc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.AsyncGeneratorFunction, 'constructor');
			if (desc) otherAsyncGeneratorFunctionCtor = desc.value;
		}
	} catch (e) {}

	function isDangerousFunctionConstructor(value) {
		return value === otherFunctionCtor ||
			value === otherAsyncFunctionCtor ||
			value === otherGeneratorFunctionCtor ||
			(otherAsyncGeneratorFunctionCtor && value === otherAsyncGeneratorFunctionCtor); // AsyncGeneratorFunction is not available on Node < 10
	}

	// SECURITY (GHSA-55hx): Cache the OTHER realm's Promise.prototype methods so
	// the apply trap can identify host-realm Promise methods and wrap callbacks.
	let otherPromiseThen;
	let otherPromiseCatch;
	let otherPromiseFinally;
	try {
		if (otherGlobalPrototypes.Promise) {
			const dt = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Promise, 'then');
			if (dt) otherPromiseThen = dt.value;
			const dc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Promise, 'catch');
			if (dc) otherPromiseCatch = dc.value;
			const df = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Promise, 'finally');
			if (df) otherPromiseFinally = df.value;
		}
	} catch (e) {
		// Best effort — if we cannot read host Promise.prototype, the sandbox-side
		// override remains the last line of defense for sandbox-realm promises.
	}

	// SECURITY (GHSA-vwrp-x96c-mhwq): Identity set of every host-realm object
	// that the sandbox must never be able to mutate. Populated at bridge init
	// with every cached intrinsic prototype + corresponding constructor.
	//
	// Sandbox code that walks `__proto__` via a Buffer.apply chain (or any
	// similar primitive) can surface one of these host intrinsics as the
	// wrapped object of a bridge proxy. The BaseHandler write traps would
	// otherwise forward the mutation into the real host object via
	// otherReflectSet / otherReflectDefineProperty / otherReflectDeleteProperty /
	// otherReflectPreventExtensions, bleeding attacker-controlled state into
	// every host-realm object of that class -- full prototype pollution plus
	// host DoS via preventExtensions.
	//
	// Enforced only on the sandbox->host direction (`!isHost`).
	const protectedHostObjects = new ThisWeakMap();
	function addProtectedHostObject(value) {
		if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
		try {
			thisReflectApply(thisWeakMapSet, protectedHostObjects, [value, true]);
		} catch (e) { /* best effort */ }
	}
	try {
		const protoKeys = thisReflectOwnKeys(otherGlobalPrototypes);
		for (let i = 0; i < protoKeys.length; i++) {
			const p = otherGlobalPrototypes[protoKeys[i]];
			addProtectedHostObject(p);
			try {
				const desc = otherSafeGetOwnPropertyDescriptor(p, 'constructor');
				if (desc && !desc.get && !desc.set) addProtectedHostObject(desc.value);
			} catch (e) { /* best effort */ }
		}
	} catch (e) { /* best effort */ }

	function isProtectedHostObject(object) {
		if (isHost) return false;
		if (object === null || (typeof object !== 'object' && typeof object !== 'function')) return false;
		try {
			return thisReflectApply(thisWeakMapHas, protectedHostObjects, [object]) === true;
		} catch (e) {
			return false;
		}
	}

	function isHostPromiseThen(value) {
		return otherPromiseThen !== undefined && value === otherPromiseThen;
	}

	function isHostPromiseCatch(value) {
		return otherPromiseCatch !== undefined && value === otherPromiseCatch;
	}

	function isHostPromiseFinally(value) {
		// .finally callbacks receive no value, but the chained promise it returns
		// will propagate the parent's rejection. We do not need to wrap the
		// onFinally itself, only ensure the returned promise's chained .then/.catch
		// (also intercepted here) are wrapped.
		return otherPromiseFinally !== undefined && value === otherPromiseFinally;
	}

	// SECURITY (GHSA-55hx): sanitizer hooks installed by setup-sandbox.js via
	// thisSetHostPromiseSanitizers(handleException, ensureThis).
	let hostPromiseSanitizeReject = null;
	let hostPromiseSanitizeFulfill = null;

	function wrapHostPromiseThenArgs(args) {
		// args is a this(sandbox)-realm safe-array of args the sandbox is passing
		// to host Promise.prototype.then. Replace function callbacks at indices 0
		// (onFulfilled) and 1 (onRejected) with sandbox wrappers that route their
		// argument through ensureThis / handleException before invoking the
		// original callback. New array — no in-place mutation.
		const out = [];
		const len = args.length;
		for (let i = 0; i < len; i++) {
			let v = args[i];
			if (i === 0 && typeof v === 'function') {
				const onFulfilled = v;
				v = function sanitizedOnFulfilled(value) {
					value = hostPromiseSanitizeFulfill(value);
					return thisReflectApply(onFulfilled, this, [value]);
				};
			} else if (i === 1 && typeof v === 'function') {
				const onRejected = v;
				v = function sanitizedOnRejected(error) {
					error = hostPromiseSanitizeReject(error);
					return thisReflectApply(onRejected, this, [error]);
				};
			}
			thisReflectDefineProperty(out, i, {
				__proto__: null,
				value: v,
				writable: true,
				enumerable: true,
				configurable: true
			});
		}
		return out;
	}

	function wrapHostPromiseCatchArgs(args) {
		const out = [];
		const len = args.length;
		for (let i = 0; i < len; i++) {
			let v = args[i];
			if (i === 0 && typeof v === 'function') {
				const onRejected = v;
				v = function sanitizedCatch(error) {
					error = hostPromiseSanitizeReject(error);
					return thisReflectApply(onRejected, this, [error]);
				};
			}
			thisReflectDefineProperty(out, i, {
				__proto__: null,
				value: v,
				writable: true,
				enumerable: true,
				configurable: true
			});
		}
		return out;
	}

	function thisSetHostPromiseSanitizers(sanitizeReject, sanitizeFulfill) {
		if (typeof sanitizeReject !== 'function' || typeof sanitizeFulfill !== 'function') {
			throw new VMError('setHostPromiseSanitizers requires two functions');
		}
		hostPromiseSanitizeReject = sanitizeReject;
		hostPromiseSanitizeFulfill = sanitizeFulfill;
	}

	// Check if an object's own property descriptors contain a dangerous function
	// constructor (data value or accessor get/set). Shallow — does NOT recurse
	// into nested object values; each nested host object that crosses the
	// bridge gets its own shallow check at that layer. Layered descriptor-
	// extraction attacks (e.g. getOwnPropertyDescriptor on
	// getOwnPropertyDescriptors result) are caught at the layer where the
	// Function constructor is exposed at depth 1. (origin/main commit 8dd0591.)
	function containsDangerousConstructor(obj) {
		if (obj === null || typeof obj !== 'object') return false;

		let keys;
		try {
			keys = otherReflectOwnKeys(obj);
		} catch (e) {
			return false;
		}

		for (let i = 0; i < keys.length; i++) {
			let desc;
			try {
				desc = otherSafeGetOwnPropertyDescriptor(obj, keys[i]);
			} catch (e) {
				continue;
			}
			if (!desc) continue;

			if (desc.get || desc.set) {
				if (isDangerousFunctionConstructor(desc.get) || isDangerousFunctionConstructor(desc.set)) return true;
			} else if (isDangerousFunctionConstructor(desc.value)) {
				return true;
			}
		}
		return false;
	}

	function thisOtherHasOwnProperty(object, key) {
		// Note: object@other(safe) key@prim throws@this(unsafe)
		try {
			return otherReflectApply(otherObjectHasOwnProperty, object, [key]) === true;
		} catch (e) { // @other(unsafe)
			throw thisFromOtherForThrow(e);
		}
	}

	// SECURITY (GHSA-grj5-jjm8-h35p): Array species self-return escape defense.
	//
	// INVARIANT: When the bridge invokes a host function, no host-realm array used as
	// `this` (context) or as an argument may have an attacker-controlled `constructor`
	// property visible to V8's internal ArraySpeciesCreate during the call.
	//
	// WHY: V8's ArraySpeciesCreate (used by Array#map/filter/slice/concat/splice and
	// TypedArray equivalents) reads `this.constructor[Symbol.species]` DIRECTLY on the
	// raw host object, completely bypassing our proxy traps. If an attacker can install
	// a sandbox function `x` with `x[Symbol.species] = x` as the host array's constructor,
	// then call `r.map(f)` through the bridge, V8 will call `new x(len)` (returning `r`
	// itself) and store mapped values directly into `r` via CreateDataPropertyOrThrow,
	// bypassing the bridge entirely -- the attacker reads them back from `r`.
	//
	// The prior fixes (ebcfe94, 9084cd6) blocked the Function-constructor exfiltration
	// chain that this primitive was originally composed with, but the primitive itself
	// -- writing raw host values into a sandbox-visible slot -- remained a bridge bypass.
	// This defense closes the class.
	//
	// Strategy:
	//   1. Before every sandbox->host function invocation (apply/construct traps), walk
	//      `context` and each element of `args`. For every host array found, neutralize
	//      its species state by installing `constructor = undefined` as a data own
	//      property. An own-property `undefined` shadows any own or inherited ctor, and
	//      ArraySpeciesCreate treats undefined as "use the default %Array% constructor"
	//      (spec ES2024 23.1.3.1 step 3), producing a fresh plain array.
	//   2. After the call completes (finally), restore the original state: if the array
	//      had an own `constructor` descriptor before, re-install it; otherwise delete
	//      our shadow.
	//   3. If any host array is non-extensible or has a non-configurable `constructor`
	//      that isn't already `undefined`, reject the call with VMError rather than
	//      proceeding with an un-neutralizable species channel.
	//
	// This neutralize-on-entry/restore-on-exit pattern is analogous to resetPromiseSpecies
	// in setup-sandbox.js, which defends the same V8-internal-bypass class for Promises.

	// SECURITY: Sentinel used to tag saved-state records. Using a unique module-local
	// object ensures we never confuse attacker-installed state with our own.
	const SPECIES_NEUTRALIZED = {__proto__: null};

	// SECURITY: Neutralize the ArraySpeciesCreate channel on a single host array.
	// Returns an opaque saved-state record to be passed to restoreArraySpeciesOn,
	// or null if `arr` did not need neutralization (not an array / not host-realm).
	// Throws VMError if the array's species state cannot be safely neutralized
	// (non-configurable attacker-installed constructor, non-extensible with a
	// constructor own property, etc.).
	function neutralizeArraySpeciesOn(arr) {
		// SECURITY: only host-realm raw arrays need neutralization. Sandbox arrays
		// that cross back are already fresh objects produced by thisFromOtherArguments
		// (which creates them with thisReflectDefineProperty in the local realm) --
		// V8 internal reads on those happen in the local realm too, and the
		// local-realm Array.prototype.constructor is not attacker-controlled.
		if (arr === null || typeof arr !== 'object') return null;
		let isHostArray;
		try {
			// SECURITY: thisArrayIsArray works cross-realm -- Array.isArray returns
			// true for any ECMAScript Array exotic object regardless of realm.
			isHostArray = thisArrayIsArray(arr);
		} catch (e) {
			return null;
		}
		if (!isHostArray) return null;

		// SECURITY: capture original own descriptor (if any) before mutating.
		let originalDesc;
		try {
			originalDesc = otherSafeGetOwnPropertyDescriptor(arr, 'constructor');
		} catch (e) { // @other(unsafe)
			throw thisFromOtherForThrow(e);
		}

		// SECURITY: if attacker pre-installed a non-configurable `constructor`, we
		// cannot safely remove or shadow it for the duration of the call. Reject.
		if (originalDesc && originalDesc.configurable === false) {
			// An existing non-configurable `constructor === undefined` data property
			// is the already-neutralized shape we want. Anything else is an attack.
			if (!(originalDesc.value === undefined && originalDesc.writable === false)) {
				throw new VMError('Unsafe array constructor cannot be neutralized');
			}
			// Already safely neutralized; no-op.
			return null;
		}

		// SECURITY: if array is non-extensible and has no own `constructor` slot, we
		// cannot install our shadow. The inherited Array.prototype.constructor value
		// is benign (host %Array%), but an attacker may have shadowed it via the
		// prototype chain (setPrototypeOf to an intermediate proto). Reject.
		let isExt;
		try {
			isExt = otherReflectIsExtensible(arr);
		} catch (e) {
			throw thisFromOtherForThrow(e);
		}
		if (!isExt && !originalDesc) {
			throw new VMError('Unsafe non-extensible array passed across bridge');
		}

		// SECURITY: install `constructor = undefined` as a data own property. This
		// shadows any inherited or attacker-installed constructor; V8's
		// ArraySpeciesCreate treats undefined as "use %Array%", producing a fresh
		// plain array that is NOT the attacker's target.
		let defined;
		try {
			defined = otherReflectDefineProperty(arr, 'constructor', {
				__proto__: null,
				value: undefined,
				writable: true,
				enumerable: false,
				configurable: true
			});
		} catch (e) { // @other(unsafe)
			throw thisFromOtherForThrow(e);
		}
		if (!defined) {
			// SECURITY: defineProperty returned false (e.g., frozen object). Reject.
			throw new VMError('Unsafe array state; cannot neutralize species');
		}

		return {
			__proto__: null,
			arr: arr,
			originalDesc: originalDesc,
			marker: SPECIES_NEUTRALIZED
		};
	}

	// SECURITY: Restore the original `constructor` state on a host array after the
	// guarded host call completes. Called from a `finally` block so that errors in
	// the host call do not leave the array in a neutralized state.
	function restoreArraySpeciesOn(saved) {
		if (!saved || saved.marker !== SPECIES_NEUTRALIZED) return;
		const {arr, originalDesc} = saved;
		try {
			if (originalDesc) {
				// SECURITY: put back exactly what was there before (including any
				// non-writable/non-enumerable flags). originalDesc has __proto__ null
				// already (via otherSafeGetOwnPropertyDescriptor).
				otherReflectDefineProperty(arr, 'constructor', originalDesc);
			} else {
				// SECURITY: no prior own property -- remove our shadow so inherited
				// constructor becomes visible again (preserves legitimate API semantics).
				otherReflectDeleteProperty(arr, 'constructor');
			}
		} catch (e) {
			// SECURITY: swallow restore errors -- the array is in an inert (undefined
			// constructor) state, which is strictly safer than leaving it unrestored
			// if there were an exception. We intentionally do NOT re-throw because
			// this runs in a finally that must not mask the primary error.
		}
	}

	// SECURITY: Walk `context` and every element of `args`, neutralize species on
	// each host array found, return a flat list of saved-state records. Used by the
	// apply/construct traps. The returned list must be passed to restoreArraySpeciesBatch
	// in a `finally` block.
	function neutralizeArraySpeciesBatch(context, args) {
		const saved = [];
		const c = neutralizeArraySpeciesOn(context);
		if (c) saved[saved.length] = c;
		if (args) {
			// SECURITY: args is @other(safe-array) produced by otherFromThisArguments,
			// length/index access is safe. We defensively use a cached length to
			// avoid accidental getter invocation.
			const len = args.length | 0;
			for (let i = 0; i < len; i++) {
				const s = neutralizeArraySpeciesOn(args[i]);
				if (s) saved[saved.length] = s;
			}
		}
		return saved;
	}

	// SECURITY: Restore every host array in a saved list. Must not throw.
	function restoreArraySpeciesBatch(savedList) {
		if (!savedList) return;
		const len = savedList.length | 0;
		for (let i = 0; i < len; i++) {
			restoreArraySpeciesOn(savedList[i]);
		}
	}

	// SECURITY (GHSA-47x8-96vw-5wg6): Host-side scrub for values returned to the
	// sandbox by any host->sandbox `apply` call. The per-value symbol filter in
	// thisFromOtherWithFactory handles primitives that transit one at a time, but
	// it does NOT remove a dangerous symbol sitting as an element of a returned
	// host array or as a key of a returned host descriptor object -- the bridge
	// wraps those containers, and the filter fires only at the moment a specific
	// element is read. Defense-in-depth: scrub the raw host container before it
	// is ever wrapped, so any further path that would enumerate it (internal
	// algorithms, direct `Reflect.*` calls, prototype-walk re-entry) sees no
	// dangerous symbol to begin with.
	//
	// Only acts on sandbox-side bridge (isHost === false) and only touches the
	// result directly; never walks into nested host objects.
	function stripDangerousSymbolsFromHostResult(ret) {
		if (isHost) return;
		if (ret === null || (typeof ret !== 'object' && typeof ret !== 'function')) return;
		let isArr;
		try {
			isArr = thisArrayIsArray(ret);
		} catch (e) {
			return;
		}
		if (isArr) {
			// Array: drop any element that is a dangerous cross-realm symbol.
			// We splice by re-indexing via otherReflectDefineProperty into a
			// compact range, then trim length. Using otherReflect* keeps us on
			// the host realm's own property machinery.
			let len;
			try {
				len = ret.length | 0;
			} catch (e) {
				return;
			}
			let w = 0;
			for (let r = 0; r < len; r++) {
				let v;
				try {
					v = otherReflectGet(ret, r);
				} catch (e) {
					return;
				}
				if (typeof v === 'symbol' && isDangerousCrossRealmSymbol(v)) continue;
				if (w !== r) {
					try {
						otherReflectDefineProperty(ret, w, {
							__proto__: null,
							value: v,
							writable: true,
							enumerable: true,
							configurable: true
						});
					} catch (e) {
						return;
					}
				}
				w++;
			}
			if (w !== len) {
				for (let i = w; i < len; i++) {
					try {
						otherReflectDeleteProperty(ret, i);
					} catch (e) { /* best effort */ }
				}
				try {
					otherReflectDefineProperty(ret, 'length', {
						__proto__: null,
						value: w,
						writable: true,
						enumerable: false,
						configurable: false
					});
				} catch (e) { /* best effort: non-writable length arrays stay over-long, per-element filter still strips */ }
			}
			return;
		}
		// Non-array object (e.g. Object.getOwnPropertyDescriptors return): delete
		// any own property keyed by a dangerous cross-realm symbol. Using the
		// host's Reflect.deleteProperty avoids any proxy invariants that apply
		// to the sandbox-local descriptor filter.
		try {
			otherReflectDeleteProperty(ret, thisSymbolNodeJSUtilInspectCustom);
		} catch (e) { /* best effort */ }
		try {
			otherReflectDeleteProperty(ret, thisSymbolNodeJSRejection);
		} catch (e) { /* best effort */ }
	}

	function thisDefaultGet(handler, object, key, desc) {
		// Note: object@other(unsafe) key@prim desc@other(safe)
		let ret; // @other(unsafe)
		if (desc.get || desc.set) {
			const getter = desc.get;
			if (!getter) return undefined;
			try {
				ret = otherReflectApply(getter, object, [key]);
			} catch (e) {
				throw thisFromOtherForThrow(e);
			}
		} else {
			ret = desc.value;
		}
		return handlerFromOtherWithContext(handler, ret);
	}

	function otherFromThisIfAvailable(to, from, key) {
		// Note: to@other(safe) from@this(safe) key@prim throws@this(unsafe)
		if (!thisReflectApply(thisObjectHasOwnProperty, from, [key])) return false;
		try {
			to[key] = otherFromThis(from[key]);
		} catch (e) { // @other(unsafe)
			throw thisFromOtherForThrow(e);
		}
		return true;
	}

	class BaseHandler extends SafeBase {

		constructor(token, object) {
			// Note: token@this(unsafe) object@other(unsafe) throws@this(unsafe)
			// SECURITY (GHSA-v37h-5mfm-c47c): Require the module-local
			// construction token. Attackers who reach BaseHandler via the
			// prototype of a leaked handler (e.g., through util.inspect
			// showProxy) cannot read this Symbol -- it lives only in the
			// closure of createBridge. Any direct `new BaseHandler(...)`,
			// `Reflect.construct(...)`, or subclass instantiation from
			// sandbox code therefore throws before the WeakMap registration
			// runs, so `getHandlerObject(this)` throws VMError later and no
			// trap method can operate on the forged instance.
			if (token !== constructionToken) throw new VMError(OPNA);
			super();
			// Store the object in a WeakMap instead of as an instance property.
			// This prevents leaking the raw object via util.inspect with showProxy:true,
			// which exposes proxy handlers and their properties.
			// NOTE: There is intentionally NO getObject() method on this class.
			// The object is retrieved via the closure-scoped getHandlerObject() function,
			// which is not accessible to attackers even if they obtain a handler reference.
			thisReflectApply(thisWeakMapSet, handlerToObject, [this, object]);
			// Store the factory in a WeakMap instead of as a method.
			// NOTE: There is intentionally NO getFactory() method on this class.
			// The factory is retrieved via the closure-scoped getHandlerFactory() function,
			// which is not accessible to attackers even if they obtain a handler reference.
			// Subclass constructors override this with their specific factory.
			thisReflectApply(thisWeakMapSet, handlerToFactory, [this, defaultFactory]);
		}

		get(target, key, receiver) {
			if (key === 'isProxy') return true;
			// Note: target@this(unsafe) key@prim receiver@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			switch (key) {
				case 'constructor': {
					// SECURITY (GHSA-grj5-jjm8-h35p): If the underlying object is a
					// host-realm array, ALWAYS return the sandbox-realm Array constructor
					// (via the target's prototype). This neutralizes the species channel
					// that V8's ArraySpeciesCreate reads via `this.constructor` during
					// Array.prototype.{map,filter,slice,concat,splice,...}. Attackers
					// who install a malicious `constructor` (directly, via defineProperty,
					// via Object.assign, or via prototype injection) cannot leak it back
					// into V8's species resolution, because this trap short-circuits to
					// the safe sandbox Array. Sandbox-originated arrays are unaffected
					// -- their target prototype is sandbox Array.prototype, and its
					// .constructor is sandbox Array (the same return value).
					//
					// This covers the case where sandbox Array.prototype.map runs on
					// a host-backed proxy and reads `r.constructor` via this proxy.get
					// trap. The apply-trap-based neutralize (below) covers the case
					// where a host Array.prototype.map runs in the host realm on the
					// raw array directly (via otherReflectApply).
					let isArr = false;
					try {
						isArr = thisArrayIsArray(target);
					} catch (e) {}
					if (isArr) {
						// SECURITY: return the cached this-realm Array constructor.
						// Do NOT read via `proto.constructor` -- that's vulnerable to
						// prototype pollution (Array.prototype.constructor = attackerFn).
						// thisArrayCtor is captured at module load time before any
						// sandbox code can execute, so it is immutable from the
						// attacker's perspective.
						return thisArrayCtor;
					}
					const desc = otherSafeGetOwnPropertyDescriptor(object, key);
					if (desc) {
						if (desc.value && isDangerousFunctionConstructor(desc.value)) return {};
						return thisDefaultGet(this, object, key, desc);
					}
					const proto = thisReflectGetPrototypeOf(target);
					if (proto === null) return undefined;
					const ctor = proto.constructor;
					// Defense in depth: block this-realm dangerous function constructors.
					// Normally handler methods are only called by the proxy mechanism
					// which handles return values safely, but if the handler is exposed
					// (e.g., via util.inspect showProxy), attackers can call get()
					// directly with a forged target, leaking raw host constructors.
					if (isThisDangerousFunctionConstructor(ctor)) return {};
					return ctor;
				}
				case '__proto__': {
					const desc = otherSafeGetOwnPropertyDescriptor(object, key);
					if (desc) return thisDefaultGet(this, object, key, desc);
					return thisReflectGetPrototypeOf(target);
				}
				case thisSymbolToStringTag:
					if (!thisOtherHasOwnProperty(object, thisSymbolToStringTag)) {
						const proto = thisReflectGetPrototypeOf(target);
						const name = thisReflectApply(thisMapGet, protoName, [proto]);
						if (name) return name;
					}
					break;
				case 'arguments':
				case 'caller':
				case 'callee':
					if (typeof object === 'function' && thisOtherHasOwnProperty(object, key)) {
						throw thisThrowCallerCalleeArgumentsAccess(key);
					}
					break;
			}
			let ret; // @other(unsafe)
			try {
				ret = otherReflectGet(object, key);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			return handlerFromOtherWithContext(this,ret);
		}

		set(target, key, value, receiver) {
			// Note: target@this(unsafe) key@prim value@this(unsafe) receiver@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			// SECURITY (GHSA-vwrp-x96c-mhwq): refuse sandbox-originated writes
			// targeting any host-realm intrinsic prototype or constructor.
			// Covers C1 (plain assignment), C2 (Reflect.set), and C5
			// (Object.assign) because all of them funnel through this trap.
			if (isProtectedHostObject(object)) throw new VMError(OPNA);
			if (key === '__proto__' && !thisOtherHasOwnProperty(object, key)) {
				return this.setPrototypeOf(target, value);
			}
			// Intercept constructor writes to host arrays.
			// V8's ArraySpeciesCreate reads constructor[Symbol.species] on the raw
			// host object, bypassing proxy traps. If an attacker sets constructor
			// to a species-returning function, map/filter/etc. store raw host values
			// directly, bypassing bridge sanitization.
			// Store the value on the proxy target (this-realm) instead of the host array.
			if (key === 'constructor' && thisArrayIsArray(object)) {
				thisReflectSet(target, key, value);
				return true;
			}
			try {
				value = otherFromThis(value);
				return otherReflectSet(object, key, value) === true;
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
		}

		getPrototypeOf(target) {
			// Note: target@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return thisReflectGetPrototypeOf(target);
		}

		setPrototypeOf(target, value) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			throw new VMError(OPNA);
		}

		apply(target, context, args) {
			// Note: target@this(unsafe) context@this(unsafe) args@this(safe-array) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			// SECURITY (GHSA-55hx): if the host function being applied is one of
			// host's Promise.prototype.then/catch/finally, wrap the sandbox-supplied
			// callbacks so their argument values flow through handleException /
			// ensureThis before the user code runs. Without this, host promise
			// machinery delivers raw rejection values whose nested fields (e.g.
			// SuppressedError.error) escape recursive sandbox-side sanitization.
			if (!isHost && hostPromiseSanitizeReject !== null) {
				if (isHostPromiseThen(object)) {
					args = wrapHostPromiseThenArgs(args);
				} else if (isHostPromiseCatch(object)) {
					args = wrapHostPromiseCatchArgs(args);
				} else if (isHostPromiseFinally(object)) {
					// .finally callback receives no args — no callback wrapping
					// needed. Sanitization for downstream .then/.catch is enforced
					// by recursive interception when those methods are called on
					// the returned promise.
				}
			}
			let ret; // @other(unsafe)
			let savedSpecies = null; // SECURITY: GHSA-grj5-jjm8-h35p -- see neutralizeArraySpeciesBatch
			try {
				context = otherFromThis(context);
				args = otherFromThisArguments(args);
				// SECURITY (GHSA-grj5-jjm8-h35p): Before invoking the host function,
				// neutralize any attacker-installed `constructor`/Symbol.species channel
				// on every host-realm array reachable as `context` or as a top-level
				// argument. V8's ArraySpeciesCreate reads these properties on the raw
				// object and will store raw host values into a sandbox-visible array,
				// bypassing the bridge, unless we shadow them here. This batch+restore
				// design supersedes the no-restore neutralize from #563 — that variant
				// permanently mutated host arrays' `constructor` to undefined, which
				// breaks legitimate downstream reads of `arr.constructor`.
				savedSpecies = neutralizeArraySpeciesBatch(context, args);
				ret = otherReflectApply(object, context, args);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			} finally {
				// SECURITY: restore the pre-call species state even if the host call
				// threw. `restoreArraySpeciesBatch` is guaranteed not to throw.
				restoreArraySpeciesBatch(savedSpecies);
			}
			// SECURITY (GHSA-47x8-96vw-5wg6): Defense-in-depth scrub on host-produced
			// container results (arrays or plain objects) before wrapping. The
			// per-element symbol filter in thisFromOtherWithFactory covers the common
			// read path, but stripping the raw host container closes bypasses that
			// enumerate the result through paths the bridge cannot intercept (e.g.
			// a host method using an extracted host Reflect/Object reference).
			stripDangerousSymbolsFromHostResult(ret);
			return thisFromOther(ret);
		}

		construct(target, args, newTarget) {
			// Note: target@this(unsafe) args@this(safe-array) newTarget@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			let ret; // @other(unsafe)
			let savedSpecies = null; // SECURITY: GHSA-grj5-jjm8-h35p
			try {
				args = otherFromThisArguments(args);
				// SECURITY (GHSA-grj5-jjm8-h35p): constructors can internally invoke
				// ArraySpeciesCreate on argument arrays (e.g., Array(arr) copies, typed
				// array constructors, Promise.all on an iterable), so neutralize args
				// before the call as well.
				savedSpecies = neutralizeArraySpeciesBatch(null, args);
				ret = otherReflectConstruct(object, args);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			} finally {
				restoreArraySpeciesBatch(savedSpecies);
			}
			// SECURITY (GHSA-47x8-96vw-5wg6): see apply() counterpart. Constructors
			// that wrap arrays (e.g. TypedArray from iterable) may return containers
			// with dangerous symbol elements/keys; strip before wrapping.
			stripDangerousSymbolsFromHostResult(ret);
			return thisFromOtherWithFactory(getHandlerFactory(this), ret, thisFromOther(object));
		}

		getOwnPropertyDescriptorDesc(target, prop, desc) {
			// Note: target@this(unsafe) prop@prim desc@other{safe} throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			if (desc && typeof object === 'function' && (prop === 'arguments' || prop === 'caller' || prop === 'callee')) desc.value = null;
			// Block sandbox access to host's Function constructor via getOwnPropertyDescriptor.
			// This mirrors the protection in the get() trap at the 'constructor' case.
			// Only block when sandbox (!isHost) accesses host objects, not when host inspects sandbox.
			if (!isHost && desc && prop === 'constructor' && desc.value && isDangerousFunctionConstructor(desc.value)) {
				return undefined;
			}
			return desc;
		}

		getOwnPropertyDescriptor(target, prop) {
			// Note: target@this(unsafe) prop@prim throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			// Filter dangerous cross-realm symbols to prevent extraction
			if (isDangerousCrossRealmSymbol(prop)) return undefined;
			const object = getHandlerObject(this); // @other(unsafe)
			let desc; // @other(safe)
			try {
				desc = otherSafeGetOwnPropertyDescriptor(object, prop);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}

			desc = this.getOwnPropertyDescriptorDesc(target, prop, desc);

			if (!desc) return undefined;

			let thisDesc;
			if (desc.get || desc.set) {
				thisDesc = {
					__proto__: null,
					get: handlerFromOtherWithContext(this,desc.get),
					set: handlerFromOtherWithContext(this,desc.set),
					enumerable: desc.enumerable === true,
					configurable: desc.configurable === true
				};
			} else {
				thisDesc = {
					__proto__: null,
					value: handlerFromOtherWithContext(this,desc.value),
					writable: desc.writable === true,
					enumerable: desc.enumerable === true,
					configurable: desc.configurable === true
				};
			}
			if (!thisDesc.configurable) {
				const oldDesc = thisSafeGetOwnPropertyDescriptor(target, prop);
				if (!oldDesc || oldDesc.configurable || oldDesc.writable !== thisDesc.writable) {
					if (!thisReflectDefineProperty(target, prop, thisDesc)) throw thisUnexpected();
				}
			}
			return thisDesc;
		}

		definePropertyDesc(target, prop, desc) {
			// Note: target@this(unsafe) prop@prim desc@this(safe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return desc;
		}

		defineProperty(target, prop, desc) {
			// Note: target@this(unsafe) prop@prim desc@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			// SECURITY (GHSA-vwrp-x96c-mhwq): refuse sandbox-originated
			// defineProperty calls targeting any host-realm intrinsic
			// prototype or constructor. Covers C3 (Object.defineProperty).
			if (isProtectedHostObject(object)) throw new VMError(OPNA);
			if (!thisReflectSetPrototypeOf(desc, null)) throw thisUnexpected();

			// Intercept defineProperty for constructor on host arrays.
			// Same rationale as the set trap: prevent ArraySpeciesCreate manipulation.
			if (prop === 'constructor' && thisArrayIsArray(object)) {
				thisReflectDefineProperty(target, prop, desc);
				return true;
			}

			desc = this.definePropertyDesc(target, prop, desc);

			if (!desc) return false;

			let otherDesc = {__proto__: null};
			let hasFunc = true;
			let hasValue = true;
			let hasBasic = true;
			hasFunc &= otherFromThisIfAvailable(otherDesc, desc, 'get');
			hasFunc &= otherFromThisIfAvailable(otherDesc, desc, 'set');
			hasValue &= otherFromThisIfAvailable(otherDesc, desc, 'value');
			hasValue &= otherFromThisIfAvailable(otherDesc, desc, 'writable');
			hasBasic &= otherFromThisIfAvailable(otherDesc, desc, 'enumerable');
			hasBasic &= otherFromThisIfAvailable(otherDesc, desc, 'configurable');

			try {
				if (!otherReflectDefineProperty(object, prop, otherDesc)) return false;
				if (otherDesc.configurable !== true && (!hasBasic || !(hasFunc || hasValue))) {
					otherDesc = otherSafeGetOwnPropertyDescriptor(object, prop);
				}
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}

			if (!otherDesc.configurable) {
				let thisDesc;
				if (otherDesc.get || otherDesc.set) {
					thisDesc = {
						__proto__: null,
						get: handlerFromOtherWithContext(this,otherDesc.get),
						set: handlerFromOtherWithContext(this,otherDesc.set),
						enumerable: otherDesc.enumerable,
						configurable: otherDesc.configurable
					};
				} else {
					thisDesc = {
						__proto__: null,
						value: handlerFromOtherWithContext(this,otherDesc.value),
						writable: otherDesc.writable,
						enumerable: otherDesc.enumerable,
						configurable: otherDesc.configurable
					};
				}
				if (!thisReflectDefineProperty(target, prop, thisDesc)) throw thisUnexpected();
			}
			return true;
		}

		deleteProperty(target, prop) {
			// Note: target@this(unsafe) prop@prim throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			// SECURITY (GHSA-vwrp-x96c-mhwq): refuse sandbox-originated
			// property deletion targeting any host-realm intrinsic prototype
			// or constructor. Covers C4 (delete hostProto.prop), which could
			// otherwise remove `hasOwnProperty`, `toString`, etc. from every
			// host object of that class.
			if (isProtectedHostObject(object)) throw new VMError(OPNA);
			try {
				return otherReflectDeleteProperty(object, prop) === true;
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
		}

		has(target, key) {
			// Note: target@this(unsafe) key@prim throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			// Filter dangerous cross-realm symbols
			if (isDangerousCrossRealmSymbol(key)) return false;
			const object = getHandlerObject(this); // @other(unsafe)
			try {
				return otherReflectHas(object, key) === true;
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
		}

		isExtensible(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			try {
				if (otherReflectIsExtensible(object)) return true;
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			if (thisReflectIsExtensible(target)) {
				doPreventExtensions(this, target);
			}
			return false;
		}

		ownKeys(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			let res; // @other(unsafe)
			try {
				res = otherReflectOwnKeys(object);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			// SECURITY (GHSA-47x8-96vw-5wg6): Iterate the raw host result directly via
			// otherReflectGet instead of wrapping it with thisFromOther first. Wrapping
			// makes per-element reads transit thisFromOtherWithFactory's 'symbol' branch,
			// which returns `undefined` for dangerous cross-realm symbols. That undefined
			// would then survive the dangerous-symbol check below and be pushed into the
			// ownKeys result -- a Proxy invariant violation (property keys must be string
			// or symbol, never undefined). Reading directly gives us the raw symbol so we
			// can detect and drop it instead of re-emitting an invalid key.
			const filtered = [];
			let len;
			try {
				len = res.length | 0;
			} catch (e) {
				len = 0;
			}
			for (let i = 0; i < len; i++) {
				let key;
				try {
					key = otherReflectGet(res, i);
				} catch (e) {
					continue;
				}
				if (typeof key !== 'string' && typeof key !== 'symbol') continue;
				if (typeof key === 'symbol' && isDangerousCrossRealmSymbol(key)) continue;
				thisReflectDefineProperty(filtered, filtered.length, {
					__proto__: null,
					value: key,
					writable: true,
					enumerable: true,
					configurable: true
				});
			}
			return filtered;
		}

		preventExtensions(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			// SECURITY (GHSA-vwrp-x96c-mhwq): refuse sandbox-originated
			// preventExtensions on any host-realm intrinsic prototype or
			// constructor. Without this the sandbox could permanently freeze
			// host prototypes, breaking every subsequent host-side attempt
			// to install or adjust properties on them -- a durable host DoS.
			if (isProtectedHostObject(object)) throw new VMError(OPNA);
			try {
				if (!otherReflectPreventExtensions(object)) return false;
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			if (thisReflectIsExtensible(target)) {
				doPreventExtensions(this, target);
			}
			return true;
		}

		enumerate(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			let res; // @other(unsafe)
			try {
				res = otherReflectEnumerate(object);
			} catch (e) { // @other(unsafe)
				throw thisFromOtherForThrow(e);
			}
			return handlerFromOtherWithContext(this,res);
		}

	}

	BaseHandler.prototype[thisSymbolNodeJSUtilInspectCustom] = undefined;
	BaseHandler.prototype[thisSymbolToStringTag] = 'VM2 Wrapper';
	BaseHandler.prototype[thisSymbolIterator] = undefined;

	function defaultFactory(object) {
		// Note: other@other(unsafe) returns@this(unsafe) throws@this(unsafe)
		// SECURITY (GHSA-v37h-5mfm-c47c): pass the closure-scoped
		// construction token. This is the only trusted construction site
		// for BaseHandler.
		return new BaseHandler(constructionToken, object);
	}

	class ProtectedHandler extends BaseHandler {

		constructor(token, object) {
			// SECURITY (GHSA-v37h-5mfm-c47c): forward the token through
			// super(). If `token` is wrong the super() call throws before
			// the factory WeakMap is touched.
			super(token, object);
			thisReflectApply(thisWeakMapSet, handlerToFactory, [this, protectedFactory]);
		}

		set(target, key, value, receiver) {
			// Note: target@this(unsafe) key@prim value@this(unsafe) receiver@this(unsafe) throws@this(unsafe)
			// SECURITY (GHSA-v37h-5mfm-c47c, GHSA-qcp4-v2jj-fjx8):
			// validateHandlerTarget catches both forged-this (handler not
			// registered) and forged-target (registered handler, attacker
			// target); subsumes the earlier getHandlerObject(this) guard.
			validateHandlerTarget(this, target);
			if (typeof value === 'function') {
				return thisReflectDefineProperty(receiver, key, {
					__proto__: null,
					value: value,
					writable: true,
					enumerable: true,
					configurable: true
				}) === true;
			}
			return super.set(target, key, value, receiver);
		}

		definePropertyDesc(target, prop, desc) {
			// Note: target@this(unsafe) prop@prim desc@this(safe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			if (desc && (desc.set || desc.get || typeof desc.value === 'function')) return undefined;
			return desc;
		}

	}

	function protectedFactory(object) {
		// Note: other@other(unsafe) returns@this(unsafe) throws@this(unsafe)
		// SECURITY (GHSA-v37h-5mfm-c47c): pass token, see defaultFactory.
		return new ProtectedHandler(constructionToken, object);
	}

	class ReadOnlyHandler extends BaseHandler {

		constructor(token, object) {
			// SECURITY (GHSA-v37h-5mfm-c47c): forward the token, see
			// ProtectedHandler for rationale.
			super(token, object);
			thisReflectApply(thisWeakMapSet, handlerToFactory, [this, readonlyFactory]);
		}

		set(target, key, value, receiver) {
			// Note: target@this(unsafe) key@prim value@this(unsafe) receiver@this(unsafe) throws@this(unsafe)
			// SECURITY (GHSA-v37h-5mfm-c47c, GHSA-qcp4-v2jj-fjx8):
			// validateHandlerTarget subsumes the earlier getHandlerObject(this)
			// guard and additionally rejects attacker-supplied targets.
			validateHandlerTarget(this, target);
			return thisReflectDefineProperty(receiver, key, {
				__proto__: null,
				value: value,
				writable: true,
				enumerable: true,
				configurable: true
			});
		}

		setPrototypeOf(target, value) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return false;
		}

		defineProperty(target, prop, desc) {
			// Note: target@this(unsafe) prop@prim desc@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return false;
		}

		deleteProperty(target, prop) {
			// Note: target@this(unsafe) prop@prim throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return false;
		}

		isExtensible(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return false;
		}

		preventExtensions(target) {
			// Note: target@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			return false;
		}

	}

	function readonlyFactory(object) {
		// Note: other@other(unsafe) returns@this(unsafe) throws@this(unsafe)
		// SECURITY (GHSA-v37h-5mfm-c47c): pass token, see defaultFactory.
		return new ReadOnlyHandler(constructionToken, object);
	}

	class ReadOnlyMockHandler extends ReadOnlyHandler {

		constructor(token, object, mock) {
			// Note: object@other(unsafe) mock:this(unsafe) throws@this(unsafe)
			// SECURITY (GHSA-v37h-5mfm-c47c): forward the token.
			super(token, object);
			this.mock = mock;
		}

		get(target, key, receiver) {
			if (key === 'isProxy') return true;
			// Note: target@this(unsafe) key@prim receiver@this(unsafe) throws@this(unsafe)
			validateHandlerTarget(this, target); // SECURITY (GHSA-qcp4-v2jj-fjx8)
			const object = getHandlerObject(this); // @other(unsafe)
			const mock = this.mock;
			if (thisReflectApply(thisObjectHasOwnProperty, mock, key) && !thisOtherHasOwnProperty(object, key)) {
				return mock[key];
			}
			return super.get(target, key, receiver);
		}

	}

	function thisFromOther(other) {
		// Note: other@other(unsafe) returns@this(unsafe) throws@this(unsafe)
		return thisFromOtherWithFactory(defaultFactory, other);
	}

	function thisProxyOther(factory, other, proto, preventUnwrap) {
		const target = thisCreateTargetObject(other, proto);
		const handler = factory(other);
		// SECURITY (GHSA-qcp4-v2jj-fjx8): pair this handler with its canonical
		// proxy target so trap methods can reject forged targets supplied via
		// a leaked handler reference. Every BaseHandler/ProtectedHandler/
		// ReadOnlyHandler/ReadOnlyMockHandler instance is created through this
		// function, so registration here is sufficient.
		thisReflectApply(thisWeakMapSet, handlerToTarget, [handler, target]);
		const proxy = new ThisProxy(target, handler);
		try {
			if (!preventUnwrap) {
				otherReflectApply(otherWeakMapSet, mappingThisToOther, [proxy, other]);
			}
			registerProxy(proxy, handler);
		} catch (e) {
			throw new VMError('Unexpected error');
		}
		if (!isHost) {
			thisReflectApply(thisWeakMapSet, mappingOtherToThis, [other, proxy]);
			return proxy;
		}
		const proxy2 = new ThisProxy(proxy, emptyFrozenObject);
		try {
			otherReflectApply(otherWeakMapSet, mappingThisToOther, [proxy2, other]);
			registerProxy(proxy2, handler);
		} catch (e) {
			throw new VMError('Unexpected error');
		}
		thisReflectApply(thisWeakMapSet, mappingOtherToThis, [other, proxy2]);
		return proxy2;
	}

	function thisEnsureThis(other) {
		const type = typeof other;
		switch (type) {
			case 'object':
				if (other === null) {
					return null;
				}
				// fallthrough
			case 'function':
				let proto = thisReflectGetPrototypeOf(other);
				if (!proto) {
					return other;
				}
				while (proto) {
					const mapping = thisReflectApply(thisMapGet, protoMappings, [proto]);
					if (mapping) {
						const mapped = thisReflectApply(thisWeakMapGet, mappingOtherToThis, [other]);
						if (mapped) return mapped;
						return mapping(defaultFactory, other);
					}
					proto = thisReflectGetPrototypeOf(proto);
				}
				return other;
			case 'symbol':
				// SECURITY (GHSA-47x8-96vw-5wg6): Strip dangerous cross-realm symbols when a
				// host value is coerced into this-realm here. thisEnsureThis sits on re-entry
				// paths where a host-wrapped `this` binding may funnel a symbol primitive back
				// into the sandbox. Keeping this case in lock-step with thisFromOtherWithFactory
				// ensures no boundary path leaks a raw cross-realm inspect-custom / rejection
				// symbol regardless of the call shape.
				if (!isHost && isDangerousCrossRealmSymbol(other)) return undefined;
				return other;
			case 'undefined':
			case 'string':
			case 'number':
			case 'boolean':
			case 'bigint':
				return other;

			default: // new, unknown types can be dangerous
				throw new VMError(`Unknown type '${type}'`);
		}
	}

	function thisFromOtherForThrow(other) {
		for (let loop = 0; loop < 10; loop++) {
			const type = typeof other;
			switch (type) {
				case 'object':
					if (other === null) {
						return null;
					}
					// fallthrough
				case 'function':
					const mapped = thisReflectApply(thisWeakMapGet, mappingOtherToThis, [other]);
					if (mapped) return mapped;
					let proto;
					try {
						proto = otherReflectGetPrototypeOf(other);
					} catch (e) { // @other(unsafe)
						other = e;
						break;
					}
					if (!proto) {
						return thisProxyOther(defaultFactory, other, null);
					}
					for (;;) {
						const mapping = thisReflectApply(thisMapGet, protoMappings, [proto]);
						if (mapping) return mapping(defaultFactory, other);
						try {
							proto = otherReflectGetPrototypeOf(proto);
						} catch (e) { // @other(unsafe)
							other = e;
							break;
						}
						if (!proto) return thisProxyOther(defaultFactory, other, thisObjectPrototype);
					}
					break;
				case 'symbol':
					// SECURITY (GHSA-47x8-96vw-5wg6): Strip dangerous cross-realm symbols when
					// they surface from a host-realm throw path. A host function could throw a
					// raw symbol as the rejection value; without this filter the sandbox's
					// transformer-instrumented catch block would bind a real host cross-realm
					// symbol and the attacker could reuse it as a computed property key.
					if (!isHost && isDangerousCrossRealmSymbol(other)) return undefined;
					return other;
				case 'undefined':
				case 'string':
				case 'number':
				case 'boolean':
				case 'bigint':
					return other;

				default: // new, unknown types can be dangerous
					throw new VMError(`Unknown type '${type}'`);
			}
		}
		throw new VMError('Exception recursion depth');
	}

	function thisFromOtherWithFactory(factory, other, proto) {
		const type = typeof other;
		switch (type) {
			case 'object':
				if (other === null) {
					return null;
				}
				// fallthrough
			case 'function':
				// Block the other realm's Function constructors from crossing the bridge.
				if (!isHost && isDangerousFunctionConstructor(other)) {
					return emptyFrozenObject;
				}
				// Cache check first — if already proxied, return existing proxy.
				// Safe because: cached proxies were created under the same preventUnwrap
				// rules, and an attacker can't retroactively add Function constructors
				// to a host object's properties from the sandbox (chicken-and-egg).
				const mapped = thisReflectApply(thisWeakMapGet, mappingOtherToThis, [other]);
				if (mapped) return mapped;
				// For objects on sandbox side, check for nested dangerous constructors.
				// If found, proxy WITHOUT unwrap registration (mappingThisToOther), so
				// the proxy cannot be unwrapped when passed back to host functions.
				// The proxy's get trap already sanitizes dangerous values on read.
				const dangerous = !isHost && containsDangerousConstructor(other);
				if (proto) {
					return thisProxyOther(factory, other, proto, dangerous);
				}
				try {
					proto = otherReflectGetPrototypeOf(other);
				} catch (e) { // @other(unsafe)
					throw thisFromOtherForThrow(e);
				}
				if (!proto) {
					return thisProxyOther(factory, other, null, dangerous);
				}
				do {
					const mapping = thisReflectApply(thisMapGet, protoMappings, [proto]);
					if (mapping) return mapping(factory, other, dangerous);
					try {
						proto = otherReflectGetPrototypeOf(proto);
					} catch (e) { // @other(unsafe)
						throw thisFromOtherForThrow(e);
					}
				} while (proto);
				return thisProxyOther(factory, other, thisObjectPrototype, dangerous);
			case 'symbol':
				// SECURITY (GHSA-47x8-96vw-5wg6): Strip dangerous cross-realm symbols returned
				// from host-side calls. thisFromOtherWithFactory is the chokepoint for every
				// host-produced value crossing into the sandbox: direct call results (apply
				// trap), property reads (get trap via handlerFromOtherWithContext), iterator
				// yields on wrapped host arrays, and descriptor getter returns (thisDefaultGet).
				// Symbol primitives bypass proxy traps, so the per-call filtering lives here.
				// Attack path (reports GHSA-47x8-96vw-5wg6 / -qcp4-v2jj-fjx8 / -f539-x546-3726):
				// the attacker reaches host `Object.getOwnPropertySymbols(Buffer.prototype)` and
				// reads the resulting host array; each symbol element transits this branch.
				// Returning undefined (rather than a sandbox-local surrogate) is deliberate:
				// an undefined computed key on a subsequent `{[sym]: fn}` coerces to the string
				// 'undefined' and so never installs a handler under the real cross-realm symbol.
				if (!isHost && isDangerousCrossRealmSymbol(other)) return undefined;
				return other;
			case 'undefined':
			case 'string':
			case 'number':
			case 'boolean':
			case 'bigint':
				return other;

			default: // new, unknown types can be dangerous
				throw new VMError(`Unknown type '${type}'`);
		}
	}

	function thisFromOtherArguments(args) {
		// Note: args@other(safe-array) returns@this(safe-array) throws@this(unsafe)
		const arr = [];
		for (let i = 0; i < args.length; i++) {
			const value = thisFromOther(args[i]);
			thisReflectDefineProperty(arr, i, {
				__proto__: null,
				value: value,
				writable: true,
				enumerable: true,
				configurable: true
			});
		}
		return arr;
	}

	function thisConnect(obj, other) {
		// Note: obj@this(unsafe) other@other(unsafe) throws@this(unsafe)
		try {
			otherReflectApply(otherWeakMapSet, mappingThisToOther, [obj, other]);
		} catch (e) {
			throw new VMError('Unexpected error');
		}
		thisReflectApply(thisWeakMapSet, mappingOtherToThis, [other, obj]);
	}

	thisAddProtoMapping(thisGlobalPrototypes.Object, otherGlobalPrototypes.Object);
	thisAddProtoMapping(thisGlobalPrototypes.Array, otherGlobalPrototypes.Array);

	for (let i = 0; i < globalsList.length; i++) {
		const key = globalsList[i];
		const tp = thisGlobalPrototypes[key];
		const op = otherGlobalPrototypes[key];
		if (tp && op) thisAddProtoMapping(tp, op, key);
	}

	for (let i = 0; i < errorsList.length; i++) {
		const key = errorsList[i];
		const tp = thisGlobalPrototypes[key];
		const op = otherGlobalPrototypes[key];
		if (tp && op) thisAddProtoMapping(tp, op, 'Error');
	}

	thisAddProtoMapping(thisGlobalPrototypes.VMError, otherGlobalPrototypes.VMError, 'Error');

	// SECURITY (GHSA-47x8-96vw-5wg6): Structural identity collapse for host
	// built-in intrinsics. The proto-mapping wiring above only rewrites the
	// proto-chain of *instances* of a built-in (e.g., a host `[]` is wrapped
	// with sandbox `Array.prototype` as its proto). It does NOT rewrite the
	// identity of the prototype object itself (host `Array.prototype`) or of
	// the constructor (host `Array`). Without that, any path that surfaces
	// one of these intrinsics back into the sandbox -- chiefly proto-walks
	// terminating at `Object.prototype` / `Function.prototype` via
	// `__lookupGetter__('__proto__')`, `Reflect.getPrototypeOf`, `__proto__`
	// getter calls, or `o.constructor` reads -- yields a wrapped host value
	// whose identity differs from the sandbox-realm intrinsic. That breaks
	// the invariant that "no host built-in is ever directly reachable from
	// sandbox code", which the symbol-filter patch (commit 67bc511) relied
	// on to keep canonical RCE payloads off-limits.
	//
	// The fix: pre-populate `mappingOtherToThis` (and its host-side mirror
	// `mappingThisToOther`) with `[hostIntrinsic, sandboxIntrinsic]` for
	// every well-known built-in. The cache lookup in
	// `thisFromOtherWithFactory` (line ~1600), `thisFromOtherForThrow`, and
	// `thisEnsureThis` short-circuits *before* any wrapping logic, so the
	// host value is collapsed to the sandbox-realm equivalent the moment it
	// crosses the boundary.
	//
	// We deliberately skip Function / AsyncFunction / GeneratorFunction /
	// AsyncGeneratorFunction CONSTRUCTORS: those remain blocked by
	// `isDangerousFunctionConstructor` -> `emptyFrozenObject` (checked in
	// `thisFromOtherWithFactory` *before* the cache lookup, so the sentinel
	// fires regardless of pre-caching). The Function PROTOTYPE, however, is
	// safe and necessary to map -- it's the proto-walk landing pad for
	// every host-realm function.
	function thisAddIdentityMapping(thisProto, otherProto) {
		// SECURITY (GHSA-47x8): Skip if either prototype is missing
		// (e.g., Node version lacks AsyncGeneratorFunction).
		if (!thisProto || !otherProto) return;
		// SECURITY (GHSA-47x8): Map the prototype object itself. Without
		// this, a host prototype reaching the sandbox is wrapped (its
		// identity becomes a fresh proxy whose proto is the sandbox
		// equivalent), so `o === Object.prototype` is false even though
		// it should be the same object from the sandbox's view.
		thisReflectApply(thisWeakMapSet, mappingOtherToThis, [otherProto, thisProto]);
		try {
			// SECURITY (GHSA-47x8): Mirror the mapping on the host side
			// so round-tripped sandbox prototypes also collapse to host
			// intrinsics. `connect`-style symmetry — same semantics as
			// `thisConnect`, just inlined to avoid the extra throw on
			// host-side weakmap failure (we want best-effort, since a
			// failure here only affects round-trip identity, not the
			// security invariant).
			otherReflectApply(otherWeakMapSet, mappingThisToOther, [thisProto, otherProto]);
		} catch (e) { /* host-side mapping is best-effort */ }
		// SECURITY (GHSA-47x8): Read the constructor via descriptor
		// (not direct property access) so we never trigger a sandbox-realm
		// getter. Both sides are pristine intrinsics at bridge-init time,
		// so this is safe; we still wrap in try/catch for defense in depth.
		let thisCtor;
		let otherCtor;
		try {
			const td = thisSafeGetOwnPropertyDescriptor(thisProto, 'constructor');
			if (td) thisCtor = td.value;
		} catch (e) { return; }
		try {
			const od = otherSafeGetOwnPropertyDescriptor(otherProto, 'constructor');
			if (od) otherCtor = od.value;
		} catch (e) { return; }
		if (typeof thisCtor !== 'function' || typeof otherCtor !== 'function') return;
		// SECURITY (GHSA-47x8): Function-family constructors stay blocked.
		// `isThisDangerousFunctionConstructor` covers this realm (Function,
		// AsyncFunction, GeneratorFunction, AsyncGeneratorFunction); the
		// host-realm equivalent is filtered by `isDangerousFunctionConstructor`
		// in `thisFromOtherWithFactory` BEFORE the cache lookup, so even if
		// we accidentally cached one the dangerous check would still fire.
		// Belt and suspenders: skip the cache write here too.
		if (isThisDangerousFunctionConstructor(thisCtor)) return;
		if (isDangerousFunctionConstructor(otherCtor)) return;
		// SECURITY (GHSA-47x8): Map the constructor itself. Without this,
		// `o.constructor` reads on a wrapped host prototype (or anywhere
		// the host constructor surfaces) yield a wrapped host function
		// rather than the sandbox-realm intrinsic.
		thisReflectApply(thisWeakMapSet, mappingOtherToThis, [otherCtor, thisCtor]);
		try {
			otherReflectApply(otherWeakMapSet, mappingThisToOther, [thisCtor, otherCtor]);
		} catch (e) { /* host-side mapping is best-effort */ }
	}

	// SECURITY (GHSA-47x8): Apply identity mapping to every well-known
	// intrinsic EXCEPT the Function-family prototypes.
	//
	// We deliberately skip Function / AsyncFunction / GeneratorFunction /
	// AsyncGeneratorFunction PROTOTYPES (and therefore their constructors).
	// Reason: those prototypes are the proto-walk landing pad for any host
	// function that reaches the sandbox. If we collapse `host Function.prototype`
	// to `sandbox Function.prototype`, then `fp.constructor` (where `fp`
	// arrived via proto-walk) reads the sandbox-realm Function constructor as
	// a regular property of the sandbox prototype — bypassing the
	// `isDangerousFunctionConstructor` -> `emptyFrozenObject` defense, which
	// only fires when the *host* Function constructor crosses the bridge.
	// The same logic applies to AsyncFunction / GeneratorFunction /
	// AsyncGeneratorFunction.prototype, whose `.constructor` is dangerous.
	//
	// Concretely, an attacker chain
	//     fp = host_Function_prototype  (reached via proto-walk)
	//     fp.constructor                (read as own data property)
	// must continue to yield `emptyFrozenObject`, not the sandbox Function.
	// Leaving `Function.prototype` un-cached preserves the existing defense:
	// `fp` stays a proxy whose get trap reads host `Function.prototype.constructor`
	// = host Function, then routes through `thisFromOtherWithFactory` whose
	// dangerous-constructor check returns `emptyFrozenObject`.
	//
	// This is consistent with the structural-leak test's "Function constructor
	// block remains in force" case and with the existing
	// `getOwnPropertyDescriptor Function constructor bypass attack` regression
	// in test/vm.js.
	thisAddIdentityMapping(thisGlobalPrototypes.Object, otherGlobalPrototypes.Object);
	thisAddIdentityMapping(thisGlobalPrototypes.Array, otherGlobalPrototypes.Array);
	for (let i = 0; i < globalsList.length; i++) {
		const key = globalsList[i];
		// SECURITY (GHSA-47x8): Skip Function — its prototype must stay
		// un-cached so the dangerous-constructor sentinel keeps firing on
		// `fp.constructor` reads through the proxy get trap.
		if (key === 'Function') continue;
		thisAddIdentityMapping(thisGlobalPrototypes[key], otherGlobalPrototypes[key]);
	}
	for (let i = 0; i < errorsList.length; i++) {
		const key = errorsList[i];
		thisAddIdentityMapping(thisGlobalPrototypes[key], otherGlobalPrototypes[key]);
	}
	// SECURITY (GHSA-47x8): AsyncFunction / GeneratorFunction /
	// AsyncGeneratorFunction prototypes are intentionally NOT cached, see
	// rationale above. Their constructors must remain blocked.

	// SECURITY (GHSA-v37h-5mfm-c47c): Rebind `.constructor` on every handler
	// class's prototype to a throw-always sentinel. Even if sandbox code
	// reaches one of these prototypes via `Object.getPrototypeOf(leakedHandler)`,
	// reading `.constructor` returns the sentinel -- not the real class --
	// so `new pp.constructor(s)` fails before any Proxy handler is created.
	// The real class references stay reachable only through closure-scoped
	// factories below, which are the only legitimate construction sites.
	function blockedHandlerConstructor() {
		throw new VMError(OPNA);
	}
	// Keep `name` unset to avoid leaking class identity.
	thisReflectDefineProperty(blockedHandlerConstructor, 'name', {
		__proto__: null, value: '', writable: false, enumerable: false, configurable: true
	});
	thisReflectDefineProperty(BaseHandler.prototype, 'constructor', {
		__proto__: null, value: blockedHandlerConstructor, writable: false, enumerable: false, configurable: false
	});
	thisReflectDefineProperty(ProtectedHandler.prototype, 'constructor', {
		__proto__: null, value: blockedHandlerConstructor, writable: false, enumerable: false, configurable: false
	});
	thisReflectDefineProperty(ReadOnlyHandler.prototype, 'constructor', {
		__proto__: null, value: blockedHandlerConstructor, writable: false, enumerable: false, configurable: false
	});
	thisReflectDefineProperty(ReadOnlyMockHandler.prototype, 'constructor', {
		__proto__: null, value: blockedHandlerConstructor, writable: false, enumerable: false, configurable: false
	});

	// SECURITY (GHSA-v37h-5mfm-c47c): We intentionally do NOT expose the raw
	// handler classes on `result`. Callers that need to construct a handler
	// must go through these closure-scoped factories, which capture the
	// construction token. `setup-sandbox.js` uses
	// `createReadOnlyMockHandler(obj, mock)` (for the `readonly` API) and
	// `newBufferHandler(Subclass, obj)` (for the `BufferHandler extends
	// ReadOnlyHandler` pattern). Neither helper exposes the token.
	result.createReadOnlyMockHandler = function createReadOnlyMockHandler(object, mock) {
		// SECURITY: the token is embedded in this closure; it is never
		// assigned to any property of `result` or of the returned handler.
		return new ReadOnlyMockHandler(constructionToken, object, mock);
	};
	result.newBufferHandler = function newBufferHandler(Subclass, object) {
		// SECURITY: `Subclass` is attacker-influenceable only in the sense
		// that a trusted caller (setup-sandbox.js) supplies it. The subclass
		// constructor MUST forward `...args` to `super(...args)` so the
		// token propagates up to BaseHandler.
		return thisReflectConstruct(Subclass, [constructionToken, object]);
	};
	// SECURITY (GHSA-v37h-5mfm-c47c): We still expose ReadOnlyHandler as a
	// superclass symbol so that setup-sandbox can declare
	// `class BufferHandler extends ReadOnlyHandler`. The class reference
	// itself is harmless -- any attempt to construct it (directly or via a
	// subclass that does not forward the token) fails the token check.
	result.ReadOnlyHandler = ReadOnlyHandler;
	// SECURITY (GHSA-55hx): expose the sanitizer registration on the bridge so
	// that setup-sandbox.js can install handleException / ensureThis as the
	// host-promise interception hooks once they are constructed.
	// (ReadOnlyMockHandler is intentionally NOT exposed — GHSA-v37h forces
	// construction through createReadOnlyMockHandler with a token.)
	result.setHostPromiseSanitizers = thisSetHostPromiseSanitizers;

	return result;
}

exports.createBridge = createBridge;
exports.VMError = VMError;
