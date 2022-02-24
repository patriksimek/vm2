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
	Promise: localPromise,
	eval: localEval
} = global;

const {
	freeze: localObjectFreeze
} = localObject;

const {
	getPrototypeOf: localReflectGetPrototypeOf,
	apply: localReflectApply,
	deleteProperty: localReflectDeleteProperty,
	has: localReflectHas,
	defineProperty: localReflectDefineProperty,
	setPrototypeOf: localReflectSetPrototypeOf,
	getOwnPropertyDescriptor: localReflectGetOwnPropertyDescriptor
} = localReflect;

const {
	isArray: localArrayIsArray
} = localArray;

const {
	ensureThis,
	ReadOnlyHandler,
	from,
	fromWithFactory,
	readonlyFactory,
	connect,
	addProtoMapping,
	VMError,
	ReadOnlyMockHandler
} = bridge;

const {
	allowAsync,
	GeneratorFunction,
	AsyncFunction,
	AsyncGeneratorFunction
} = data;

const localWeakMapGet = LocalWeakMap.prototype.get;

function localUnexpected() {
	return new VMError('Should not happen');
}

// global is originally prototype of host.Object so it can be used to climb up from the sandbox.
if (!localReflectSetPrototypeOf(context, localObject.prototype)) throw localUnexpected();

Object.defineProperties(global, {
	global: {value: global, writable: true, configurable: true, enumerable: true},
	globalThis: {value: global, writable: true, configurable: true},
	GLOBAL: {value: global, writable: true, configurable: true},
	root: {value: global, writable: true, configurable: true}
});

if (!localReflectDefineProperty(global, 'VMError', {
	__proto__: null,
	value: VMError,
	writable: true,
	enumerable: false,
	configurable: true
})) throw localUnexpected();

// Fixes buffer unsafe allocation
/* eslint-disable no-use-before-define */
class BufferHandler extends ReadOnlyHandler {

	apply(target, thiz, args) {
		if (args.length > 0 && typeof args[0] === 'number') {
			return LocalBuffer.alloc(args[0]);
		}
		return localReflectApply(LocalBuffer.from, LocalBuffer, args);
	}

	construct(target, args, newTarget) {
		if (args.length > 0 && typeof args[0] === 'number') {
			return LocalBuffer.alloc(args[0]);
		}
		return localReflectApply(LocalBuffer.from, LocalBuffer, args);
	}

}
/* eslint-enable no-use-before-define */

const LocalBuffer = fromWithFactory(obj => new BufferHandler(obj), host.Buffer);


if (!localReflectDefineProperty(global, 'Buffer', {
	__proto__: null,
	value: LocalBuffer,
	writable: true,
	enumerable: false,
	configurable: true
})) throw localUnexpected();

addProtoMapping(LocalBuffer.prototype, host.Buffer.prototype, 'Uint8Array');

/**
 *
 * @param {*} size Size of new buffer
 * @this LocalBuffer
 * @return {LocalBuffer}
 */
function allocUnsafe(size) {
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
	let str = this.hexSlice(0, actualMax).replace(/(.{2})/g, '$1 ').trim();
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

let currentPrepareStackTrace = LocalError.prepareStackTrace;
const wrappedPrepareStackTrace = new LocalWeakMap();
if (typeof currentPrepareStackTrace === 'function') {
	wrappedPrepareStackTrace.set(currentPrepareStackTrace, currentPrepareStackTrace);
}

let OriginalCallSite;
LocalError.prepareStackTrace = (e, sst) => {
	OriginalCallSite = sst[0].constructor;
};
new LocalError().stack;
if (typeof OriginalCallSite === 'function') {
	LocalError.prepareStackTrace = undefined;

	function makeCallSiteGetters(list) {
		const callSiteGetters = [];
		for (let i=0; i<list.length; i++) {
			const name = list[i];
			const func = OriginalCallSite.prototype[name];
			callSiteGetters[i] = {__proto__: null,
				name,
				propName: '_' + name,
				func: (thiz) => {
					return localReflectApply(func, thiz, []);
				}
			};
		}
		return callSiteGetters;
	}

	function applyCallSiteGetters(thiz, callSite, getters) {
		for (let i=0; i<getters.length; i++) {
			const getter = getters[i];
			localReflectDefineProperty(thiz, getter.propName, {
				__proto__: null,
				value: getter.func(callSite)
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
		'getPromiseIndex'
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


	for (let i=0; i<callSiteGetters.length; i++) {
		const name = callSiteGetters[i].name;
		const funcProp = localReflectGetOwnPropertyDescriptor(OriginalCallSite.prototype, name);
		if (!funcProp) continue;
		const propertyName = callSiteGetters[i].propName;
		const func = {func() {
			return this[propertyName];
		}}.func;
		const nameProp = localReflectGetOwnPropertyDescriptor(func, 'name');
		if (!nameProp) throw localUnexpected();
		nameProp.value = name;
		if (!localReflectDefineProperty(func, 'name', nameProp)) throw localUnexpected();
		funcProp.value = func;
		if (!localReflectDefineProperty(CallSite.prototype, name, funcProp)) throw localUnexpected();
	}

	if (!localReflectDefineProperty(LocalError, 'prepareStackTrace', {
		configurable: false,
		enumerable: false,
		get() {
			return currentPrepareStackTrace;
		},
		set(value) {
			if (typeof(value) !== 'function') {
				currentPrepareStackTrace = value;
				return;
			}
			const wrapped = localReflectApply(localWeakMapGet, wrappedPrepareStackTrace, [value]);
			if (wrapped) {
				currentPrepareStackTrace = wrapped;
				return;
			}
			const newWrapped = (error, sst) => {
				if (localArrayIsArray(sst)) {
					for (let i=0; i < sst.length; i++) {
						const cs = sst[i];
						if (typeof cs === 'object' && localReflectGetPrototypeOf(cs) === OriginalCallSite.prototype) {
							sst[i] = new CallSite(cs);
						}
					}
				}
				return value(error, sst);
			};
			wrappedPrepareStackTrace.set(value, newWrapped);
			wrappedPrepareStackTrace.set(newWrapped, newWrapped);
			currentPrepareStackTrace = newWrapped;
		}
	})) throw localUnexpected();
} else if (oldPrepareStackTraceDesc) {
	localReflectDefineProperty(LocalError, 'prepareStackTrace', oldPrepareStackTraceDesc);
} else {
	localReflectDeleteProperty(LocalError, 'prepareStackTrace');
}

/*
 * Exception sanitization
 */

const withProxy = localObjectFreeze({
	__proto__: null,
	has(target, key) {
		if (key === host.INTERNAL_STATE_NAME) return false;
		return localReflectHas(target, key);
	}
});

const interanState = localObjectFreeze({
	__proto__: null,
	wrapWith(x) {
		if (x === null || x === undefined) return x;
		return new LocalProxy(localObject(x), withProxy);
	},
	handleException: ensureThis,
	import(what) {
		throw new VMError('Dynamic Import not supported');
	}
});

if (!localReflectDefineProperty(global, host.INTERNAL_STATE_NAME, {
	__proto__: null,
	configurable: false,
	enumerable: false,
	writable: false,
	value: interanState
})) throw localUnexpected();

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
	}
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
	}
};

const AsyncErrorHandler = {
	__proto__: null,
	apply(target, thiz, args) {
		throw throwAsync();
	},
	construct(target, args, newTarget) {
		throw throwAsync();
	}
};

function makeCheckFunction(isAsync, isGenerator) {
	if (isAsync && !allowAsync) return AsyncErrorHandler;
	return {
		__proto__: FunctionHandler,
		isAsync,
		isGenerator
	};
}

function overrideWithProxy(obj, prop, value, handler) {
	const proxy = new LocalProxy(value, handler);
	if (!localReflectDefineProperty(obj, prop, {__proto__: null, value: proxy})) throw localUnexpected();
	return proxy;
}

const proxiedFunction = overrideWithProxy(localFunction.prototype, 'constructor', localFunction, makeCheckFunction(false, false));
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
	overrideWithProxy(AsyncGeneratorFunction.prototype, 'constructor', AsyncGeneratorFunction, makeCheckFunction(true, true));
}

global.Function = proxiedFunction;
global.eval = new LocalProxy(localEval, EvalHandler);

/*
 * Promise sanitization
 */

if (localPromise && !allowAsync) {

	const PromisePrototype = localPromise.prototype;

	overrideWithProxy(PromisePrototype, 'then', PromisePrototype.then, AsyncErrorHandler);
	// This seems not to work, and will produce
	// UnhandledPromiseRejectionWarning: TypeError: Method Promise.prototype.then called on incompatible receiver [object Object].
	// This is likely caused since the host.Promise.prototype.then cannot use the VM Proxy object.
	// Contextify.connect(host.Promise.prototype.then, Promise.prototype.then);

	if (PromisePrototype.finally) {
		overrideWithProxy(PromisePrototype, 'finally', PromisePrototype.finally, AsyncErrorHandler);
		// Contextify.connect(host.Promise.prototype.finally, Promise.prototype.finally);
	}
	if (Promise.prototype.catch) {
		overrideWithProxy(PromisePrototype, 'catch', PromisePrototype.catch, AsyncErrorHandler);
		// Contextify.connect(host.Promise.prototype.catch, Promise.prototype.catch);
	}

}

function readonly(other, mock) {
	// Note: other@other(unsafe) mock@other(unsafe) returns@this(unsafe) throws@this(unsafe)
	if (!mock) return fromWithFactory(readonlyFactory, other);
	const tmock = from(mock);
	return fromWithFactory(obj=>new ReadOnlyMockHandler(obj, tmock), other);
}

return {
	__proto__: null,
	readonly,
	global
};
