'use strict'

const global = this;
const console = host.console;

// global is originally prototype of host.Object so it can be used to climb up from the sandbox.
Object.setPrototypeOf(global, Object.prototype);

Object.defineProperties(global, {
	global: {value: global},
	GLOBAL: {value: global},
	root: {value: global},
	isVM: {value: true}
});

const DEBUG = false;
const OPNA = 'Operation not allowed on contextified object.';
const ERROR_CST = Error.captureStackTrace;
const FROZEN_TRAPS = {
	set: (target, key) => false,
	setPrototypeOf: (target, key) => false,
	defineProperty: (target, key) => false,
	deleteProperty: (target, key) => false,
	isExtensible: (target, key) => false,
	preventExtensions: (target) => false
}

// Map of contextified objects to original objects
const Contextified = new host.WeakMap();
const Decontextified = new host.WeakMap();

/**
 * VMError definition.
 */

global.VMError = class VMError extends Error {
	constructor(message, code) {
		super(message);

		this.name = 'VMError';
		this.code = code;

		ERROR_CST(this, this.constructor);
	}
}

/**
 * Decontextify.
 */

const Decontextify = {
	proxies: new host.WeakMap(),

	arguments: function(args) {
		if (!host.Array.isArray(args)) return new host.Array();

		const arr = new host.Array();
		for (let i = 0, l = args.length; i < l; i++) arr[i] = Decontextify.value(args[i]);
		return arr;
	},
	instance: function(instance, klass, deepTraps, flags) {
		return Decontextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return instance;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				if (key === '__proto__') return klass.prototype;

				try {
					return Decontextify.value(instance[key], null, deepTraps, flags);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return klass.prototype;
			}
		}, deepTraps, flags);
	},
	function: function(fnc, traps, deepTraps, flags, mock) {
		const self = Decontextify.object(fnc, host.Object.assign({
			apply: (target, context, args) => {
				try {
					context = Contextify.value(context);

					// Set context of all arguments to vm's context.
					return Decontextify.value(fnc.apply(context, Contextify.arguments(args)));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				try {
					return Decontextify.instance(new fnc(...Contextify.arguments(args)), self, deepTraps, flags);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return fnc;
				if (key === 'isVMProxy') return true;
				if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
				if (key === 'constructor') return host.Function;
				if (key === '__proto__') return host.Function.prototype;

				try {
					return Decontextify.value(fnc[key], null, deepTraps, flags);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return host.Function.prototype;
			}
		}, traps), deepTraps);

		return self;
	},
	object: function(object, traps, deepTraps, flags, mock) {
		const proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return object;
				if (key === 'isVMProxy') return true;
				if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
				if (key === 'constructor') return host.Object;
				if (key === '__proto__') return host.Object.prototype;

				try {
					return Decontextify.value(object[key], null, deepTraps, flags);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				try {
					object[key] = Contextify.value(value);
					return true;
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getOwnPropertyDescriptor: (target, prop) => {
				try {
					var def = host.Object.getOwnPropertyDescriptor(object, prop);
				} catch (e) {
					throw Decontextify.value(e);
				}

				// Following code prevents V8 to throw
				// TypeError: 'getOwnPropertyDescriptor' on proxy: trap reported non-configurability for property '<prop>' which is either non-existant or configurable in the proxy target

				if (!def) {
					return undefined;
				} else if (def.get || def.set) {
					return {
						get: Decontextify.value(def.get) || undefined,
						set: Decontextify.value(def.set) || undefined,
						enumerable: def.enumerable === true,
						configurable: def.configurable === true
					}
				} else {
					return {
						value: Decontextify.value(def.value),
						writable: def.writable === true,
						enumerable: def.enumerable === true,
						configurable: def.configurable === true
					}
				}
			},
			defineProperty: (target, key, descriptor) => {
				try {
					if (descriptor.get || descriptor.set) {
						return host.Object.defineProperty(target, key, {
							get: Contextify.value(descriptor.get, null, deepTraps, flags) || undefined,
							set: Contextify.value(descriptor.set, null, deepTraps, flags) || undefined,
							enumerable: descriptor.enumerable === true,
							configurable: descriptor.configurable === true
						})
					} else {
						return host.Object.defineProperty(target, key, {
							value: Contextify.value(descriptor.value, null, deepTraps, flags),
							writable: descriptor.writable === true,
							enumerable: descriptor.enumerable === true,
							configurable: descriptor.configurable === true
						})
					}
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return host.Object.prototype;
			},
			setPrototypeOf: (target) => {
				throw new host.Error(OPNA);
			}
		}, traps, deepTraps));

		Decontextify.proxies.set(object, proxy);
		Decontextified.set(proxy, object);
		return proxy;
	},
	value: function(value, traps, deepTraps, flags, mock) {
		if (Contextified.has(value)) {
			// Contextified object has returned back from vm
			return Contextified.get(value);
		} else if (Decontextify.proxies.has(value)) {
			// Decontextified proxy already exists, reuse
			return Decontextify.proxies.get(value);
		}

		switch (typeof value) {
			case 'object':
				if (value === null) {
					return null;
				} else if (value instanceof Number)         { return host.Number(value);
				} else if (value instanceof String)         { return host.String(value);
				} else if (value instanceof Boolean)        { return host.Boolean(value);
				} else if (value instanceof Date)           { return Decontextify.instance(value, host.Date, deepTraps, flags);
				} else if (value instanceof RangeError)     { return Decontextify.instance(value, host.RangeError, deepTraps, flags);
				} else if (value instanceof ReferenceError) { return Decontextify.instance(value, host.ReferenceError, deepTraps, flags);
				} else if (value instanceof SyntaxError)    { return Decontextify.instance(value, host.SyntaxError, deepTraps, flags);
				} else if (value instanceof TypeError)      { return Decontextify.instance(value, host.TypeError, deepTraps, flags);
				} else if (value instanceof VMError)        { return Decontextify.instance(value, host.VMError, deepTraps, flags);
				} else if (value instanceof Error)          { return Decontextify.instance(value, host.Error, deepTraps, flags);
				} else if (value instanceof Array)          { return Decontextify.instance(value, host.Array, deepTraps, flags);
				} else if (value instanceof RegExp)         { return Decontextify.instance(value, host.RegExp, deepTraps, flags);
				} else if (value instanceof Map)            { return Decontextify.instance(value, host.Map, deepTraps, flags);
				} else if (value instanceof WeakMap)        { return Decontextify.instance(value, host.WeakMap, deepTraps, flags);
				} else if (value instanceof Set)            { return Decontextify.instance(value, host.Set, deepTraps, flags);
				} else if (value instanceof WeakSet)        { return Decontextify.instance(value, host.WeakSet, deepTraps, flags);
				} else if (value instanceof Promise)        { return Decontextify.instance(value, host.Promise, deepTraps, flags);
				} else {
					return Decontextify.object(value, traps, deepTraps, flags, mock);
				}
			case 'function':
				return Decontextify.function(value, traps, deepTraps, flags, mock);

			case 'undefined':
				return undefined;

			default: // string, number, boolean, symbol
				return value;
		}
	}
}

/**
 * Contextify.
 */

const Contextify = {
	proxies: new host.WeakMap(),

	arguments: function(args) {
		if (!host.Array.isArray(args)) return new Array();

		const arr = new Array();
		for (let i = 0, l = args.length; i < l; i++) arr[i] = Contextify.value(args[i]);
		return arr;
	},
	instance: function(instance, klass, deepTraps, flags) {
		return Contextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return instance;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				if (key === '__proto__') return klass.prototype;

				try {
					return Contextify.value(instance[key], null, deepTraps, flags);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return klass.prototype;
			}
		}, deepTraps, flags);
	},
	function: function(fnc, traps, deepTraps, flags, mock) {
		const self = Contextify.object(fnc, host.Object.assign({
			apply: (target, context, args) => {
				try {
					context = Decontextify.value(context);

					// Set context of all arguments to host's context.
					return Contextify.value(fnc.apply(context, Decontextify.arguments(args)));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				// Fixes buffer unsafe allocation for node v6/7
				if (host.version < 8 && fnc === host.Buffer && 'number' === typeof args[0]) {
					args[0] = new Array(args[0]).fill(0);
				}

				try {
					return Contextify.instance(new fnc(...Decontextify.arguments(args)), self, deepTraps, flags);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return fnc;
				if (key === 'isVMProxy') return true;
				if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
				if (key === 'constructor') return Function;
				if (key === '__proto__') return Function.prototype;

				try {
					return Contextify.value(fnc[key], null, deepTraps, flags);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return Function.prototype;
			}
		}, traps), deepTraps);

		return self;
	},
	object: function(object, traps, deepTraps, flags, mock) {
		const proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return object;
				if (key === 'isVMProxy') return true;
				if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
				if (key === 'constructor') return Object;
				if (key === '__proto__') return Object.prototype;

				try {
					return Contextify.value(object[key], null, deepTraps, flags);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				if (flags && flags.protected && typeof value === 'function') return false;

				try {
					object[key] = Decontextify.value(value);
					return true;
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getOwnPropertyDescriptor: (target, prop) => {
				try {
					var def = host.Object.getOwnPropertyDescriptor(object, prop);
				} catch (e) {
					throw Contextify.value(e);
				}

				// Following code prevents V8 to throw
				// TypeError: 'getOwnPropertyDescriptor' on proxy: trap reported non-configurability for property '<prop>' which is either non-existant or configurable in the proxy target

				if (!def) {
					return undefined;
				} else if (def.get || def.set) {
					return {
						get: Contextify.value(def.get, null, deepTraps, flags) || undefined,
						set: Contextify.value(def.set, null, deepTraps, flags) || undefined,
						enumerable: def.enumerable === true,
						configurable: def.configurable === true
					}
				} else {
					return {
						value: Contextify.value(def.value, null, deepTraps, flags),
						writable: def.writable === true,
						enumerable: def.enumerable === true,
						configurable: def.configurable === true
					}
				}
			},
			defineProperty: (target, key, descriptor) => {
				if (flags && flags.protected && typeof descriptor.value === 'function') return false;

				try {
					if (descriptor.get || descriptor.set) {
						return host.Object.defineProperty(target, key, {
							get: Decontextify.value(descriptor.get, null, deepTraps) || undefined,
							set: Decontextify.value(descriptor.set, null, deepTraps) || undefined,
							enumerable: descriptor.enumerable === true,
							configurable: descriptor.configurable === true
						})
					} else {
						return host.Object.defineProperty(target, key, {
							value: Decontextify.value(descriptor.value, null, deepTraps),
							writable: descriptor.writable === true,
							enumerable: descriptor.enumerable === true,
							configurable: descriptor.configurable === true
						})
					}
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return Object.prototype;
			},
			setPrototypeOf: (target) => {
				throw new VMError(OPNA);
			}
		}, traps, deepTraps));

		Contextify.proxies.set(object, proxy);
		Contextified.set(proxy, object);
		return proxy;
	},
	value: function(value, traps, deepTraps, flags, mock) {
		if (Decontextified.has(value)) {
			// Decontextified object has returned back to vm
			return Decontextified.get(value);
		} else if (Contextify.proxies.has(value)) {
			// Contextified proxy already exists, reuse
			return Contextify.proxies.get(value);
		}

		switch (typeof value) {
			case 'object':
				if (value === null) {
					return null;
				} else if (value instanceof host.Number)         { return host.Number(value);
				} else if (value instanceof host.String)         { return host.String(value);
				} else if (value instanceof host.Boolean)        { return host.Boolean(value);
				} else if (value instanceof host.Date)           { return Contextify.instance(value, Date, deepTraps, flags);
				} else if (value instanceof host.RangeError)     { return Contextify.instance(value, RangeError, deepTraps, flags);
				} else if (value instanceof host.ReferenceError) { return Contextify.instance(value, ReferenceError, deepTraps, flags);
				} else if (value instanceof host.SyntaxError)    { return Contextify.instance(value, SyntaxError, deepTraps, flags);
				} else if (value instanceof host.TypeError)      { return Contextify.instance(value, TypeError, deepTraps, flags);
				} else if (value instanceof host.VMError)        { return Contextify.instance(value, VMError, deepTraps, flags);
				} else if (value instanceof host.Error)          { return Contextify.instance(value, Error, deepTraps, flags);
				} else if (value instanceof host.Array)          { return Contextify.instance(value, Array, deepTraps, flags);
				} else if (value instanceof host.RegExp)         { return Contextify.instance(value, RegExp, deepTraps, flags);
				} else if (value instanceof host.Map)            { return Contextify.instance(value, Map, deepTraps, flags);
				} else if (value instanceof host.WeakMap)        { return Contextify.instance(value, WeakMap, deepTraps, flags);
				} else if (value instanceof host.Set)            { return Contextify.instance(value, Set, deepTraps, flags);
				} else if (value instanceof host.WeakSet)        { return Contextify.instance(value, WeakSet, deepTraps, flags);
				} else if (value instanceof host.Promise)        { return Contextify.instance(value, Promise, deepTraps, flags);
				} else if (value instanceof host.Buffer)         { return Contextify.instance(value, LocalBuffer, deepTraps, flags);
				} else {
					return Contextify.object(value, traps, deepTraps, flags, mock);
				}
			case 'function':
				return Contextify.function(value, traps, deepTraps, flags, mock);

			case 'undefined':
				return undefined;

			default: // string, number, boolean, symbol
				return value;
		}
	},
	globalValue: function(value, name) {
		return global[name] = Contextify.value(value);
	},
	readonly: function(value, mock) {
		return Contextify.value(value, null, FROZEN_TRAPS, null, mock);
	},
	protected: function(value, mock) {
		return Contextify.value(value, null, null, {protected: true}, mock);
	}
}

const LocalBuffer = global.Buffer = Contextify.readonly(host.Buffer, {
	allocUnsafe: function(size) { return this.alloc(size) },
	allocUnsafeSlow: function(size) { return this.alloc(size) }
});

return {
	Contextify,
	Decontextify,
	Buffer: LocalBuffer
}
