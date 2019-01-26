/* global host */
/* eslint-disable block-spacing, no-multi-spaces, brace-style, no-array-constructor, new-cap, no-use-before-define */

'use strict';

// eslint-disable-next-line no-invalid-this, no-shadow
const global = this;

const local = host.Object.create(null);
local.Object = Object;
local.Reflect = Reflect;

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
const captureStackTrace = Error.captureStackTrace;

const FROZEN_TRAPS = host.Object.create(null);
FROZEN_TRAPS.set = (target, key) => false;
FROZEN_TRAPS.setPrototypeOf = (target, key) => false;
FROZEN_TRAPS.defineProperty = (target, key) => false;
FROZEN_TRAPS.deleteProperty = (target, key) => false;
FROZEN_TRAPS.isExtensible = (target, key) => false;
FROZEN_TRAPS.preventExtensions = (target) => false;

// Map of contextified objects to original objects
const Contextified = new host.WeakMap();
const Decontextified = new host.WeakMap();

// Fake setters make sure we use correctly scoped definer for getter/setter definition
function fakeDefineGetter(receiver, useLocalDefiner) {
	return function __defineGetter__(key, value) {
		(useLocalDefiner ? local.Object : host.Object).defineProperty(receiver, key, {get: value, enumerable: true, configurable: true});
	};
}

function fakeDefineSetter(receiver, useLocalDefiner) {
	return function __defineSetter__(key, value) {
		(useLocalDefiner ? local.Object : host.Object).defineProperty(receiver, key, {set: value, enumerable: true, configurable: true});
	};
}

const hasInstance = Object[Symbol.hasInstance];
function instanceOf(value, construct) {
	return hasInstance.call(construct, value);
}

/**
 * VMError definition.
 */

class VMError extends Error {
	constructor(message, code) {
		super(message);

		this.name = 'VMError';
		this.code = code;

		captureStackTrace(this, this.constructor);
	}
}

global.VMError = VMError;

/**
 * Decontextify.
 */

const Decontextify = host.Object.create(null);
Decontextify.proxies = new host.WeakMap();

Decontextify.arguments = args => {
	if (!host.Array.isArray(args)) return new host.Array();

	const arr = new host.Array();
	for (let i = 0, l = args.length; i < l; i++) arr[i] = Decontextify.value(args[i]);
	return arr;
};
Decontextify.instance = (instance, klass, deepTraps, flags) => {
	if (typeof instance === 'function') return Decontextify.function(instance);

	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);

	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return instance;
		if (key === 'isVMProxy') return true;
		if (key === 'constructor') return klass;
		if (key === '__proto__') return klass.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver);

		try {
			return Decontextify.value(instance[key], null, deepTraps, flags);
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return klass && klass.prototype;
	};

	return Decontextify.object(instance, base, deepTraps, flags);
};
Decontextify.function = (fnc, traps, deepTraps, flags, mock) => {
	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);
	let proxy;

	base.apply = (target, context, args) => {
		try {
			context = Contextify.value(context);

			// Set context of all arguments to vm's context.
			return Decontextify.value(fnc.apply(context, Contextify.arguments(args)));
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.construct = (target, args, newTarget) => {
		try {
			return Decontextify.instance(new fnc(...Contextify.arguments(args)), proxy, deepTraps, flags);
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return fnc;
		if (key === 'isVMProxy') return true;
		if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
		if (key === 'constructor') return host.Function;
		if (key === '__proto__') return host.Function.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver);

		try {
			return Decontextify.value(fnc[key], null, deepTraps, flags);
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return host.Function.prototype;
	};

	proxy = Decontextify.object(fnc, host.Object.assign(base, traps), deepTraps);
	return proxy;
};
Decontextify.object = (object, traps, deepTraps, flags, mock) => {
	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);

	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return object;
		if (key === 'isVMProxy') return true;
		if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
		if (key === 'constructor') return host.Object;
		if (key === '__proto__') return host.Object.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver);

		try {
			return Decontextify.value(object[key], null, deepTraps, flags);
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.set = (target, key, value, receiver) => {
		try {
			object[key] = Contextify.value(value);
			return true;
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.getOwnPropertyDescriptor = (target, prop) => {
		let def;

		try {
			def = host.Object.getOwnPropertyDescriptor(object, prop);
		} catch (e) {
			throw Decontextify.value(e);
		}

		// Following code prevents V8 to throw
		// TypeError: 'getOwnPropertyDescriptor' on proxy: trap reported non-configurability for property '<prop>'
		// which is either non-existant or configurable in the proxy target

		if (!def) {
			return undefined;
		} else if (def.get || def.set) {
			return {
				get: Decontextify.value(def.get) || undefined,
				set: Decontextify.value(def.set) || undefined,
				enumerable: def.enumerable === true,
				configurable: def.configurable === true
			};
		} else {
			return {
				value: Decontextify.value(def.value),
				writable: def.writable === true,
				enumerable: def.enumerable === true,
				configurable: def.configurable === true
			};
		}
	};
	base.defineProperty = (target, key, descriptor) => {
		// There's a chance accessing a property throws an error so we must not access them
		// in try catch to prevent contextyfing local objects.
		const getter = Contextify.value(descriptor.get, null, deepTraps, flags);
		const setter = Contextify.value(descriptor.set, null, deepTraps, flags);
		const valuer = Contextify.value(descriptor.value, null, deepTraps, flags);
		const enumerable = descriptor.enumerable === true;
		const configurable = descriptor.configurable === true;
		const writable = descriptor.writable === true;

		try {
			if (descriptor.get || descriptor.set) {
				return host.Object.defineProperty(target, key, {
					get: getter || undefined,
					set: setter || undefined,
					enumerable: enumerable,
					configurable: configurable
				});
			} else {
				return host.Object.defineProperty(target, key, {
					value: valuer,
					writable: writable,
					enumerable: enumerable,
					configurable: configurable
				});
			}
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return host.Object.prototype;
	};
	base.setPrototypeOf = (target) => {
		throw new host.Error(OPNA);
	};
	base.has = (target, key) => {
		try {
			return key in object;
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.isExtensible = target => {
		try {
			return Decontextify.value(local.Object.isExtensible(object));
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.ownKeys = target => {
		try {
			return Decontextify.value(local.Reflect.ownKeys(object));
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.preventExtensions = target => {
		try {
			local.Object.preventExtensions(object);
			return true;
		} catch (e) {
			throw Decontextify.value(e);
		}
	};
	base.enumerate = target => {
		try {
			return Decontextify.value(local.Reflect.enumerate(object));
		} catch (e) {
			throw Decontextify.value(e);
		}
	};

	const proxy = new host.Proxy(object, host.Object.assign(base, traps, deepTraps));
	Decontextify.proxies.set(object, proxy);
	Decontextified.set(proxy, object);
	return proxy;
};
Decontextify.value = (value, traps, deepTraps, flags, mock) => {
	if (Contextified.has(value)) {
		// Contextified object has returned back from vm
		return Contextified.get(value);
	} else if (Decontextify.proxies.has(value)) {
		// Decontextified proxy already exists, reuse
		return Decontextify.proxies.get(value);
	}

	try {
		// If for some reason we get already scoped value, get out.
		// Decontextifying already scoped value breaks the security.
		if (instanceOf(value, host.Object)) return value;
	} catch (e) {
		throw new VMError('Failed to decontextify object.');
	}

	switch (typeof value) {
		case 'object':
			try {
				if (value === null) {
					return null;
				} else if (instanceOf(value, Number))         { return host.Number(value);
				} else if (instanceOf(value, String))         { return host.String(value);
				} else if (instanceOf(value, Boolean))        { return host.Boolean(value);
				} else if (instanceOf(value, Date))           { return Decontextify.instance(value, host.Date, deepTraps, flags);
				} else if (instanceOf(value, RangeError))     { return Decontextify.instance(value, host.RangeError, deepTraps, flags);
				} else if (instanceOf(value, ReferenceError)) { return Decontextify.instance(value, host.ReferenceError, deepTraps, flags);
				} else if (instanceOf(value, SyntaxError))    { return Decontextify.instance(value, host.SyntaxError, deepTraps, flags);
				} else if (instanceOf(value, TypeError))      { return Decontextify.instance(value, host.TypeError, deepTraps, flags);
				} else if (instanceOf(value, VMError))        { return Decontextify.instance(value, host.VMError, deepTraps, flags);
				} else if (instanceOf(value, Error))          { return Decontextify.instance(value, host.Error, deepTraps, flags);
				} else if (instanceOf(value, Array))          { return Decontextify.instance(value, host.Array, deepTraps, flags);
				} else if (instanceOf(value, RegExp))         { return Decontextify.instance(value, host.RegExp, deepTraps, flags);
				} else if (instanceOf(value, Map))            { return Decontextify.instance(value, host.Map, deepTraps, flags);
				} else if (instanceOf(value, WeakMap))        { return Decontextify.instance(value, host.WeakMap, deepTraps, flags);
				} else if (instanceOf(value, Set))            { return Decontextify.instance(value, host.Set, deepTraps, flags);
				} else if (instanceOf(value, WeakSet))        { return Decontextify.instance(value, host.WeakSet, deepTraps, flags);
				} else if (Promise && instanceOf(value, Promise)) { return Decontextify.instance(value, host.Promise, deepTraps, flags);
				} else if (host.Object.getPrototypeOf(value) === null) {
					return Decontextify.instance(value, null, deepTraps, flags);
				} else {
					return Decontextify.object(value, traps, deepTraps, flags, mock);
				}
			} catch (e) {
				throw Decontextify.value(e);
			}
		case 'function':
			return Decontextify.function(value, traps, deepTraps, flags, mock);

		case 'undefined':
			return undefined;

		default: // string, number, boolean, symbol
			return value;
	}
};

/**
 * Contextify.
 */

const Contextify = host.Object.create(null);
Contextify.proxies = new host.WeakMap();

Contextify.arguments = args => {
	if (!host.Array.isArray(args)) return new Array();

	const arr = new Array();
	for (let i = 0, l = args.length; i < l; i++) arr[i] = Contextify.value(args[i]);
	return arr;
};
Contextify.instance = (instance, klass, deepTraps, flags) => {
	if (typeof instance === 'function') return Contextify.function(instance);

	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);

	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return instance;
		if (key === 'isVMProxy') return true;
		if (key === 'constructor') return klass;
		if (key === '__proto__') return klass.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver, true);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver, true);

		try {
			return Contextify.value(instance[key], null, deepTraps, flags);
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return klass && klass.prototype;
	};

	return Contextify.object(instance, base, deepTraps, flags);
};
Contextify.function = (fnc, traps, deepTraps, flags, mock) => {
	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);
	let proxy;

	base.apply = (target, context, args) => {
		try {
			context = Decontextify.value(context);

			// Set context of all arguments to host's context.
			return Contextify.value(fnc.apply(context, Decontextify.arguments(args)));
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.construct = (target, args, newTarget) => {
		// Fixes buffer unsafe allocation for node v6/7
		if (host.version < 8 && fnc === host.Buffer && 'number' === typeof args[0]) {
			args[0] = new Array(args[0]).fill(0);
		}

		try {
			return Contextify.instance(new fnc(...Decontextify.arguments(args)), proxy, deepTraps, flags);
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return fnc;
		if (key === 'isVMProxy') return true;
		if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
		if (key === 'constructor') return Function;
		if (key === '__proto__') return Function.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver, true);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver, true);

		try {
			return Contextify.value(fnc[key], null, deepTraps, flags);
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return Function.prototype;
	};

	proxy = Contextify.object(fnc, host.Object.assign(base, traps), deepTraps);
	return proxy;
};
Contextify.object = (object, traps, deepTraps, flags, mock) => {
	// We must not use normal object because there's a chance object already contains malicious code in the prototype
	const base = host.Object.create(null);

	base.get = (target, key, receiver) => {
		if (key === 'vmProxyTarget' && DEBUG) return object;
		if (key === 'isVMProxy') return true;
		if (mock && host.Object.prototype.hasOwnProperty.call(mock, key)) return mock[key];
		if (key === 'constructor') return Object;
		if (key === '__proto__') return Object.prototype;
		if (key === '__defineGetter__') return fakeDefineGetter(receiver, true);
		if (key === '__defineSetter__') return fakeDefineSetter(receiver, true);

		try {
			return Contextify.value(object[key], null, deepTraps, flags);
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.set = (target, key, value, receiver) => {
		if (flags && flags.protected && typeof value === 'function') return false;

		try {
			object[key] = Decontextify.value(value);
			return true;
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.getOwnPropertyDescriptor = (target, prop) => {
		let def;

		try {
			def = host.Object.getOwnPropertyDescriptor(object, prop);
		} catch (e) {
			throw Contextify.value(e);
		}

		// Following code prevents V8 to throw
		// TypeError: 'getOwnPropertyDescriptor' on proxy: trap reported non-configurability for property '<prop>'
		// which is either non-existant or configurable in the proxy target

		if (!def) {
			return undefined;
		} else if (def.get || def.set) {
			return {
				get: Contextify.value(def.get, null, deepTraps, flags) || undefined,
				set: Contextify.value(def.set, null, deepTraps, flags) || undefined,
				enumerable: def.enumerable === true,
				configurable: def.configurable === true
			};
		} else {
			return {
				value: Contextify.value(def.value, null, deepTraps, flags),
				writable: def.writable === true,
				enumerable: def.enumerable === true,
				configurable: def.configurable === true
			};
		}
	};
	base.defineProperty = (target, key, descriptor) => {
		// There's a chance accessing a property throws an error so we must not access them
		// in try catch to prevent contextyfing local objects.
		const getter = Decontextify.value(descriptor.get, null, deepTraps, flags);
		const setter = Decontextify.value(descriptor.set, null, deepTraps, flags);
		const valuer = Decontextify.value(descriptor.value, null, deepTraps, flags);
		const enumerable = descriptor.enumerable === true;
		const configurable = descriptor.configurable === true;
		const writable = descriptor.writable === true;

		if (flags && flags.protected) {
			if (typeof getter === 'function' || typeof setter === 'function' || typeof valuer === 'function') return false;
		}

		try {
			if (descriptor.get || descriptor.set) {
				return host.Object.defineProperty(object, key, {
					get: getter || undefined,
					set: setter || undefined,
					enumerable: enumerable,
					configurable: configurable
				});
			} else {
				return host.Object.defineProperty(object, key, {
					value: valuer,
					writable: writable,
					enumerable: enumerable,
					configurable: configurable
				});
			}
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.getPrototypeOf = (target) => {
		return local.Object.prototype;
	};
	base.setPrototypeOf = (target) => {
		throw new VMError(OPNA);
	};
	base.has = (target, key) => {
		try {
			return key in object;
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.isExtensible = target => {
		try {
			return Contextify.value(host.Object.isExtensible(object));
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.ownKeys = target => {
		try {
			return Contextify.value(host.Reflect.ownKeys(object));
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.preventExtensions = target => {
		try {
			host.Object.preventExtensions(object);
			return true;
		} catch (e) {
			throw Contextify.value(e);
		}
	};
	base.enumerate = target => {
		try {
			return Contextify.value(host.Reflect.enumerate(object));
		} catch (e) {
			throw Contextify.value(e);
		}
	};

	const proxy = new host.Proxy(object, host.Object.assign(base, traps, deepTraps));
	Contextify.proxies.set(object, proxy);
	Contextified.set(proxy, object);
	return proxy;
};
Contextify.value = (value, traps, deepTraps, flags, mock) => {
	if (Decontextified.has(value)) {
		// Decontextified object has returned back to vm
		return Decontextified.get(value);
	} else if (Contextify.proxies.has(value)) {
		// Contextified proxy already exists, reuse
		return Contextify.proxies.get(value);
	}

	try {
		// If for some reason we get already scoped value, get out.
		// Contextifying already scoped value breaks the security.
		if (instanceOf(value, local.Object)) return value;
	} catch (e) {
		throw new VMError('Failed to contextify object.');
	}

	switch (typeof value) {
		case 'object':
			try {
				if (value === null) {
					return null;
				} else if (instanceOf(value, host.Number))         { return host.Number(value);
				} else if (instanceOf(value, host.String))         { return host.String(value);
				} else if (instanceOf(value, host.Boolean))        { return host.Boolean(value);
				} else if (instanceOf(value, host.Date))           { return Contextify.instance(value, Date, deepTraps, flags);
				} else if (instanceOf(value, host.RangeError))     { return Contextify.instance(value, RangeError, deepTraps, flags);
				} else if (instanceOf(value, host.ReferenceError)) { return Contextify.instance(value, ReferenceError, deepTraps, flags);
				} else if (instanceOf(value, host.SyntaxError))    { return Contextify.instance(value, SyntaxError, deepTraps, flags);
				} else if (instanceOf(value, host.TypeError))      { return Contextify.instance(value, TypeError, deepTraps, flags);
				} else if (instanceOf(value, host.VMError))        { return Contextify.instance(value, VMError, deepTraps, flags);
				} else if (instanceOf(value, host.Error))          { return Contextify.instance(value, Error, deepTraps, flags);
				} else if (instanceOf(value, host.Array))          { return Contextify.instance(value, Array, deepTraps, flags);
				} else if (instanceOf(value, host.RegExp))         { return Contextify.instance(value, RegExp, deepTraps, flags);
				} else if (instanceOf(value, host.Map))            { return Contextify.instance(value, Map, deepTraps, flags);
				} else if (instanceOf(value, host.WeakMap))        { return Contextify.instance(value, WeakMap, deepTraps, flags);
				} else if (instanceOf(value, host.Set))            { return Contextify.instance(value, Set, deepTraps, flags);
				} else if (instanceOf(value, host.WeakSet))        { return Contextify.instance(value, WeakSet, deepTraps, flags);
				} else if (instanceOf(value, host.Promise))        { return Contextify.instance(value, Promise, deepTraps, flags);
				} else if (instanceOf(value, host.Buffer))         { return Contextify.instance(value, LocalBuffer, deepTraps, flags);
				} else if (host.Object.getPrototypeOf(value) === null) {
					return Contextify.instance(value, null, deepTraps, flags);
				} else {
					return Contextify.object(value, traps, deepTraps, flags, mock);
				}
			} catch (e) {
				throw Contextify.value(e);
			}
		case 'function':
			return Contextify.function(value, traps, deepTraps, flags, mock);

		case 'undefined':
			return undefined;

		default: // string, number, boolean, symbol
			return value;
	}
};
Contextify.globalValue = (value, name) => {
	return (global[name] = Contextify.value(value));
};
Contextify.readonly = (value, mock) => {
	return Contextify.value(value, null, FROZEN_TRAPS, null, mock);
};
Contextify.protected = (value, mock) => {
	return Contextify.value(value, null, null, {protected: true}, mock);
};

const LocalBuffer = global.Buffer = Contextify.readonly(host.Buffer, {
	allocUnsafe: function allocUnsafe(size) {
		return this.alloc(size);
	},
	allocUnsafeSlow: function allocUnsafeSlow(size) {
		return this.alloc(size);
	}
});

return {
	Contextify,
	Decontextify,
	Buffer: LocalBuffer
};
