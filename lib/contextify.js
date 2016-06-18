'use strict'

const global = this;
const console = host.console;

host.Object.defineProperties(global, {
	global: {value: global},
	GLOBAL: {value: global},
	root: {value: global},
	isVM: {value: true}
});

const DEBUG = false;
const OPNA = 'Operation not allowed on contextified object.';
const BUFFER_STATICS = ['alloc', 'allocUnsafe', 'allocUnsafeSlow', 'concat', 'from'];
const ERROR_CST = Error.captureStackTrace;

// Map of contextified objects to original objects
const Contextified = new host.WeakMap();
const Decontextified = new host.WeakMap();

/**
 * Buffer proxy definition.
 */

const LocalBuffer = global.Buffer = new host.Proxy(function(){}, {
	construct: (target, args, newTarget) => {
		try {
			let b = args[0] instanceof host.Buffer ? args[0] : new host.Buffer(...Decontextify.arguments(args));
			return Contextify.class(b, LocalBuffer);
		} catch (e) {
			throw Contextify.value(e);
		}
	}
})

for (let i = 0, l = BUFFER_STATICS.length; i < l; i++) {
	(function(prop) {
		LocalBuffer[prop] = function(...args) {
			try {
				return Contextify.class(host.Buffer[prop](...Decontextify.arguments(args)), LocalBuffer);
			} catch (e) {
				throw Contextify.value(e);
			}
		}
	})(BUFFER_STATICS[i])
}

LocalBuffer.compare = function(...args) {
	try {
		return Contextify.value(host.Buffer.compare(...Decontextify.arguments(args)));
	} catch (e) {
		throw Contextify.value(e);
	}
}

LocalBuffer.byteLength = function(...args) {
	try {
		return Contextify.value(host.Buffer.byteLength(...Decontextify.arguments(args)));
	} catch (e) {
		throw Contextify.value(e);
	}
}

LocalBuffer.isEncoding = function(...args) {
	try {
		return Contextify.value(host.Buffer.isEncoding(...Decontextify.arguments(args)));
	} catch (e) {
		throw Contextify.value(e);
	}
}

LocalBuffer.isBuffer = function(obj) {
	return obj instanceof LocalBuffer;
}

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
		
		let arr = new host.Array();
		for (let i = 0, l = args.length; i < l; i++) arr[i] = Decontextify.value(args[i]);
		return arr;
	},
	class: function(instance, klass) {
		return Decontextify.object(instance, {
			getPrototypeOf: (target) => {
				return klass.prototype;
			}
		}, {
			constructor: klass
		});
	},
	function: function(fnc) {
		return Decontextify.object(fnc, {
			apply: (target, context, args) => {
				try {
					context = Contextify.value(context);
					
					// Set context of all arguments to vm's context.
					return Decontextify.value(target.apply(context, Contextify.arguments(args)));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				try {
					return Decontextify.class(new fnc(...Contextify.arguments(args)), host.Object);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return host.Function.prototype;
			}
		}, {
			constructor: host.Function
		});
	},
	object: function(object, traps, mock) {
		let proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (mock && mock.hasOwnProperty(key)) return mock[key];
				if (key === 'constructor') return host.Object;
				
				try {
					return Decontextify.value(target[key]);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new host.Error(OPNA);
				
				try {
					target[key] = Contextify.value(value);
					return true;
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getOwnPropertyDescriptor: (target, prop) => {
				return Decontextify.object(host.Object.getOwnPropertyDescriptor(target, prop));
			},
			getPrototypeOf: (target) => {
				return host.Object.prototype;
			},
			setPrototypeOf: (target) => {
				throw new host.Error(OPNA);
			},
			defineProperty: (target, key, descriptor) => {
				throw new host.VMError(OPNA);
			},
			deleteProperty: (target, key) => {
				throw new host.VMError(OPNA);
			},
			isExtensible: (target) => {
				return false;
			}
		}, traps));
		
		Decontextify.proxies.set(object, proxy);
		Decontextified.set(proxy, object);
		return proxy;
	},
	value: function(value) {
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
				} else if (value instanceof Date)           { return Decontextify.class(value, host.Date);
				} else if (value instanceof RangeError)     { return Decontextify.class(value, host.RangeError);
				} else if (value instanceof ReferenceError) { return Decontextify.class(value, host.ReferenceError);
				} else if (value instanceof SyntaxError)    { return Decontextify.class(value, host.SyntaxError);
				} else if (value instanceof TypeError)      { return Decontextify.class(value, host.TypeError);
				} else if (value instanceof VMError)        { return Decontextify.class(value, host.VMError);
				} else if (value instanceof Error)          { return Decontextify.class(value, host.Error);
				} else if (value instanceof Array)          { return Decontextify.class(value, host.Array);
				} else if (value instanceof RegExp)         { return Decontextify.class(value, host.RegExp);
				} else if (value instanceof Map)            { return Decontextify.class(value, host.Map);
				} else if (value instanceof WeakMap)        { return Decontextify.class(value, host.WeakMap);
				} else if (value instanceof Set)            { return Decontextify.class(value, host.Set);
				} else if (value instanceof WeakSet)        { return Decontextify.class(value, host.WeakSet);
				} else if (value instanceof Promise)        { return Decontextify.class(value, host.Promise);
				} else {
					return Decontextify.object(value);
				}
			case 'function':
				return Decontextify.function(value);
			
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
		
		let arr = new Array();
		for (let i = 0, l = args.length; i < l; i++) arr[i] = Contextify.value(args[i]);
		return arr;
	},
	class: function(instance, klass) {
		return Contextify.object(instance, {
			getPrototypeOf: (target) => {
				return klass.prototype;
			}
		}, {
			constructor: klass
		});
	},
	function: function(fnc) {
		return Contextify.object(fnc, {
			apply: (target, context, args) => {
				try {
					context = Decontextify.value(context);
				
					// Set context of all arguments to host's context.
					return Contextify.value(target.apply(context, Decontextify.arguments(args)));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				try {
					return Contextify.class(new fnc(...Decontextify.arguments(args)), Object);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return Function.prototype;
			}
		}, {
			constructor: Function
		});
	},
	object: function(object, traps, mock) {
		let proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (mock && mock.hasOwnProperty(key)) return mock[key];
				if (key === 'constructor') return Object;
				
				try {
					return Contextify.value(target[key]);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new Error(OPNA);
				
				try {
					target[key] = Decontextify.value(value);
					return true;
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getOwnPropertyDescriptor: (target, prop) => {
				return Contextify.object(host.Object.getOwnPropertyDescriptor(target, prop));
			},
			getPrototypeOf: (target) => {
				return Object.prototype;
			},
			setPrototypeOf: (target) => {
				throw new VMError(OPNA);
			},
			defineProperty: (target, key, descriptor) => {
				throw new VMError(OPNA);
			},
			deleteProperty: (target, key) => {
				throw new VMError(OPNA);
			},
			isExtensible: (target) => {
				return false;
			}
		}, traps));

		Contextify.proxies.set(object, proxy);
		Contextified.set(proxy, object);
		return proxy;
	},
	value: function(value) {
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
				} else if (value instanceof host.Date)           { return Contextify.class(value, Date);
				} else if (value instanceof host.RangeError)     { return Contextify.class(value, RangeError);
				} else if (value instanceof host.ReferenceError) { return Contextify.class(value, ReferenceError);
				} else if (value instanceof host.SyntaxError)    { return Contextify.class(value, SyntaxError);
				} else if (value instanceof host.TypeError)      { return Contextify.class(value, TypeError);
				} else if (value instanceof host.VMError)        { return Contextify.class(value, VMError);
				} else if (value instanceof host.Error)          { return Contextify.class(value, Error);
				} else if (value instanceof host.Array)          { return Contextify.class(value, Array);
				} else if (value instanceof host.RegExp)         { return Contextify.class(value, RegExp);
				} else if (value instanceof host.Map)            { return Contextify.class(value, Map);
				} else if (value instanceof host.WeakMap)        { return Contextify.class(value, WeakMap);
				} else if (value instanceof host.Set)            { return Contextify.class(value, Set);
				} else if (value instanceof host.WeakSet)        { return Contextify.class(value, WeakSet);
				} else if (value instanceof host.Promise)        { return Contextify.class(value, Promise);
				} else if (value instanceof host.Buffer)         { return Contextify.class(value, LocalBuffer);
				} else {
					return Contextify.object(value);
				}
			case 'function':
				return Contextify.function(value);
			
			case 'undefined':
				return undefined;
			
			default: // string, number, boolean, symbol
				return value;
		}
	},
	globalValue: function(value, name) {
		return global[name] = Contextify.value(value);
	}
}

return {
	Contextify,
	Decontextify
}
