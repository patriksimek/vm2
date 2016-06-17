'use strict'

const global = this;

host.Object.defineProperties(global, {
	global: {value: global},
	GLOBAL: {value: global},
	root: {value: global},
	isVM: {value: true}
});

const DEBUG = false;
const OPNA = 'Operation not allowed on contextified object.';
const BUFFER_STATICS = ['alloc', 'allocUnsafe', 'allocUnsafeSlow', 'concat', 'from'];

// Map of contextified objects to original objects
const Contextified = new host.WeakMap();
const Decontextified = new host.WeakMap();

/**
 * Buffer proxy definition.
 */

const LocalBuffer = global.Buffer = new host.Proxy(function(){}, {
	construct: (target, args, newTarget) => {
		try {
			let b = args[0] instanceof host.Buffer ? args[0] : host.Reflect.construct(host.Buffer, Decontextify.object(args));
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
				return Contextify.class(host.Buffer[prop](...Decontextify.object(args)), LocalBuffer);
			} catch (e) {
				throw Contextify.value(e);
			}
		}
	})(BUFFER_STATICS[i])
}

LocalBuffer.compare = function(...args) {
	try {
		return Contextify.value(host.Buffer.compare(...Decontextify.object(args)));
	} catch (e) {
		throw Contextify.value(e);
	}
}

LocalBuffer.byteLength = function(...args) {
	try {
		return Contextify.value(host.Buffer.byteLength(...Decontextify.object(args)));
	} catch (e) {
		throw Contextify.value(e);
	}
}

LocalBuffer.isEncoding = function(...args) {
	try {
		return Contextify.value(host.Buffer.isEncoding(...Decontextify.object(args)));
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
		
		Error.captureStackTrace(this, this.constructor);
	}
}

/**
 * Decontextify.
 */

const Decontextify = {
	proxies: new host.WeakMap(),
	
	class: function(instance, klass) {
		return Decontextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				
				try {
					return Decontextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return klass.prototype;
			},
			setPrototypeOf: (target) => {
				throw new host.VMError(OPNA);
			}
		});
	},
	function: function(fnc) {
		return Decontextify.object(fnc, {
			apply: (target, context, args) => {
				try {
					context = Contextify.value(context);
					
					// Set context of all arguments to vm's context.
					return Decontextify.value(host.Reflect.apply(target, context, args.map(function(item) { return Contextify.value(item); })));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				try {
					return Decontextify.class(host.Reflect.construct(fnc, Contextify.object(args)), host.Object);
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return host.Function;
				
				try {
					return Decontextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return host.Function.prototype;
			}
		});
	},
	object: function(object, traps) {
		let proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return host.Object;
				
				try {
					return Decontextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Decontextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new host.Error(OPNA);
				
				try {
					return host.Reflect.set(target, key, Contextify.value(value), target);
				} catch (e) {
					throw Decontextify.value(e);
				}
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
	
	class: function(instance, klass) {
		return Contextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				
				try {
					return Contextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return klass.prototype;
			},
			setPrototypeOf: (target) => {
				throw new VMError(OPNA);
			}
		});
	},
	function: function(fnc) {
		return Contextify.object(fnc, {
			apply: (target, context, args) => {
				try {
					context = Decontextify.value(context);
				
					// Set context of all arguments to host's context.
					return Contextify.value(host.Reflect.apply(target, context, args.map(function(item) { return Decontextify.value(item); })));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			construct: (target, args, newTarget) => {
				try {
					return Contextify.class(host.Reflect.construct(fnc, Decontextify.object(args)), Object);
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return Function;
				
				try {
					return Contextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			getPrototypeOf: (target) => {
				return Function.prototype;
			}
		});
	},
	object: function(object, traps) {
		let proxy = new host.Proxy(object, host.Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return Object;
				
				try {
					return Contextify.value(host.Reflect.get(target, key, target));
				} catch (e) {
					throw Contextify.value(e);
				}
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new Error(OPNA);
				
				try {
					return host.Reflect.set(target, key, Decontextify.value(value), target);
				} catch (e) {
					throw Contextify.value(e);
				}
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
				} else if (value instanceof host.Buffer)         { return new LocalBuffer(value);
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
	}
}

return {
	contextify: (value, options = {}) => {
		let o;
		
		if (options.class) {
			o = Contextify.class(value, options.class);
		} else if (options.readonly) {
			o = Contextify.object(value, {
				set: (target, key) => {
					return false;
				}
			})
		} else {
			o = Contextify.value(value);
		}
		
		if (options.global) this[options.global] = o;
		return o;
	},
	decontextify: (value) => {
		return Decontextify.value(value);
	}
}
