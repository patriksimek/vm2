'use strict'

const global = this;

Object.defineProperties(global, {
	global: {value: global},
	GLOBAL: {value: global},
	root: {value: global},
	isVM: {value: true}
});

const DEBUG = false;
const OPNA = 'Operation not allowed on contextified object.';

// Map of contextified objects to original objects
const Contextified = new WeakMap();
const Decontextified = new WeakMap();

const Decontextify = {
	proxies: new WeakMap(),
	
	class: function(instance, klass) {
		return Decontextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				return Decontextify.value(Reflect.get(target, key, target));
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
		return Decontextify.object(fnc, {
			apply: (target, context, args) => {
				context = Contextify.value(context);
				
				// Set context of all arguments to vm's context.
				return Decontextify.value(Reflect.apply(target, context, args.map(function(item) { return Contextify.value(item); })));
			},
			construct: (target, args, newTarget) => {
				return Decontextify.class(Reflect.construct(fnc, Contextify.object(args)), host.Object);
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return host.Function;
				return Decontextify.value(Reflect.get(target, key, target));
			},
			getPrototypeOf: (target) => {
				return host.Function.prototype;
			}
		});
	},
	object: function(object, traps) {
		let proxy = new Proxy(object, Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return host.Object;
				return Decontextify.value(Reflect.get(target, key, target));
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new host.Error(OPNA);
				
				Reflect.set(target, key, Contextify.value(value), target);
				return true;
			},
			getPrototypeOf: (target) => {
				return host.Object.prototype;
			},
			setPrototypeOf: (target) => {
				throw new host.Error(OPNA);
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
				} else if (value instanceof Number) {
					return host.Number(value);
				} else if (value instanceof String) {
					return host.String(value);
				} else if (value instanceof Boolean) {
					return host.Boolean(value);
				} else if (value instanceof Date) {
					return Decontextify.class(value, host.Date);
				} else if (value instanceof Error) {
					return Decontextify.class(value, host.Error);
				} else if (value instanceof VMError) {
					return Decontextify.class(value, host.VMError);
				} else if (value instanceof Array) {
					return Decontextify.class(value, host.Array);
				} else if (value instanceof RegExp) {
					return Decontextify.class(value, host.RegExp);
				} else {
					return Decontextify.object(value)
				}
			case 'function':
				return Decontextify.function(value);
			
			case 'undefined':
				return undefined;
			
			default:
				return value;
		}
	}
}

const Contextify = {
	proxies: new WeakMap(),
	
	class: function(instance, klass) {
		return Contextify.object(instance, {
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return klass;
				return Contextify.value(Reflect.get(target, key, target));
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
				context = Decontextify.value(context);
				
				// Set context of all arguments to host's context.
				return Contextify.value(Reflect.apply(target, context, args.map(function(item) { return Decontextify.value(item); })));
			},
			construct: (target, args, newTarget) => {
				return Contextify.class(Reflect.construct(fnc, Decontextify.object(args)), Object);
			},
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return Function;
				return Contextify.value(Reflect.get(target, key, target));
			},
			getPrototypeOf: (target) => {
				return Function.prototype;
			}
		});
	},
	object: function(object, traps) {
		let proxy = new Proxy(object, Object.assign({
			get: (target, key, receiver) => {
				if (key === 'vmProxyTarget' && DEBUG) return target;
				if (key === 'isVMProxy') return true;
				if (key === 'constructor') return Object;
				return Contextify.value(Reflect.get(target, key, target));
			},
			set: (target, key, value, receiver) => {
				if (key === 'constructor' || key === 'prototype' || key === '__proto__') throw new host.Error(OPNA);
				
				Reflect.set(target, key, Decontextify.value(value), target);
				return true;
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
				} else if (value instanceof host.Number) {
					return Number(value);
				} else if (value instanceof host.String) {
					return String(value);
				} else if (value instanceof host.Boolean) {
					return Boolean(value);
				} else if (value instanceof host.Date) {
					return Contextify.class(value, Date);
				} else if (value instanceof host.Error) {
					return Contextify.class(value, Error);
				} else if (value instanceof host.VMError) {
					return Contextify.class(value, VMError);
				} else if (value instanceof host.Array) {
					return Contextify.class(value, Array);
				} else if (value instanceof host.RegExp) {
					return Contextify.class(value, RegExp);
				} else if (value instanceof host.Buffer) {
					return new Buffer(value);
				} else {
					return Contextify.object(value)
				}
			case 'function':
				return Contextify.function(value);
			
			case 'undefined':
				return undefined;
			
			default:
				return value;
		}
	}
}

/**
 * Buffer proxy definition.
 */

global.Buffer = new Proxy(function(){}, {
	construct: (target, args, newTarget) => {
		let b = args[0] instanceof host.Buffer ? args[0] : Reflect.construct(host.Buffer, Decontextify.object(args));
		return Contextify.class(b, Buffer);
	}
})

global.Buffer.isBuffer = function(obj) {
	return obj instanceof Buffer;
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
