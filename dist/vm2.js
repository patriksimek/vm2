/*!
 * vm2 3.5.0
 * https://github.com/patriksimek/vm2

 * Released under the MIT license
 * http://simdom.org/license
*/

window.vm2 = {};
((exports, require, __dirname, Buffer) => {
	const fs = require('fs');
const vm = require('vm');
const pa = require('path');
const {EventEmitter} = require('events');

const sb = fs.readFileSync(`${__dirname}/sandbox.js`, 'utf8');
const cf = fs.readFileSync(`${__dirname}/contextify.js`, 'utf8');

const PROTECTED = ['constructor', '__proto__'];

const _compileToJS = function compileToJS(code, compiler) {
	if ('function' === typeof compiler) return compiler(code);

	switch (compiler) {
		case 'coffeescript':
		case 'coffee-script':
		case 'cs':
		case 'text/coffeescript':
			try {
				return require('coffee-script').compile(code, {header: false, bare: true});
			} catch (ex) {
				throw VMError('Coffee-Script compiler is not installed.');
			}

		case 'javascript':
		case 'java-script':
		case 'js':
		case 'text/javascript':
			return code;

		default:
			throw new VMError(`Unsupported compiler '${compiler}'.`);
	}
};

/**
 * Class Script
 * 
 * @class
 */

class VMScript {
	/**
	 * Create VMScript instance.
	 *
	 * @param {String} code Code to run.
	 * @param {String} [filename] Filename that shows up in any stack traces produced from this script.
	 * @return {VMScript}
	 */

	constructor(code, filename) {
		this.code = code;
		this.filename = filename || 'vm.js';
	}

	/**
	 * Wraps the code.
	 *
	 * @return {VMScript}
	 */
	
	wrap(prefix, postfix) {
		if (this._wrapped) return this;
		this.code = prefix + this.code + postfix;
		this._wrapped = true;
		return this;
	}

	/**
	 * Compiles the code. If called multiple times, the code is only compiled once.
	 *
	 * @return {VMScript}
	 */
	
	compile() {
		if (this._compiled) return this;
		
		this._compiled = new vm.Script(this.code, {
			filename: this.filename,
			displayErrors: false
		})
		
		return this;
	}
}

/**
 * Class VM.
 *
 * @property {Object} options VM options.
 */

class VM extends EventEmitter {
	/**
	 * Makes the object read only.
	 *
	 * @static
	 * @param {*} object Object to freeze.
	 * @return {*} Frozen object.
	 */

	/**
	 * Create VM instance.
	 *
	 * @param {Object} [options] VM options.
	 * @return {VM}
	 */

	constructor(options = {}) {
		super();

		// defaults
		this.options = {
			timeout: options.timeout != null ? options.timeout : undefined,
			sandbox: options.sandbox != null ? options.sandbox : null,
			compiler: options.compiler != null ? options.compiler : 'javascript'
		};

		const host = {
			console,
			String,
			Number,
			Buffer,
			Boolean,
			Array,
			Date,
			Error,
			EvalError,
			RangeError,
			ReferenceError,
			SyntaxError,
			TypeError,
			URIError,
			RegExp,
			Function,
			Object,
			VMError,
			Proxy,
			Reflect,
			Map,
			WeakMap,
			Set,
			WeakSet,
			Promise
		};

		this._context = vm.createContext();

		Reflect.defineProperty(this, '_internal', {
			value: vm.runInContext(`(function(require, host) { ${cf} \n})`, this._context, {
				filename: `${__dirname}/contextify.js`,
				displayErrors: false
			}).call(this._context, require, host)
		});

		// prepare global sandbox
		if (this.options.sandbox) {
			if ('object' !== typeof this.options.sandbox) {
				throw new VMError("Sandbox must be object.");
			}

			for (let name in this.options.sandbox) {
				this._internal.Contextify.globalValue(this.options.sandbox[name], name);
			}
		}
	}

	/**
	 * Freezes the object inside VM making it read-only. Not available for primitive values.
	 *
	 * @static
	 * @param {*} object Object to freeze.
	 * @param {String} [globalName] Whether to add the object to global.
	 * @return {*} Object to freeze.
	 */

	freeze(value, globalName) {
		this._internal.Contextify.readonly(value);
		if (globalName) this._internal.Contextify.globalValue(value, globalName);
		return value;
	}

	/**
	 * Protects the object inside VM making impossible to set functions as it's properties. Not available for primitive values.
	 *
	 * @static
	 * @param {*} object Object to protect.
	 * @param {String} [globalName] Whether to add the object to global.
	 * @return {*} Object to protect.
	 */

	protect(value, globalName) {
		this._internal.Contextify.protected(value);
		if (globalName) this._internal.Contextify.globalValue(value, globalName);
		return value;
	}

	/**
	 * Run the code in VM.
	 *
	 * @param {String} code Code to run.
	 * @return {*} Result of executed code.
	 */

	run(code) {
		if (this.options.compiler !== 'javascript') {
			code = _compileToJS(code, this.options.compiler);
		}
		
		const script = code instanceof VMScript ? code : new VMScript(code);

		try {
			return this._internal.Decontextify.value(script.compile()._compiled.runInContext(this._context, {
				filename: script.filename,
				displayErrors: false,
				timeout: this.options.timeout
			}));
		} catch (e) {
			throw this._internal.Decontextify.value(e);
		}
	}
}

/**
 * Class NodeVM.
 * 
 * @class
 * @extends {EventEmitter}
 * @property {Object} module Pointer to main module.
 */

class NodeVM extends EventEmitter {
	/**
	 * Create NodeVM instance.
	 *
	 * Unlike VM, NodeVM lets you use require same way like in regular node.
	 *
	 * @param {Object} [options] VM options.
	 * @return {NodeVM}
	 */

	constructor(options = {}) {
		super();

		// defaults
		this.options = {
			sandbox: options.sandbox != null ? options.sandbox : null,
			console: options.console != null ? options.console : 'inherit',
			require: options.require != null ? options.require : false,
			compiler: options.compiler != null ? options.compiler : 'javascript',
			require: options.require != null ? options.require : false,
			nesting: options.nesting != null ? options.nesting : false,
			wrapper: options.wrapper != null ? options.wrapper : 'commonjs'
		};

		const host = {
			require,
			process,
			console,
			setTimeout,
			setInterval,
			setImmediate,
			clearTimeout,
			clearInterval,
			clearImmediate,
			String,
			Number,
			Buffer,
			Boolean,
			Array,
			Date,
			Error,
			EvalError,
			RangeError,
			ReferenceError,
			SyntaxError,
			TypeError,
			URIError,
			RegExp,
			Function,
			Object,
			VMError,
			Proxy,
			Reflect,
			Map,
			WeakMap,
			Set,
			WeakSet,
			Promise
		}

		if (this.options.nesting) {
			host.VM = VM;
			host.NodeVM = NodeVM;
		}

		this._context = vm.createContext();

		Object.defineProperty(this, '_internal', {
			value: vm.runInContext(`(function(require, host) { ${cf} \n})`, this._context, {
				filename: `${__dirname}/contextify.js`,
				displayErrors: false
			}).call(this._context, require, host)
		})

		const closure = vm.runInContext(`(function (vm, host, Contextify, Decontextify, Buffer) { ${sb} \n})`, this._context, {
			filename: `${__dirname}/sandbox.js`,
			displayErrors: false
		})

		Object.defineProperty(this, '_prepareRequire', {
			value: closure.call(this._context, this, host, this._internal.Contextify, this._internal.Decontextify, this._internal.Buffer)
		})

		// prepare global sandbox
		if (this.options.sandbox) {
			if ('object' !== typeof this.options.sandbox) {
				throw new VMError("Sandbox must be object.");
			}

			for (let name in this.options.sandbox) {
				this._internal.Contextify.globalValue(this.options.sandbox[name], name);
			}
		}

		if (this.options.require && this.options.require.import) {
			if (!Array.isArray(this.options.require.import)) {
				this.options.require.import = [this.options.require.import];
			}

			for (let i = 0, l = this.options.require.import.length; i < l; i++) {
				this.require(this.options.require.import[i]);
			}
		}
	}

	/**
	 * @deprecated
	 */

	call(method, ...args) {
		if ('function' === typeof method) {
			return method.apply(args);

		} else {
			throw new VMError("Unrecognized method type.");
		}
	}

	/**
	 * Freezes the object inside VM making it read-only. Not available for primitive values.
	 *
	 * @static
	 * @param {*} object Object to freeze.
	 * @param {String} [globalName] Whether to add the object to global.
	 * @return {*} Object to freeze.
	 */

	freeze(value, globalName) {
		this._internal.Contextify.readonly(value);
		if (global) this._internal.Contextify.globalValue(value, globalName);
		return value;
	}

	/**
	 * Protects the object inside VM making impossible to set functions as it's properties. Not available for primitive values.
	 *
	 * @static
	 * @param {*} object Object to protect.
	 * @param {String} [globalName] Whether to add the object to global.
	 * @return {*} Object to protect.
	 */

	protect(value, globalName) {
		this._internal.Contextify.protected(value);
		if (global) this._internal.Contextify.globalValue(value, globalName);
		return value;
	}

	/**
	 * Require a module in VM and return it's exports.
	 *
	 * @param {String} module Module name.
	 * @return {*} Exported module.
	 */

	require(module) {
		return this.run(`module.exports = require('${module}');`, 'vm.js');
	}

	/**
	 * Run the code in NodeVM.
	 *
	 * First time you run this method, code is executed same way like in node's regular `require` - it's executed with `module`, `require`, `exports`, `__dirname`, `__filename` variables and expect result in `module.exports'.
	 *
	 * @param {String} code Code to run.
	 * @param {String} [filename] Filename that shows up in any stack traces produced from this script.
	 * @return {*} Result of executed code.
	 */

	run(code, filename) {
		if (this.options.compiler !== 'javascript') {
			code = _compileToJS(code, this.options.compiler);
		}

		if (filename) {
			filename = pa.resolve(filename);
			var dirname = pa.dirname(filename);

		} else {
			filename = null;
			var dirname = null;
		}

		const module = vm.runInContext("({exports: {}})", this._context, {
			displayErrors: false
		});
		
		const script = code instanceof VMScript ? code : new VMScript(code, filename);
		script.wrap('(function (exports, require, module, __filename, __dirname) { ', ' \n})');

		try {
			const closure = script.compile()._compiled.runInContext(this._context, {
				filename: script.filename,
				displayErrors: false
			});

			var returned = closure.call(this._context, module.exports, this._prepareRequire(dirname), module, filename, dirname);
		} catch (e) {
			throw this._internal.Decontextify.value(e);
		}

		if (this.options.wrapper === 'commonjs') {
			return this._internal.Decontextify.value(module.exports);
		} else {
			return this._internal.Decontextify.value(returned);
		}
	}

	/**
	 * Create NodeVM and run code inside it.
	 *
	 * @param {String} script Javascript code.
	 * @param {String} [filename] File name (used in stack traces only).
	 * @param {Object} [options] VM options.
	 * @return {NodeVM} VM.
	 */

	static code(script, filename, options) {
		if (filename != null) {
			if ('object' === typeof filename) {
				options = filename;
				filename = null;
			} else if ('string' === typeof filename) {
				filename = pa.resolve(filename);
			} else {
				throw new VMError("Invalid arguments.");
			}
		}

		if (arguments.length > 3) {
			throw new VMError("Invalid number of arguments.");
		}

		return new NodeVM(options).run(script, filename);
	}

	/**
	 * Create NodeVM and run script from file inside it.
	 *
	 * @param {String} [filename] File name (used in stack traces only).
	 * @param {Object} [options] VM options.
	 * @return {NodeVM} VM.
	 */

	static file(filename, options) {
		filename = pa.resolve(filename);

		if (!fs.existsSync(filename)) {
			throw new VMError(`Script '${filename}' not found.`);
		}

		if (fs.statSync(filename).isDirectory()) {
			throw new VMError("Script must be file, got directory.");
		}

		return new NodeVM(options).run(fs.readFileSync(filename, 'utf8'), filename);
	}
}

/**
 * VMError.
 *
 * @class
 * @extends {Error}
 * @property {String} stack Call stack.
 * @property {String} message Error message.
 */

class VMError extends Error {
	/**
	 * Create VMError instance.
	 *
	 * @param {String} message Error message.
	 * @return {VMError}
	 */

	constructor(message) {
		super(message);

		this.name = 'VMError';

		Error.captureStackTrace(this, this.constructor);
	}
}

exports.VMError = VMError;
exports.NodeVM = NodeVM;
exports.VM = VM;
exports.VMScript = VMScript;

})(vm2, (module) => {
	switch (module) {
		case 'fs': return {
			readFileSync(path) {
				switch (path) {
					case './contextify.js': return "\"use strict\";const global=this,console=host.console;\"[object Window]\"!==Object.prototype.toString.call(global)&&Object.setPrototypeOf(global,Object.prototype),Object.defineProperties(global,{global:{value:global},GLOBAL:{value:global},root:{value:global},isVM:{value:!0}});const DEBUG=!1,OPNA=\"Operation not allowed on contextified object.\",ERROR_CST=Error.captureStackTrace,FROZEN_TRAPS={set:(t,e)=>!1,setPrototypeOf:(t,e)=>!1,defineProperty:(t,e)=>!1,deleteProperty:(t,e)=>!1,isExtensible:(t,e)=>!1,preventExtensions:t=>!1},Contextified=new host.WeakMap,Decontextified=new host.WeakMap;global.VMError=class extends Error{constructor(t,e){super(t),this.name=\"VMError\",this.code=e,ERROR_CST(this,this.constructor)}};const Decontextify={proxies:new host.WeakMap,arguments:function(t){if(!host.Array.isArray(t))return new host.Array;const e=new host.Array;for(let n=0,o=t.length;n<o;n++)e[n]=Decontextify.value(t[n]);return e},instance:function(t,e,n,o){return Decontextify.object(t,{get:(r,i,a)=>{if(\"isVMProxy\"===i)return!0;if(\"constructor\"===i)return e;if(\"__proto__\"===i)return e.prototype;try{return Decontextify.value(t[i],null,n,o)}catch(t){throw Decontextify.value(t)}},getPrototypeOf:t=>e.prototype},n,o)},function:function(t,e,n,o,r){const i=Decontextify.object(t,host.Object.assign({apply:(e,n,o)=>{try{return n=Contextify.value(n),Decontextify.value(t.apply(n,Contextify.arguments(o)))}catch(t){throw Decontextify.value(t)}},construct:(e,r,a)=>{try{return Decontextify.instance(new t(...Contextify.arguments(r)),i,n,o)}catch(t){throw Decontextify.value(t)}},get:(e,i,a)=>{if(\"isVMProxy\"===i)return!0;if(r&&i in r)return r[i];if(\"constructor\"===i)return host.Function;if(\"__proto__\"===i)return host.Function.prototype;try{return Decontextify.value(t[i],null,n,o)}catch(t){throw Decontextify.value(t)}},getPrototypeOf:t=>host.Function.prototype},e),n);return i},object:function(t,e,n,o,r){const i=new host.Proxy(t,host.Object.assign({get:(e,i,a)=>{if(\"isVMProxy\"===i)return!0;if(r&&i in r)return r[i];if(\"constructor\"===i)return host.Object;if(\"__proto__\"===i)return host.Object.prototype;try{return Decontextify.value(t[i],null,n,o)}catch(t){throw Decontextify.value(t)}},set:(e,n,o,r)=>{try{return t[n]=Contextify.value(o),!0}catch(t){throw Decontextify.value(t)}},getOwnPropertyDescriptor:(e,n)=>{try{var o=host.Object.getOwnPropertyDescriptor(t,n)}catch(t){throw Decontextify.value(t)}return o?o.get||o.set?{get:Decontextify.value(o.get)||void 0,set:Decontextify.value(o.set)||void 0,enumerable:!0===o.enumerable,configurable:!0===o.configurable}:{value:Decontextify.value(o.value),writable:!0===o.writable,enumerable:!0===o.enumerable,configurable:!0===o.configurable}:void 0},defineProperty:(t,e,r)=>{try{return r.get||r.set?host.Object.defineProperty(t,e,{get:Contextify.value(r.get,null,n,o)||void 0,set:Contextify.value(r.set,null,n,o)||void 0,enumerable:!0===r.enumerable,configurable:!0===r.configurable}):host.Object.defineProperty(t,e,{value:Contextify.value(r.value,null,n,o),writable:!0===r.writable,enumerable:!0===r.enumerable,configurable:!0===r.configurable})}catch(t){throw Decontextify.value(t)}},getPrototypeOf:t=>host.Object.prototype,setPrototypeOf:t=>{throw new host.Error(OPNA)}},e,n));return Decontextify.proxies.set(t,i),Decontextified.set(i,t),i},value:function(t,e,n,o,r){if(Contextified.has(t))return Contextified.get(t);if(Decontextify.proxies.has(t))return Decontextify.proxies.get(t);switch(typeof t){case\"object\":return null===t?null:t instanceof Number?host.Number(t):t instanceof String?host.String(t):t instanceof Boolean?host.Boolean(t):t instanceof Date?Decontextify.instance(t,host.Date,n,o):t instanceof EvalError?Decontextify.instance(t,host.EvalError,n,o):t instanceof RangeError?Decontextify.instance(t,host.RangeError,n,o):t instanceof ReferenceError?Decontextify.instance(t,host.ReferenceError,n,o):t instanceof SyntaxError?Decontextify.instance(t,host.SyntaxError,n,o):t instanceof TypeError?Decontextify.instance(t,host.TypeError,n,o):t instanceof URIError?Decontextify.instance(t,host.URIError,n,o):t instanceof VMError?Decontextify.instance(t,host.VMError,n,o):t instanceof Error?Decontextify.instance(t,host.Error,n,o):t instanceof Array?Decontextify.instance(t,host.Array,n,o):t instanceof RegExp?Decontextify.instance(t,host.RegExp,n,o):t instanceof Map?Decontextify.instance(t,host.Map,n,o):t instanceof WeakMap?Decontextify.instance(t,host.WeakMap,n,o):t instanceof Set?Decontextify.instance(t,host.Set,n,o):t instanceof WeakSet?Decontextify.instance(t,host.WeakSet,n,o):t instanceof Promise?Decontextify.instance(t,host.Promise,n,o):Decontextify.object(t,e,n,o,r);case\"function\":return Decontextify.function(t,e,n,o,r);case\"undefined\":return;default:return t}}},Contextify={proxies:new host.WeakMap,arguments:function(t){if(!host.Array.isArray(t))return new Array;const e=new Array;for(let n=0,o=t.length;n<o;n++)e[n]=Contextify.value(t[n]);return e},instance:function(t,e,n,o){return Contextify.object(t,{get:(r,i,a)=>{if(\"isVMProxy\"===i)return!0;if(\"constructor\"===i)return e;if(\"__proto__\"===i)return e.prototype;try{return Contextify.value(t[i],null,n,o)}catch(t){throw Contextify.value(t)}},getPrototypeOf:t=>e.prototype},n,o)},function:function(t,e,n,o,r){const i=Contextify.object(t,host.Object.assign({apply:(e,n,o)=>{try{return n=Decontextify.value(n),Contextify.value(t.apply(n,Decontextify.arguments(o)))}catch(t){throw Contextify.value(t)}},construct:(e,r,a)=>{try{return Contextify.instance(new t(...Decontextify.arguments(r)),i,n,o)}catch(t){throw Contextify.value(t)}},get:(e,i,a)=>{if(\"isVMProxy\"===i)return!0;if(r&&i in r)return r[i];if(\"constructor\"===i)return Function;if(\"__proto__\"===i)return Function.prototype;try{return Contextify.value(t[i],null,n,o)}catch(t){throw Contextify.value(t)}},getPrototypeOf:t=>Function.prototype},e),n);return i},object:function(t,e,n,o,r){const i=new host.Proxy(t,host.Object.assign({get:(e,i,a)=>{if(\"isVMProxy\"===i)return!0;if(r&&i in r)return r[i];if(\"constructor\"===i)return Object;if(\"__proto__\"===i)return Object.prototype;try{return Contextify.value(t[i],null,n,o)}catch(t){throw Contextify.value(t)}},set:(e,n,r,i)=>{if(o&&o.protected&&\"function\"==typeof r)return!1;try{return t[n]=Decontextify.value(r),!0}catch(t){throw Contextify.value(t)}},getOwnPropertyDescriptor:(e,r)=>{try{var i=host.Object.getOwnPropertyDescriptor(t,r)}catch(t){throw Contextify.value(t)}return i?i.get||i.set?{get:Contextify.value(i.get,null,n,o)||void 0,set:Contextify.value(i.set,null,n,o)||void 0,enumerable:!0===i.enumerable,configurable:!0===i.configurable}:{value:Contextify.value(i.value,null,n,o),writable:!0===i.writable,enumerable:!0===i.enumerable,configurable:!0===i.configurable}:void 0},defineProperty:(t,e,r)=>{if(o&&o.protected&&\"function\"==typeof r.value)return!1;try{return r.get||r.set?host.Object.defineProperty(t,e,{get:Decontextify.value(r.get,null,n)||void 0,set:Decontextify.value(r.set,null,n)||void 0,enumerable:!0===r.enumerable,configurable:!0===r.configurable}):host.Object.defineProperty(t,e,{value:Decontextify.value(r.value,null,n),writable:!0===r.writable,enumerable:!0===r.enumerable,configurable:!0===r.configurable})}catch(t){throw Contextify.value(t)}},getPrototypeOf:t=>Object.prototype,setPrototypeOf:t=>{throw new VMError(OPNA)}},e,n));return Contextify.proxies.set(t,i),Contextified.set(i,t),i},value:function(t,e,n,o,r){if(Decontextified.has(t))return Decontextified.get(t);if(Contextify.proxies.has(t))return Contextify.proxies.get(t);switch(typeof t){case\"object\":return null===t?null:t instanceof host.Number?host.Number(t):t instanceof host.String?host.String(t):t instanceof host.Boolean?host.Boolean(t):t instanceof host.Date?Contextify.instance(t,Date,n,o):t instanceof host.EvalError?Contextify.instance(t,EvalError,n,o):t instanceof host.RangeError?Contextify.instance(t,RangeError,n,o):t instanceof host.ReferenceError?Contextify.instance(t,ReferenceError,n,o):t instanceof host.SyntaxError?Contextify.instance(t,SyntaxError,n,o):t instanceof host.TypeError?Contextify.instance(t,TypeError,n,o):t instanceof host.URIError?Contextify.instance(t,URIError,n,o):t instanceof host.VMError?Contextify.instance(t,VMError,n,o):t instanceof host.Error?Contextify.instance(t,Error,n,o):t instanceof host.Array?Contextify.instance(t,Array,n,o):t instanceof host.RegExp?Contextify.instance(t,RegExp,n,o):t instanceof host.Map?Contextify.instance(t,Map,n,o):t instanceof host.WeakMap?Contextify.instance(t,WeakMap,n,o):t instanceof host.Set?Contextify.instance(t,Set,n,o):t instanceof host.WeakSet?Contextify.instance(t,WeakSet,n,o):t instanceof host.Promise?Contextify.instance(t,Promise,n,o):t instanceof host.Buffer?Contextify.instance(t,LocalBuffer,n,o):Contextify.object(t,e,n,o,r);case\"function\":return Contextify.function(t,e,n,o,r);case\"undefined\":return;default:return t}},globalValue:function(t,e){return global[e]=Contextify.value(t)},readonly:function(t,e){return Contextify.value(t,null,FROZEN_TRAPS,null,e)},protected:function(t,e){return Contextify.value(t,null,null,{protected:!0},e)}},LocalBuffer=global.Buffer=Contextify.readonly(host.Buffer);return{Contextify:Contextify,Decontextify:Decontextify,Buffer:LocalBuffer};";
					case './sandbox.js': return "const{Script:Script}=host.require(\"vm\"),fs=host.require(\"fs\"),pa=host.require(\"path\"),console=host.console,BUILTIN_MODULES=host.process.binding(\"natives\"),JSON_PARSE=JSON.parse;return((e,r)=>{\"use strict\";const t=this,n=new r.WeakMap,o={},i={},s={[\".json\"](e,r){try{var t=fs.readFileSync(r,\"utf8\")}catch(e){throw Contextify.value(e)}e.exports=JSON_PARSE(t)},[\".node\"](t,n){if(\"sandbox\"===e.options.require.context)throw new VMError(\"Native modules can be required only with context set to 'host'.\");try{t.exports=Contextify.readonly(r.require(n))}catch(e){throw Contextify.value(e)}},[\".js\"](n,o,i){if(\"sandbox\"!==e.options.require.context)try{n.exports=Contextify.readonly(r.require(o))}catch(e){throw Contextify.value(e)}else{try{var s=`(function (exports, require, module, __filename, __dirname) { 'use strict'; ${fs.readFileSync(o,\"utf8\")} \n});`,u=new Script(s,{filename:o||\"vm.js\",displayErrors:!1}).runInContext(t,{filename:o||\"vm.js\",displayErrors:!1})}catch(e){throw Contextify.value(e)}u(n.exports,n.require,n,o,i)}}},u=function(e){e=pa.resolve(e);const r=fs.existsSync(e),t=!!r&&fs.statSync(e).isDirectory();if(r&&!t)return e;if(fs.existsSync(`${e}.js`))return`${e}.js`;if(fs.existsSync(`${e}.node`))return`${e}.node`;if(fs.existsSync(`${e}.json`))return`${e}.json`;if(fs.existsSync(`${e}/package.json`)){try{var n=JSON.parse(fs.readFileSync(`${e}/package.json`,\"utf8\"));null==n.main&&(n.main=\"index.js\")}catch(e){throw new VMError(`Module '${modulename}' has invalid package.json`,\"EMODULEINVALID\")}return u(`${e}/${n.main}`)}return fs.existsSync(`${e}/index.js`)?`${e}/index.js`:fs.existsSync(`${e}/index.node`)?`${e}/index.node`:null},c=function(e){if(\"buffer\"===e)return{Buffer:Buffer};if(o[e])return o[e].exports;if(\"util\"===e)return Contextify.readonly(r.require(e),{inherits:function(e,r){e.super_=r,Object.setPrototypeOf(e.prototype,r.prototype)}});if(\"events\"===e)try{const n=new Script(`(function (exports, require, module, process) { 'use strict'; ${BUILTIN_MODULES[e]} \n});`,{filename:`${e}.vm.js`}),i=o[e]={exports:{},require:c};return n.runInContext(t)(i.exports,i.require,i,r.process),i.exports}catch(e){throw Contextify.value(e)}return Contextify.readonly(r.require(e))},l=function(t){return function(n){if(e.options.nesting&&\"vm2\"===n)return{VM:Contextify.readonly(r.VM),NodeVM:Contextify.readonly(r.NodeVM)};if(!e.options.require)throw new VMError(`Access denied to require '${n}'`,\"EDENIED\");if(null==n)throw new VMError(\"Module '' not found.\",\"ENOTFOUND\");if(\"string\"!=typeof n)throw new VMError(`Invalid module name '${n}'`,\"EINVALIDNAME\");if(e.options.require.mock&&e.options.require.mock[n])return Contextify.readonly(e.options.require.mock[n]);if(BUILTIN_MODULES[n]){if(r.Array.isArray(e.options.require.builtin)){if(e.options.require.builtin.indexOf(\"*\")>=0){if(e.options.require.builtin.indexOf(`-${n}`)>=0)throw new VMError(`Access denied to require '${n}'`,\"EDENIED\")}else if(-1===e.options.require.builtin.indexOf(n))throw new VMError(`Access denied to require '${n}'`,\"EDENIED\")}else{if(!e.options.require.builtin)throw new VMError(`Access denied to require '${n}'`,\"EDENIED\");if(!e.options.require.builtin[n])throw new VMError(`Access denied to require '${n}'`,\"EDENIED\")}return c(n)}if(!e.options.require.external)throw new VMError(`Access denied to require '${n}'`,\"EDENIED\");if(/^(\.|\.\/|\.\.\/)/.exec(n)){if(!t)throw new VMError(\"You must specify script path to load relative modules.\",\"ENOPATH\");o=u(`${t}/${n}`)}else if(/^(\/|\\|[a-zA-Z]:\\)/.exec(n))var o=u(n);else{if(!t)throw new VMError(\"You must specify script path to load relative modules.\",\"ENOPATH\");const e=t.split(pa.sep);for(;e.length;){let r=e.join(pa.sep);if(o=u(`${r}${pa.sep}node_modules${pa.sep}${n}`))break;e.pop()}}if(!o)throw new VMError(`Cannot find module '${n}'`,\"ENOTFOUND\");if(i[o])return i[o].exports;const f=pa.dirname(o),a=pa.extname(o);if(e.options.require.root){const r=pa.resolve(e.options.require.root);if(0!==f.indexOf(r))throw new VMError(`Module '${n}' is not allowed to be required. The path is outside the border!`,\"EDENIED\")}const p=i[o]={filename:o,exports:{},require:l(f)};if(s[a])return s[a](p,o,f),p.exports;throw new VMError(`Failed to load '${n}': Unknown type.`,\"ELOADFAIL\")}};return t.setTimeout=function(e,t,...o){const i=r.setTimeout(function(){e.apply(null,o)},t),s={ref:()=>i.ref(),unref:()=>i.unref()};return n.set(s,i),s},t.setInterval=function(e,t,...o){const i=r.setInterval(function(){e.apply(null,o)},t),s={ref:()=>i.ref(),unref:()=>i.unref()};return n.set(s,i),s},t.setImmediate=function(e,...t){const o=r.setImmediate(function(){e.apply(null,t)}),i={ref:()=>o.ref(),unref:()=>o.unref()};return n.set(i,o),i},t.clearTimeout=function(e){return r.clearTimeout(n.get(e)),null},t.clearInterval=function(e){return r.clearInterval(n.get(e)),null},t.clearImmediate=function(e){return r.clearImmediate(n.get(e)),null},t.process={argv:[],title:r.process.title,version:r.process.version,versions:Contextify.readonly(r.process.versions),arch:r.process.arch,platform:r.process.platform,env:{},pid:r.process.pid,features:Contextify.readonly(r.process.features),nextTick:e=>r.process.nextTick(()=>e.call(null)),hrtime:()=>r.process.hrtime(),cwd:()=>r.process.cwd(),on(e,t){if(\"beforeExit\"!==e&&\"exit\"!==e)throw new Error(`Access denied to listen for '${e}' event.`);return r.process.on(e,Decontextify.value(t)),this},once(e,t){if(\"beforeExit\"!==e&&\"exit\"!==e)throw new Error(`Access denied to listen for '${e}' event.`);return r.process.once(e,Decontextify.value(t)),this},listeners:e=>Contextify.readonly(r.process.listeners(e)),removeListener(e,t){return r.process.removeListener(e,Decontextify.value(t)),this},umask(){if(arguments.length)throw new Error(\"Access denied to set umask.\");return r.process.umask()}},\"inherit\"===e.options.console?t.console=Contextify.readonly(r.console):\"redirect\"===e.options.console&&(t.console={log:(...r)=>(e.emit(\"console.log\",...Decontextify.arguments(r)),null),info:(...r)=>(e.emit(\"console.info\",...Decontextify.arguments(r)),null),warn:(...r)=>(e.emit(\"console.warn\",...Decontextify.arguments(r)),null),error:(...r)=>(e.emit(\"console.error\",...Decontextify.arguments(r)),null),dir:(...r)=>(e.emit(\"console.dir\",...Decontextify.arguments(r)),null),time:()=>{},timeEnd:()=>{},trace:(...r)=>(e.emit(\"console.trace\",...Decontextify.arguments(r)),null)}),l})(vm,host);";
					default: throw new Error('File '+ path +' not present.');
				}
			}
		};
		case 'path': return {
			resolve(path) {
				return path;
			}
		};
		case 'events': return {
			EventEmitter: class EventEmitter {}
		};
		case 'vm':
			const wrapper = {exports: {}};
			((module, exports) => {
				CONTEXT_MINIMAL = [
	'String', 'Array', 'Boolean', 'Date', 'Function', 'Number', 'RegExp', 'Object',
	'Proxy', 'Reflect', 'Map', 'WeakMap', 'Set', 'WeakSet', 'Promise', 'Symbol',
	'Error', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError',
	'Infinity', 'JSON', 'Math', 'NaN', 'undefined',
	'decodeURI', 'decodeURIComponent', 'encodeURI', 'encodeURIComponent', 'escape', 'unescape',
	'eval', 'isFinite', 'isNaN', 'parseFloat', 'parseInt'
]

class Script {
	constructor(code, options) {
		this._code = code;
	}

	runInContext(context, options) {
		return context.eval(this._code);
	}
}

exports.Script = Script;
exports.createContext = function(sandbox, type = CONTEXT_MINIMAL) {
	const iframe = document.createElement('iframe');
	iframe.classList.add('vm2-context');
	iframe.style.display = 'none';
	document.body.appendChild(iframe);

	if (sandbox) {
		Object.keys(sandbox).forEach((key) => {
			iframe.contentWindow[key] = sandbox[key];
		})
	}

	// Remove unwanted window properties
	Object.getOwnPropertyNames(iframe.contentWindow).forEach((key) => {
		if (type.indexOf(key) === -1) {
			delete iframe.contentWindow[key]
		}
	})

	return iframe.contentWindow;
}
exports.disposeContext = (context) => {
	document.body.removeChild(context);
}
exports.runInContext = (code, context, options) => {
	return new Script(code).runInContext(context, options);
}
			})(wrapper, wrapper.exports);
			return wrapper.exports;

		default: throw new Error('Module '+ module +' not present.');
	}
}, '.', class Buffer {});
