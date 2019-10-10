/* eslint-disable global-require, no-use-before-define */

'use strict';

const fs = require('fs');
const vm = require('vm');
const pa = require('path');
const {EventEmitter} = require('events');
const {INSPECT_MAX_BYTES} = require('buffer');

const COFFEE_SCRIPT_COMPILER = {compiler: null};
function getCoffeeScriptCompiler() {
	if (!COFFEE_SCRIPT_COMPILER.compiler) {
		try {
			const coffeeScript = require('coffee-script');
			COFFEE_SCRIPT_COMPILER.compiler = (code, filename) => {
				return coffeeScript.compile(code, {header: false, bare: true});
			};
		} catch (e) {
			throw new VMError('Coffee-Script compiler is not installed.');
		}
	}
	return COFFEE_SCRIPT_COMPILER.compiler;
}

function jsCompiler(code, filename) {
	return code;
}

function lookupCompiler(compiler) {
	if ('function' === typeof compiler) return compiler;
	switch (compiler) {
		case 'coffeescript':
		case 'coffee-script':
		case 'cs':
		case 'text/coffeescript':
			return getCoffeeScriptCompiler();
		case 'javascript':
		case 'java-script':
		case 'js':
		case 'text/javascript':
			return jsCompiler;
		default:
			throw new VMError(`Unsupported compiler '${compiler}'.`);
	}
}

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
	 * @param {{ lineOffset: number, columnOffset: number }} [options] Options that define vm.Script options.
	 * @return {VMScript}
	 */

	constructor(code, filename, options) {
		this._code = String(code);
		this.options = options || {};
		this.filename = filename || this.options.filename || 'vm.js';
		this._prefix = '';
		this._suffix = '';
		this._compiledVM = null;
		this._compiledNodeVM = null;
		this._compiler = lookupCompiler(this.options.compiler || 'javascript');
		this._unresolvedFilename = this.options.filename || this.filename;
	}

	/**
	 * Wraps the code.
	 * Will invalidate the code cache.
	 *
	 * @return {VMScript}
	 */

	wrap(prefix, suffix) {
		const strPrefix = String(prefix);
		const strSuffix = String(suffix);
		if (this._prefix === strPrefix && this._suffix === strSuffix) return this;
		this._prefix = strPrefix;
		this._suffix = strSuffix;
		this._compiledVM = null;
		this._compiledNodeVM = null;
		return this;
	}

	/**
	 * This code will be compiled to VM code.
	 *
	 * @return {VMScript}
	 */

	compile() {
		return this._compileVM();
	}

	/**
	 * For backwards compatibility.
	 * 
	 * @return {String} The wrapped code
	 */
	get code() {
		return this._prefix + this._code + this._suffix;
	}

	/**
	 * For backwards compatibility.
	 * Will invalidate the code cache.
	 * 
	 * @param {String} newCode The new code to run.
	 */
	set code(newCode) {
		const strNewCode = String(newCode);
		if (strNewCode === this._prefix + this._code + this._suffix) return;
		this._code = strNewCode;
		this._prefix = '';
		this._suffix = '';
		this._compiledVM = null;
		this._compiledNodeVM = null;
	}

	/**
	 * Will compile the code for VM and cache it
	 * 
	 * @return {VMScript}
	 */
	_compileVM() {
		if (this._compiledVM) return this;

		this._compiledVM = new vm.Script(this._compiler(this._prefix + this._code + this._suffix, this._unresolvedFilename), {
			filename: this.filename,
			displayErrors: false,
			lineOffset: this.options.lineOffset || 0,
			columnOffset: this.options.columnOffset || 0
		});

		return this;
	}

	/**
	 * Will compile the code for NodeVM and cache it
	 * 
	 * @return {VMScript}
	 */
	_compileNodeVM() {
		if (this._compiledNodeVM) return this;

		this._compiledNodeVM = new vm.Script('(function (exports, require, module, __filename, __dirname) { ' +
				this._compiler(this._prefix + this._code + this._suffix, this._unresolvedFilename) + '\n})', {
			filename: this.filename,
			displayErrors: false,
			lineOffset: this.options.lineOffset || 0,
			columnOffset: this.options.columnOffset || 0
		});

		return this;
	}

	_runInVM(context) {
		return this._compiledVM.runInContext(context, {
			filename: this.filename,
			displayErrors: false
		});
	}

	_runInNodeVM(context) {
		return this._compiledNodeVM.runInContext(context, {
			filename: this.filename,
			displayErrors: false
		});
	}

}

function loadScript(filename) {
	const data = fs.readFileSync(filename, 'utf8');
	return new VMScript(data, filename);
}

const SCRIPT_CACHE = {
	cf: loadScript(`${__dirname}/contextify.js`).wrap('(function(require, host) { ', '\n})')._compileVM(),
	sb: loadScript(`${__dirname}/sandbox.js`).wrap('(function (vm, host, Contextify, Decontextify, Buffer) { ', '\n})')._compileVM(),
	exp: new VMScript('({exports: {}})')._compileVM(),
	runTimeout: new VMScript('fn()', 'timeout_bridge.js')._compileVM()
};

const TIMEOUT_CONTEXT = {context: null};

function doWithTimeout(fn, timeout) {
	if (!TIMEOUT_CONTEXT.context) {
		TIMEOUT_CONTEXT.context = vm.createContext();
	}
	TIMEOUT_CONTEXT.context.fn = fn;
	try {
		return SCRIPT_CACHE.runTimeout._compiledVM.runInContext(TIMEOUT_CONTEXT.context, {
			filename: SCRIPT_CACHE.runTimeout.filename,
			displayErrors: false,
			timeout
		});
	} finally {
		TIMEOUT_CONTEXT.context.fn = null;
	}
}

/**
 * Class VM.
 *
 * @property {Object} options VM options.
 */

class VM extends EventEmitter {
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
			timeout: options.timeout,
			sandbox: options.sandbox,
			compiler: lookupCompiler(options.compiler || 'javascript'),
			eval: options.eval === false ? false : true,
			wasm: options.wasm === false ? false : true
		};

		const host = {
			version: parseInt(process.versions.node.split('.')[0]),
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
			Promise,
			Symbol,
			INSPECT_MAX_BYTES
		};

		this._context = vm.createContext(undefined, {
			codeGeneration: {
				strings: this.options.eval,
				wasm: this.options.wasm
			}
		});

		Reflect.defineProperty(this, '_internal', {
			value: SCRIPT_CACHE.cf._runInVM(this._context).call(this._context, require, host)
		});

		// prepare global sandbox
		if (this.options.sandbox) {
			if ('object' !== typeof this.options.sandbox) {
				throw new VMError('Sandbox must be object.');
			}

			for (const name in this.options.sandbox) {
				if (Object.prototype.hasOwnProperty.call(this.options.sandbox, name)) {
					this._internal.Contextify.globalValue(this.options.sandbox[name], name);
				}
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
	 * @param {String} [filename] Filename that shows up in any stack traces produced from this script.
	 * @return {*} Result of executed code.
	 */

	run(code, filename) {
		const script = code instanceof VMScript ? code : new VMScript(code, filename, {compiler: this.options.compiler});
		script._compileVM();

		if (!this.options.timeout) {
			try {
				return this._internal.Decontextify.value(script._runInVM(this._context));
			} catch (e) {
				throw this._internal.Decontextify.value(e);
			}
		}

		return doWithTimeout(()=>{
			try {
				return this._internal.Decontextify.value(script._runInVM(this._context));
			} catch (e) {
				throw this._internal.Decontextify.value(e);
			}
		}, this.options.timeout);
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
			sandbox: options.sandbox,
			console: options.console || 'inherit',
			require: options.require || false,
			compiler: lookupCompiler(options.compiler || 'javascript'),
			eval: options.eval === false ? false : true,
			wasm: options.wasm === false ? false : true,
			nesting: options.nesting || false,
			wrapper: options.wrapper || 'commonjs',
			sourceExtensions: options.sourceExtensions || ['js']
		};

		const host = {
			version: parseInt(process.versions.node.split('.')[0]),
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
			Promise,
			Symbol,
			INSPECT_MAX_BYTES
		};

		if (this.options.nesting) {
			host.VM = VM;
			host.NodeVM = NodeVM;
		}

		this._context = vm.createContext(undefined, {
			codeGeneration: {
				strings: this.options.eval,
				wasm: this.options.wasm
			}
		});

		Object.defineProperty(this, '_internal', {
			value: SCRIPT_CACHE.cf._runInVM(this._context).call(this._context, require, host)
		});

		const closure = SCRIPT_CACHE.sb._runInVM(this._context);

		Object.defineProperty(this, '_prepareRequire', {
			value: closure.call(this._context, this, host, this._internal.Contextify, this._internal.Decontextify, this._internal.Buffer)
		});

		// prepare global sandbox
		if (this.options.sandbox) {
			if ('object' !== typeof this.options.sandbox) {
				throw new VMError('Sandbox must be object.');
			}

			for (const name in this.options.sandbox) {
				if (Object.prototype.hasOwnProperty.call(this.options.sandbox, name)) {
					this._internal.Contextify.globalValue(this.options.sandbox[name], name);
				}
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
			throw new VMError('Unrecognized method type.');
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
	 * First time you run this method, code is executed same way like in node's regular `require` - it's executed with
	 * `module`, `require`, `exports`, `__dirname`, `__filename` variables and expect result in `module.exports'.
	 *
	 * @param {String} code Code to run.
	 * @param {String} [filename] Filename that shows up in any stack traces produced from this script.
	 * @return {*} Result of executed code.
	 */

	run(code, filename) {
		let dirname;
		let returned;
		let resolvedFilename;

		if (filename) {
			resolvedFilename = pa.resolve(filename);
			dirname = pa.dirname(filename);
		} else {
			resolvedFilename = null;
			dirname = null;
		}

		const module = SCRIPT_CACHE.exp._runInVM(this._context);

		const script = code instanceof VMScript ? code : new VMScript(code, resolvedFilename, {compiler: this.options.compiler, filename});
		script._compileNodeVM();

		try {
			const closure = script._runInNodeVM(this._context);

			returned = closure.call(this._context, module.exports, this._prepareRequire(dirname), module, filename, dirname);
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
	 * @return {*} Result of executed code.
	 */

	static code(script, filename, options) {
		if (filename != null) {
			if ('object' === typeof filename) {
				options = filename;
				filename = null;
			} else if ('string' === typeof filename) {
				filename = pa.resolve(filename);
			} else {
				throw new VMError('Invalid arguments.');
			}
		}

		if (arguments.length > 3) {
			throw new VMError('Invalid number of arguments.');
		}

		return new NodeVM(options).run(script, filename);
	}

	/**
	 * Create NodeVM and run script from file inside it.
	 *
	 * @param {String} [filename] File name (used in stack traces only).
	 * @param {Object} [options] VM options.
	 * @return {*} Result of executed code.
	 */

	static file(filename, options) {
		filename = pa.resolve(filename);

		if (!fs.existsSync(filename)) {
			throw new VMError(`Script '${filename}' not found.`);
		}

		if (fs.statSync(filename).isDirectory()) {
			throw new VMError('Script must be file, got directory.');
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
