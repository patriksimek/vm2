const fs = require('fs');
const vm = require('vm');
const pa = require('path');
const {EventEmitter} = require('events');

const sb = fs.readFileSync(`${__dirname}/sandbox.js`, 'utf8');
const cf = fs.readFileSync(`${__dirname}/contextify.js`, 'utf8');

const _compileToJS = function(code, compiler) {
	if ('function' === typeof compiler) return compiler(code);

	switch (compiler) {
		case 'coffeescript':
		case 'coffee-script':
		case 'cs':
		case 'text/coffeescript':
			return require('coffee-script').compile(code, {header: false, bare: true});
		
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
			timeout: options.timeout != null ? options.timeout : undefined,
			sandbox: options.sandbox != null ? options.sandbox : null,
			compiler: options.compiler != null ? options.compiler : 'javascript'
		};

		let host = {
			console,
			String,
			Number,
			Buffer,
			Boolean,
			Array,
			Date,
			Error,
			RangeError,
			ReferenceError,
			SyntaxError,
			TypeError,
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
	 * Run the code in VM.
	 * 
	 * @param {String} code Code to run.
	 * @return {*} Result of executed code.
	 */
	
	run(code) {
		if (this.options.compiler !== 'javascript') {
			code = _compileToJS(code, this.options.compiler);
		}

		let script = new vm.Script(code, {
			filename: "vm.js",
			displayErrors: false
		});
		
		try {
			return this._internal.Decontextify.value(script.runInContext(this._context, {
				filename: "vm.js",
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
			nesting: options.nesting != null ? options.nesting : false
		};

		let host = {
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
			RangeError,
			ReferenceError,
			SyntaxError,
			TypeError,
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
		
		let closure = vm.runInContext(`(function (vm, host, Contextify, Decontextify, Buffer) { ${sb} \n})`, this._context, {
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
	 * Require a module in VM and return it's exports.
	 *
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

		let module = vm.runInContext("({exports: {}})", this._context, {
			displayErrors: false
		});
		
		let script = new vm.Script(`(function (exports, require, module, __filename, __dirname) { ${code} \n})`, {
			filename: filename || "vm.js",
			displayErrors: false
		});
		
		try {
			let closure = script.runInContext(this._context, {
				filename: filename || "vm.js",
				displayErrors: false
			});
	
			closure.call(this._context, module.exports, this._prepareRequire(dirname), module, filename, dirname);
		} catch (e) {
			throw this._internal.Decontextify.value(e);
		}

		return this._internal.Decontextify.value(module.exports);
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
 * @param {String} message Error message.
 * 
 * @class
 * @extends {Error}
 * @property {String} stack Call stack.
 * @property {String} message Error message.
 */

class VMError extends Error {
	constructor(message) {
		super(message);
		
		this.name = 'VMError';

		Error.captureStackTrace(this, this.constructor);
	}
}

exports.VMError = VMError;
exports.NodeVM = NodeVM;
exports.VM = VM;
