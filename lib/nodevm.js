'use strict';

/**
 * This callback will be called to resolve a module if it couldn't be found.
 *
 * @callback resolveCallback
 * @param {string} moduleName - Name of the module used to resolve.
 * @param {string} dirname - Name of the current directory.
 * @return {(string|undefined)} The file or directory to use to load the requested module.
 */

/**
 * This callback will be called to require a module instead of node's require.
 *
 * @callback customRequire
 * @param {string} moduleName - Name of the module requested.
 * @return {*} The required module object.
 */

const fs = require('fs');
const pa = require('path');
const {
	Script
} = require('vm');
const {
	VMError
} = require('./bridge');
const {
	VMScript,
	MODULE_PREFIX,
	STRICT_MODULE_PREFIX,
	MODULE_SUFFIX
} = require('./script');
const {
	transformer
} = require('./transformer');
const {
	VM
} = require('./vm');
const {
	resolverFromOptions
} = require('./resolver-compat');

const objectDefineProperty = Object.defineProperty;
const objectDefineProperties = Object.defineProperties;

/**
 * Host objects
 *
 * @private
 */
const HOST = Object.freeze({
	__proto__: null,
	version: parseInt(process.versions.node.split('.')[0]),
	process,
	console,
	setTimeout,
	setInterval,
	setImmediate,
	clearTimeout,
	clearInterval,
	clearImmediate
});

/**
 * Compile a script.
 *
 * @private
 * @param {string} filename - Filename of the script.
 * @param {string} script - Script.
 * @return {vm.Script} The compiled script.
 */
function compileScript(filename, script) {
	return new Script(script, {
		__proto__: null,
		filename,
		displayErrors: false
	});
}

let cacheSandboxScript = null;
let cacheMakeNestingScript = null;

const NESTING_OVERRIDE = Object.freeze({
	__proto__: null,
	vm2: vm2NestingLoader
});

/**
 * Event caused by a <code>console.debug</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.debug"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.log</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.log"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.info</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.info"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.warn</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.warn"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.error</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.error"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.dir</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.dir"
 * @type {...*}
 */

/**
 * Event caused by a <code>console.trace</code> call if <code>options.console="redirect"</code> is specified.
 *
 * @public
 * @event NodeVM."console.trace"
 * @type {...*}
 */

/**
 * Class NodeVM.
 *
 * @public
 * @extends {VM}
 * @extends {EventEmitter}
 */
class NodeVM extends VM {

	/**
	 * Create a new NodeVM instance.<br>
	 *
	 * Unlike VM, NodeVM lets you use require same way like in regular node.<br>
	 *
	 * However, it does not use the timeout.
	 *
	 * @public
	 * @param {Object} [options] - VM options.
	 * @param {Object} [options.sandbox] - Objects that will be copied into the global object of the sandbox.
	 * @param {(string|compileCallback)} [options.compiler="javascript"] - The compiler to use.
	 * @param {boolean} [options.eval=true] - Allow the dynamic evaluation of code via eval(code) or Function(code)().<br>
	 * Only available for node v10+.
	 * @param {boolean} [options.wasm=true] - Allow to run wasm code.<br>
	 * Only available for node v10+.
	 * @param {("inherit"|"redirect"|"off")} [options.console="inherit"] - Sets the behavior of the console in the sandbox.
	 * <code>inherit</code> to enable console, <code>redirect</code> to redirect to events, <code>off</code> to disable console.
	 * @param {Object|boolean} [options.require=false] - Allow require inside the sandbox.
	 * @param {(boolean|string[]|Object)} [options.require.external=false] - <b>WARNING: When allowing require the option <code>options.require.root</code>
	 * should be set to restrict the script from requiring any module. Values can be true, an array of allowed external modules or an object.
	 * @param {(string[])} [options.require.external.modules] - Array of allowed external modules. Also supports wildcards, so specifying ['@scope/*-ver-??],
	 * for instance, will allow using all modules having a name of the form @scope/something-ver-aa, @scope/other-ver-11, etc.
	 * @param {boolean} [options.require.external.transitive=false] - Boolean which indicates if transitive dependencies of external modules are allowed.
	 * @param {string[]} [options.require.builtin=[]] - Array of allowed built-in modules, accepts ["*"] for all.
	 * @param {(string|string[])} [options.require.root] - Restricted path(s) where local modules can be required. If omitted every path is allowed.
	 * @param {Object} [options.require.mock] - Collection of mock modules (both external or built-in).
	 * @param {("host"|"sandbox")} [options.require.context="host"] - <code>host</code> to require modules in host and proxy them to sandbox.
	 * <code>sandbox</code> to load, compile and require modules in sandbox.
	 * Builtin modules except <code>events</code> always required in host and proxied to sandbox.
	 * @param {string[]} [options.require.import] - Array of modules to be loaded into NodeVM on start.
	 * @param {resolveCallback} [options.require.resolve] - An additional lookup function in case a module wasn't
	 * found in one of the traditional node lookup paths.
	 * @param {customRequire} [options.require.customRequire=require] - Custom require to require host and built-in modules.
	 * @param {boolean} [options.nesting=false] -
	 * <b>WARNING: Allowing this is a security risk as scripts can create a NodeVM which can require any host module.</b>
	 * Allow nesting of VMs.
	 * @param {("commonjs"|"none")} [options.wrapper="commonjs"] - <code>commonjs</code> to wrap script into CommonJS wrapper,
	 * <code>none</code> to retrieve value returned by the script.
	 * @param {string[]} [options.sourceExtensions=["js"]] - Array of file extensions to treat as source code.
	 * @param {string[]} [options.argv=[]] - Array of arguments passed to <code>process.argv</code>.
	 * This object will not be copied and the script can change this object.
	 * @param {Object} [options.env={}] - Environment map passed to <code>process.env</code>.
	 * This object will not be copied and the script can change this object.
	 * @param {boolean} [options.strict=false] - If modules should be loaded in strict mode.
	 * @throws {VMError} If the compiler is unknown.
	 */
	constructor(options = {}) {
		const {
			compiler,
			eval: allowEval,
			wasm,
			console: consoleType = 'inherit',
			require: requireOpts = false,
			nesting = false,
			wrapper = 'commonjs',
			sourceExtensions = ['js'],
			argv,
			env,
			strict = false,
			sandbox
		} = options;

		// Throw this early
		if (sandbox && 'object' !== typeof sandbox) {
			throw new VMError('Sandbox must be an object.');
		}

		super({__proto__: null, compiler: compiler, eval: allowEval, wasm});

		// This is only here for backwards compatibility.
		objectDefineProperty(this, 'options', {__proto__: null, value: {
			console: consoleType,
			require: requireOpts,
			nesting,
			wrapper,
			sourceExtensions,
			strict
		}});

		const resolver = resolverFromOptions(this, requireOpts, nesting && NESTING_OVERRIDE, this._compiler);

		objectDefineProperty(this, '_resolver', {__proto__: null, value: resolver});

		if (!cacheSandboxScript) {
			cacheSandboxScript = compileScript(`${__dirname}/setup-node-sandbox.js`,
				`(function (host, data) { ${fs.readFileSync(`${__dirname}/setup-node-sandbox.js`, 'utf8')}\n})`);
		}

		const closure = this._runScript(cacheSandboxScript);

		const extensions = {
			__proto__: null
		};

		const loadJS = (mod, filename) => resolver.loadJS(this, mod, filename);

		for (let i = 0; i < sourceExtensions.length; i++) {
			extensions['.' + sourceExtensions[i]] = loadJS;
		}

		if (!extensions['.json']) extensions['.json'] = (mod, filename) => resolver.loadJSON(this, mod, filename);
		if (!extensions['.node']) extensions['.node'] = (mod, filename) => resolver.loadNode(this, mod, filename);


		this.readonly(HOST);
		this.readonly(resolver);
		this.readonly(this);

		const {
			Module,
			jsonParse,
			createRequireForModule,
			requireImpl
		} = closure(HOST, {
			__proto__: null,
			argv,
			env,
			console: consoleType,
			vm: this,
			resolver,
			extensions
		});

		objectDefineProperties(this, {
			__proto__: null,
			_Module: {__proto__: null, value: Module},
			_jsonParse: {__proto__: null, value: jsonParse},
			_createRequireForModule: {__proto__: null, value: createRequireForModule},
			_requireImpl: {__proto__: null, value: requireImpl},
			_cacheRequireModule: {__proto__: null, value: null, writable: true}
		});


		resolver.init(this);

		// prepare global sandbox
		if (sandbox) {
			this.setGlobals(sandbox);
		}

		if (requireOpts && requireOpts.import) {
			if (Array.isArray(requireOpts.import)) {
				for (let i = 0, l = requireOpts.import.length; i < l; i++) {
					this.require(requireOpts.import[i]);
				}
			} else {
				this.require(requireOpts.import);
			}
		}
	}

	/**
	 * @ignore
	 * @deprecated Just call the method yourself like <code>method(args);</code>
	 * @param {function} method - Function to invoke.
	 * @param {...*} args - Arguments to pass to the function.
	 * @return {*} Return value of the function.
	 * @todo Can we remove this function? It even had a bug that would use args as this parameter.
	 * @throws {*} Rethrows anything the method throws.
	 * @throws {VMError} If method is not a function.
	 * @throws {Error} If method is a class.
	 */
	call(method, ...args) {
		if ('function' === typeof method) {
			return method(...args);
		} else {
			throw new VMError('Unrecognized method type.');
		}
	}

	/**
	 * Require a module in VM and return it's exports.
	 *
	 * @public
	 * @param {string} module - Module name.
	 * @return {*} Exported module.
	 * @throws {*} If the module couldn't be found or loading it threw an error.
	 */
	require(module) {
		const path = this._resolver.pathResolve('.');
		let mod = this._cacheRequireModule;
		if (!mod || mod.path !== path) {
			const filename = this._resolver.pathConcat(path, '/vm.js');
			mod = new (this._Module)(filename, path);
			this._resolver.registerModule(mod, filename, path, null, false);
			this._cacheRequireModule = mod;
		}
		return this._requireImpl(mod, module, true);
	}

	/**
	 * Run the code in NodeVM.
	 *
	 * First time you run this method, code is executed same way like in node's regular `require` - it's executed with
	 * `module`, `require`, `exports`, `__dirname`, `__filename` variables and expect result in `module.exports'.
	 *
	 * @param {(string|VMScript)} code - Code to run.
	 * @param {(string|Object)} [options] - Options map or filename.
	 * @param {string} [options.filename="vm.js"] - Filename that shows up in any stack traces produced from this script.<br>
	 * This is only used if code is a String.
	 * @param {boolean} [options.strict] - If modules should be loaded in strict mode. Defaults to NodeVM options.
	 * @param {("commonjs"|"none")} [options.wrapper] - <code>commonjs</code> to wrap script into CommonJS wrapper,
	 * <code>none</code> to retrieve value returned by the script. Defaults to NodeVM options.
	 * @return {*} Result of executed code.
	 * @throws {SyntaxError} If there is a syntax error in the script.
	 * @throws {*} If the script execution terminated with an exception it is propagated.
	 * @fires NodeVM."console.debug"
	 * @fires NodeVM."console.log"
	 * @fires NodeVM."console.info"
	 * @fires NodeVM."console.warn"
	 * @fires NodeVM."console.error"
	 * @fires NodeVM."console.dir"
	 * @fires NodeVM."console.trace"
	 */
	run(code, options) {
		let script;
		let filename;

		if (typeof options === 'object') {
			filename = options.filename;
		} else {
			filename = options;
			options = {__proto__: null};
		}

		const {
			strict = this.options.strict,
			wrapper = this.options.wrapper,
			module: customModule,
			require: customRequire,
			dirname: customDirname = null
		} = options;

		let sandboxModule = customModule;
		let dirname = customDirname;

		if (code instanceof VMScript) {
			script = strict ? code._compileNodeVMStrict() : code._compileNodeVM();
			if (!sandboxModule) {
				const resolvedFilename = this._resolver.pathResolve(code.filename);
				dirname = this._resolver.pathDirname(resolvedFilename);
				sandboxModule = new (this._Module)(resolvedFilename, dirname);
				this._resolver.registerModule(sandboxModule, resolvedFilename, dirname, null, false);
			}
		} else {
			const unresolvedFilename = filename || 'vm.js';
			if (!sandboxModule) {
				if (filename) {
					const resolvedFilename = this._resolver.pathResolve(filename);
					dirname = this._resolver.pathDirname(resolvedFilename);
					sandboxModule = new (this._Module)(resolvedFilename, dirname);
					this._resolver.registerModule(sandboxModule, resolvedFilename, dirname, null, false);
				} else {
					sandboxModule = new (this._Module)(null, null);
					sandboxModule.id = unresolvedFilename;
				}
			}
			const prefix = strict ? STRICT_MODULE_PREFIX : MODULE_PREFIX;
			let scriptCode = this._compiler(code, unresolvedFilename);
			scriptCode = transformer(null, scriptCode, false, false).code;
			script = new Script(prefix + scriptCode + MODULE_SUFFIX, {
				__proto__: null,
				filename: unresolvedFilename,
				displayErrors: false
			});
		}

		const closure = this._runScript(script);

		const usedRequire = customRequire || this._createRequireForModule(sandboxModule);

		const ret = Reflect.apply(closure, this.sandbox, [sandboxModule.exports, usedRequire, sandboxModule, filename, dirname]);
		return wrapper === 'commonjs' ? sandboxModule.exports : ret;
	}

	/**
	 * Create NodeVM and run code inside it.
	 *
	 * @public
	 * @static
	 * @param {string} script - Code to execute.
	 * @param {string} [filename] - File name (used in stack traces only).
	 * @param {Object} [options] - VM options.
	 * @param {string} [options.filename] - File name (used in stack traces only). Used if <code>filename</code> is omitted.
	 * @return {*} Result of executed code.
	 * @see {@link NodeVM} for the options.
	 * @throws {SyntaxError} If there is a syntax error in the script.
	 * @throws {*} If the script execution terminated with an exception it is propagated.
	 */
	static code(script, filename, options) {
		let unresolvedFilename;
		if (filename != null) {
			if ('object' === typeof filename) {
				options = filename;
				unresolvedFilename = options.filename;
			} else if ('string' === typeof filename) {
				unresolvedFilename = filename;
			} else {
				throw new VMError('Invalid arguments.');
			}
		} else if ('object' === typeof options) {
			unresolvedFilename = options.filename;
		}

		if (arguments.length > 3) {
			throw new VMError('Invalid number of arguments.');
		}

		const resolvedFilename = typeof unresolvedFilename === 'string' ? pa.resolve(unresolvedFilename) : undefined;

		return new NodeVM(options).run(script, resolvedFilename);
	}

	/**
	 * Create NodeVM and run script from file inside it.
	 *
	 * @public
	 * @static
	 * @param {string} filename - Filename of file to load and execute in a NodeVM.
	 * @param {Object} [options] - NodeVM options.
	 * @return {*} Result of executed code.
	 * @see {@link NodeVM} for the options.
	 * @throws {Error} If filename is not a valid filename.
	 * @throws {SyntaxError} If there is a syntax error in the script.
	 * @throws {*} If the script execution terminated with an exception it is propagated.
	 */
	static file(filename, options) {
		const resolvedFilename = pa.resolve(filename);

		if (!fs.existsSync(resolvedFilename)) {
			throw new VMError(`Script '${filename}' not found.`);
		}

		if (fs.statSync(resolvedFilename).isDirectory()) {
			throw new VMError('Script must be file, got directory.');
		}

		return new NodeVM(options).run(fs.readFileSync(resolvedFilename, 'utf8'), resolvedFilename);
	}
}

function vm2NestingLoader(resolver, vm, id) {
	if (!cacheMakeNestingScript) {
		cacheMakeNestingScript = compileScript('nesting.js', '(vm, nodevm) => ({VM: vm, NodeVM: nodevm})');
	}
	const makeNesting = vm._runScript(cacheMakeNestingScript);
	return makeNesting(vm.readonly(VM), vm.readonly(NodeVM));
}

exports.NodeVM = NodeVM;
