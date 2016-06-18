const {Script} = host.require('vm');
const fs = host.require('fs');
const pa = host.require('path');

const BUILTIN_MODULES = host.process.binding('natives');
const JSON_PARSE = JSON.parse;

/**
 * @param {Object} host Hosts's internal objects.
 */

return ((vm, host) => {
	'use strict';
	
	const global = this;

	const TIMERS = new host.WeakMap()
	const BUILTINS = {};
	const CACHE = {};
	const EXTENSIONS = {
		[".json"](module, filename) {
			try {
				var code = fs.readFileSync(filename, "utf8");
			} catch (e) {
				throw Contextify.value(e);
			}
			
			module.exports = JSON_PARSE(code);
		},
		[".node"](module, filename) {
			if (vm.options.require.context !== 'host') throw new VMError('Native modules can be required only with context set to \'host\'.');
			
			try {
				module.exports = contextify(host.require(filename));
			} catch (e) {
				throw Contextify.value(e);
			}
		},
		[".js"](module, filename, dirname) {
			if (vm.options.require.context === 'host') {
				try {
					module.exports = contextify(host.require(filename));
				} catch (e) {
					throw Contextify.value(e);
				}
			} else {
				try {
					// Load module
					var code = `(function (exports, require, module, __filename, __dirname) { 'use strict'; ${fs.readFileSync(filename, "utf8")} \n});`;
			
					// Precompile script
					let script = new Script(code, { 
						filename: filename || "vm.js",
						displayErrors: false
					});

					var closure = script.runInContext(global, { 
						filename: filename || "vm.js",
						displayErrors: false
					});
				} catch (ex) {
					throw Contextify.value(e);
				}
		
				// run script
				closure(module.exports, module.require, module, filename, dirname);
			}
		}
	};
	
	/**
	 * Resolve filename.
	 */

	const _resolveFilename = function(path) {
		path = pa.resolve(path);
		
		let exists = fs.existsSync(path);
		let isdir = exists ? fs.statSync(path).isDirectory() : false;
	
		// direct file match
		if (exists && !isdir) return path;

		// load as file
		
		if (fs.existsSync(`${path}.js`)) return `${path}.js`;
		if (fs.existsSync(`${path}.node`)) return `${path}.node`;
		if (fs.existsSync(`${path}.json`)) return `${path}.json`;
	
		// load as directory
		
		if (fs.existsSync(`${path}/package.json`)) {
			try {
				var pkg = JSON.parse(fs.readFileSync(`${path}/package.json`, "utf8"));
				if (pkg.main == null) pkg.main = "index.js";
			} catch (ex) {
				throw new VMError(`Module '${modulename}' has invalid package.json`, "EMODULEINVALID");
			}
			
			return _resolveFilename(`${path}/${pkg.main}`);
		}
		
		if (fs.existsSync(`${path}/index.js`)) return `${path}/index.js`;
		if (fs.existsSync(`${path}/index.node`)) return `${path}/index.node`;
	
		return null;
	};
	
	/**
	 * Builtin require.
	 */
	
	const _requireBuiltin = function(modulename) {
		if (host.Array.isArray(vm.options.require.builtin)) {
			if (vm.options.require.builtin.indexOf('*') >= 0) {
				if (vm.options.require.builtin.indexOf(`-${modulename}`) >= 0) {
					throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");
				}
			} else if (vm.options.require.builtin.indexOf(modulename) === -1) {
				throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");
			}
		} else if (vm.options.require.builtin) {
			if (!vm.options.require.builtin[modulename]) {
				throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");
			}
		} else {
			throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");
		}
		
		if (BUILTINS[modulename]) return BUILTINS[modulename].exports;
		if (modulename === 'buffer') return ({Buffer});
		if (modulename === 'events') {
			let script = new Script(`(function (exports, require, module, process) { 'use strict'; ${BUILTIN_MODULES[modulename]} \n});`, {
				filename: `${modulename}.sb.js`
			});
			
			// setup module scope
			let module = BUILTINS[modulename] = {
				exports: {},
				require: _requireBuiltin
			};
	
			// run script
			script.runInContext(global)(module.exports, module.require, module, host.process);
			
			return module.exports;
		}
		
		return contextify(host.require(modulename), {readonly: true});
	};
	
	/**
	 * Prepare require.
	 */
	
	const _prepareRequire = function(current_dirname) {
		const _require = function(modulename) {
			if (vm.options.nesting && modulename === 'vm2') return {VM: contextify(host.VM), NodeVM: contextify(host.NodeVM)};
			if (!vm.options.require) throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");
			if (modulename == null) throw new VMError("Module '' not found.", "ENOTFOUND");
			if (typeof modulename !== 'string') throw new VMError(`Invalid module name '${modulename}'`, "EINVALIDNAME");
			
			// Do we have a mock module?
			
			if (vm.options.require.mock && vm.options.require.mock[modulename]) {
				return contextify(vm.options.require.mock[modulename]);
			}
			
			// Is module builtin module?
			
			if (BUILTIN_MODULES[modulename]) return _requireBuiltin(modulename);
			if (!vm.options.require.external) throw new VMError(`Access denied to require '${modulename}'`, "EDENIED");

			if (/^(\.|\.\/|\.\.\/)/.exec(modulename)) {
				// Module is relative file, e.g. ./script.js or ../script.js
				
				if (!current_dirname) throw new VMError("You must specify script path to load relative modules.", "ENOPATH");

				var filename = _resolveFilename(`${current_dirname}/${modulename}`);
			} else if (/^(\/|\\|[a-zA-Z]:\\)/.exec(modulename)) {
				// Module is absolute file, e.g. /script.js or //server/script.js or C:\script.js
	
				var filename = _resolveFilename(modulename);
			} else {
				// Check node_modules in path
				
				if (!current_dirname) throw new VMError("You must specify script path to load relative modules.", "ENOPATH");

				let paths = current_dirname.split(pa.sep);
				
				while (paths.length) {
					let path = paths.join(pa.sep);
					
					//console.log modulename, "#{path}#{pa.sep}node_modules#{pa.sep}#{modulename}"
					
					var filename = _resolveFilename(`${path}${pa.sep}node_modules${pa.sep}${modulename}`);
					if (filename) break;
	
					paths.pop();
				}
			}
	
			if (!filename) throw new VMError(`Cannot find module '${modulename}'`, "ENOTFOUND");
			
			// return cache whenever possible
			if (CACHE[filename]) return CACHE[filename].exports;

			let dirname = pa.dirname(filename);
			let extname = pa.extname(filename);
	
			if (vm.options.require.root) {
				let requiredPath = pa.resolve(vm.options.require.root);
				if (dirname.indexOf(requiredPath) !== 0) {
					throw new VMError(`Module '${modulename}' is not allowed to be required. The path is outside the border!`, "EDENIED");
				}
			}
			
			let module = CACHE[filename] = {
				filename,
				exports: {},
				require: _prepareRequire(dirname)
			};
			
			// lookup extensions
			
			if (EXTENSIONS[extname]) {
				EXTENSIONS[extname](module, filename, dirname);
				return module.exports;
			}
	
			throw new VMError(`Failed to load '${modulename}': Unknown type.`, "ELOADFAIL");
		};
		
		return _require;
	};

	/**
	 * Prepare sandbox.
	 */
	
	global.setTimeout = function(callback, ...args) {
		let tmr = host.setTimeout(function() {
			callback.apply(null, args)
		});
		
		let local = {
			ref() { return tmr.ref(); },
			unref() { return tmr.unref(); }
		};
		
		TIMERS.set(local, tmr);
		return local;
	};
		
	global.setInterval = function(callback, ...args) {
		let tmr = host.setInterval(function() {
			callback.apply(null, args)
		});
		
		let local = {
			ref() { return tmr.ref(); },
			unref() { return tmr.unref(); }
		};
		
		TIMERS.set(local, tmr);
		return local;
	};
	
	global.setImmediate = function(callback, ...args) {
		let tmr = host.setImmediate(function() {
			callback.apply(null, args)
		});
		
		let local = {
			ref() { return tmr.ref(); },
			unref() { return tmr.unref(); }
		};
		
		TIMERS.set(local, tmr);
		return local;
	};
		
	global.clearTimeout = function(local) {
		host.clearTimeout(TIMERS.get(local));
		return null;
	};
		
	global.clearInterval = function(local) {
		host.clearInterval(TIMERS.get(local));
		return null;
	};
		
	global.clearImmediate = function(local) {
		host.clearImmediate(TIMERS.get(local));
		return null;
	};
		
	global.process = {
		argv: [],
		title: host.process.title,
		version: host.process.version,
		versions: contextify(host.process.versions),
		arch: host.process.arch,
		platform: host.process.platform,
		env: {},
		pid: host.process.pid,
		features: contextify(host.process.features),
		nextTick(callback) { return host.process.nextTick(() => callback.call(null)); },
		hrtime() { return host.process.hrtime(); },
		cwd() { return host.process.cwd(); },
		on(name, handler) {
			if (name !== 'beforeExit' && name !== 'exit') {
				throw new Error(`Access denied to listen for '${name}' event.`);
			}
			
			host.process.on(name, decontextify(handler));
			return this;
		},
		
		once(name, handler) {
			if (name !== 'beforeExit' && name !== 'exit') {
				throw new Error(`Access denied to listen for '${name}' event.`);
			}

			host.process.once(name, decontextify(handler));
			return this;
		},
		
		listeners(name) {
			return contextify(host.process.listeners(name));
		},
		
		removeListener(name, handler) {
			host.process.removeListener(name, decontextify(handler));
			return this;
		},
		
		umask() {
			if (arguments.length) {
				throw new Error("Access denied to set umask.");
			}
			
			return host.process.umask();
		}
	};
	
	if (vm.options.console === 'inherit') {
		global.console = contextify(host.console, {readonly: true});
	} else if (vm.options.console === 'redirect') {
		global.console = {
			log(...args) {
				vm.emit('console.log', ...decontextify(args));
				return null;
			},	
			info(...args) {
				vm.emit('console.info', ...decontextify(args));
				return null;
			},
			warn(...args) {
				vm.emit('console.warn', ...decontextify(args));
				return null;
			},
			error(...args) {
				vm.emit('console.error', ...decontextify(args));
				return null;
			},
			dir(...args) {
				vm.emit('console.dir', ...decontextify(args));
				return null;
			},
			time: () => {},
			timeEnd: () => {},
			trace(...args) {
				vm.emit('console.trace', ...decontextify(args));
				return null;
			}
		};
	}

	/*
	Return contextized require.
	*/

	return _prepareRequire;
})(vm, host);
