{Script} = host.require 'vm'
noop = ->
fakeHandlers = {}

NATIVE_MODULES = host.process.binding 'natives'

###
@param {Object} host Hosts's internal objects.
###

return do (vm, host) =>
	'use strict'
	
	global = @

	NATIVES = {}
	CACHE = {}
	EXTENSIONS =
		".json": (module, filename) ->
			module.exports = JSON.parse fs.readFileSync(filename, "utf8")
	
	###
	Resolve filename.
	###

	_resolveFilename = (path) ->
		path = pa.resolve path
		
		exists = fs.existsSync(path)
		isdir = if exists then fs.statSync(path).isDirectory() else false
	
		# direct file match
		if exists and not isdir then return path

		# load as file
		
		if fs.existsSync "#{path}.js" then return "#{path}.js"
		if fs.existsSync "#{path}.json" then return "#{path}.json"
	
		# load as directory
		
		if fs.existsSync "#{path}/package.json"
			try
				pkg = JSON.parse fs.readFileSync("#{path}/package.json", "utf8")
				pkg.main ?= "index.js"
				
			catch ex
				throw new VMError "Module '#{modulename}' has invalid package.json", "EMODULEINVALID"
				
			return _resolveFilename "#{path}/#{pkg.main}"
			
		if fs.existsSync "#{path}/index.js" then return "#{path}/index.js"
	
		null
	
	###
	Native require.
	###
	
	_requireNative = (modulename) ->
		if Array.isArray vm.options.require.native
			if '*' in vm.options.require.native
				if "-#{modulename}" in vm.options.require.native
					throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
			
			else if modulename not in vm.options.require.native
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
		
		else if vm.options.require.native
			if not vm.options.require.native[modulename]
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
		
		else
			throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
		
		if NATIVES[modulename]
			return NATIVES[modulename].exports
		
		if modulename is 'buffer'
			return {Buffer: Buffer}
		
		if modulename is 'events'
			script = new Script "(function (exports, require, module, process) { 'use strict'; #{NATIVE_MODULES[modulename]} \n});", 
				filename: "#{modulename}.sb.js"
			
			# setup module scope
			NATIVES[modulename] = module =
				exports: {}
				require: _requireNative
	
			# run script
			script.runInContext(global) module.exports, module.require, module, host.process
	
			return module.exports
		
		return contextify host.require(modulename), readonly: true
	
	###
	Prepare require.
	###

	_prepareRequire = (current_dirname) ->
		_require = (modulename) ->
			unless vm.options.require
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
			
			unless modulename?
				throw new VMError "Module '' not found.", "ENOTFOUND"
				
			if typeof modulename isnt 'string'
				throw new VMError "Invalid module name '#{modulename}'", "EINVALIDNAME"
	
			# Is module native module
			
			if NATIVE_MODULES[modulename]
				return _requireNative modulename
			
			unless vm.options.require.external
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"

			if /^(\.|\.\/|\.\.\/)/.exec modulename
				# Module is relative file, e.g. ./script.js or ../script.js
				
				if not current_dirname
					throw new VMError "You must specify script path to load relative modules.", "ENOPATH"

				filename = _resolveFilename "#{current_dirname}/#{modulename}"
			
			else if /^(\/|\\|[a-zA-Z]:\\)/.exec modulename
				# Module is absolute file, e.g. /script.js or //server/script.js or C:\script.js
	
				filename = _resolveFilename modulename
	
			else
				# Check node_modules in path
				
				if not current_dirname
					throw new VMError "You must specify script path to load relative modules.", "ENOPATH"

				paths = current_dirname.split pa.sep
				
				while paths.length
					path = paths.join pa.sep
					
					#console.log modulename, "#{path}#{pa.sep}node_modules#{pa.sep}#{modulename}"
					
					filename = _resolveFilename "#{path}#{pa.sep}node_modules#{pa.sep}#{modulename}"
					if filename then break
	
					paths.pop()

			unless filename
				throw new VMError "Module '#{modulename}' not found", "ENOTFOUND"
			
			# return cache whenever possible
			if CACHE[filename]
				return CACHE[filename].exports
			
			dirname = pa.dirname filename
			extname = pa.extname filename

			if vm.options.require.root
				requiredPath = pa.resolve vm.options.require.root
				if dirname.indexOf(requiredPath) isnt 0
					throw new VMError "Module '#{modulename}' is not allowed to be required. The path is outside the border!", "EDENIED"
			
			CACHE[filename] = module =
				filename: filename
				exports: {}
				require: _prepareRequire dirname
			
			# lookup extensions
			
			if EXTENSIONS[extname]
				try
					EXTENSIONS[extname] module, filename
					return module.exports
					
				catch ex
					throw new VMError "Failed to load '#{filename}': [#{ex.message}]", "ELOADFAIL"

			# Watch for .js
	
			try
				# Load module
				code = "(function (exports, require, module, __filename, __dirname) { 'use strict'; #{fs.readFileSync(filename, "utf8")} \n});"
				
			catch ex
				throw new VMError "Failed to load '#{filename}': [#{ex.message}]", "ELOADFAIL"
	
			# Precompile script
			script = new Script code, 
				filename: filename ? "vm"
				displayErrors: false

			closure = script.runInContext global, 
				filename: filename ? "vm"
				displayErrors: false

			# run script
			closure module.exports, module.require, module, filename, dirname
	
			module.exports
		
		_require.cache = CACHE
		_require.extensions = EXTENSIONS
		_require
	
	###
	Prepare sandbox.
	###
	
	global.setTimeout = (callback) ->
		arguments[0] = -> callback.call null
		tmr = host.setTimeout arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.setInterval = (callback) ->
		arguments[0] = -> callback.call null
		host.setInterval arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.setImmediate = (callback) ->
		arguments[0] = -> callback.call null
		host.setImmediate arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.clearTimeout = ->
		host.clearTimeout arguments...
		null
		
	global.clearInterval = ->
		host.clearInterval arguments...
		null
		
	global.clearImmediate = ->
		host.clearImmediate arguments...
		null
		
	global.process =
		argv: []
		title: host.process.title
		version: host.process.version
		versions: contextify host.process.versions
		arch: host.process.arch
		platform: host.process.platform
		env: {}
		pid: host.process.pid
		features: contextify host.process.features
		nextTick: (callback) -> host.process.nextTick -> callback.call null
		hrtime: -> host.process.hrtime()
		cwd: -> host.process.cwd()
		on: (name, handler) ->
			if name not in ['beforeExit', 'exit']
				throw new Error "Access denied to listen for '#{name}' event."
			
			fake = -> handler.call null
			fakeHandlers[name] ?= new Map()
			fakeHandlers[name].set handler, fake
			
			host.process.on name, fake
			@
		
		once: (name, handler) ->
			if name not in ['beforeExit', 'exit']
				throw new Error "Access denied to listen for '#{name}' event."
			
			if fakeHandlers[name]?.has handler
				return @
			
			fake = ->
				fakeHandlers[name].delete handler
				handler.call null
			
			fakeHandlers[name] ?= new Map()
			fakeHandlers[name].set handler, fake
			
			host.process.once name, fake
			@
		
		listeners: (name) ->
			if not fakeHandlers[name] then return []
			array = []
			fakeHandlers[name].forEach (value, key) ->
				array.push key
			
			array
		
		removeListener: (name, handler) ->
			fake = fakeHandlers[name]?.get handler
			if not fake? then return @
			fakeHandlers[name].delete handler
			
			host.process.removeListener name, fake
			@
		
		umask: ->
			if arguments.length
				throw new Error "Access denied to set umask."
			
			host.process.umask()
	
	if vm.options.console is 'inherit'
		global.console = contextify host.console, readonly: true
				
	else if vm.options.console is 'redirect'
		global.console =
			log: (args...) ->
				vm.emit 'console.log', decontextify(args)...
				null
				
			info: (args...) ->
				vm.emit 'console.info', decontextify(args)...
				null
				
			warn: (args...) ->
				vm.emit 'console.warn', decontextify(args)...
				null
				
			error: (args...) ->
				vm.emit 'console.error', decontextify(args)...
				null
				
			dir: (args...) ->
				vm.emit 'console.dir', decontextify(args)...
				null
				
			time: noop
			timeEnd: noop
			trace: (args...) ->
				vm.emit 'console.trace', decontextify(args)...
				null

	fs = host.require 'fs'
	pa = host.require 'path'
	
	###
	Return contextized require.
	###
	
	_prepareRequire
