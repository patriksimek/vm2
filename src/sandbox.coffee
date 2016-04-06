{Script} = parent.require 'vm'
noop = ->
fakeHandlers = {}

NATIVE_MODULES = parent.process.binding 'natives'

###
@param {Object} parent Parent's global object.
###

return do (vm, parent) =>
	'use strict'

	EXTENSIONS =
		".json": (module, filename) ->
			module.exports = JSON.parse fs.readFileSync(filename, "utf8")

	# setup sandbox global
	global = @
	global.global = global.GLOBAL = global.root = global
	global.isVM = true

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
		if fs.existsSync "#{path}.node" then return "#{path}.node"
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
		if fs.existsSync "#{path}/index.node" then return "#{path}/index.node"
	
		null

	###
	Prepare require.
	###
	
	_requireNative = (modulename) ->
		'use strict'
		
		if vm.natives[modulename]
			return vm.natives[modulename].exports

		# precompile native source
		script = new Script "(function (exports, require, module, process) { 'use strict'; #{NATIVE_MODULES[modulename]} \n});", 
			filename: "#{modulename}.sb.js"
		
		# setup module scope
		vm.natives[modulename] = module =
			exports: {}
			require: _requireNative

		# run script
		script.runInContext(global) module.exports, module.require, module, parent.process

		return module.exports
	
	_prepareRequire = (current_dirname) ->
		_require = (modulename) ->
			# make sure vm cant access this function via arguments.callee.caller
			'use strict'
			
			unless vm.options.require
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
			
			unless modulename?
				throw new VMError "Module '' not found.", "ENOTFOUND"
				
			if typeof modulename isnt 'string'
				throw new VMError "Invalid module name '#{modulename}'", "EINVALIDNAME"
	
			# Is module native module
			
			if NATIVE_MODULES[modulename]
				if vm.options.requireNative
					if vm.options.requireNative[modulename]
						return _requireNative modulename
				
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
			
			unless vm.options.requireExternal
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"
	
			if /^(\.\/|\.\.\/)/.exec modulename
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
			if vm.cache[filename]
				return vm.cache[filename].exports
			
			dirname = pa.dirname filename
			extname = pa.extname filename

			if vm.options.requireRoot
				requiredPath = pa.resolve vm.options.requireRoot
				if dirname.indexOf(requiredPath) isnt 0
					throw new VMError "Module '#{modulename}' is not allowed to be required. The path is outside the border!", "EDENIED"
			
			vm.cache[filename] = module =
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

			# Watch for .node
			
			if extname is '.node'
				try
					parent.process.dlopen module, filename
					return module.exports
					
				catch ex
					throw new VMError "Failed to load '#{filename}': [#{ex.message}]", "ELOADFAIL"
			
			# Watch for .js
	
			try
				# Load module
				strictText = if vm.options.useStrict then "'use strict'; " else ""
				code = "(function (exports, require, module, __filename, __dirname) { #{strictText}#{fs.readFileSync(filename, "utf8")} \n});"
				
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
		
		_require.cache = vm.cache
		_require.extensions = EXTENSIONS
		_require
	
	###
	Prepare sandbox.
	###
	
	global.setTimeout = (callback) ->
		arguments[0] = -> callback.call null
		tmr = parent.setTimeout arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.setInterval = (callback) ->
		arguments[0] = -> callback.call null
		parent.setInterval arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.setImmediate = (callback) ->
		arguments[0] = -> callback.call null
		parent.setImmediate arguments...
		
		ref: -> tmr.ref()
		unref: -> tmr.unref()
		
	global.clearTimeout = ->
		parent.clearTimeout arguments...
		null
		
	global.clearInterval = ->
		parent.clearInterval arguments...
		null
		
	global.clearImmediate = ->
		parent.clearImmediate arguments...
		null
		
	global.process =
		argv: []
		title: parent.process.title
		version: parent.process.version
		versions: contextify parent.process.versions
		arch: parent.process.arch
		platform: parent.process.platform
		env: {}
		pid: parent.process.pid
		features: contextify parent.process.features
		nextTick: (callback) -> parent.process.nextTick -> callback.call null
		hrtime: -> parent.process.hrtime()
		cwd: -> parent.process.cwd()
		on: (name, handler) ->
			if name not in ['beforeExit', 'exit']
				throw new Error "Access denied to listen for '#{name}' event."
			
			fake = -> handler.call null
			fakeHandlers[name] ?= new Map()
			fakeHandlers[name].set handler, fake
			
			parent.process.on name, fake
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
			
			parent.process.once name, fake
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
			
			parent.process.removeListener name, fake
			@
		
		umask: ->
			if arguments.length
				throw new Error "Access denied to set umask."
			
			parent.process.umask()
	
	if vm.options.console is 'inherit'
		global.console =
			log: ->
				parent.console.log arguments...
				null
				
			info: ->
				parent.console.info arguments...
				null
				
			warn: ->
				parent.console.warn arguments...
				null
				
			error: ->
				parent.console.error arguments...
				null
				
			dir: ->
				parent.console.dir arguments...
				null
				
			time: ->
				parent.console.time arguments...
				null
				
			timeEnd: ->
				parent.console.timeEnd arguments...
				null
				
			trace: ->
				parent.console.trace arguments...
				null
				
	else if vm.options.console is 'redirect'
		global.console =
			log: ->
				vm.emit 'console.log', arguments...
				null
				
			info: ->
				vm.emit 'console.info', arguments...
				null
				
			warn: ->
				vm.emit 'console.warn', arguments...
				null
				
			error: ->
				vm.emit 'console.error', arguments...
				null
				
			dir: ->
				vm.emit 'console.dir', arguments...
				null
				
			time: noop
			timeEnd: noop
			trace: ->
				vm.emit 'console.trace', arguments...
				null
	
	if parent.DTRACE_HTTP_SERVER_RESPONSE
		global.DTRACE_HTTP_SERVER_RESPONSE = -> parent.DTRACE_HTTP_SERVER_RESPONSE arguments...
		global.DTRACE_HTTP_SERVER_REQUEST = -> parent.DTRACE_HTTP_SERVER_REQUEST arguments...
		global.DTRACE_HTTP_CLIENT_RESPONSE = -> parent.DTRACE_HTTP_CLIENT_RESPONSE arguments...
		global.DTRACE_HTTP_CLIENT_REQUEST = -> parent.DTRACE_HTTP_CLIENT_REQUEST arguments...
		global.DTRACE_NET_STREAM_END = -> parent.DTRACE_NET_STREAM_END arguments...
		global.DTRACE_NET_SERVER_CONNECTION = -> parent.DTRACE_NET_SERVER_CONNECTION arguments...
		global.DTRACE_NET_SOCKET_READ = -> parent.DTRACE_NET_SOCKET_READ arguments...
		global.DTRACE_NET_SOCKET_WRITE = -> parent.DTRACE_NET_SOCKET_WRITE arguments...
	
	if parent.COUNTER_NET_SERVER_CONNECTION
		global.COUNTER_NET_SERVER_CONNECTION = -> parent.COUNTER_NET_SERVER_CONNECTION arguments...
		global.COUNTER_NET_SERVER_CONNECTION_CLOSE = -> parent.COUNTER_NET_SERVER_CONNECTION_CLOSE arguments...
		global.COUNTER_HTTP_SERVER_REQUEST = -> parent.COUNTER_HTTP_SERVER_REQUEST arguments...
		global.COUNTER_HTTP_SERVER_RESPONSE = -> parent.COUNTER_HTTP_SERVER_RESPONSE arguments...
		global.COUNTER_HTTP_CLIENT_REQUEST = -> parent.COUNTER_HTTP_CLIENT_REQUEST arguments...
		global.COUNTER_HTTP_CLIENT_RESPONSE = -> parent.COUNTER_HTTP_CLIENT_RESPONSE arguments...
	
	if vm.options.require and vm.options.requireNative?['buffer'] is true
		global.Buffer = _requireNative('buffer').Buffer

	fs = parent.require 'fs'
	pa = parent.require 'path'

	###
	VMError definition.
	###

	class global.VMError extends Error
		constructor: (message, code) ->
			@name = @constructor.name
			@message = message
			@code = code
			
			super()
			Error.captureStackTrace @, @constructor
	
	###
	Return contextized variables.
	###
 
	cache: {}
	module:
		filename: __filename
		exports: {}
		require: _prepareRequire __dirname
	
	proxy: (method, args...) ->
		args[index] = contextify arg for arg, index in args
		method.apply null, args
