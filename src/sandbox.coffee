fs = parent.require 'fs'
pa = parent.require 'path'
{Script} = parent.require 'vm'
noop = ->

NATIVE_MODULES = parent.process.binding 'natives'
EXTENSIONS =
	".json": (module, filename) ->
		module.exports = JSON.parse fs.readFileSync(filename, "utf8")

###
@param {Object} parent Parent's global object.
###

return do (vm, parent) =>
  #'use strict'

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

		if modulename is "buffer"
      # use the pure JS version of buffer as the native does some crazy binding
      # and somehow crashes the non-contexted buffer
			modulename = "buffer/"

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

				if vm.options.fakeNative.indexOf modulename >= 0
					# some node modules require fs at the beginning even if they dont need
					# BE careful with this option
					return {}
				else
					throw new VMError "Access denied to require '#{modulename}'", "EDENIED"

			unless vm.options.requireExternal
				throw new VMError "Access denied to require '#{modulename}'", "EDENIED"

			if /^(\.\/|\.\.\/)/.exec modulename
				# Module is relative file, e.g. ./script.js or ../script.js

				filename = _resolveFilename "#{current_dirname}/#{modulename}"

			else if /^(\/|\\|[a-zA-Z]:\\)/.exec modulename
				# Module is absolute file, e.g. /script.js or //server/script.js or C:\script.js

				filename = _resolveFilename modulename

			else
				# Check node_modules in path

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

			vm.cache[filename] = module =
				filename: filename
				exports: {}
				require: _prepareRequire dirname
				paths: []

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
				if vm.options.useStrict
					strictText = "'use strict';"
				else
					strictText = ""
				code = "(function (exports, require, module, __filename, __dirname) { #{strictText} #{fs.readFileSync(filename, "utf8")} \n});"
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
		#arguments[0] = -> callback.call null
		parent.setTimeout arguments...
	global.setInterval = (callback) ->
		#arguments[0] = -> callback.call null
		parent.setInterval arguments...
	global.setImmediate = (callback) ->
		#arguments[0] = -> callback.call null
		parent.setImmediate arguments...
	global.clearTimeout = -> parent.clearTimeout arguments...
	global.clearInterval = -> parent.clearInterval arguments...
	global.clearImmediate = -> parent.clearImmediate arguments...
	global.process =
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
		on: (name) ->
			#console.log("unable to subscribe to "+ name)
		removeListener: (name) ->
			#console.log("unable to remove "+ name)

	if vm.options.console is 'inherit'
		global.process.stdout = parent.process.stdout
		global.console =
			log: -> parent.console.log arguments...
			info: -> parent.console.info arguments...
			warn: -> parent.console.warn arguments...
			error: -> parent.console.error arguments...
			dir: -> parent.console.dir arguments...
			time: -> parent.console.time arguments...
			timeEnd: -> parent.console.timeEnd arguments...
			trace: -> parent.console.trace arguments...

	else if vm.options.console is 'redirect'
		global.process.stdout =
			getWindowSize: parent.process.stdout.getWindowSize
			write: -> vm.emit "process.write", arguments...
		global.console =
			log: -> vm.emit 'console.log', arguments...
			info: -> vm.emit 'console.info', arguments...
			warn: -> vm.emit 'console.warn', arguments...
			error: -> vm.emit 'console.error', arguments...
			dir: -> vm.emit 'console.dir', arguments...
			time: -> noop
			timeEnd: -> noop
			trace: -> vm.emit 'console.trace', arguments...

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

	global.Buffer = _requireNative('buffer').Buffer

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
		paths: []

	proxy: (method, args...) ->
		args[index] = contextify arg for arg, index in args
		method.apply null, args
