version = process.versions.node.split '.'
if parseInt(version[0]) is 0 and parseInt(version[1]) < 11
	throw new Error "vm2 requires Node.js version 0.11+ or io.js 1.0+ (current version: #{process.versions.node})"

fs = require 'fs'
vm = require 'vm'
pa = require 'path'
ut = require 'util'
{EventEmitter} = require 'events'

sb = fs.readFileSync "#{__dirname}/sandbox.js", "utf8"
cf = fs.readFileSync "#{__dirname}/contextify.js", "utf8"

AVAILABLE_NATIVE_MODULES = [
	'assert',
	'buffer',
	'child_process',
	'constants',
	'crypto', 'tls', 
	'dgram', 'dns', 'http', 'https', 'net', 'querystring', 'url',
	'domain',
	'events', 
	'fs', 'path',
	'module',
	'os',
	'punycode',
	'stream',
	'string_decoder',
	'timers',
	'tty', 
	'util', 'sys',
	'vm',
	'zlib'
]

###
Prepare value for contextification.

@property {Object} value Value to prepare.
@return {Object} Prepared value.

@private
###

_prepareContextify = (value) ->
	if typeof value is 'object'
		if value is null then return value
		if value instanceof String then return String value
		if value instanceof Number then return Number value
		if value instanceof Boolean then return Boolean value
		if value instanceof Array then return (_prepareContextify i for i in value)
		if value instanceof Error then return value
		if value instanceof Date then return value
		if value instanceof RegExp then return value
		if value instanceof Buffer then return value
		
		o = {}
		for key in Object.getOwnPropertyNames value
			desc = Object.getOwnPropertyDescriptor value, key
			desc.value = _prepareContextify desc.value if desc.value?
			Object.defineProperty o, key, desc
		
		return o

	else
		value

_compileToJS = (code, language) ->
	switch language
		when 'coffeescript', 'coffee-script', 'cs', 'text/coffeescript'
			return require('coffee-script').compile code, {header: false, bare: true}
		
		when 'javascript', 'java-script', 'js', 'text/javascript'
			return code
		
		else
			throw new VMError "Unsupported language '#{language}'."

###
Class VM.

@property {Boolean} running True if VM was initialized.
@property {Object} options VM options.
@property {Object} context VM's context.
###

class VM extends EventEmitter
	running: false
	options: null
	context: null
	
	###
	Create VM instance.
	
	@param {Object} [options] VM options.
	@return {VM}
	###
	
	constructor: (options = {}) ->
		# defaults
		@options =
			timeout: options.timeout ? undefined
			sandbox: options.sandbox ? null
			language: options.language ? 'javascript'
	
	###
	Run the code in VM.
	
	@param {String} code Code to run.
	@return {*} Result of executed code.
	###
	
	run: (code) ->
		'use strict'

		if @options.language isnt 'javascript'
			code = _compileToJS code, @options.language
		
		if @running
			script = new vm.Script code,
				filename: "vm"
				displayErrors: false
				
			return script.runInContext @context,
				filename: "vm"
				displayErrors: false
				timeout: @options.timeout
		
		@context = vm.createContext()
		contextify = vm.runInContext("(function(require) { #{cf} \n})", @context, {filename: "contextify.js", displayErrors: false}).call @context, require
		
		# prepare global sandbox
		if @options.sandbox
			unless typeof @options.sandbox is 'object'
				throw new VMError "Sandbox must be object"
			
			for name, value of @options.sandbox
				contextify _prepareContextify(value), name
		
		script = new vm.Script code,
			filename: "vm"
			displayErrors: false
		
		# run script
		@running = true
		script.runInContext @context,
			filename: "vm"
			displayErrors: false
			timeout: @options.timeout
		
###
Class NodeVM.

@property {Object} cache Cache of loaded modules.
@property {Object} natives Cache of native modules.
@property {Object} module Pointer to main module.
@property {Function} proxy Proxy used by `call` method to securely call methods in VM.
###

class NodeVM extends VM
	cache: null
	natives: null # cache of native modules
	module: null
	proxy: null
	
	###
	Create NodeVM instance.
	
	Unlike VM, NodeVM lets you use require same way like in regular node.
	
	@param {Object} [options] VM options.
	@return {NodeVM}
	###
	
	constructor: (options = {}) ->
		#@cache is initialized inside vm's context (security reasons)
		@natives = {}
		
		# defaults
		@options =
			sandbox: options.sandbox ? null
			console: options.console ? 'inherit'
			require: options.require ? false
			language: options.language ? 'javascript'
			requireExternal: options.requireExternal ? false
			requireNative: {}
			requireRoot : options.requireRoot ? false
			useStrict: options.useStrict ? true

		# convert array of modules to collection to speed things up
		if options.requireNative
			if Array.isArray options.requireNative
				@options.requireNative[mod] = true for mod in options.requireNative when mod in AVAILABLE_NATIVE_MODULES
			
		else
			# by default, add all available native modules
			@options.requireNative[mod] = true for mod in AVAILABLE_NATIVE_MODULES
	
	###
	Securely call method in VM. All arguments except functions are cloned during the process to prevent context leak. Functions are wrapped to secure closures. 
	
	Buffers are copied!
	
	IMPORTANT: Method doesn't check for circular objects! If you send circular structure as an argument, you process will stuck in infinite loop.
	
	@param {Function} method Method to execute.
	@param {...*} argument Arguments.
	@return {*} Return value of executed method.
	###
	
	call: (method) ->
		'use strict'
		
		unless @running
			throw new VMError "VM is not running"
		
		if typeof method is 'function'
			return @proxy arguments...

		else
			throw new VMError "Unrecognized method type"
	
	###
	Run the code in NodeVM. 
	
	First time you run this method, code is executed same way like in node's regular `require` - it's executed with `module`, `require`, `exports`, `__dirname`, `__filename` variables and expect result in `module.exports'.
	
	@param {String} code Code to run.
	@param {String} [filename] Filename that shows up in any stack traces produced from this script.
	@return {*} Result of executed code.
	###
	
	run: (code, filename) ->
		'use strict'
		
		if global.isVM
			throw new VMError "You can't nest VMs"
		
		if @options.language isnt 'javascript'
			code = _compileToJS code, @options.language

		if filename
			filename = pa.resolve filename
			dirname = pa.dirname filename
		
		else
			filename = null
			dirname = null

		if @running
			script = new vm.Script code,
				filename: filename ? "vm"
				displayErrors: false
				
			return script.runInContext @context,
				filename: filename ? "vm"
				displayErrors: false

		# objects to be transfered to vm
		parent =
			require: require
			process: process
			console: console
			setTimeout: setTimeout
			setInterval: setInterval
			setImmediate: setImmediate
			clearTimeout: clearTimeout
			clearInterval: clearInterval
			clearImmediate: clearImmediate
		
		if global.DTRACE_HTTP_SERVER_RESPONSE
			parent.DTRACE_HTTP_SERVER_RESPONSE = global.DTRACE_HTTP_SERVER_RESPONSE
			parent.DTRACE_HTTP_SERVER_REQUEST = global.DTRACE_HTTP_SERVER_REQUEST
			parent.DTRACE_HTTP_CLIENT_RESPONSE = global.DTRACE_HTTP_CLIENT_RESPONSE
			parent.DTRACE_HTTP_CLIENT_REQUEST = global.DTRACE_HTTP_CLIENT_REQUEST
			parent.DTRACE_NET_STREAM_END = global.DTRACE_NET_STREAM_END
			parent.DTRACE_NET_SERVER_CONNECTION = global.DTRACE_NET_SERVER_CONNECTION
			parent.DTRACE_NET_SOCKET_READ = global.DTRACE_NET_SOCKET_READ
			parent.DTRACE_NET_SOCKET_WRITE = global.DTRACE_NET_SOCKET_WRITE
		
		if global.COUNTER_NET_SERVER_CONNECTION
			parent.COUNTER_NET_SERVER_CONNECTION = global.COUNTER_NET_SERVER_CONNECTION
			parent.COUNTER_NET_SERVER_CONNECTION_CLOSE = global.COUNTER_NET_SERVER_CONNECTION_CLOSE
			parent.COUNTER_HTTP_SERVER_REQUEST = global.COUNTER_HTTP_SERVER_REQUEST
			parent.COUNTER_HTTP_SERVER_RESPONSE = global.COUNTER_HTTP_SERVER_RESPONSE
			parent.COUNTER_HTTP_CLIENT_REQUEST = global.COUNTER_HTTP_CLIENT_REQUEST
			parent.COUNTER_HTTP_CLIENT_RESPONSE = global.COUNTER_HTTP_CLIENT_RESPONSE
		
		@context = vm.createContext()
		contextify = vm.runInContext("(function(require) { #{cf} \n})", @context, {filename: "contextify.js", displayErrors: false}).call @context, require
		
		closure = vm.runInContext "(function (vm, parent, contextify, __dirname, __filename) { #{sb} \n})", @context,
			filename: "sandbox.js"
			displayErrors: false
		
		{@cache, @module, @proxy} = closure.call @context, @, parent, contextify, dirname, filename
		@cache[filename] = @module
		
		# prepare global sandbox
		if @options.sandbox
			unless typeof @options.sandbox is 'object'
				throw new VMError "Sandbox must be object"
			
			for name, value of @options.sandbox
				contextify _prepareContextify(value), name

		# run script
		@running = true
		script = new vm.Script "(function (exports, require, module, __filename, __dirname) { #{code} \n})",
			filename: filename ? "vm"
			displayErrors: false
			
		closure = script.runInContext @context,
			filename: filename ? "vm"
			displayErrors: false

		closure.call @context, @module.exports, @module.require, @module, filename, dirname

		@module.exports

	###
	Create NodeVM and run code inside it.
	
	@param {String} script Javascript code.
	@param {String} [filename] File name (used in stack traces only).
	@param {Object} [options] VM options.
	@return {NodeVM} VM.
	###
	
	@code: (script, filename, options) ->
		if filename?
			if typeof filename is 'object'
				options = filename
				filename = null
			
			else if typeof filename is 'string'
				filename = pa.resolve filename
			
			else
				console.log arguments
				throw new VMError "Invalid arguments"
		
		if arguments.length > 3
			throw new VMError "Invalid number of arguments"
		
		_vm = new NodeVM options
		_vm.run script, filename
		_vm
	
	###
	Create NodeVM and run script from file inside it.
	
	@param {String} [filename] File name (used in stack traces only).
	@param {Object} [options] VM options.
	@return {NodeVM} VM.
	###
	
	@file: (filename, options) ->
		_vm = new NodeVM options
		filename = pa.resolve filename
		
		unless fs.existsSync filename
			throw new VMError "Script '#{filename}' not found"
		
		if fs.statSync(filename).isDirectory()
			throw new VMError "Script must be file, got directory"

		_vm.run fs.readFileSync(filename, 'utf8'), filename
		_vm

###
VMError.

@param {String} message Error message.

@class
@extends {Error}
@property {String} stack Call stack.
@property {String} message Error message.
###

class VMError extends Error
	constructor: (message) ->
		@name = @constructor.name
		@message = message
		
		super()
		Error.captureStackTrace @, @constructor

module.exports.VM = VM
module.exports.NodeVM = NodeVM
module.exports.VMError = VMError
