'use strict'

version = process.versions.node.split '.'
if parseInt(version[0]) < 6
	throw new Error "vm2 requires Node.js version 6 or newer (current version: #{process.versions.node})"

fs = require 'fs'
vm = require 'vm'
pa = require 'path'
ut = require 'util'
{EventEmitter} = require 'events'

sb = fs.readFileSync "#{__dirname}/sandbox.js", "utf8"
cf = fs.readFileSync "#{__dirname}/contextify.js", "utf8"

_compileToJS = (code, compiler) ->
	if 'function' is typeof compiler
		return compiler code
	
	switch compiler
		when 'coffeescript', 'coffee-script', 'cs', 'text/coffeescript'
			return require('coffee-script').compile code, {header: false, bare: true}
		
		when 'javascript', 'java-script', 'js', 'text/javascript'
			return code
		
		else
			throw new VMError "Unsupported compiler '#{compiler}'."

###
Class VM.

@property {Boolean} running True if VM was initialized.
@property {Object} options VM options.
###

class VM extends EventEmitter
	options: null
	
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
			compiler: options.compiler ? 'javascript'

		host =
			String: String
			Number: Number
			Buffer: Buffer
			Boolean: Boolean
			Array: Array
			Date: Date
			Error: Error
			RegExp: RegExp
			Function: Function
			Object: Object
			VMError: VMError

		@_context = vm.createContext vm.runInNewContext "({})"

		Reflect.defineProperty @, '_internal',
			value: vm.runInContext("(function(console, require, host) { #{cf} \n})", @_context, {
				filename: "contextify.js"
				displayErrors: false
			}).call @_context, console, require, host
		
		# prepare global sandbox
		if @options.sandbox
			unless typeof @options.sandbox is 'object'
				throw new VMError "Sandbox must be object"
			
			for name, value of @options.sandbox
				@_internal.contextify value, global: name
	
	###
	Run the code in VM.
	
	@param {String} code Code to run.
	@return {*} Result of executed code.
	###
	
	run: (code) ->
		if @options.compiler isnt 'javascript'
			code = _compileToJS code, @options.compiler

		script = new vm.Script code,
			filename: "vm.js"
			displayErrors: false
		
		@_internal.decontextify script.runInContext @_context,
			filename: "vm.js"
			displayErrors: false
			timeout: @options.timeout
		
###
Class NodeVM.

@property {Object} module Pointer to main module.
###

class NodeVM extends VM
	_require: null # contextified require
	
	###
	Create NodeVM instance.
	
	Unlike VM, NodeVM lets you use require same way like in regular node.
	
	@param {Object} [options] VM options.
	@return {NodeVM}
	###
	
	constructor: (options = {}) ->
		# defaults
		@options =
			sandbox: options.sandbox ? null
			console: options.console ? 'inherit'
			require: options.require ? false
			compiler: options.compiler ? 'javascript'
			require: options.require ? false

		host =
			require: require
			process: process
			console: console
			setTimeout: setTimeout
			setInterval: setInterval
			setImmediate: setImmediate
			clearTimeout: clearTimeout
			clearInterval: clearInterval
			clearImmediate: clearImmediate
			String: String
			Number: Number
			Buffer: Buffer
			Boolean: Boolean
			Array: Array
			Date: Date
			Error: Error
			RegExp: RegExp
			Function: Function
			Object: Object
			VMError: VMError

		@_context = vm.createContext vm.runInNewContext "({})"

		Object.defineProperty @, '_internal',
			value: vm.runInContext("(function(require, host) { #{cf} \n})", @_context, {
				filename: "contextify.js"
				displayErrors: false
			}).call @_context, require, host
		
		closure = vm.runInContext "(function (vm, host, contextify, decontextify) { #{sb} \n})", @_context,
			filename: "sandbox.js"
			displayErrors: false

		Object.defineProperty @, '_prepareRequire',
			value: closure.call @_context, @, host, @_internal.contextify, @_internal.decontextify

		# prepare global sandbox
		if @options.sandbox
			unless typeof @options.sandbox is 'object'
				throw new VMError "Sandbox must be object"
			
			for name, value of @options.sandbox
				@_internal.contextify value, global: name
		
		if @options.require?.import
			if not Array.isArray @options.require.import
				@options.require.import = [@options.require?.import]
			
			@require mdl for mdl in @options.require?.import
		
		@
	
	###
	Securely call method in VM. All arguments except functions are cloned during the process to prevent context leak. Functions are wrapped to secure closures. 
	
	Buffers are copied!
	
	IMPORTANT: Method doesn't check for circular objects! If you send circular structure as an argument, you process will stuck in infinite loop.
	
	@param {Function} method Method to execute.
	@param {...*} args Arguments.
	@return {*} Return value of executed method.
	@deprecated
	###
	
	call: (method, args...) ->
		if typeof method is 'function'
			return method.apply args

		else
			throw new VMError "Unrecognized method type"
	
	###
	Require a module in VM and return it's exports.
	###
	
	require: (module) ->
		@run "module.exports = require('#{module}');", 'vm.js'
	
	###
	Run the code in NodeVM. 
	
	First time you run this method, code is executed same way like in node's regular `require` - it's executed with `module`, `require`, `exports`, `__dirname`, `__filename` variables and expect result in `module.exports'.
	
	@param {String} code Code to run.
	@param {String} [filename] Filename that shows up in any stack traces produced from this script.
	@return {*} Result of executed code.
	###
	
	run: (code, filename) ->
		if @options.compiler isnt 'javascript'
			code = _compileToJS code, @options.compiler

		if filename
			filename = pa.resolve filename
			dirname = pa.dirname filename
		
		else
			filename = null
			dirname = null

		module = vm.runInContext "({exports: {}})", @_context,
			displayErrors: false
		
		script = new vm.Script "(function (exports, require, module, __filename, __dirname) { #{code} \n})",
			filename: filename ? "vm.js"
			displayErrors: false
			
		closure = script.runInContext @_context,
			filename: filename ? "vm.js"
			displayErrors: false

		closure.call @_context, module.exports, @_prepareRequire(dirname), module, filename, dirname

		@_internal.decontextify module.exports

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
