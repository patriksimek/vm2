{VM, NodeVM} = require '../'
assert = require "assert"

vm = null

describe 'contextify', ->
	before (done) ->
		vm = new VM
			sandbox:
				test:
					string: "text"
					stringO: new String "text"
					number: 1
					numberO: new Number 1
					boolean: true
					booleanO: new Boolean true
					date: new Date()
					regexp: /xxx/
					buffer: new Buffer 0
					function: ->
					object: {x: 1}
					nil: null
					undef: undefined
					
		done()
		
	it 'string', (done) ->
		assert.equal vm.run("typeof(test.stringO) === 'string' && test.string.valueOf instanceof Object"), true
		done()
	
	it 'number', (done) ->
		assert.equal vm.run("typeof(test.numberO) === 'number' && test.number.valueOf instanceof Object"), true
		done()
	
	it 'boolean', (done) ->
		assert.equal vm.run("typeof(test.booleanO) === 'boolean' && test.boolean.valueOf instanceof Object"), true
		done()
	
	it 'date', (done) ->
		assert.equal vm.run("test.date instanceof Date"), true
		done()
	
	it 'regexp', (done) ->
		assert.equal vm.run("test.regexp instanceof RegExp"), true
		done()
	
	it 'buffer', (done) ->
		assert.equal vm.run("test.buffer"), null
		done()
	
	it 'function', (done) ->
		assert.equal vm.run("test.function instanceof Function"), true
		done()
	
	it 'object', (done) ->
		assert.equal vm.run("test.object instanceof Object && test.object.x === 1"), true
		done()
	
	it 'null', (done) ->
		assert.equal vm.run("test.nil === null"), true
		done()
	
	it 'undefined', (done) ->
		assert.equal vm.run("test.undef === undefined"), true
		done()
	
	after (done) ->
		vm = null
		done()

describe 'VM', ->
	before (done) ->
		sandbox =
			round: (number) ->
				Math.round number
			
			sub: {}
		
		Object.defineProperty sandbox.sub, 'getter',
			get: ->
				while true
					1

		vm = new VM
			timeout: 10
			sandbox: sandbox
					
		done()

	it 'globals', (done) ->
		assert.equal vm.run("round(1.5)"), 2
		
		done()
		
	it 'errors', (done) ->
		assert.throws ->
			vm.run "notdefined"
		, /notdefined is not defined/
		
		done()

	it 'timeout', (done) ->
		assert.throws ->
			new VM(timeout: 10).run "while (true) {}"
		, /Script execution timed out\./
		
		assert.throws ->
			vm.run "sub.getter"
		, /Script execution timed out\./

		done()

	it 'timers', (done) ->
		assert.equal vm.run("global.setTimeout"), undefined
		assert.equal vm.run("global.setInterval"), undefined
		assert.equal vm.run("global.setImmediate"), undefined
		
		done()
	
	after (done) ->
		vm = null
		done()

describe 'NodeVM', ->
	before (done) ->
		vm = new NodeVM
					
		done()
		
	it 'globals', (done) ->
		vm.run "module.exports = global"
		assert.equal vm.module.exports.isVM, true
		
		done()

	it 'errors', (done) ->
		assert.throws ->
			vm.run "notdefined"
		, /notdefined is not defined/
		
		done()
		
	it 'prevent global access', (done) ->
		assert.throws ->
			vm.run "process.exit()"
		, /(undefined is not a function|process\.exit is not a function)/
		
		done()
	
	it 'arguments attack', (done) ->
		assert.throws ->
			console.log vm.run("(function() {return arguments.callee.caller.toString()})()")
		, /Cannot read property 'toString' of null/
		
		done()
	
	it 'global attack', (done) ->
		assert.equal vm.run("console.log.constructor('return (function(){return this})().SANDBOX')()"), true
		
		done()

	it.skip 'timeout (not supported by Node\'s VM)', (done) ->
		assert.throws ->
			new NodeVM(timeout: 10).run "while (true) {}"
		, /Script execution timed out\./

		done()
	
	after (done) ->
		vm = null
		done()

describe 'modules', ->
	it 'require json', (done) ->
		vm = new NodeVM
			require: true
			requireExternal: true
		
		assert.equal vm.run("module.exports = require('#{__dirname}/data/json.json')").working, true
		
		done()
	
	it 'run coffee-script', (done) ->
		vm = new NodeVM
			require: true
			requireExternal: true
			language: 'coffeescript'
		
		assert.equal vm.run("module.exports = working: true").working, true
		
		done()
		
	it 'disabled require', (done) ->
		vm = new NodeVM
		
		assert.throws ->
			vm.run "require('fs')"
		, /Access denied to require 'fs'/
		
		done()
		
	it 'enabled require for certain modules', (done) ->
		vm = new NodeVM
			require: true
			requireNative: ['fs']
		
		assert.doesNotThrow ->
			vm.run "require('fs')"
		
		done()
		
	it 'require relative without path', (done) ->
		vm = new NodeVM
			require: true
			requireExternal: true
		
		assert.throws ->
			vm.run "require('foobar')"
		, /You must specify script path to load relative modules/
		
		done()
		
	it 'require relative', (done) ->
		vm = new NodeVM
			require: true
			requireExternal: true
		
		vm.run "require('foobar')", __filename

		done()

	it 'arguments attack', (done) ->
		vm = new NodeVM
		assert.doesNotThrow ->
			vm.run "module.exports.fce = function fce(msg) { arguments.callee.caller.toString(); }"
			
			# direct call, bad practice
			vm.module.exports.fce()
		
		vm = new NodeVM
		assert.throws ->
			vm.run "module.exports.fce = function fce(msg) { arguments.callee.caller.toString(); }"
			
			# proxied call, good practice
			vm.call vm.module.exports.fce
		, /Cannot read property 'toString' of null/
		
		vm = new NodeVM
		assert.throws ->
			vm.run "module.exports.fce = function fce(msg) { fce.caller.toString(); }"
			
			# proxied call, good practice
			vm.call vm.module.exports.fce
		, /Cannot read property 'toString' of null/
		
		done()
	
	it 'native module arguments attack', (done) ->
		vm = new NodeVM
			require: true
			requireNative: ['fs']
			sandbox:
				parentfilename: __filename
				done: done
		
		vm.run "var fs = require('fs'); fs.exists(parentfilename, function() {try {arguments.callee.caller.toString()} catch (err) {return done();}; done(new Error('Missing expected exception'))});"

	it 'path attack', (done) ->
		vm = new NodeVM
			require: true
			requireExternal: true
			requireRoot: __dirname
		
		assert.throws ->
			vm.run "var test = require('../package.json')", __filename

		, /Module '\.\.\/package.json' is not allowed to be required\. The path is outside the border!/
		
		done()
	
	it 'process events', (done) ->
		vm = new NodeVM
			sandbox:
				VM2_COUNTER: 0
		
		sandbox = vm.run "global.VM2_HANDLER = function() { VM2_COUNTER++ }; process.on('exit', VM2_HANDLER); module.exports = global;"
		process.emit 'exit'
		assert.strictEqual sandbox.VM2_COUNTER, 1
		assert.strictEqual vm.run("process.listeners('exit')[0] === VM2_HANDLER;"), true
		vm.run "process.removeListener('exit', VM2_HANDLER);"
		process.emit 'exit'
		assert.strictEqual sandbox.VM2_COUNTER, 1
		
		done()

	after (done) ->
		vm = null
		done()
