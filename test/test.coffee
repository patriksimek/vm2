{VM, NodeVM} = require '../'
assert = require "assert"

global.isVM = false

vm = null

describe 'contextify', ->
	class TestClass
		constructor: ->
			@greeting = 'hello'
		
		greet: (name) ->
			"#{@greeting} #{name}"
	
	sandbox = 
		test:
			string: "text"
			stringO: new String "text"
			number: 1
			numberO: new Number 1
			boolean: true
			booleanO: new Boolean true
			date: new Date()
			regexp: /xxx/
			buffer: new Buffer [0x00, 0x01]
			function: -> -> {}
			object:
				x: 1
				y: -> (i) -> i instanceof Object
				z: (i) ->
					if i not instanceof Object then throw new Error "Not instanceof parent Object."
					i
				
			nil: null
			undef: undefined
			klass: TestClass
			
	before (done) ->
		vm = new VM
			sandbox: sandbox
		
		done()
	
	it 'common', (done) ->
		assert.strictEqual sandbox.test.object.y is sandbox.test.object.y.valueOf(), true
		
		assert.strictEqual vm.run("test.object.y instanceof Function"), true
		assert.strictEqual vm.run("test.object.y.valueOf() instanceof Function"), true
		assert.strictEqual vm.run("test.object.y").isVMProxy, undefined
		assert.strictEqual vm.run("test.object.y.valueOf()").isVMProxy, undefined
		assert.strictEqual vm.run("test.object.y") is vm.run("test.object.y.valueOf()"), true
		assert.strictEqual vm.run("test.object.y === test.object.y.valueOf()"), true
		
		assert.strictEqual vm.run("test.object").y instanceof Function, true
		assert.strictEqual vm.run("test.object").y.valueOf() instanceof Function, true
		assert.strictEqual vm.run("test.object").y.isVMProxy, undefined
		assert.strictEqual vm.run("test.object").y.valueOf().isVMProxy, undefined
		assert.strictEqual vm.run("test.object").y is vm.run("test.object").y.valueOf(), true
		assert.strictEqual vm.run("test.valueOf()") is vm.run("test").valueOf(), true

		assert.strictEqual vm.run("test.object.y.constructor instanceof Function"), true
		assert.strictEqual vm.run("test.object.y.constructor('return (function(){return this})().isVM')()"), true
		assert.strictEqual vm.run("test.object.valueOf() instanceof Object"), true
		assert.strictEqual vm.run("test.object.valueOf().y instanceof Function"), true
		assert.strictEqual vm.run("test.object.valueOf().y.constructor instanceof Function"), true
		assert.strictEqual vm.run("test.object.valueOf().y.constructor('return (function(){return this})().isVM')()"), true

		o = vm.run("let x = {a: test.date, b: test.date};x")
		assert.strictEqual vm.run("x.valueOf().a instanceof Date"), true
		assert.strictEqual o instanceof Object, true
		assert.strictEqual o.a instanceof Date, true
		assert.strictEqual o.b instanceof Date, true
		assert.strictEqual o.a is o.b, true
		assert.strictEqual o.a is sandbox.test.date, true
		
		#console.log o
		#console.log {a: sandbox.test.date, b: sandbox.test.date}

		o = vm.run("let y = new Date(); let z = {a: y, b: y};z")
		assert.strictEqual o.isVMProxy, true
		assert.strictEqual o instanceof Object, true
		assert.strictEqual o.a instanceof Date, true
		assert.strictEqual o.b instanceof Date, true
		assert.strictEqual o.a is o.b, true
		
		#console.log o

		done()
	
	it 'class', (done) ->
		assert.strictEqual vm.run("new test.klass()").isVMProxy, undefined
		assert.strictEqual vm.run("new test.klass()").greet('friend'), 'hello friend'
		assert.strictEqual vm.run("new test.klass()") instanceof TestClass, true
	
		# subclassing inside vm is not supported		
		#assert.strictEqual vm.run("class MyClass extends test.klass {greet(name) { return 'hello '+ super.greet(name); }};new MyClass()").greet('friend'), 'hello hello friend'
		
		#vm.run("class MyClass2 {}")
		#klass = vm.run("class MyClass3 extends MyClass2 {}")
		#console.log new klass
		#`var localKlass = class MyClass3 extends klass {}`
		
		return done()
		
		#console.log vm.run("class MyClass2 extends test.klass {greet(name) { return 'hello '+ super.greet(name); }};MyClass2.staticVar = 1;MyClass2.staticVar")

		#vm2 = new VM
		#	sandbox: sandbox
		#	compiler: 'coffeescript'
		#
		#console.log vm2.run("class MyClass extends test.klass\n\tgreet: (name) -> 'hello ' + super name\n\nnew MyClass").greet('friend')

		done()
	
	it 'string', (done) ->
		assert.strictEqual vm.run("(test.string).constructor === String"), true
		assert.strictEqual vm.run("typeof(test.stringO) === 'string' && test.string.valueOf instanceof Object"), true
		done()
	
	it 'number', (done) ->
		assert.strictEqual vm.run("typeof(test.numberO) === 'number' && test.number.valueOf instanceof Object"), true
		done()
	
	it 'boolean', (done) ->
		assert.strictEqual vm.run("typeof(test.booleanO) === 'boolean' && test.boolean.valueOf instanceof Object"), true
		done()
	
	it 'date', (done) ->
		assert.strictEqual vm.run("test.date instanceof Date"), true
		assert.strictEqual vm.run("test.date") instanceof Date, true
		assert.strictEqual vm.run("test.date"), sandbox.test.date
		
		done()
	
	it 'regexp', (done) ->
		assert.strictEqual vm.run("test.regexp instanceof RegExp"), true
		done()
	
	it 'buffer', (done) ->
		assert.strictEqual vm.run("test.buffer.inspect()"), '<Buffer 00 01>', '#1'
		assert.strictEqual vm.run("test.buffer instanceof Buffer"), true, '#2'
		assert.strictEqual vm.run("test.buffer") instanceof Buffer, true, '#3'
		assert.strictEqual vm.run("test.buffer"), sandbox.test.buffer, '#4'
		assert.strictEqual vm.run("class Buffer2 extends Buffer {};new Buffer2(5)").fill(1).inspect(), '<Buffer 01 01 01 01 01>'
		done()
	
	it 'function', (done) ->
		assert.strictEqual vm.run("test.function instanceof Function"), true, '#1'
		assert.strictEqual vm.run("test.function() instanceof Function"), true, '#2'
		assert.strictEqual vm.run("test.function()() instanceof Object"), true, '#3'
		done()
	
	it 'object', (done) ->
		assert.strictEqual vm.run("test.object instanceof Object && test.object.x === 1"), true, '#1'
		assert.strictEqual vm.run("test.object.y instanceof Function"), true, '#2'
		assert.strictEqual vm.run("test.object.y() instanceof Function"), true, '#3'
		assert.strictEqual vm.run("test.object.y()({})"), true, '#4'
		assert.strictEqual vm.run("test.object.z({}) instanceof Object"), true, '#5'
		assert.strictEqual vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty instanceof Function"), true, '#6'
		assert.strictEqual vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty.constructor('return (function(){return this})().isVM')()"), true, '#7'
		done()
	
	it 'null', (done) ->
		assert.strictEqual vm.run("test.nil === null"), true
		done()
	
	it 'undefined', (done) ->
		assert.strictEqual vm.run("test.undef === undefined"), true
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
		
		assert.throws ->
			vm.run "Object.defineProperty(sub, 'test', {});"
		, (err) ->
			assert.equal err.name, 'VMError'
			assert.equal err.message, 'Operation not allowed on contextified object.'
			true
		
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

	it '#32 attack', (done) ->
		vm2 = new VM()

		assert.strictEqual vm2.run("this.constructor.constructor('return Function(\\'return Function\\')')()() === this.constructor.constructor('return Function')()"), true

		assert.throws ->
			vm2.run("const ForeignFunction = global.constructor.constructor;
				const process1 = ForeignFunction(\"return process\")();
				const require1 = process1.mainModule.require;
				const console1 = require1(\"console\");
				const fs1 = require1(\"fs\");
				console1.log(fs1.statSync('.'));")
		, /process is not defined/
		
		done()
	
	after (done) ->
		vm = null
		done()

describe 'NodeVM', ->
	before (done) ->
		vm = new NodeVM
					
		done()
		
	it 'globals', (done) ->
		ex = vm.run "module.exports = global"
		assert.equal ex.isVM, true
		
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
			console.log vm.run("module.exports = (function() {return arguments.callee.caller.caller.toString()})()")
		, /Cannot read property 'toString' of null/
		
		done()
	
	it 'global attack', (done) ->
		assert.equal vm.run("module.exports = console.log.constructor('return (function(){return this})().isVM')()"), true
		
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
			require:
				external: true
		
		assert.equal vm.run("module.exports = require('#{__dirname}/data/json.json')").working, true
		
		done()
	
	it 'run coffee-script', (done) ->
		vm = new NodeVM
			require:
				external: true
				
			compiler: 'coffeescript'
		
		assert.equal vm.run("module.exports = working: true").working, true
		
		done()
		
	it 'disabled require', (done) ->
		vm = new NodeVM
		
		assert.throws ->
			vm.run "require('fs')"
		, /Access denied to require 'fs'/
		
		done()
		
	it 'disable setters on native modules', (done) ->
		vm = new NodeVM
			require:
				native: ['fs']
		
		vm.run "require('fs').readFileSync = undefined"
		assert.strictEqual require('fs').readFileSync instanceof Function, true
		
		done()
		
	it 'enabled require for certain modules', (done) ->
		vm = new NodeVM
			require:
				native: ['fs']
		
		assert.doesNotThrow ->
			vm.run "require('fs')"
		
		done()
		
	it 'require relative', (done) ->
		vm = new NodeVM
			require:
				external: true
		
		vm.run "require('foobar')", __filename

		done()

	it 'arguments attack', (done) ->
		vm = new NodeVM
		assert.throws ->
			vm.run("module.exports = function fce(msg) { return arguments.callee.caller.toString(); }")()
		, /Cannot read property 'toString' of null/

		vm = new NodeVM
		assert.throws ->
			vm.run("module.exports = function fce(msg) { return fce.caller.toString(); }")()
		, /Cannot read property 'toString' of null/
		
		done()
	
	it 'native module arguments attack', (done) ->
		vm = new NodeVM
			require:
				native: ['fs']
			sandbox:
				parentfilename: __filename
				done: done
		
		vm.run "var fs = require('fs'); fs.exists(parentfilename, function() {try {arguments.callee.caller.toString()} catch (err) {return done();}; done(new Error('Missing expected exception'))});"

	it 'path attack', (done) ->
		vm = new NodeVM
			require:
				external: true
				root: __dirname
		
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
		assert.strictEqual vm.run("module.exports = process.listeners('exit')[0] === VM2_HANDLER;"), true
		vm.run "process.removeListener('exit', VM2_HANDLER);"
		process.emit 'exit'
		assert.strictEqual sandbox.VM2_COUNTER, 1
		
		done()

	after (done) ->
		vm = null
		done()
