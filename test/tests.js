const assert = require("assert");
const {NodeVM, VM} = require('..');

global.isVM = false;

describe('contextify', () => {
	let vm;
	
	class TestClass {
		constructor() {
			this.greeting = 'hello';
		}

		greet(name) {
			return `${this.greeting} ${name}`;
		}
	}

	let sandbox = {
		test: {
			string: "text",
			stringO: new String("text"),
			number: 1,
			numberO: new Number(1),
			boolean: true,
			booleanO: new Boolean(true),
			date: new Date(),
			regexp: /xxx/,
			buffer: new Buffer([0x00, 0x01]),
			"function"() { return () => ({}) },
			object: {
				x: 1,
				y() { return i => i instanceof Object; },
				z(i) {
					if (!(i instanceof Object)) throw new Error("Not instanceof parent Object.");
					return i;
				}
			},
			nil: null,
			undef: void 0,
			klass: TestClass
		}
	}
	
	before(done => {
		vm = new VM({sandbox});
		done();
	})
	
	it('common', done => {
		assert.strictEqual(sandbox.test.object.y === sandbox.test.object.y.valueOf(), true);
		assert.strictEqual(vm.run("test.object.y instanceof Function"), true);
		assert.strictEqual(vm.run("test.object.y.valueOf() instanceof Function"), true);
		assert.strictEqual(vm.run("test.object.y").isVMProxy, void 0);
		assert.strictEqual(vm.run("test.object.y.valueOf()").isVMProxy, void 0);
		assert.strictEqual(vm.run("test.object.y") === vm.run("test.object.y.valueOf()"), true);
		assert.strictEqual(vm.run("test.object.y === test.object.y.valueOf()"), true);
		assert.strictEqual(vm.run("test.object").y instanceof Function, true);
		assert.strictEqual(vm.run("test.object").y.valueOf() instanceof Function, true);
		assert.strictEqual(vm.run("test.object").y.isVMProxy, void 0);
		assert.strictEqual(vm.run("test.object").y.valueOf().isVMProxy, void 0);
		assert.strictEqual(vm.run("test.object").y === vm.run("test.object").y.valueOf(), true);
		assert.strictEqual(vm.run("test.valueOf()") === vm.run("test").valueOf(), true);
		assert.strictEqual(vm.run("test.object.y.constructor instanceof Function"), true);
		assert.strictEqual(vm.run("test.object.y.constructor('return (function(){return this})().isVM')()"), true);
		assert.strictEqual(vm.run("test.object.valueOf() instanceof Object"), true);
		assert.strictEqual(vm.run("test.object.valueOf().y instanceof Function"), true);
		assert.strictEqual(vm.run("test.object.valueOf().y.constructor instanceof Function"), true);
		assert.strictEqual(vm.run("test.object.valueOf().y.constructor('return (function(){return this})().isVM')()"), true);
		
		let o = vm.run("let x = {a: test.date, b: test.date};x");
		assert.strictEqual(vm.run("x.valueOf().a instanceof Date"), true);
		assert.strictEqual(o instanceof Object, true);
		assert.strictEqual(o.a instanceof Date, true);
		assert.strictEqual(o.b instanceof Date, true);
		assert.strictEqual(o.a === o.b, true);
		assert.strictEqual(o.a === sandbox.test.date, true);
		
		o = vm.run("let y = new Date(); let z = {a: y, b: y};z");
		assert.strictEqual(o.isVMProxy, true);
		assert.strictEqual(o instanceof Object, true);
		assert.strictEqual(o.a instanceof Date, true);
		assert.strictEqual(o.b instanceof Date, true);
		assert.strictEqual(o.a === o.b, true);
		
		done();
	})
	
	it('class', done => {
		assert.strictEqual(vm.run("new test.klass()").isVMProxy, void 0);
		assert.strictEqual(vm.run("new test.klass()").greet('friend'), 'hello friend');
		assert.strictEqual(vm.run("new test.klass()") instanceof TestClass, true);
		
		done();
	})
	
	it('string', done => {
		assert.strictEqual(vm.run("(test.string).constructor === String"), true);
		assert.strictEqual(vm.run("typeof(test.stringO) === 'string' && test.string.valueOf instanceof Object"), true);
		
		done();
	})
	
	it('number', done => {
		assert.strictEqual(vm.run("typeof(test.numberO) === 'number' && test.number.valueOf instanceof Object"), true);
		
		done();
	})
	
	it('boolean', done => {
		assert.strictEqual(vm.run("typeof(test.booleanO) === 'boolean' && test.boolean.valueOf instanceof Object"), true);
		
		done();
	})
	
	it('date', done => {
		assert.strictEqual(vm.run("test.date instanceof Date"), true);
		assert.strictEqual(vm.run("test.date") instanceof Date, true);
		assert.strictEqual(vm.run("test.date"), sandbox.test.date);
		
		done();
	})
	
	it('regexp', done => {
		assert.strictEqual(vm.run("test.regexp instanceof RegExp"), true);
		
		done();
	})
	
	it('buffer', done => {
		assert.strictEqual(vm.run("test.buffer.inspect()"), '<Buffer 00 01>', '#1');
		assert.strictEqual(vm.run("test.buffer instanceof Buffer"), true, '#2');
		assert.strictEqual(vm.run("test.buffer") instanceof Buffer, true, '#3');
		assert.strictEqual(vm.run("test.buffer"), sandbox.test.buffer, '#4');
		assert.strictEqual(vm.run("class Buffer2 extends Buffer {};new Buffer2(5)").fill(1).inspect(), '<Buffer 01 01 01 01 01>');
		
		done();
	})
	
	it('function', done => {
		assert.strictEqual(vm.run("test.function instanceof Function"), true, '#1');
		assert.strictEqual(vm.run("test.function() instanceof Function"), true, '#2');
		assert.strictEqual(vm.run("test.function()() instanceof Object"), true, '#3');
		
		done();
	})
	
	it('object', done => {
		assert.strictEqual(vm.run("test.object instanceof Object && test.object.x === 1"), true, '#1');
		assert.strictEqual(vm.run("test.object.y instanceof Function"), true, '#2');
		assert.strictEqual(vm.run("test.object.y() instanceof Function"), true, '#3');
		assert.strictEqual(vm.run("test.object.y()({})"), true, '#4');
		assert.strictEqual(vm.run("test.object.z({}) instanceof Object"), true, '#5');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty instanceof Function"), true, '#6');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty.constructor('return (function(){return this})().isVM')()"), true, '#7');
		
		done();
	})
	
	it('null', done => {
		assert.strictEqual(vm.run("test.nil === null"), true);
		
		done();
	})
	
	it('undefined', done => {
		assert.strictEqual(vm.run("test.undef === undefined"), true);
		
		done();
	})
	
	after(done => {
		vm = null;
		
		done();
	})
})

describe('VM', () => {
	let vm;
	
	before(done => {
		let sandbox = {
			round(number) { return Math.round(number); },
			sub: {}
		}
		
		Object.defineProperty(sandbox.sub, 'getter', {
			get() {
				let results;
				results = [];
				while (true) {
					results.push(1);
				}
				return results;
			}
		})
		
		vm = new VM({
			timeout: 10,
			sandbox
		})
		
		done();
	})
	
	it('globals', done => {
		assert.equal(vm.run("round(1.5)"), 2);
		
		done();
	})
	
	it('errors', done => {
		assert.throws(() => vm.run("notdefined"), /notdefined is not defined/);
		assert.throws(() => vm.run("Object.defineProperty(sub, 'test', {})"), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, 'Operation not allowed on contextified object.');
			return true;
		})
		
		done();
	})
	
	it('timeout', done => {
		assert.throws(() => new VM({
			timeout: 10
		}).run("while (true) {}"), /Script execution timed out\./);
		assert.throws(() => vm.run("sub.getter"), /Script execution timed out\./);
		
		done();
	})
	
	it('timers', done => {
		assert.equal(vm.run("global.setTimeout"), void 0);
		assert.equal(vm.run("global.setInterval"), void 0);
		assert.equal(vm.run("global.setImmediate"), void 0);
		
		done();
	})
	
	it('#32 attacks', done => {
		let vm2 = new VM({sandbox: {log: console.log, boom: function() { throw new Error(); }}});
		
		assert.strictEqual(vm2.run("this.constructor.constructor('return Function(\\'return Function\\')')()() === this.constructor.constructor('return Function')()"), true);
		
		assert.throws(() => vm2.run(`
			const ForeignFunction = global.constructor.constructor;
			const process1 = ForeignFunction("return process")();
			const require1 = process1.mainModule.require;
			const console1 = require1("console");
			const fs1 = require1("fs");
			console1.log(fs1.statSync('.'));
		`), /process is not defined/);

		assert.throws(() => vm2.run(`
		    try {
		        log.__proto__ = null;
		    }
		    catch (e) {
		        const foreignFunction = e.constructor.constructor;
		        const process = foreignFunction("return process")();
		        const require = process.mainModule.require;
		        const fs = require("fs");
		        log(fs.statSync('.'));
		    }
		`), /process is not defined/);

		assert.throws(() => vm2.run(`
		    try {
		        boom();
		    }
		    catch (e) {
		        const foreignFunction = e.constructor.constructor;
		        const process = foreignFunction("return process")();
		        const require = process.mainModule.require;
		        const fs = require("fs");
		        log(fs.statSync('.'));
		    }
		`), /process is not defined/);

		assert.doesNotThrow(() => vm2.run(`
			function exploit(o) {
				throw new Error('Shouldnt be there.');
			}
			
			Reflect.construct = exploit;
			new Buffer([0]);
		`));

		assert.doesNotThrow(() => vm2.run(`
			global.Proxy = function() {
				throw new Error('Shouldnt be there.');
			}
		`));
		
		assert.doesNotThrow(() => vm2.run(`
			global.String = function(text) {
				throw new Error('Shouldnt be there.');
			};(function(text) {})
		`)('asdf'));
		
		assert.doesNotThrow(() => vm2.run(`
			global.String = function(text) {
				throw new Error('Shouldnt be there.');
			};(function(text) {})
		`)(new String('asdf')));
		
		assert.doesNotThrow(() => vm2.run(`
			global.Buffer = function(value) {
				throw new Error('Shouldnt be there.');
			};(function(value) {})
		`)(new Buffer(1)));
		
		done();
	})
	
	after(done => {
		vm = null;
		
		done();
	})
})

describe('NodeVM', () => {
	let vm;
	
	before(done => {
		vm = new NodeVM;
		
		done();
	})
	
	it('globals', done => {
		let ex;
		ex = vm.run("module.exports = global");
		assert.equal(ex.isVM, true);
		
		done();
	})
	
	it('errors', done => {
		assert.throws(() => vm.run("notdefined"), /notdefined is not defined/);
		
		done();
	})
	
	it('prevent global access', done => {
		assert.throws(() => vm.run("process.exit()"), /(undefined is not a function|process\.exit is not a function)/);
		
		done();
	})
	
	it('arguments attack', done => {
		assert.throws(() => console.log(vm.run("module.exports = (function() {return arguments.callee.caller.caller.toString()})()")), /Cannot read property 'toString' of null/);
		
		done();
	})
	
	it('global attack', done => {
		assert.equal(vm.run("module.exports = console.log.constructor('return (function(){return this})().isVM')()"), true);
		
		done();
	})
	
	it.skip('timeout (not supported by Node\'s VM)', done => {
		assert.throws(() => new NodeVM({
			timeout: 10
		}).run("while (true) {}"), /Script execution timed out\./);
		
		done();
	})
	
	after(done => {
		vm = null;
		
		done();
	})
})

describe('modules', () => {
	it('require json', done => {
		let vm = new NodeVM({
			require: {
				external: true
			}
		})
		
		assert.equal(vm.run(`module.exports = require('${__dirname}/data/json.json')`).working, true);
		
		done();
	})
	
	it.skip('run coffee-script', done => {
		let vm = new NodeVM({
			require: {
				external: true
			},
			compiler: 'coffeescript'
		})
		
		assert.equal(vm.run("module.exports = working: true").working, true);
		
		done();
	})
	
	it('disabled require', done => {
		let vm = new NodeVM;
		
		assert.throws(() => vm.run("require('fs')"), /Access denied to require 'fs'/);
		
		done();
	})
	
	it('disable setters on native modules', done => {
		let vm = new NodeVM({
			require: {
				"native": ['fs']
			}
		})
		
		vm.run("require('fs').readFileSync = undefined");
		assert.strictEqual(require('fs').readFileSync instanceof Function, true);
		
		done();
	})
	
	it('enabled require for certain modules', done => {
		let vm = new NodeVM({
			require: {
				"native": ['fs']
			}
		})
		
		assert.doesNotThrow(() => vm.run("require('fs')"));
		
		done();
	})
	
	it('require relative', done => {
		let vm = new NodeVM({
			require: {
				external: true
			}
		})
		
		vm.run("require('foobar')", __filename);
		
		done();
	})
	
	it('arguments attack', done => {
		let vm = new NodeVM;
		
		assert.throws(() => vm.run("module.exports = function fce(msg) { return arguments.callee.caller.toString(); }")(), /Cannot read property 'toString' of null/);
		
		vm = new NodeVM;
		
		assert.throws(() => vm.run("module.exports = function fce(msg) { return fce.caller.toString(); }")(), /Cannot read property 'toString' of null/);
		
		done();
	})
	
	it('native module arguments attack', done => {
		let vm = new NodeVM({
			require: {
				"native": ['fs']
			},
			sandbox: {
				parentfilename: __filename,
				done
			}
		})
		
		vm.run("var fs = require('fs'); fs.exists(parentfilename, function() {try {arguments.callee.caller.toString()} catch (err) {return done();}; done(new Error('Missing expected exception'))})");
	})
	
	it('path attack', done => {
		let vm = new NodeVM({
			require: {
				external: true,
				root: __dirname
			}
		})
		
		assert.throws(() => vm.run("var test = require('../package.json')", __filename), /Module '\.\.\/package.json' is not allowed to be required\. The path is outside the border!/);
		
		done();
	})
	
	it('process events', done => {
		let vm = new NodeVM({
			sandbox: {
				VM2_COUNTER: 0
			}
		})
		
		let sandbox = vm.run("global.VM2_HANDLER = function() { VM2_COUNTER++ }; process.on('exit', VM2_HANDLER); module.exports = global;");
		process.emit('exit');
		assert.strictEqual(sandbox.VM2_COUNTER, 1);
		assert.strictEqual(vm.run("module.exports = process.listeners('exit')[0] === VM2_HANDLER;"), true);
		vm.run("process.removeListener('exit', VM2_HANDLER);");
		process.emit('exit');
		assert.strictEqual(sandbox.VM2_COUNTER, 1);
		
		done();
	})
	
	it('timers', done => {
		let vm = new NodeVM({
			sandbox: {
				done
			}
		})
		
		vm.run('let i = setImmediate(function() { global.TICK = true; });clearImmediate(i);');
		
		setImmediate(() => {
			assert.strictEqual(vm.run('module.exports = global.TICK'), void 0);
			vm.run('setImmediate(done);');
		})
	})
})

describe('nesting', () => {
	it('NodeVM', done => {
		let vm = new NodeVM({
			nesting: true
		})
		
		let nestedObject = vm.run(`
			const {VM} = require('vm2');
			const vm = new VM();
			let o = vm.run('({})');
			module.exports = o;
		`, 'vm.js');
		
		assert.strictEqual(nestedObject.constructor.constructor === Function, true);
		
		done();
	})
})
