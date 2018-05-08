const assert = require("assert");
const {NodeVM, VM, VMScript} = require('..');

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
		assert,
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
			klass: TestClass,
			symbol1: Symbol('foo'),
			symbol2: Symbol.for('foo'),
			symbol3: Symbol.iterator,
			error: new Error('test')
		}
	}

	before(() => {
		vm = new VM({sandbox});
	})

	it('common', () => {
		assert.ok(vm.run(`global.__proto__ === Object.prototype`));
		assert.ok(vm.run(`global.__proto__.constructor === Object`));
		assert.ok(vm.run(`Object.__proto__ === Function.prototype`));
		assert.ok(vm.run(`Object.__proto__.constructor === Function`));
		assert.ok(vm.run(`Object.prototype.__proto__ === null`));
		assert.ok(vm.run(`Function.__proto__ === Function.prototype`));
		assert.ok(vm.run(`Function.__proto__.constructor === Function`));
		assert.ok(vm.run(`Function.prototype.__proto__ === Object.prototype`));
		assert.ok(vm.run(`Array.__proto__ === Function.prototype`));
		assert.ok(vm.run(`Array.__proto__.constructor === Function`));
		assert.ok(vm.run(`Array.prototype.__proto__ === Object.prototype`));

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
	})

	it('class', () => {
		assert.strictEqual(vm.run("new test.klass()").isVMProxy, undefined);
		assert.strictEqual(vm.run("new test.klass()").greet('friend'), 'hello friend');
		assert.strictEqual(vm.run("new test.klass()") instanceof TestClass, true);

		//vm.run("class LocalClass extends test.klass {}");
	})

	it('string', () => {
		assert.strictEqual(vm.run("(test.string).constructor === String"), true);
		assert.strictEqual(vm.run("typeof(test.stringO) === 'string' && test.string.valueOf instanceof Object"), true);
	})

	it('number', () => {
		assert.strictEqual(vm.run("typeof(test.numberO) === 'number' && test.number.valueOf instanceof Object"), true);
	})

	it('boolean', () => {
		assert.strictEqual(vm.run("typeof(test.booleanO) === 'boolean' && test.boolean.valueOf instanceof Object"), true);
	})

	it('date', () => {
		assert.strictEqual(vm.run("test.date instanceof Date"), true);
		assert.strictEqual(vm.run("test.date") instanceof Date, true);
		assert.strictEqual(vm.run("test.date"), sandbox.test.date);
	})

	it('regexp', () => {
		assert.strictEqual(vm.run("test.regexp instanceof RegExp"), true);
	})

	it('buffer', () => {
		assert.strictEqual(vm.run("test.buffer.inspect()"), '<Buffer 00 01>', '#1');
		assert.strictEqual(vm.run("test.buffer instanceof Buffer"), true, '#2');
		assert.strictEqual(vm.run("test.buffer") instanceof Buffer, true, '#3');
		assert.strictEqual(vm.run("test.buffer"), sandbox.test.buffer, '#4');
		assert.strictEqual(vm.run("class Buffer2 extends Buffer {};new Buffer2(5)").fill(1).inspect(), '<Buffer 01 01 01 01 01>');

		let {a, b, c, d} = vm.run(`
			let a = new Buffer([0x01, 0x02]);
			let b = Buffer.alloc(3, 0x03);
			let c = Buffer.from(a);
			let d = Buffer.concat([a, b, c]);

			assert.ok(a instanceof Buffer, '#1');
			assert.ok(b instanceof Buffer, '#2');
			assert.ok(c instanceof Buffer, '#3');
			assert.ok(d instanceof Buffer, '#4');
			assert.ok(a.constructor === Buffer, '#5');
			assert.ok(b.constructor === Buffer, '#6');
			assert.ok(c.constructor === Buffer, '#7');
			assert.ok(d.constructor === Buffer, '#8');
			assert.ok(a.constructor.constructor === Function, '#9');
			assert.ok(b.constructor.constructor === Function, '#10');
			assert.ok(c.constructor.constructor === Function, '#11');
			assert.ok(d.constructor.constructor === Function, '#12');

			({a: a, b: b, c: c, d: d})
		`);

		assert.ok(a instanceof Buffer);
		assert.ok(b instanceof Buffer);
		assert.ok(c instanceof Buffer);
		assert.ok(d instanceof Buffer);
		assert.ok(a.constructor === Buffer);
		assert.ok(b.constructor === Buffer);
		assert.ok(c.constructor === Buffer);
		assert.ok(d.constructor === Buffer);
		assert.ok(a.constructor.constructor === Function);
		assert.ok(b.constructor.constructor === Function);
		assert.ok(c.constructor.constructor === Function);
		assert.ok(d.constructor.constructor === Function);
	})

	it('function', () => {
		assert.strictEqual(vm.run("test.function instanceof Function"), true, '#1');
		assert.strictEqual(vm.run("test.function() instanceof Function"), true, '#2');
		assert.strictEqual(vm.run("test.function()() instanceof Object"), true, '#3');
	})

	it('object', () => {
		assert.strictEqual(vm.run("test.object instanceof Object && test.object.x === 1"), true, '#1');
		assert.strictEqual(vm.run("test.object.y instanceof Function"), true, '#2');
		assert.strictEqual(vm.run("test.object.y() instanceof Function"), true, '#3');
		assert.strictEqual(vm.run("test.object.y()({})"), true, '#4');
		assert.strictEqual(vm.run("test.object.z({}) instanceof Object"), true, '#5');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty instanceof Function"), true, '#6');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty.constructor('return (function(){return this})().isVM')()"), true, '#7');
	})

	it('null', () => {
		assert.strictEqual(vm.run("test.nil === null"), true);
	})

	it('undefined', () => {
		assert.strictEqual(vm.run("test.undef === undefined"), true);
	})

	it('symbol', () => {
		assert.strictEqual(vm.run("Symbol.for('foo') === test.symbol2"), true);
		assert.strictEqual(vm.run("test.symbol1.constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("test.symbol2.constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("test.symbol3.constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("Symbol('foo').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("Symbol('foobar').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("Symbol.keyFor(test.symbol2)"), 'foo');
	})

	it('error', () => {
		assert.strictEqual(vm.run("test.error.constructor.constructor === Function;"), true);
	})

	after(() => {
		vm = null;
	})
})

describe('VM', () => {
	let vm;

	before(() => {
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
	})

	it('globals', () => {
		assert.equal(vm.run("round(1.5)"), 2);
	})

	it('errors', () => {
		assert.throws(() => vm.run("notdefined"), /notdefined is not defined/);
		assert.throws(() => vm.run("Object.setPrototypeOf(sub, {})"), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, 'Operation not allowed on contextified object.');
			return true;
		})
	})

	it('timeout', () => {
		assert.throws(() => new VM({
			timeout: 10
		}).run("while (true) {}"), /Script execution timed out\./);
		assert.throws(() => vm.run("sub.getter"), /Script execution timed out\./);
	})

	it('timers', () => {
		assert.equal(vm.run("global.setTimeout"), void 0);
		assert.equal(vm.run("global.setInterval"), void 0);
		assert.equal(vm.run("global.setImmediate"), void 0);
	})

	it('various attacks #1', () => {
		let vm2 = new VM({sandbox: {log: console.log, boom: function() { throw new Error(); }}});

		assert.strictEqual(vm2.run("this.constructor.constructor('return Function(\\'return Function\\')')()() === this.constructor.constructor('return Function')()"), true);

		assert.throws(() => vm2.run(`
			const ForeignFunction = global.constructor.constructor;
			const process1 = ForeignFunction("return process")();
		`), /process is not defined/, '#1');

		assert.throws(() => vm2.run(`
		    try {
		        boom();
		    }
		    catch (e) {
		        const foreignFunction = e.constructor.constructor;
		        const process = foreignFunction("return process")();
		    }
		`), /process is not defined/, '#2');

		assert.doesNotThrow(() => vm2.run(`
			function exploit(o) {
				throw new Error('Shouldnt be there.');
			}

			Reflect.construct = exploit;
			new Buffer([0]);
		`), '#3');

		assert.doesNotThrow(() => vm2.run(`
			global.Proxy = function() {
				throw new Error('Shouldnt be there.');
			}
		`), '#4');

		assert.doesNotThrow(() => vm2.run(`
			global.String = function(text) {
				throw new Error('Shouldnt be there.');
			};(function(text) {})
		`)('asdf'), '#5');

		assert.doesNotThrow(() => vm2.run(`
			global.String = function(text) {
				throw new Error('Shouldnt be there.');
			};(function(text) {})
		`)(new String('asdf')), '#6');

		assert.doesNotThrow(() => vm2.run(`
			global.Buffer = function(value) {
				throw new Error('Shouldnt be there.');
			};(function(value) {})
		`)(new Buffer(1)), '#7');
	})

	it('various attacks #2', () => {
		let vm2 = new VM({
			sandbox: {
				boom: function() {},
				error: new Error('test')
			}
		});

		assert.doesNotThrow(() => vm2.run(`
			Object.assign = function (o) {
				throw new Error('Shouldnt be there.');
			};
			new Buffer([0]);
		`), '#1');

		assert.doesNotThrow(() => vm2.run(`
			try {
				new Buffer();
			} catch (e) {
				if (e.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
			}
		`), '#2');

		assert.doesNotThrow(() => vm2.run(`
			let o;
			Array.prototype.map = function(callback) {
				o = callback(boom);
				return [];
			};
			boom(boom);
			if (o && o.constructor !== Function) throw new Error('Shouldnt be there.');
		`), '#3');

		assert.doesNotThrow(() => vm2.run(`
			let method = () => {};
			let proxy = new Proxy(method, {
				apply: (target, context, args) => {
					if (target.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
					if (args.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
				}
			});
			proxy
		`)('asdf'), '#4');

		assert.doesNotThrow(() => vm2.run(`
			let proxy2 = new Proxy(function() {}, {
				apply: (target, context, args) => {
					if (args.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
				}
			});
			proxy2
		`)('asdf'), '#5');

		assert.strictEqual(vm2.run(`
			global.DEBUG = true;
			boom.vmProxyTarget
		`), undefined, '#6');

		assert.throws(() => vm2.run(`
			global.constructor.constructor('return this')().constructor.constructor('return process')()
		`), /process is not defined/, '#7');

		assert.throws(() => vm2.run(`
			global.__proto__.constructor.constructor('return this')().constructor.constructor('return process')()
		`), /process is not defined/, '#8');

		assert.doesNotThrow(() => vm2.run(`
			if (!(Object.keys(boom) instanceof Array)) throw new Error('Shouldnt be there.');
			if (!(Reflect.ownKeys(boom) instanceof Array)) throw new Error('Shouldnt be there.');
		`));
	})
	
	it('buffer attack', () => {
		let vm2 = new VM();
		
		assert.strictEqual(vm2.run(`
			new Buffer(100).toString('hex');
		`), '00'.repeat(100), '#1');
		
		assert.strictEqual(vm2.run(`
			Buffer.allocUnsafe(100).constructor.constructor === Function;
		`), true, '#2');
		
		assert.strictEqual(vm2.run(`
			Buffer.allocUnsafe(100).toString('hex');
		`), '00'.repeat(100), '#3');
		
		assert.strictEqual(vm2.run(`
			class MyBuffer extends Buffer {}; new MyBuffer(100).toString('hex');
			`), '00'.repeat(100), '#4');
	})

	after(() => {
		vm = null;
	})
})

describe('NodeVM', () => {
	let vm;

	before(() => {
		vm = new NodeVM;
	})

	it('globals', () => {
		let ex;
		ex = vm.run("module.exports = global");
		assert.equal(ex.isVM, true);
	})

	it('errors', () => {
		assert.throws(() => vm.run("notdefined"), /notdefined is not defined/);
	})

	it('prevent global access', () => {
		assert.throws(() => vm.run("process.exit()"), /(undefined is not a function|process\.exit is not a function)/);
	})

	it('arguments attack', () => {
		assert.strictEqual(vm.run("module.exports = (function() { return arguments.callee.caller.constructor === Function; })()"), true);
		assert.throws(() => vm.run("module.exports = (function() { return arguments.callee.caller.caller.toString(); })()"), /Cannot read property 'toString' of null/);
	})

	it('global attack', () => {
		assert.equal(vm.run("module.exports = console.log.constructor('return (function(){return this})().isVM')()"), true);
	})

	it.skip('timeout (not supported by Node\'s VM)', () => {
		assert.throws(() => new NodeVM({
			timeout: 10
		}).run("while (true) {}"), /Script execution timed out\./);
	})

	after(() => {
		vm = null;
	})
})

describe('modules', () => {
	it('require json', () => {
		let vm = new NodeVM({
			require: {
				external: true
			}
		})

		assert.equal(vm.run(`module.exports = require('${__dirname}/data/json.json')`).working, true);
	})

	it.skip('run coffee-script', () => {
		let vm = new NodeVM({
			require: {
				external: true
			},
			compiler: 'coffeescript'
		})

		assert.equal(vm.run("module.exports = working: true").working, true);
	})

	it('optionally can run a custom compiler function', () => {
		var ranCustomCompiler = false
		const scriptCode = 'var a = 1;'
		let vm = new NodeVM({
			compiler: (code) => {
				ranCustomCompiler = true
				assert.equal(code, scriptCode)
			}
		})
		vm.run(scriptCode)
		assert.equal(ranCustomCompiler, true);
	})

	it('optionally passes a filename to a custom compiler function', () => {
		var ranCustomCompiler = false
		let vm = new NodeVM({
			compiler: (code, filename) => {
				ranCustomCompiler = true
				assert.equal(filename, '/a/b/c.js')
			}
		})
		vm.run("module.exports = working: true", '/a/b/c.js')
		assert.equal(ranCustomCompiler, true);
	})

	it('disabled require', () => {
		let vm = new NodeVM;

		assert.throws(() => vm.run("require('fs')"), /Access denied to require 'fs'/);
	})

	it('disable setters on builtin modules', () => {
		let vm = new NodeVM({
			require: {
				builtin: ['fs']
			}
		})

		vm.run("require('fs').readFileSync = undefined");
		assert.strictEqual(require('fs').readFileSync instanceof Function, true);

		vm.run("require('fs').readFileSync.thisPropertyShouldntBeThere = true");
		assert.strictEqual(require('fs').readFileSync.thisPropertyShouldntBeThere, undefined);

		assert.throws(() => vm.run("Object.defineProperty(require('fs'), 'test', {})"), err => {
			assert.ok(err instanceof TypeError);
			assert.equal(err.name, 'TypeError');
			assert.equal(err.message, '\'defineProperty\' on proxy: trap returned falsish for property \'test\'');
			return true;
		})

		assert.throws(() => vm.run("'use strict'; delete require('fs').readFileSync"), err => {
			assert.ok(err instanceof TypeError);
			assert.equal(err.name, 'TypeError');
			assert.equal(err.message, '\'deleteProperty\' on proxy: trap returned falsish for property \'readFileSync\'');
			return true;
		})
	})

	it('enabled require for certain modules', () => {
		let vm = new NodeVM({
			require: {
				builtin: ['fs']
			}
		})

		assert.doesNotThrow(() => vm.run("require('fs')"));
	})

	it('require relative', () => {
		let vm = new NodeVM({
			require: {
				external: true
			},
		})

		vm.run("require('foobar')", __filename);
	})

	it('can require a module inside the vm', () => {
		let vm = new NodeVM({
			require: {
				external: true
			}
		})

		vm.run("require('mocha')", __filename);
	})

	it('can deny requiring modules inside the vm', () => {
		let vm = new NodeVM({
			require: {
				external: false
			},
		})

		assert.throws(() => vm.run("require('mocha')", __filename), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, 'Access denied to require \'mocha\'');
			return true;
		})
	})

	it('can whitelist modules inside the vm', () => {
		let vm = new NodeVM({
			require: {
				external: ['mocha']
			}
		})

		assert.ok(vm.run("require('mocha')", __filename))
		assert.throws(() => vm.run("require('unknown')", __filename), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, "The module 'unknown' is not whitelisted in VM.");
			return true;
		})
	})


	it('arguments attack', () => {
		let vm = new NodeVM;

		assert.throws(() => vm.run("module.exports = function fce(msg) { return arguments.callee.caller.toString(); }")(), /Cannot read property 'toString' of null/);

		vm = new NodeVM;

		assert.throws(() => vm.run("module.exports = function fce(msg) { return fce.caller.toString(); }")(), /Cannot read property 'toString' of null/);
	})

	it('builtin module arguments attack', done => {
		let vm = new NodeVM({
			require: {
				builtin: ['fs']
			},
			sandbox: {
				parentfilename: __filename,
				done
			}
		})

		vm.run("var fs = require('fs'); fs.exists(parentfilename, function() {try {arguments.callee.caller.toString()} catch (err) {return done();}; done(new Error('Missing expected exception'))})");
	})

	it('path attack', () => {
		let vm = new NodeVM({
			require: {
				external: true,
				root: __dirname
			}
		})

		assert.throws(() => vm.run("var test = require('../package.json')", __filename), /Module '\.\.\/package.json' is not allowed to be required\. The path is outside the border!/);
	})

	it('process events', () => {
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

	it('mock', () => {
		let vm = new NodeVM({
			require: {
				mock: {
					fs: {
						readFileSync() { return 'Nice try!'; }
					}
				}
			}
		})

		assert.strictEqual(vm.run("module.exports = require('fs').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("module.exports = require('fs').readFileSync.constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("module.exports = require('fs').readFileSync()"), 'Nice try!');
	})
})

describe('nesting', () => {
	it('NodeVM', () => {
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
	})
})

describe('wrappers', () => {
	it('none', () => {
		let vm = new NodeVM({
			wrapper: 'none'
		})
		
		assert.strictEqual(vm.run('return 2 + 2'), 4)
	})
})

describe('precompiled scripts', () => {
	it('VM', () => {
		let vm = new VM();
		let script = new VMScript("Math.random()");
		let val1 = vm.run(script);
		let val2 = vm.run(script);
		assert.ok('number' === typeof val1 && 'number' === typeof val2);
		assert.ok( val1 != val2);
	})
	
	it('NodeVM', () => {
		let vm = new NodeVM();
		let script = new VMScript("module.exports = Math.random()");
		let val1 = vm.run(script);
		let val2 = vm.run(script);
		assert.ok('number' === typeof val1 && 'number' === typeof val2);
		assert.ok( val1 != val2);
	})
})

describe('freeze, protect', () => {
	it('without freeze', () => {
		let x = {
			a: () => 'a',
			b: () => 'b',
			c: {
				d: () => 'd'
			}
		}

		let vm = new VM({
			sandbox: {x}
		});
		vm.run('x.a = () => { return `-` }; x.c.d = () => { return `---` }; (y) => { y.b = () => { return `--` } }')(x);
		
		assert.strictEqual(x.a(), '-');
		assert.strictEqual(x.b(), '--');
		assert.strictEqual(x.c.d(), '---');
	})

	it('with freeze', () => {
		let x = {
			a: () => 'a',
			b: () => 'b',
			c: {
				d: () => 'd'
			}
		};

		let vm = new VM();
		vm.freeze(x, 'x');

		assert.throws(() => {
			vm.run('"use strict"; x.a = () => { return `-` };');
		}, /'set' on proxy: trap returned falsish for property 'a'/);

		assert.throws(() => {
			vm.run('"use strict"; (y) => { y.b = () => { return `--` } }')(x);
		}, /'set' on proxy: trap returned falsish for property 'b'/);

		assert.throws(() => {
			vm.run('"use strict"; x.c.d = () => { return `---` };');
		}, /'set' on proxy: trap returned falsish for property 'd'/);

		vm.run('x.a = () => { return `-` };');
		assert.strictEqual(x.a(), 'a');

		vm.run('(y) => { y.b = () => { return `--` } }')(x);
		assert.strictEqual(x.b(), 'b');

		vm.run('x.c.d = () => { return `---` };');
		assert.strictEqual(x.c.d(), 'd');
	})

	it('without protect', () => {
		let vm = new VM(), obj = {};
		vm.run('(i) => { i.text = "test" }')(obj);
		vm.run('(i) => { i.func = () => {} }')(obj);
		vm.run('(i) => { delete i.func }')(obj);
	})

	it('with protect', () => {
		let vm = new VM(), obj = {
			date: new Date(),
			array: [{},{}]
		};

		vm.protect(obj);

		vm.run('(i) => { i.func = () => {} }')(obj);
		assert.strictEqual(typeof obj.func, 'undefined');

		assert.throws(() => {
			vm.run('"use strict"; (i) => { i.func = () => {} }')(obj);
		});

		vm.run('(i) => { i.array.func = () => {} }')(obj);
		assert.strictEqual(typeof obj.array.func, 'undefined');

		assert.throws(() => {
			vm.run('"use strict"; (i) => { i.array.func = () => {} }')(obj);
		});

		vm.run('(i) => { i.array[0].func = () => {} }')(obj);
		assert.strictEqual(typeof obj.array[0].func, 'undefined');

		assert.throws(() => {
			vm.run('"use strict"; (i) => { i.array[0].func = () => {} }')(obj);
		});

		assert.strictEqual(vm.run('(i) => i.array.map(item => 1).join(",")')(obj), '1,1');
		assert.strictEqual(vm.run('(i) => /x/.test(i.date)')(obj), false);
	})
})

describe('source extensions', () => {
	it('does not find a TS module with the default settings', () => {
		let vm = new NodeVM({
			require: {
				external: true
			}
		})
		assert.throws(() => {
			vm.run("require('./data/custom_extension')", __filename);
		})
	})

it('finds a TS module with source extensions set', () => {
		let vm = new NodeVM({
			require: {
				external: true
			},
			sourceExtensions: ["ts", "js"]
		})

		vm.run("require('./data/custom_extension')", __filename);
	})
})
