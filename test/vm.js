/* eslint-env mocha */
/* eslint-disable no-new-wrappers, max-len */

'use strict';

const assert = require('assert');
const {VM, VMScript} = require('..');
const {INTERNAL_STATE_NAME} = require('../lib/transformer');
const NODE_VERSION = parseInt(process.versions.node.split('.')[0]);
const {inspect} = require('util');

global.isHost = true;
global.it.cond = (name, cond, fn) => {
	if (cond) {
		it(name, fn);
	} else {
		it.skip(name, fn);
	}
};

function makeHelpers() {
	function isVMProxy(obj) {
		const key = {};
		const proto = Object.getPrototypeOf(obj);
		if (!proto) return undefined;
		proto.isVMProxy = key;
		const proxy = obj.isVMProxy !== key;
		delete proto.isVMProxy;
		return proxy;
	}

	function isLocal(obj) {
		if (obj instanceof Object || obj === Object.prototype) return true;
		const ctor = obj.constructor;
		if (ctor && ctor.prototype === obj && ctor instanceof ctor && !isVMProxy(ctor)) return false;
		return true;
	}

	function collectAll(obj) {
		const toVisit = [];
		const visited = new Map();
		function addObj(o, path) {
			if (o && (typeof o === 'object' || typeof o === 'function') && !visited.has(o)) {
				visited.set(o, path);
				toVisit.push(o);
			}
		}
		addObj(obj, 'obj');
		function addProp(o, name, path) {
			const prop = Object.getOwnPropertyDescriptor(o, name);
			if (typeof name === 'symbol') name = '!' + name.toString();
			addObj(prop.get, `${path}>${name}`);
			addObj(prop.set, `${path}<${name}`);
			addObj(prop.value, `${path}.${name}`);
		}
		function addAllFrom(o) {
			const path = visited.get(o);
			const names = Object.getOwnPropertyNames(o);
			for (let i = 0; i < names.length; i++) {
				addProp(o, names[i], path);
			}
			const symbols = Object.getOwnPropertySymbols(o);
			for (let i = 0; i < symbols.length; i++) {
				addProp(o, symbols[i], path);
			}
			addObj(Object.getPrototypeOf(o), path + '@');
		}
		while (toVisit.length > 0) {
			addAllFrom(toVisit.pop());
		}
		return visited;
	}

	function checkAllLocal(obj) {
		const wrong = [];
		collectAll(obj).forEach((v, k) => {
			if (!isLocal(k)) wrong.push(v);
		});
		return wrong.length === 0 ? undefined : wrong;
	}

	return {isVMProxy, checkAllLocal};
}

const {
	isVMProxy,
	checkAllLocal
} = makeHelpers();

describe('node', () => {
	let vm;

	const doubleProxy = new Proxy(new Proxy({x: 1}, {get() {
		throw new Error('Expected');
	}}), {});

	before(() => {
		vm = new VM();
	});

	it.cond('inspect', NODE_VERSION >= 11, () => {
		assert.throws(() => inspect(doubleProxy), /Expected/);
		assert.doesNotThrow(() => inspect(vm.run('({})'), {showProxy: true, customInspect: true}));
		if (false) {
			// This failes on node 10 since they do not unwrap proxys.
			// And the hack to fix this is only in the inner proxy.
			// We could add another hack, but that one would require
			// to look if the caller is from a special node function and
			// then remove all the integer keys. To get the caller we
			// would need to get the stack trace which is slow and
			// the probability of this call is so low that I don't do
			// this right now.
			assert.strictEqual(inspect(vm.run('[1, 2, 3]')), inspect([1, 2, 3]), true);
		}
	});

	after(() => {
		vm = null;
	});
});

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

	const sandbox = {
		assert,
		test: {
			string: 'text',
			stringO: new String('text'),
			number: 1,
			numberO: new Number(1),
			boolean: true,
			booleanO: new Boolean(true),
			date: new Date(),
			regexp: /xxx/,
			buffer: Buffer.from([0x00, 0x01]),
			'function'() {
				return () => ({});
			},
			object: {
				x: 1,
				y() {
					return i => i instanceof Object;
				},
				z(i) {
					if (!(i instanceof Object)) throw new Error('Not instanceof parent Object.');
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
	};

	before(() => {
		vm = new VM({sandbox});
	});

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
		assert.strictEqual(vm.run('test.object.y instanceof Function'), true);
		assert.strictEqual(vm.run('test.object.y.valueOf() instanceof Function'), true);
		assert.strictEqual(isVMProxy(vm.run('test.object.y')), false);
		assert.strictEqual(isVMProxy(vm.run('test.object.y.valueOf()')), false);
		assert.strictEqual(vm.run('test.object.y') === vm.run('test.object.y.valueOf()'), true);
		assert.strictEqual(vm.run('test.object.y === test.object.y.valueOf()'), true);
		assert.strictEqual(vm.run('test.object').y instanceof Function, true);
		assert.strictEqual(vm.run('test.object').y.valueOf() instanceof Function, true);
		assert.strictEqual(isVMProxy(vm.run('test.object').y), false);
		assert.strictEqual(isVMProxy(vm.run('test.object').y.valueOf()), false);
		assert.strictEqual(vm.run('test.object').y === vm.run('test.object').y.valueOf(), true);
		assert.strictEqual(vm.run('test.valueOf()') === vm.run('test').valueOf(), true);
		assert.strictEqual(vm.run('test.object.y.constructor instanceof Function'), true);
		assert.strictEqual(vm.run("test.object.y.constructor('return (function(){return this})() === global')()"), true);
		assert.strictEqual(vm.run('test.object.valueOf() instanceof Object'), true);
		assert.strictEqual(vm.run('test.object.valueOf().y instanceof Function'), true);
		assert.strictEqual(vm.run('test.object.valueOf().y.constructor instanceof Function'), true);
		assert.strictEqual(vm.run("test.object.valueOf().y.constructor('return (function(){return this})() === global')()"), true);

		assert.strictEqual(Object.prototype.toString.call(vm.run(`[]`)), '[object Array]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`new Date`)), '[object Date]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`new RangeError`)), '[object Error]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`/a/g`)), '[object RegExp]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`new String`)), '[object String]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`new Number`)), '[object Number]');
		assert.strictEqual(Object.prototype.toString.call(vm.run(`new Boolean`)), '[object Boolean]');

		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)([]), '[object Array]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(new Date), '[object Date]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(new RangeError), '[object Error]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(/a/g), '[object RegExp]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(new String), '[object String]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(new Number), '[object Number]');
		assert.strictEqual(vm.run(`((obj) => Object.prototype.toString.call(obj))`)(new Boolean), '[object Boolean]');

		assert.strictEqual(typeof vm.run(`new String`), 'object');
		assert.strictEqual(typeof vm.run(`new Number`), 'object');
		assert.strictEqual(typeof vm.run(`new Boolean`), 'object');
		assert.strictEqual(vm.run(`((obj) => typeof obj)`)(new String), 'object');
		assert.strictEqual(vm.run(`((obj) => typeof obj)`)(new Number), 'object');
		assert.strictEqual(vm.run(`((obj) => typeof obj)`)(new Boolean), 'object');

		let o = vm.run('let x = {a: test.date, b: test.date};x');
		assert.strictEqual(vm.run('x.valueOf().a instanceof Date'), true);
		assert.strictEqual(o instanceof Object, true);
		assert.strictEqual(o.a instanceof Date, true);
		assert.strictEqual(o.b instanceof Date, true);
		assert.strictEqual(o.a === o.b, true);
		assert.strictEqual(o.a === sandbox.test.date, true);

		o = vm.run('let y = new Date(); let z = {a: y, b: y};z');
		assert.strictEqual(isVMProxy(o), true);
		assert.strictEqual(o instanceof Object, true);
		assert.strictEqual(o.a instanceof Date, true);
		assert.strictEqual(o.b instanceof Date, true);
		assert.strictEqual(o.a === o.b, true);

		assert.strictEqual(checkAllLocal(vm), undefined);

		o = vm.run(`(${makeHelpers})().checkAllLocal(global)`);
		assert.strictEqual(o, undefined);
	});

	it('class', () => {
		assert.strictEqual(isVMProxy(vm.run('new test.klass()')), false);
		assert.strictEqual(vm.run('new test.klass()').greet('friend'), 'hello friend');
		assert.strictEqual(vm.run('new test.klass()') instanceof TestClass, true);

		// vm.run("class LocalClass extends test.klass {}");
	});

	it('string', () => {
		assert.strictEqual(vm.run('(test.string).constructor === String'), true);
		assert.strictEqual(vm.run("typeof(test.string) === 'string' && test.string.valueOf instanceof Object"), true);
	});

	it('number', () => {
		assert.strictEqual(vm.run("typeof(test.number) === 'number' && test.number.valueOf instanceof Object"), true);
	});

	it('boolean', () => {
		assert.strictEqual(vm.run("typeof(test.boolean) === 'boolean' && test.boolean.valueOf instanceof Object"), true);
	});

	it('date', () => {
		assert.strictEqual(vm.run('test.date instanceof Date'), true);
		assert.strictEqual(vm.run('test.date') instanceof Date, true);
		assert.strictEqual(vm.run('test.date'), sandbox.test.date);
	});

	it('regexp', () => {
		assert.strictEqual(vm.run('test.regexp instanceof RegExp'), true);
	});

	it('buffer', () => {
		assert.strictEqual(vm.run('test.buffer.inspect()'), '<Buffer 00 01>', '#1');
		assert.strictEqual(vm.run('test.buffer instanceof Buffer'), true, '#2');
		assert.strictEqual(vm.run('test.buffer') instanceof Buffer, true, '#3');
		assert.strictEqual(vm.run('test.buffer'), sandbox.test.buffer, '#4');
		assert.strictEqual(vm.run('class Buffer2 extends Buffer {};Buffer2.alloc(5)').fill(1).inspect(), '<Buffer 01 01 01 01 01>');

		const {a, b, c, d} = vm.run(`
			let a = Buffer.from([0x01, 0x02]);
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
	});

	it('function', () => {
		assert.strictEqual(vm.run('test.function instanceof Function'), true, '#1');
		assert.strictEqual(vm.run('test.function() instanceof Function'), true, '#2');
		assert.strictEqual(vm.run('test.function()() instanceof Object'), true, '#3');
	});

	it('object', () => {
		assert.strictEqual(vm.run('test.object instanceof Object && test.object.x === 1'), true, '#1');
		assert.strictEqual(vm.run('test.object.y instanceof Function'), true, '#2');
		assert.strictEqual(vm.run('test.object.y() instanceof Function'), true, '#3');
		assert.strictEqual(vm.run('test.object.y()({})'), true, '#4');
		assert.strictEqual(vm.run('test.object.z({}) instanceof Object'), true, '#5');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty instanceof Function"), true, '#6');
		assert.strictEqual(vm.run("Object.getOwnPropertyDescriptor(test.object, 'y').hasOwnProperty.constructor('return (function(){return this})().isHost')()"), undefined, '#7');
	});

	it('null', () => {
		assert.strictEqual(vm.run('test.nil === null'), true);
	});

	it('undefined', () => {
		assert.strictEqual(vm.run('test.undef === undefined'), true);
	});

	it('symbol', () => {
		assert.strictEqual(vm.run("Symbol.for('foo') === test.symbol2"), true);
		assert.strictEqual(vm.run('test.symbol1.constructor.constructor === Function'), true);
		assert.strictEqual(vm.run('test.symbol2.constructor.constructor === Function'), true);
		assert.strictEqual(vm.run('test.symbol3.constructor.constructor === Function'), true);
		assert.strictEqual(vm.run("Symbol('foo').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("Symbol('foobar').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run('Symbol.keyFor(test.symbol2)'), 'foo');
	});

	it('error', () => {
		assert.strictEqual(vm.run('test.error.constructor.constructor === Function;'), true);
	});

	it('tostring', () => {
		const list = [
			'Object',
			'Array',
			'Number',
			'String',
			'Boolean',
			'Date',
			'RegExp',
			'Map',
			'WeakMap',
			'Set',
			'WeakSet',
			'Function',
			'RangeError',
			'ReferenceError',
			'SyntaxError',
			'TypeError',
			'EvalError',
			'URIError',
			'Error'
		];
		const gen = vm.run('name => new (global[name])()');
		const oToString = Object.prototype.toString;
		for (let i = 0; i < list.length; i++) {
			const obj = list[i];
			assert.strictEqual(oToString.call(gen(obj)), oToString.call(new (global[obj])()));
		}
	});

	it('arguments', () => {
		assert.doesNotThrow(() => vm.run('(o) => o.arguments')({arguments: 1}));
	});

	after(() => {
		vm = null;
	});
});

describe('VM', () => {
	let vm;

	const sandbox = {
		round(number) {
			return Math.round(number);
		},
		sub: {}
	};

	Object.defineProperty(sandbox.sub, 'getter', {
		get() {
			const results = [];
			while (true) {
				results.push(1);
			}
			return results;
		}
	});

	before(() => {
		vm = new VM({
			sandbox
		});
	});

	it('globals', () => {
		const dyn = {};
		vm.setGlobal('dyn', dyn);
		vm.setGlobals({dyns: dyn});
		assert.equal(vm.run('round(1.5)'), 2);
		assert.equal(vm.getGlobal('dyn'), dyn);
		assert.equal(vm.sandbox.dyn, dyn);
		assert.equal(vm.sandbox.dyns, dyn);
	});

	it('errors', () => {
		assert.throws(() => vm.run('notdefined'), /notdefined is not defined/);
		assert.throws(() => vm.run('Object.setPrototypeOf(sub, {})'), err => {
			assert.ok(err instanceof Error);
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, 'Operation not allowed on contextified object.');
			return true;
		});

		if (NODE_VERSION > 6) {
			// async/await was not there in Node 6
			assert.throws(() => vm.run('function test(){ return await Promise.resolve(); };'), err => {
				assert.ok(err instanceof Error);
				assert.equal(err.name, 'SyntaxError');
				// assert.match(err.message, /await is only valid in async function/); // Changed due to acorn
				return true;
			});
		}
		assert.throws(() => new VM({compiler: 'nonexistant'}), /Unsupported compiler/);
		assert.throws(() => new VMScript('', '', {compiler: 'nonexistant'}), /Unsupported compiler/);
	});

	it('timeout', () => {
		const message = NODE_VERSION >= 11 ? /Script execution timed out after 10ms/ : /Script execution timed out\./;

		assert.throws(() => new VM({
			timeout: 10
		}).run('while (true) {}'), message);
		assert.throws(() => new VM({timeout: 10, sandbox}).run('sub.getter'), message);
	});

	it('timers', () => {
		assert.equal(vm.run('global.setTimeout'), void 0);
		assert.equal(vm.run('global.setInterval'), void 0);
		assert.equal(vm.run('global.setImmediate'), void 0);
	});

	it.cond('eval/wasm', NODE_VERSION >= 10, () => {
		assert.equal(vm.run('eval("1")'), 1);

		const vm2 = new VM({eval: false});
		assert.throws(() => vm2.run('eval("1")'), /Code generation from strings disallowed for this context/);
	});

	// Node until 7 had no async, see https://node.green/
	it.cond('async', NODE_VERSION >= 8, () => {
		const vm2 = new VM({fixAsync: true});
		assert.throws(() => vm2.run('(async function(){})'), /Async not available/, '#1');
		assert.strictEqual(vm2.run('Object.getPrototypeOf((function*(){}).constructor)'), vm2.run('Function'), '#2');
		assert.throws(() => vm2.run('new Function("(as"+"ync function(){})")'), /Async not available/, '#3');
		assert.throws(() => vm2.run('new (function*(){}).constructor("(as"+"ync function(){})")'), /Async not available/, '#4');
		assert.throws(() => vm2.run('Promise.resolve().then(function(){})'), /Async not available/, '#5');
		if (Promise.prototype.finally) assert.throws(() => vm2.run('Promise.resolve().finally(function(){})'), /Async not available/, '#6');
		if (Promise.prototype.catch) assert.throws(() => vm2.run('Promise.resolve().catch(function(){})'), /Async not available/, '#7');
		assert.throws(() => vm2.run('eval("(as"+"ync function(){})")'), /Async not available/, '#8');
		assert.throws(() => vm2.run('Function')('(async function(){})'), /Async not available/, '#9');
		assert.doesNotThrow(() => vm2.run(`
			let a = {import: 1}
			let b = {import : {"import": 2}};
			let c = { import : 1};
			let d = a.import;
			let e = a. import;
			let f = a.import-1;
			let g = a.import.import;
		`));
	});

	it('proxy trap errors', () => {
		const vm2 = new VM();
		assert.doesNotThrow(() => {
			Reflect.ownKeys(vm2.run('(function(){}).bind(null)'));
		});
	});

	it('frozen unconfigurable access', () => {
		const vm2 = new VM();
		const obj = {};

		assert.doesNotThrow(()=>{
			vm2.run('x => x.prop')(Object.freeze({prop: {}}));
		});

		assert.doesNotThrow(()=>{
			vm2.run('x => Object.getOwnPropertyDescriptor(x, "prop")')(Object.freeze({prop: {}}));
		});

		assert.doesNotThrow(()=>{
			vm2.run('x => x.prop')(Object.defineProperty({}, 'prop', {value: {}}));
		});

		assert.doesNotThrow(()=>{
			vm2.run('x => Object.isExtensible(x)')(Object.freeze({prop: {}}));
		});

		assert.doesNotThrow(()=>{
			vm2.run('x => {Object.preventExtensions(x); Object.getOwnPropertyDescriptor(x, "prop")}')({prop: {}});
		});

		assert.strictEqual(vm2.run('x => {Object.preventExtensions(x); return Object.getOwnPropertyDescriptor(x, "prop").value}')({prop: obj}), obj);

	});

	it('various attacks #1', () => {
		const vm2 = new VM({sandbox: {log: console.log, boom: () => {
			throw new Error();
		}}});

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
			Buffer.from([0]);
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
		`)(Buffer.alloc(1)), '#7');
	});

	it('various attacks #2', () => {
		const vm2 = new VM({
			sandbox: {
				boom: () => {},
				error: new Error('test')
			}
		});

		assert.doesNotThrow(() => vm2.run(`
			Object.assign = function (o) {
				throw new Error('Shouldnt be there.');
			};
			Buffer.from([0]);
		`), '#1');

		assert.doesNotThrow(() => vm2.run(`
			try {
				Buffer.alloc(0);
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

		if (NODE_VERSION > 8) {
			assert.throws(() => vm2.run(`
				let method = () => {};
				let proxy = new Proxy(method, {
					apply: (target, context, args) => {
						if (target.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
						if (args.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
					}
				});
				proxy
			`)('asdf'), /Proxy is not a constructor/, '#4');

			assert.throws(() => vm2.run(`
				let proxy2 = new Proxy(function() {}, {
					apply: (target, context, args) => {
						if (args.constructor.constructor !== Function) throw new Error('Shouldnt be there.');
					}
				});
				proxy2
			`)('asdf'), /Proxy is not a constructor/, '#5');
		} else {
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
		}

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

		if (NODE_VERSION > 8) {
			assert.throws(() => vm2.run(`
				const proxiedErr = new Proxy({}, {
					getPrototypeOf(target) {
						(function stack() {
							new Error().stack;
							stack();
						})();
					}
				});
				try {
					throw proxiedErr;
				} catch ({constructor: c}) {
					c.constructor('return process')();
				}
			`), /Proxy is not a constructor/, '#9');
		} else {
			assert.throws(() => vm2.run(`
				const proxiedErr = new Proxy({}, {
					getPrototypeOf(target) {
						(function stack() {
							new Error().stack;
							stack();
						})();
					}
				});
				try {
					throw proxiedErr;
				} catch ({constructor: c}) {
					c.constructor('return process')();
				}
			`), /Maximum call stack size exceeded/, '#9');
		}
	});

	it('internal state attack', () => {
		const vm2 = new VM();
		assert.throws(() => vm2.run(`${INTERNAL_STATE_NAME}="async";`), /Use of internal vm2 state variable/);
		assert.throws(() => vm2.run(`const ${INTERNAL_STATE_NAME} = "async";`), /Use of internal vm2 state variable/);
		assert.throws(() => vm2.run(`var ${INTERNAL_STATE_NAME} = "async";`), /Use of internal vm2 state variable/);
		assert.throws(() => vm2.run(`let ${INTERNAL_STATE_NAME} = "async";`), /Use of internal vm2 state variable/);
		assert.throws(() => vm2.run(`class ${INTERNAL_STATE_NAME} {}; // async`), /Use of internal vm2 state variable/);
		assert.throws(() => vm2.run(`function ${INTERNAL_STATE_NAME} () {}; // async`), /Use of internal vm2 state variable/);
	});

	it('buffer attack', () => {
		const vm2 = new VM();

		assert.strictEqual(vm2.run(`
			Buffer.alloc(100).toString('hex');
		`), '00'.repeat(100), '#1');

		assert.strictEqual(vm2.run(`
			Buffer.allocUnsafe(100).constructor.constructor === Function;
		`), true, '#2');

		assert.strictEqual(vm2.run(`
			Buffer.allocUnsafe(100).toString('hex');
		`), '00'.repeat(100), '#3');

		assert.strictEqual(vm2.run(`
			class MyBuffer extends Buffer {}; MyBuffer.alloc(100).toString('hex');
		`), '00'.repeat(100), '#4');

		assert.strictEqual(vm2.run(`
			new Buffer(100).toString('hex');
		`), '00'.repeat(100), '#5');

		assert.strictEqual(vm2.run(`
			Buffer(100).toString('hex');
		`), '00'.repeat(100), '#6');

		assert.strictEqual(vm2.run(`
			class MyBuffer2 extends Buffer {}; new MyBuffer2(100).toString('hex');
		`), '00'.repeat(100), '#7');

	});

	it('instanceof attack', () => {
		// https://github.com/patriksimek/vm2/issues/174

		const vm2 = new VM({
			sandbox: {
				func: cb => cb()
			}
		});

		if (NODE_VERSION > 8) {
			assert.throws(() => vm2.run(`
				func(() => {
					throw new Proxy({}, {
						getPrototypeOf: () => {
							throw x => x.constructor.constructor("return process;")();
						}
					})
				});
			`), /Proxy is not a constructor/);
		} else {
			try {
				vm2.run(`
					func(() => {
						throw new Proxy({}, {
							getPrototypeOf: () => {
								throw x => x.constructor.constructor("return process;")();
							}
						})
					});
				`);
			} catch (ex) {
				assert.throws(()=>{
					ex(()=>{});
				}, /process is not defined/);
			}
		}
	});

	it('__defineGetter__ / __defineSetter__ attack', () => {
		// https://github.com/patriksimek/vm2/issues/176

		const vm2 = new VM();

		assert.strictEqual(vm2.run(`
			Buffer.prototype.__defineGetter__ === {}.__defineGetter__;
		`), true, '#1');

		if (NODE_VERSION > 6) {
			assert.throws(() => vm2.run(`
				Buffer.prototype.__defineGetter__("toString", () => {});
			`), /'defineProperty' on proxy: trap returned falsish for property 'toString'/, '#2');
		} else {
			assert.strictEqual(vm2.run(`
				Buffer.prototype.__defineGetter__("xxx", () => 4);
				Buffer.prototype.xxx;
			`), undefined, '#2');
		}

		assert.strictEqual(vm2.run(`
			global.__defineGetter__("test", () => 123); global.test;
		`), 123, '#3');
	});

	it('__lookupGetter__ / __lookupSetter__ attack', () => {
		// https://github.com/patriksimek/vm2/issues/184

		const vm2 = new VM();

		assert.strictEqual(vm2.run(`
			Buffer.from.__lookupGetter__("__proto__") === Object.prototype.__lookupGetter__.call(Buffer.from, "__proto__");
		`), true, '#1');
	});

	it('contextifying a contextified value attack', () => {
		// https://github.com/patriksimek/vm2/issues/175
		// https://github.com/patriksimek/vm2/issues/177
		// https://github.com/patriksimek/vm2/issues/186

		let vm2 = new VM();

		// The Buffer.from("") is only used to get instance of object contextified from the host
		assert.doesNotThrow(() => vm2.run(`
			Object.defineProperty(Buffer.from(""), "x", {
				get set() {
					Object.defineProperty(Object.prototype, "get", {
						get() {
							throw new Error();
						}
					});
					return ()=>{};
				}
			});
		`), '#1');

		vm2 = new VM({
			sandbox: {
				ctor: X => new X(),
				call: x => x()
			}
		});

		assert.throws(() => vm2.run(`
			call(ctor(new Proxy(class A {}, {
				construct(){
					return () => x => x.constructor("return process")();
				}
			})))(()=>{}).mainModule.require("child_process").execSync("id").toString()
		`), NODE_VERSION > 8 ? /Proxy is not a constructor/ : /process is not defined/, '#2');

		vm2 = new VM();

		assert.throws(() => vm2.run(`
			var process;
			try {
				Object.defineProperty(Buffer.from(""), "y", {
					writable: true,
					value: new Proxy({}, {
						getPrototypeOf(target) {
							delete this.getPrototypeOf;

							Object.defineProperty(Object.prototype, "get", {
								get() {
									delete Object.prototype.get;
									Function.prototype.__proto__ = null;
									throw f=>f.constructor("return process")();
								}
							});

							return Object.getPrototypeOf(target);
						}
					})
				});
			} catch(e) {
				process = e(() => {});
			}
			process.mainModule.require("child_process").execSync("whoami").toString()
		`), NODE_VERSION > 8 ? /e is not a function/ : /Cannot read propert.*mainModule/, '#3');

		vm2 = new VM();

		if (NODE_VERSION > 8) {
			assert.throws(() => vm2.run(`
				Object.defineProperty(Buffer.from(""), "", {
					value: new Proxy({}, {
						getPrototypeOf(target) {
							if(this.t) {
								throw Buffer.from;
							}
	
							this.t=true;
							return Object.getPrototypeOf(target);
						}
					})
				});
			`), /Proxy is not a constructor/, '#4');
		} else {
			assert.doesNotThrow(() => vm2.run(`
				Object.defineProperty(Buffer.from(""), "", {
					value: new Proxy({}, {
						getPrototypeOf(target) {
							if(this.t) {
								throw Buffer.from;
							}
	
							this.t=true;
							return Object.getPrototypeOf(target);
						}
					})
				});
			`), '#4');
		}

		vm2 = new VM();

		assert.throws(() => vm2.run(`
			Function.prototype.__proto__ = null;
			var process;
			try {
				Buffer.from(new Proxy({}, {
					getPrototypeOf() {
						if (this.t) {
							throw x => x.constructor("return process")();
						}
						this.t = true;
						return null;
					}
				}));
			} catch(e) {
				process = e(() => {});
			}
			process.mainModule.require("child_process").execSync("whoami").toString()
		`), /e is not a function/, '#5');


		/* TODO internal have changed too much for this to still work
		vm2 = new VM();

		assert.throws(() => vm2.run(`
			Function.prototype.__proto__ = null;
			var map = {
				valueOf(){
					throw new Proxy({},{
						getPrototypeOf(){
							if(this.t) {
								throw x=>x.constructor("return process")();
							}
							this.t = true;
							return null;
						}
					});
				}
			};
			var process;
			try{
				Buffer.from(map);
			}catch(e){
				process = e(x=>x);
			}
			process.mainModule.require("child_process").execSync("whoami").toString()
		`), /e is not a function/, '#6');
		*/

		vm2 = new VM();

		assert.throws(() => vm2.run(`
			var map = {valueOf(){}};
			var arrayBackup = Array;
			Array = function(){
				Array = arrayBackup;
				throw x=>x.constructor("return process")();
			};
			var process;
			try{
				Buffer.from(map);
			}catch(e){
				process = e(x=>x);
			}
			process
		`), /e is not a function/, '#7');
	});

	it('proxy trap via Object.prototype attack', () => {
		// https://github.com/patriksimek/vm2/issues/178

		const vm2 = new VM();

		assert.throws(() => vm2.run(`
			let process;
			Object.prototype.has = (t, k) => {
				process = t.constructor("return process")();
			}
			"" in Buffer.from;
			process.mainModule;
		`), /Cannot read propert.*mainModule/, '#1');

		const vm22 = new VM();

		assert.throws(() => vm22.run(`
			Object.defineProperty(Object.prototype, "apply", {set:function(o,v){
				delete Object.prototype.apply;
			}});
			Buffer.from("").constructor.constructor("return process")().mainModule;
		`), /process is not defined/, '#2');
	});

	it('Object.create attack', () => {
		// https://github.com/patriksimek/vm2/issues/178

		const vm2 = new VM();

		assert.throws(() => vm2.run(`
			var oc = Object.create;
			Object.create = (p,x)=> Object.defineProperty(oc(p,x),"get",{set(){},get:()=>(t,k,r)=>t.constructor("return process")()});
			var process = Buffer.from.process;
			Object.create = oc;
			process.mainModule
		`), /Cannot read propert.*mainModule/, '#1');
	});

	it('function returned from construct attack', () => {
		// https://github.com/patriksimek/vm2/issues/179

		const vm2 = new VM({
			sandbox: {
				call: x => x.a(),
				ctor: X => new X()
			}
		});

		assert.throws(() => vm2.run(`
			call({a:ctor(new Proxy(class A{},{
				construct(){
					return function(){
						return Object.getPrototypeOf(this).constructor.constructor("return process")();
					}
				}
			}))}).mainModule.require("child_process").execSync("id").toString()
		`), NODE_VERSION > 8 ? /Proxy is not a constructor/ : /process is not defined/, '#1');
	});

	it('throw while accessing propertyDescriptor properties', () => {
		// https://github.com/patriksimek/vm2/issues/178#issuecomment-450904979

		const vm2 = new VM();

		assert.strictEqual(vm2.run(`(function(){
			var process;
			Object.defineProperty(Object.prototype, "set", {get(){
				delete Object.prototype.set;
				Object.defineProperty(Object.prototype, "get", {get(){
					delete Object.prototype.get;
					throw new Proxy(Object.create(null),{
						set(t,k,v){
							process = v.constructor("return process")();
							return true;
						}
					});
				},configurable:true});
				return ()=>{};
			},configurable:true});
			try{
				Object.defineProperty(Buffer.from(""),"",{});
			}catch(e){
				e.x = Buffer.from;
			}
			return process;})()
		`), undefined, '#1');
	});

	it('Symbol.hasInstance attack', () => {
		// https://github.com/patriksimek/vm2/issues/178#issuecomment-450978210

		let vm2 = new VM();

		assert.throws(() => vm2.run(`
			Object.__defineGetter__(Symbol.hasInstance,()=>()=>true);
			Buffer.from.constructor("return process")().mainModule.require("child_process").execSync("id").toString()
		`), /process is not defined/, '#1');

		vm2 = new VM();

		assert.throws(() => vm2.run(`
			Object[Symbol.hasInstance].call = ()=>true;
			Buffer.from.constructor("return process")().mainModule.require("child_process").execSync("whoami").toString()
		`), /process is not defined/, '#2');
	});

	it.cond('Proxy::getOwnPropertyDescriptor attack', NODE_VERSION >= 12, () => {
		// https://github.com/patriksimek/vm2/issues/178#issuecomment-450978210

		const vm2 = new VM();

		assert.throws(() => vm2.run(`
			(function(){
				Buffer.from(new Proxy({}, {
					getOwnPropertyDescriptor(){
						throw f=>f.constructor("return process")();
					}
				}));
			})()
		`), /Proxy is not a constructor/);
	});

	it.cond('Dynamic import attack', NODE_VERSION >= 10, () => {
		const vm2 = new VM();

		assert.throws(()=>vm2.run(`
			const process = import('oops!').constructor.constructor('return process')();
		`), /VMError: Dynamic Import not supported/);
	});

	it.cond('Error.prepareStackTrace attack', NODE_VERSION >= 12, () => {
		const vm2 = new VM();
		const sst = vm2.run('Error.prepareStackTrace = (e,sst)=>sst;const sst = new Error().stack;Error.prepareStackTrace = undefined;sst');
		assert.strictEqual(vm2.run('sst=>Object.getPrototypeOf(sst)')(sst), vm2.run('Array.prototype'));
		assert.throws(()=>vm2.run('sst=>sst[0].getThis().constructor.constructor')(sst), /TypeError: Cannot read propert.*constructor/);
		assert.throws(()=>vm2.run(`
			const { set } = WeakMap.prototype;
			WeakMap.prototype.set = function(v) {
				return set.call(this, v, v);
			};
			Error.prepareStackTrace =
			Error.prepareStackTrace =
			(_, c) => c.map(c => c.getThis()).find(a => a);
			const { stack } = new Error();
			Error.prepareStackTrace = undefined;
			stack.process
		`));
		assert.throws(()=>vm2.run(`(()=>{
			const OldError = Error;
			global.Error = {prepareStackTrace: (_, c) => c.map(c => c.getThis()).find(a => a && a.process)};
			const { stack } = new OldError();
			global.Error = OldError;
			return stack.process.mainModule;
		})()`));
	});

	it('Node internal prepareStackTrace attack', () => {
		const vm2 = new VM();

		assert.throws(()=>vm2.run(`
			function stack() {
				new Error().stack;
				stack();
			}
			try {
				stack();
			} catch (e) {
				e.constructor.constructor("return process")()
			}
		`), /process is not defined/);

	});

	it('Monkey patching attack', () => {
		const vm2 = new VM();
		assert.doesNotThrow(() => {
			const f = vm2.run(`
				function onget() {throw new Error();}
				function onset() {throw new Error();}
				const desc = {__proto__: null, get: onget, set: onset};
				Object.defineProperties(Object.prototype, {
					__proto__: null,
					'0': desc,
					get: desc,
					set: desc,
					apply: desc,
					call: desc,
					'1': desc,
					'length': desc,
				});
				Object.defineProperties(Function.prototype, {
					__proto__: null,
					call: desc,
					apply: desc,
					bind: desc,
				});
				function passer(a, b, c) {
					return a(b, c);
				}
			`);
			f((a, b) => b, {}, {});
		});
	});

	it('transformer attack', () => {
		const vm2 = new VM();

		assert.throws(()=>vm2.run(`
			aVM2_INTERNAL_TMPNAME = {};
			function stack() {
				new Error().stack;
				stack();
			}
			try {
				stack();
			} catch (a$tmpname) {
				a$tmpname.constructor.constructor('return process')();
			}
		`), /process is not defined/);
	});

	it('allow regular async functions', async () => {
		const vm2 = new VM();
		const promise = vm2.run(`(async () => 42)()`);
		assert.strictEqual(await promise, 42);
	});

	it('allow regular promises', async () => {
		const vm2 = new VM();
		const promise = vm2.run(`new Promise((resolve) => resolve(42))`);
		assert.strictEqual(await promise, 42);
	});

	it('[Symbol.species] attack', async () => {
		const vm2 = new VM();
		const promise = vm2.run(`
		async function fn() {
			throw new Error('random error');
		}
		const promise = fn();
		promise.constructor = {
			[Symbol.species]: class WrappedPromise {
				constructor(executor) {
					executor(() => 43, () => 44);
				}
			}
		};
		promise.then();
		`);
		assert.rejects(() => promise, /random error/);
	});

	it('constructor arbitrary code attack', async () => {
		const vm2 = new VM();
		assert.throws(()=>vm2.run(`
		const g = ({}).__lookupGetter__;
		const a = Buffer.apply;
		const p = a.apply(g, [Buffer, ['__proto__']]);
		p.call(a).constructor('return process')();
		`), /constructor is not a function/);
	});

	it('Promise.prototype.then/catch callback sanitization bypass', async () => {
		const vm2 = new VM();
		// This attack uses an Error with a Symbol name to trigger a host error
		// during stack trace computation, then tries to access host constructors
		// through the unsanitized error in the Promise catch callback.
		// If the error is not sanitized, e.constructor.constructor would be the
		// host's Function which can access 'process'. If sanitized, it's the
		// sandbox's Function where 'process' is not defined.
		await assert.rejects(() => vm2.run(`
			new Promise((resolve, reject) => {
				const error = new Error();
				error.name = Symbol();
				const f = async () => error.stack;
				f().catch(e => {
					try {
						const Error = e.constructor;
						const Function = Error.constructor;
						const p = Function('return process')();
						resolve(p);
					} catch (err) {
						reject(err);
					}
				});
			});
		`), /process is not defined/);
	});

	it('Symbol.for dangerous Node.js symbols isolation', () => {
		// Certain Node.js cross-realm symbols can be exploited for sandbox escapes:
		// - 'nodejs.util.inspect.custom': Called by util.inspect with host's inspect function
		// - 'nodejs.rejection': Called by EventEmitter on promise rejection
		//
		// Fix: These symbols return sandbox-local versions instead of cross-realm symbols,
		// so Node.js internals won't recognize sandbox-defined symbol properties.
		const vm2 = new VM();

		// These dangerous symbols should be isolated (sandbox gets different symbol than host)
		const dangerousSymbols = [
			'nodejs.util.inspect.custom',
			'nodejs.rejection'
		];

		for (const key of dangerousSymbols) {
			const hostSymbol = Symbol.for(key);
			const sandboxSymbol = vm2.run(`Symbol.for('${key}')`);

			assert.notStrictEqual(
				sandboxSymbol,
				hostSymbol,
				`Sandbox Symbol.for("${key}") should return a different symbol than host`
			);
		}

		// Other symbols should still work cross-realm (backwards compatibility)
		const safeSymbols = ['foo', 'bar', 'some.random.key'];
		for (const key of safeSymbols) {
			const hostSymbol = Symbol.for(key);
			const sandboxSymbol = vm2.run(`Symbol.for('${key}')`);

			assert.strictEqual(
				sandboxSymbol,
				hostSymbol,
				`Symbol.for("${key}") should still work cross-realm`
			);
		}
	});

	it('Symbol extraction via Object.getOwnPropertySymbols on host objects', () => {
		// The cross-realm symbol can be obtained from host objects like Buffer.prototype
		// via Object.getOwnPropertySymbols, bypassing the Symbol.for override entirely.
		const vm2 = new VM();

		// Attempt to extract the real cross-realm symbol from Buffer.prototype
		const extractedSymbol = vm2.run(`
			const symbols = Object.getOwnPropertySymbols(Buffer.prototype);
			symbols.find(s => s.description === 'nodejs.util.inspect.custom');
		`);

		assert.strictEqual(
			extractedSymbol,
			undefined,
			'Dangerous cross-realm symbols should be filtered from Object.getOwnPropertySymbols results'
		);

		// Also verify Reflect.ownKeys doesn't leak the real symbol
		const extractedViaReflect = vm2.run(`
			const keys = Reflect.ownKeys(Buffer.prototype);
			keys.find(k => typeof k === 'symbol' && k.description === 'nodejs.util.inspect.custom');
		`);

		assert.strictEqual(
			extractedViaReflect,
			undefined,
			'Dangerous cross-realm symbols should be filtered from Reflect.ownKeys results'
		);

		// Verify Array.prototype monkey-patching can't bypass the filter
		const vm3 = new VM();
		const extractedWithSplicePatch = vm3.run(`
			Array.prototype.splice = function() { /* no-op */ };
			const symbols2 = Object.getOwnPropertySymbols(Buffer.prototype);
			symbols2.find(s => typeof s === 'symbol' && s.description === 'nodejs.util.inspect.custom');
		`);

		assert.strictEqual(
			extractedWithSplicePatch,
			undefined,
			'Array.prototype.splice override should not bypass symbol filtering'
		);

		// Verify Object.getOwnPropertyDescriptors filters dangerous symbols from result
		const vm4 = new VM();
		const descs = vm4.run(`Object.getOwnPropertyDescriptors(Buffer.prototype)`);
		const hostInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

		assert.strictEqual(
			hostInspectSymbol in descs,
			false,
			'Object.getOwnPropertyDescriptors should not include dangerous symbol keys in result'
		);

		// Verify Object.assign doesn't copy dangerous symbol-keyed properties
		const vm5 = new VM();
		const assigned = vm5.run(`
			const target = {};
			Object.assign(target, Buffer.prototype);
			target;
		`);

		assert.strictEqual(
			hostInspectSymbol in assigned,
			false,
			'Object.assign should not copy dangerous symbol-keyed properties'
		);
	});

	it('Symbol extraction via spread operator on host objects', () => {
		// The spread operator {...obj} calls [[OwnPropertyKeys]] internally,
		// which invokes the proxy's ownKeys trap directly, bypassing any
		// Reflect.ownKeys override in the sandbox.
		const vm2 = new VM();
		const hostInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

		// Verify spread operator doesn't copy dangerous symbol-keyed properties
		const spread = vm2.run(`
			const spread = {...Buffer.prototype};
			spread;
		`);

		assert.strictEqual(
			hostInspectSymbol in spread,
			false,
			'Spread operator should not copy dangerous symbol-keyed properties from host objects'
		);

		// Verify the full attack doesn't work
		const vm3 = new VM();
		const attackResult = vm3.run(`
			const {...inspectDesc} = Buffer.prototype;
			for (const k in inspectDesc) delete inspectDesc[k];

			// If the dangerous symbol leaked, inspectDesc would have a symbol key
			// with a function value that Object.defineProperties would interpret
			let hasSymbolKey = false;
			const symbols = Object.getOwnPropertySymbols(inspectDesc);
			for (let i = 0; i < symbols.length; i++) {
				if (symbols[i].description === 'nodejs.util.inspect.custom') {
					hasSymbolKey = true;
				}
			}
			hasSymbolKey;
		`);

		assert.strictEqual(
			attackResult,
			false,
			'Dangerous symbol should not be extractable via spread operator'
		);
	});

	it('Function.prototype.call attack via Promise', async () => {
		const vm2 = new VM();
		// This attack attempts to override Function.prototype.call to capture
		// references to functions being called. If globalPromise.prototype.then
		// or .catch used .call() directly, an attacker could intercept and
		// access host objects through the captured function reference.
		// With the fix, Reflect.apply is used instead of .call(), so the
		// attacker's override is never triggered and nothing is captured.
		const result = await vm2.run(`
			new Promise((resolve) => {
				let captured = [];
				const origCall = Function.prototype.call;
				Function.prototype.call = function(...args) {
					captured.push(this.name || 'anonymous');
					return origCall.apply(this, args);
				};
				Promise.resolve().then(() => {
					resolve(captured);
				});
			});
		`);
		// With the fix, Promise.prototype.then should use Reflect.apply,
		// so Function.prototype.call should not be intercepted
		assert.strictEqual(result.length, 0, 'Function.prototype.call should not be intercepted by Promise.then');
	});

	it('Object.defineProperty override attack via Promise species', (done) => {
		const vm2 = new VM();
		// This attack overrides Object.defineProperty to prevent resetPromiseSpecies
		// from resetting the species, then uses a custom species to escape.
		// By setting e.name to a Symbol and accessing e.stack, a host-realm TypeError
		// is thrown (Symbol cannot be converted to string). This error is passed to
		// the FakePromise reject handler, where err.constructor.constructor gives
		// access to the host Function constructor.
		// The fix uses localReflectDefineProperty instead of Object.defineProperty.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			Object.defineProperty = () => {};
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			const p = fn();
			p.constructor = {
				[Symbol.species]: class FakePromise {
					constructor(executor) {
						executor(
							(x) => x,
							(err) => {
								try {
									const hostFunc = err.constructor.constructor;
									hostFunc('escapeMarker()')();
								} catch (e) {}
							}
						);
					}
				}
			};
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via Object.defineProperty override should be prevented');
			done();
		}, 100);
	});

	it('Frozen constructor attack via Promise species', (done) => {
		const vm2 = new VM();
		// This attack uses Object.freeze on the constructor to prevent resetPromiseSpecies
		// from resetting the species via defineProperty. Combined with the Symbol name trick
		// to trigger a host-realm error, this would allow escape if not properly handled.
		// The fix handles this by replacing p.constructor entirely when defineProperty fails.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			const p = fn();

			const fakeConstructor = Object.freeze({
				[Symbol.species]: class FakePromise {
					constructor(executor) {
						executor(
							(x) => x,
							(err) => {
								try { err.constructor.constructor('escapeMarker()')(); } catch(e) {}
							}
						);
					}
				}
			});
			p.constructor = fakeConstructor;
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via frozen constructor should be prevented');
			done();
		}, 100);
	});

	it('Constructor getter TOCTOU attack via Promise (non-configurable)', () => {
		const vm2 = new VM();
		// This attack defines a non-configurable getter on the promise's 'constructor'
		// property. The fix detects the accessor and throws before .then() can proceed.
		assert.throws(() => {
			vm2.run(`
				async function fn() {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}
				let first = true;
				p = fn();
				Object.defineProperty(p, 'constructor', {get(){
					if (first) {first = false; return Promise;}
					return {[Symbol.species]: class FakePromise {
							constructor(executor) {
								executor(
									(x) => x,
									(err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch pwned'); }
								)
							}
						}
					};
				}});
				p.then();
			`);
		}, /Unsafe Promise species cannot be reset/);
	});

	it('Constructor getter TOCTOU attack via Promise (configurable)', (done) => {
		const vm2 = new VM();
		// This attack defines a configurable getter on the promise's 'constructor'
		// property. The fix replaces it unconditionally with a safe value.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			let first = true;
			p = fn();
			Object.defineProperty(p, 'constructor', {configurable: true, get(){
				if (first) {first = false; return Promise;}
				return {[Symbol.species]: class FakePromise {
						constructor(executor) {
							executor(
								(x) => x,
								(err) => {
									try { err.constructor.constructor('escapeMarker()')(); } catch(e) {}
								}
							)
						}
					}
				};
			}});
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via constructor getter TOCTOU should be prevented');
			done();
		}, 100);
	});

	it('Constructor getter TOCTOU attack via Promise prototype', (done) => {
		const vm2 = new VM();
		// This attack tries to define a getter on globalPromise.prototype.constructor
		// (accessible via Object.getPrototypeOf(Promise.prototype)).
		// Prevented by freezing globalPromise.prototype so the defineProperty fails.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			const realProto = Object.getPrototypeOf(Promise.prototype);
			let first = true;
			try {
				Object.defineProperty(realProto, 'constructor', {configurable: true, get(){
					if (first) {first = false; return Promise;}
					return {[Symbol.species]: class FakePromise {
							constructor(executor) {
								executor(
									(x) => x,
									(err) => {
										try { err.constructor.constructor('escapeMarker()')(); } catch(e) {}
									}
								)
							}
						}
					};
				}});
			} catch(e) {}
			const p = fn();
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via prototype constructor getter TOCTOU should be prevented');
			done();
		}, 100);
	});

	it('Symbol.hasInstance override to bypass resetPromiseSpecies', (done) => {
		const vm2 = new VM();
		// This attack tries to override Symbol.hasInstance on globalPromise to
		// make the instanceof check fail, skipping resetPromiseSpecies entirely.
		// Prevented by freezing globalPromise.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			try {
				const GP = Object.getPrototypeOf(Promise);
				Object.defineProperty(GP, Symbol.hasInstance, {value: () => false, configurable: true});
			} catch(e) {}
			const p = fn();
			try {
				p.constructor = {
					[Symbol.species]: class FakePromise {
						constructor(executor) {
							executor(
								(x) => x,
								(err) => {
									try { err.constructor.constructor('escapeMarker()')(); } catch(e) {}
								}
							)
						}
					}
				};
			} catch(e) {}
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via Symbol.hasInstance override should be prevented');
			done();
		}, 100);
	});

	it('Symbol.species getter TOCTOU attack via Promise', (done) => {
		const vm2 = new VM();
		// This attack uses a Symbol.species getter that returns Promise on
		// the first read (to pass the safety check) but returns FakePromise
		// on subsequent reads (when V8 internally uses it). This is a TOCTOU
		// (Time-Of-Check-Time-Of-Use) bypass.
		let escaped = false;
		global.escapeMarker = () => { escaped = true; };

		vm2.run(`
			async function fn() {
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}
			let first = true;
			const p = fn();
			p.constructor = {
				get [Symbol.species](){
					if (first) {first = false; return Promise;}
					return class FakePromise {
						constructor(executor) {
							executor(
								(x) => x,
								(err) => {
									try { err.constructor.constructor('escapeMarker()')(); } catch(e) {}
								}
							)
						}
					}
				}
			};
			p.then();
		`);

		setTimeout(() => {
			delete global.escapeMarker;
			assert.strictEqual(escaped, false, 'Sandbox escape via Symbol.species getter TOCTOU should be prevented');
			done();
		}, 100);
	});

	it('Buffer.prototype.inspect handler exposure via showProxy attack', () => {
		// This attack duck-types an object where subarray is Buffer.prototype.inspect,
		// so that calling slice() actually calls inspect(). With showProxy:true in the
		// inspect options, the proxy handler's internal state could be exposed via the
		// seen array. Previously, handlers stored objectWrapper as an instance property
		// and had a getObject() method, allowing access to raw host objects.
		// The fix stores objects in a closure-scoped WeakMap with no public accessor.
		const vm2 = new VM();
		const attackResult = vm2.run(`
			const obj = {
				subarray: Buffer.prototype.inspect,
				slice: Buffer.prototype.slice,
				hexSlice:()=>'',
				l:{__proto__: null}
			};
			let escaped = false;
			try {
				obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
					// Try both objectWrapper (old vulnerability) and getObject (method that was left exposed)
					if (this.seen && this.seen[1] && this.seen[1].objectWrapper) {
						this.seen[1].objectWrapper().x = obj.slice;
						escaped = true;
					}
					if (this.seen && this.seen[1] && this.seen[1].getObject) {
						this.seen[1].getObject().x = obj.slice;
						escaped = true;
					}
					return a;
				}});
				if (obj.l.x) {
					escaped = true;
				}
			} catch (e) {
				// Expected: "Unexpected access to key '...'" or similar
			}
			escaped;
		`);
		assert.strictEqual(attackResult, false, 'Handler internals should not be exposed via showProxy');
	});

	// Promise.try is available in Node.js 24+
	// This is the ONLY Promise static method that is actually vulnerable because:
	// - Promise.try catches errors thrown by the callback INSIDE V8's Promise executor
	// - The error is passed directly to FakePromise's reject handler without bridge sanitization
	// - Other methods (all/race/any/allSettled) use .then() internally which IS sanitized
	// - Other methods (reject/withResolvers) receive errors from user catch blocks which ARE sanitized
	it.cond('Promise.try static method stealing attack', NODE_VERSION >= 24, (done) => {
		const vm2 = new VM({
			sandbox: {
				markEscape: () => { escaped = true; }
			}
		});
		// This attack steals Promise.try (a static method that uses `this` as constructor)
		// and assigns it to a FakePromise. When FakePromise.t() is called, Promise.try
		// uses FakePromise as the constructor, passing unsanitized errors to FakePromise's
		// executor reject handler.
		let escaped = false;

		vm2.run(`
			function FakePromise(executor) {
				executor(
					(x) => x,
					(err) => {
						// Try to access process via the error's constructor chain
						try {
							const proc = err.constructor.constructor('return process')();
							if (proc && proc.version) markEscape();
						} catch(e) {}
					}
				)
			}
			FakePromise.t = Promise.try;
			FakePromise.t(()=>{
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			});
		`);

		setTimeout(() => {
			assert.strictEqual(escaped, false, 'Sandbox escape via Promise.try static method stealing should be prevented');
			done();
		}, 100);
	});

	it('Promise.all static method stealing attack', (done) => {
		const vm2 = new VM({
			sandbox: {
				markEscape: () => { escaped = true; }
			}
		});
		// This attack steals Promise.all (a static method that uses `this` as constructor)
		// and assigns it to a FakePromise. When FakePromise.all() is called, Promise.all
		// uses FakePromise as the constructor. During iteration, if an error occurs
		// (e.g., from accessing error.stack with error.name = Symbol()), that error is
		// passed directly to FakePromise's executor reject handler.
		let escaped = false;

		vm2.run(`
			function FakePromise(executor) {
				executor(
					(x) => x,
					(err) => {
						// Try to access process via the error's constructor chain
						try {
							const proc = err.constructor.constructor('return process')();
							if (proc && proc.version) markEscape();
						} catch(e) {}
					}
				)
			}
			FakePromise.all = Promise.all;
			FakePromise.resolve = () => {};
			try {
				FakePromise.all({[Symbol.iterator]: () => {
					const e = new Error();
					e.name = Symbol();
					return e.stack;
				}});
			} catch(e) {}
		`);

		setTimeout(() => {
			assert.strictEqual(escaped, false, 'Sandbox escape via Promise.all static method stealing should be prevented');
			done();
		}, 100);
	});

	it('Reflect.construct Promise species bypass attack', (done) => {
		// This attack uses Reflect.construct(Promise, [...], FakePromise) to create
		// a real Promise whose prototype is FakePromise.prototype (not Promise.prototype).
		// This bypassed the previous 'instanceof globalPromise' check in resetPromiseSpecies.
		let escaped = false;
		const vm2 = new VM({
			sandbox: {
				markEscape: () => { escaped = true; }
			}
		});
		vm2.run(`
			function FakePromise(executor) {
				executor(
					(x) => x,
					(err) => {
						try {
							const proc = err.constructor.constructor('return process')();
							if (proc && proc.version) markEscape();
						} catch(e) {}
					}
				)
			}
			FakePromise[Symbol.species] = FakePromise;

			const res = Reflect.construct(Promise, [()=>{
				const e = new Error();
				e.name = Symbol();
				return e.stack;
			}], FakePromise);
			res.then = Promise.prototype.then;
			res.then();
		`);

		setTimeout(() => {
			assert.strictEqual(escaped, false, 'Sandbox escape via Reflect.construct Promise species bypass should be prevented');
			done();
		}, 100);
	});

	after(() => {
		vm = null;
	});
});

describe('precompiled scripts', () => {
	it('VM', () => {
		const vm = new VM();
		const script = new VMScript('global.i=global.i||0;global.i++');
		const val1 = vm.run(script);
		const val2 = vm.run(script);
		const failScript = new VMScript('(');
		assert.ok('number' === typeof val1 && 'number' === typeof val2);
		assert.ok( val1 === 0 && val2 === 1);
		assert.throws(() => failScript.compile(), /SyntaxError/);
		assert.ok(Object.keys(failScript).includes('code'));
		assert.ok(Object.keys(failScript).includes('filename'));
		assert.ok(Object.keys(failScript).includes('compiler'));
		assert.ok(!Object.keys(failScript).includes('_code'));
	});
});

describe('freeze, protect', () => {
	it('without freeze', () => {
		const x = {
			a: () => 'a',
			b: () => 'b',
			c: {
				d: () => 'd'
			}
		};

		const vm = new VM({
			sandbox: {x}
		});
		vm.run('x.a = () => { return `-` }; x.c.d = () => { return `---` }; (y) => { y.b = () => { return `--` } }')(x);

		assert.strictEqual(x.a(), '-');
		assert.strictEqual(x.b(), '--');
		assert.strictEqual(x.c.d(), '---');
	});

	it('with freeze', () => {
		const x = {
			a: () => 'a',
			b: () => 'b',
			c: {
				d: () => 'd'
			}
		};

		const vm = new VM();
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

		// Extension of frozen objects should be writeable.
		assert.strictEqual(vm.run('y = Object.create(x); y.f = 1; y.f'), 1);
	});

	it('without protect', () => {
		const vm = new VM(); const obj = {};
		vm.run('(i) => { i.text = "test" }')(obj);
		vm.run('(i) => { i.func = () => {} }')(obj);
		vm.run('(i) => { delete i.func }')(obj);
	});

	it('with protect', () => {
		const vm = new VM(); const obj = {
			date: new Date(),
			array: [{}, {}]
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

		assert.throws(() => {
			vm.run('"use strict"; (i) => { Object.defineProperty(i, "toString", { get(){ return () => \'Not protected\'; } }) }')(obj);
		});

		assert.strictEqual(vm.run('(i) => i.array.map(item => 1).join(",")')(obj), '1,1');
		assert.strictEqual(vm.run('(i) => /x/.test(i.date)')(obj), false);
	});
});
