/* eslint-env mocha */
/* eslint-disable no-new-wrappers, max-len */

'use strict';

const assert = require('assert');
const {VM, VMScript} = require('..');
const {INTERNAL_STATE_NAME} = require('../lib/transformer');
const NODE_VERSION = parseInt(process.versions.node.split('.')[0]);
const {inspect} = require('util');

global.isHost = true;

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
			Object.setPrototypeOf(prop, null);
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
	it('inspect', () => {
		assert.throws(() => inspect(doubleProxy), /Expected/);
		assert.doesNotThrow(() => inspect(vm.run('({})'), {showProxy: true, customInspect: true}));
		if (NODE_VERSION !== 10 && false) {
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

	if (NODE_VERSION >= 10) {
		it('eval/wasm', () => {
			assert.equal(vm.run('eval("1")'), 1);

			const vm2 = new VM({eval: false});
			assert.throws(() => vm2.run('eval("1")'), /Code generation from strings disallowed for this context/);
		});
	}

	if (NODE_VERSION > 7) {
		// Node until 7 had no async, see https://node.green/
		it('async', () => {
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
	}

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
		`), /process is not defined/, '#2');

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
		`), /Cannot read propert.*mainModule/, '#3');

		vm2 = new VM();

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
		`), /process is not defined/, '#1');
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

	it('Proxy::getOwnPropertyDescriptor attack', () => {
		// https://github.com/patriksimek/vm2/issues/178#issuecomment-450978210

		const vm2 = new VM();

		assert.throws(() => vm2.run(`
			(function(){
				try{
					Buffer.from(new Proxy({}, {
						getOwnPropertyDescriptor(){
							throw f=>f.constructor("return process")();
						}
					}));
				}catch(e){
					return e(()=>{}).mainModule.require("child_process").execSync("whoami").toString();
				}
			})()
		`), /process is not defined/);
	});

	if (NODE_VERSION >= 10) {
		it('Dynamic import attack', () => {

			const vm2 = new VM();

			assert.throws(()=>vm2.run(`
				const process = import('oops!').constructor.constructor('return process')();
			`), /VMError: Dynamic Import not supported/);
		});
	}

	it('Error.prepareStackTrace attack', () => {
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
