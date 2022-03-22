/* eslint-env mocha */
/* eslint-disable no-new-wrappers, max-len */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const {EventEmitter} = require('events');
const {NodeVM, VMScript} = require('..');
// const NODE_VERSION = parseInt(process.versions.node.split('.')[0]);

global.isHost = true;

describe('NodeVM', () => {
	let vm;

	const customArgv = [];
	const customEnv = {};

	before(() => {
		vm = new NodeVM({
			argv: customArgv,
			env: customEnv
		});
	});

	it('globals', () => {
		const ex = vm.run('module.exports = global');
		assert.equal(ex.isHost, undefined);
	});

	it('options', ()=>{
		const vmProcess = vm.run('module.exports = process');
		assert.equal(vmProcess.argv, customArgv);
		assert.equal(vmProcess.env, customEnv);
	});

	it('errors', () => {
		assert.throws(() => vm.run('notdefined'), /notdefined is not defined/);
	});

	it('prevent global access', () => {
		assert.throws(() => vm.run('process.exit()'), /(undefined is not a function|process\.exit is not a function)/);
	});

	it('arguments attack', () => {
		assert.strictEqual(vm.run('module.exports = (function() { return arguments.callee.caller.constructor === Function; })()'), true);
		assert.throws(() => vm.run('module.exports = (function() { return arguments.callee.caller.caller.toString(); })()'), /Cannot read propert.*toString/);
	});

	it('global attack', () => {
		assert.equal(vm.run("module.exports = console.log.constructor('return (function(){return this})().isHost')()"), undefined);
	});

	it('shebang', () => {
		assert.doesNotThrow(() => vm.run('#!shebang'));
	});

	it('strict', () => {
		assert.doesNotThrow(() => vm.run('newGlobal = 2;'));
		assert.throws(() => new NodeVM({strict: true}).run('newGlobal = 2;'), /ReferenceError: newGlobal is not defined/);
	});

	it.skip('timeout (not supported by Node\'s VM)', () => {
		assert.throws(() => new NodeVM({
			timeout: 10
		}).run('while (true) {}'), /Script execution timed out\./);
	});

	after(() => {
		vm = null;
	});
});

describe('modules', () => {
	it('require json', () => {
		const vm = new NodeVM({
			require: {
				external: true,
				context: 'sandbox'
			}
		});

		assert.equal(vm.run(`module.exports = require('./data/json.json')`, `${__dirname}/vm.js`).working, true);
	});

	it.skip('run coffee-script', () => {
		const vm = new NodeVM({
			require: {
				external: true
			},
			compiler: 'coffeescript'
		});

		assert.equal(vm.run('module.exports = working: true').working, true);
	});

	it('optionally can run a custom compiler function', () => {
		let ranCustomCompiler = false;
		const scriptCode = 'var a = 1;';
		const vm = new NodeVM({
			compiler: (code) => {
				ranCustomCompiler = true;
				assert.equal(code, scriptCode);
			}
		});
		vm.run(scriptCode);
		assert.equal(ranCustomCompiler, true);
	});

	it('optionally passes a filename to a custom compiler function', () => {
		let ranCustomCompiler = false;
		const vm = new NodeVM({
			compiler: (code, filename) => {
				ranCustomCompiler = true;
				assert.equal(filename, '/a/b/c.js');
			}
		});
		vm.run('module.exports = working: true', '/a/b/c.js');
		assert.equal(ranCustomCompiler, true);
	});

	it('disabled require', () => {
		const vm = new NodeVM;

		assert.throws(() => vm.run("require('fs')"), /Cannot find module 'fs'/);
	});

	it('disable setters on builtin modules', () => {
		const vm = new NodeVM({
			require: {
				builtin: ['fs']
			}
		});

		vm.run("require('fs').readFileSync = undefined");
		assert.strictEqual(fs.readFileSync instanceof Function, true);

		vm.run("require('fs').readFileSync.thisPropertyShouldntBeThere = true");
		assert.strictEqual(fs.readFileSync.thisPropertyShouldntBeThere, undefined);

		assert.throws(() => vm.run("Object.defineProperty(require('fs'), 'test', {})"), err => {
			assert.ok(err instanceof TypeError);
			assert.equal(err.name, 'TypeError');
			assert.equal(err.message, '\'defineProperty\' on proxy: trap returned falsish for property \'test\'');
			return true;
		});

		assert.throws(() => vm.run("'use strict'; delete require('fs').readFileSync"), err => {
			assert.ok(err instanceof TypeError);
			assert.equal(err.name, 'TypeError');
			assert.equal(err.message, '\'deleteProperty\' on proxy: trap returned falsish for property \'readFileSync\'');
			return true;
		});
	});

	it('enabled require for certain modules', () => {
		const vm = new NodeVM({
			require: {
				builtin: ['fs']
			}
		});

		assert.doesNotThrow(() => vm.run("require('fs')"));
	});

	it('require relative', () => {
		const vm = new NodeVM({
			require: {
				external: true
			},
		});

		vm.run("require('foobar')", __filename);
	});

	it('can require a module inside the vm', () => {
		const vm = new NodeVM({
			require: {
				external: true
			}
		});

		vm.run("require('mocha')", __filename);
	});

	it('can deny requiring modules inside the vm', () => {
		const vm = new NodeVM({
			require: {
				external: false
			},
		});

		assert.throws(() => vm.run("require('mocha')", __filename), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, 'Cannot find module \'mocha\'');
			return true;
		});
	});

	it('can whitelist modules inside the vm', () => {
		const vm = new NodeVM({
			require: {
				external: ['mocha']
			}
		});

		assert.ok(vm.run("require('mocha')", __filename));
		assert.throws(() => vm.run("require('unknown')", __filename), err => {
			assert.equal(err.name, 'VMError');
			assert.equal(err.message, "Cannot find module 'unknown'");
			return true;
		});
	});

	it('allows specific transitive external dependencies in sandbox context', () => {
		const vm = new NodeVM({
			require: {
				external: {
					modules: ['module1'],
					transitive: true
				},
				context: 'sandbox'
			}
		});

		assert.ok(vm.run("require('module1')", __filename));
	});

	it('can resolve paths based on a custom resolver', () => {
		const vm = new NodeVM({
			require: {
				external: ['my-module'],
				resolve: moduleName => path.resolve(__dirname, 'additional-modules', moduleName)
			}
		});

		assert.ok(vm.run("require('my-module')", __filename));
	});

	it('allows for multiple root folders', () => {
		const vm = new NodeVM({
			require: {
				external: ['mocha'],
				root: [
					path.resolve(__dirname),
					path.resolve(__dirname, '..', 'node_modules')
				]
			}
		});

		assert.ok(vm.run("require('mocha')", __filename));
	});

	it('falls back to index.js if the file specified in the package.json "main" attribute is missing', () => {
		const vm = new NodeVM({
			require: {
				external: true
			}
		});

		assert.equal(vm.run("module.exports = require('module-with-wrong-main').bar()", __filename), 1);
	});

	it('attempts to add extension if the file specified in the package.json "main" attribute is missing', () => {
		const vm = new NodeVM({
			require: {
				external: true
			}
		});

		assert.equal(vm.run("module.exports = require('module-main-without-extension').bar()", __filename), 1);
	});

	it('module with exports', () => {
		const vm = new NodeVM({
			require: {
				external: [
					'with-exports'
				]
			}
		});

		assert.strictEqual(vm.run("module.exports = require('with-exports')", __filename).ok, true);

	});

	it('whitelist check before custom resolver', () => {
		const vm = new NodeVM({
			require: {
				external: [],
				resolve: () => {
					throw new Error('Unexpected');
				},
			},
		});

		assert.throws(() => vm.run("require('mocha')", __filename), /Cannot find module 'mocha'/);
	});

	it('root path checking', () => {
		const vm = new NodeVM({
			require: {
				external: true,
				root: `${__dirname}/node_modules/module`
			},
		});

		assert.throws(() => vm.run("require('module2')", __filename), /Cannot find module 'module2'/);
	});

	it('relative require not allowed to enter node modules', () => {
		const vm = new NodeVM({
			require: {
				external: ['mocha'],
				root: `${__dirname}`
			},
		});

		assert.throws(() => vm.run("require('./node_modules/module2')", __filename), /Cannot find module '\.\/node_modules\/module2'/);
	});

	it('outer require', () => {
		const vm = new NodeVM({
			require: {
				external: [],
				context: 'sandbox',
				root: `${__dirname}`
			},
		});
		assert.strictEqual(vm.require(`${__dirname}/data/json.json`).working, true);
		assert.strictEqual(vm.require(`${__dirname}/additional-modules/my-module`).additional_module, true);
	});

	it('arguments attack', () => {
		let vm = new NodeVM;

		assert.throws(() => vm.run('module.exports = function fce(msg) { return arguments.callee.caller.toString(); }')(), /Cannot read propert.*toString/);

		vm = new NodeVM;

		assert.throws(() => vm.run('module.exports = function fce(msg) { return fce.caller.toString(); }')(), /Cannot read propert.*toString/);
	});

	it('builtin module arguments attack', done => {
		const vm = new NodeVM({
			require: {
				builtin: ['fs']
			},
			sandbox: {
				parentfilename: __filename,
				done
			}
		});

		vm.run("var fs = require('fs'); fs.exists(parentfilename, function() {try {arguments.callee.caller.toString()} catch (err) {return done();}; done(new Error('Missing expected exception'))})");
	});

	it('path attack', () => {
		const vm = new NodeVM({
			require: {
				external: true,
				root: __dirname
			}
		});

		assert.throws(() => vm.run("var test = require('../package.json')", __filename), /Cannot find module '\.\.\/package.json'/);
	});

	it('process events', () => {
		const vm = new NodeVM({
			sandbox: {
				VM2_COUNTER: 0
			}
		});

		const sandbox = vm.run("global.VM2_HANDLER = function() { VM2_COUNTER++ }; process.on('exit', VM2_HANDLER); module.exports = global;");
		process.emit('exit');
		assert.strictEqual(sandbox.VM2_COUNTER, 1);
		assert.strictEqual(vm.run("module.exports = process.listeners('exit')[0] === VM2_HANDLER;"), true);
		vm.run("process.removeListener('exit', VM2_HANDLER);");
		process.emit('exit');
		assert.strictEqual(sandbox.VM2_COUNTER, 1);

		process.on('exit', () => {}); // Attach event in host
		assert.strictEqual(process.listeners('exit').length, 1); // Sandbox must only see it's own handlers

		const vmm = new NodeVM({});
		assert.strictEqual(vmm.run("module.exports = process.listeners('exit')").length, 0); // Listeners must not be visible cross-sandbox
	});

	it('timers #1', done => {
		const vm = new NodeVM({
			sandbox: {
				done
			}
		});

		vm.run('let i = setImmediate(function() { global.TICK = true; });clearImmediate(i);');

		setImmediate(() => {
			assert.strictEqual(vm.run('module.exports = global.TICK'), void 0);
			vm.run('setImmediate(done);');
		});
	});

	it('timers #2', done => {
		const start = Date.now();
		const vm = new NodeVM({
			sandbox: {
				done: (arg) => {
					assert.strictEqual(arg, 1337);
					assert.ok(Date.now() - start >= 200);
					done();
				}
			}
		});

		vm.run('setTimeout((arg) => done(arg), 200, 1337);');
	});

	it('mock', () => {
		const vm = new NodeVM({
			require: {
				mock: {
					fs: {
						readFileSync() {
							return 'Nice try!';
						}
					}
				}
			}
		});

		assert.strictEqual(vm.run("module.exports = require('fs').constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("module.exports = require('fs').readFileSync.constructor.constructor === Function"), true);
		assert.strictEqual(vm.run("module.exports = require('fs').readFileSync()"), 'Nice try!');
	});

	it('missing contextify attack', () => {
		const vm = new NodeVM();

		// https://github.com/patriksimek/vm2/issues/276
		assert.strictEqual(vm.run('const timeout = setTimeout(()=>{});module.exports = !timeout.ref || timeout.ref().constructor.constructor === Function'), true);

		// https://github.com/patriksimek/vm2/issues/285
		assert.strictEqual(vm.run(`try {
			process.listeners({toString(){return {};}});
			module.exports = true;
		  } catch(e) {
			module.exports = e.constructor.constructor === Function;
		  }`), true);

	});

	it('native event emitter', () => {
		const vm = new NodeVM({
			require: {
				builtin: ['events']
			}
		});

		assert.ok(vm.run(`const {EventEmitter} = require('events'); const ee = new EventEmitter(); let tr; ee.on('test', ()=>{tr = true;}); ee.emit('test'); return tr`, {wrapper: 'none'}));
		assert.ok(vm.run('const {EventEmitter} = require("events"); return new EventEmitter()', {wrapper: 'none'}) instanceof EventEmitter);
		assert.ok(vm.run('return nei => nei instanceof require("events").EventEmitter', {wrapper: 'none'})(new EventEmitter()));
		assert.ok(vm.run(`
		const {EventEmitter} = require('events');
		class EEE extends EventEmitter {
			test() {return true;}
		}
		return new EEE().test();
		`, {wrapper: 'none'}));

	});

	it('cache modules', () => {
		const vm = new NodeVM({
			require: {
				context: 'sandbox',
				external: ['module1', 'module2', 'require'],
				builtin: ['*']
			}
		});
		assert.ok(vm.run('return require("module1") === require("module2")', {filename: `${__dirname}/vm.js`, wrapper: 'none'}));
		assert.ok(vm.run('return require("require").require("fs") === require("fs")', {filename: `${__dirname}/vm.js`, wrapper: 'none'}));
		assert.ok(vm.run('return require("require").require("buffer") === require("buffer")', {filename: `${__dirname}/vm.js`, wrapper: 'none'}));
		assert.ok(vm.run('return require("require").require("util") === require("util")', {filename: `${__dirname}/vm.js`, wrapper: 'none'}));
	});

	it('strict module name checks', () => {
		const vm = new NodeVM({
			require: {
				external: ['module']
			}
		});
		assert.throws(()=>vm.run('require("module1")', `${__dirname}/vm.js`), /Cannot find module 'module1'/);
	});

	it('module name globs', () => {
		const vm = new NodeVM({
			require: {
				external: ['mo?ule1', 'm*e2']
			}
		});
		assert.doesNotThrow(()=>vm.run('require("module1");require("module2")', `${__dirname}/vm.js`));
	});

	it('module name glob escape', () => {
		const vm = new NodeVM({
			require: {
				external: ['module1*']
			}
		});
		assert.throws(()=>vm.run('require("module1/../module2")', `${__dirname}/vm.js`), /Cannot find module 'module1\/..\/module2'/);
	});

});

describe('nesting', () => {
	it('NodeVM', () => {
		const vm = new NodeVM({
			nesting: true
		});

		const nestedObject = vm.run(`
			const {VM} = require('vm2');
			const vm = new VM();
			let o = vm.run('({})');
			module.exports = o;
		`, 'vm.js');

		assert.strictEqual(nestedObject.constructor.constructor === Function, true);
	});
});

describe('wrappers', () => {
	it('none', () => {
		const vm = new NodeVM({
			wrapper: 'none'
		});

		assert.strictEqual(vm.run('return 2 + 2'), 4);
	});
});

describe('precompiled scripts', () => {
	it('NodeVM', () => {
		const vm = new NodeVM();
		const script = new VMScript('module.exports = Math.random()');
		const val1 = vm.run(script);
		const val2 = vm.run(script);
		assert.ok('number' === typeof val1 && 'number' === typeof val2);
		assert.ok( val1 != val2);
	});
	it('VMScript options', () => {
		const vm = new NodeVM();
		// V8 Stack Trace API: https://v8.dev/docs/stack-trace-api
		const code = `module.exports = getStack(new Error());
function customPrepareStackTrace(error, structuredStackTrace) {
  return {
    fileName: structuredStackTrace[0].getFileName(),
    lineNumber: structuredStackTrace[0].getLineNumber(),
    columnNumber: structuredStackTrace[0].getColumnNumber()
  };
};
function getStack(error) {
  var original = Error.prepareStackTrace;
  Error.prepareStackTrace = customPrepareStackTrace;
  Error.captureStackTrace(error, getStack);
  var stack = error.stack;
  Error.prepareStackTrace = original;
  return stack;
}`;
		const script = new VMScript(code, 'test.js', {
			lineOffset: 10,
			columnOffset: 20
		});
		const stack = vm.run(script);
		assert.strictEqual(stack.fileName, 'test.js');
		// line number start with 1
		assert.strictEqual(stack.lineNumber, 10 + 1);
		// column number start with 0
		// columnNumber was move just a tad to the right.
		// because, vmScript wrap the code for commonjs
		// Note: columnNumber option affect only the first line of the script
		// https://github.com/nodejs/node/issues/26780
		assert.ok(stack.columnNumber > (code.indexOf('new Error') + 20));

	});
});

describe('source extensions', () => {
	it('does not find a TS module with the default settings', () => {
		const vm = new NodeVM({
			require: {
				external: true
			}
		});
		assert.throws(() => {
			vm.run("require('./data/custom_extension')", __filename);
		});
	});

	it('finds a TS module with source extensions set', () => {
		const vm = new NodeVM({
			require: {
				external: true
			},
			sourceExtensions: ['ts', 'js']
		});

		vm.run("require('./data/custom_extension')", __filename);
	});
});
