'use strict';

const assert = require('assert');
const {VM, NodeVM, VMScript} = require('..');

global.isHost = true;

// TypeScript >= 7 has no transpileModule() in its package entry point, so the
// built-in TypeScript compiler cannot work there at all. Probe the capability
// rather than the version number, and skip the transpile case when it is absent
// -- the dedicated 'incompatible TypeScript' block below covers that path.
const TS_CAN_TRANSPILE = (() => {
	try {
		const ts = require('typescript');
		return typeof ts.transpileModule === 'function' && !!ts.ModuleKind;
	} catch (e) {
		return false;
	}
})();

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('Compilers', () => {
	it.cond('run TypeScript', TS_CAN_TRANSPILE, () => {
		const vm = new VM();
		const script = new VMScript('1 as number', {
			compiler: 'typescript'
		});
		const val = vm.run(script);
		assert.strictEqual(val, 1);
	});

	it('run CoffeeScript', () => {
		const vm = new NodeVM({
			require: {
				external: true
			},
			compiler: 'coffeescript'
		});

		assert.equal(vm.run('module.exports = working: true').working, true);
	});

	// TypeScript 7 removed transpileModule() / ModuleKind from the package entry
	// point (they moved behind the unstable `typescript/unstable/*` subpaths, which
	// provide no single-file transpile equivalent). `require('typescript')` still
	// succeeds there, so the failure used to surface as an opaque TypeError at
	// compile time. These tests pin the fail-fast behaviour by swapping the cached
	// module for a 7.x-shaped stub.
	describe('incompatible TypeScript', () => {
		const tsPath = require.resolve('typescript');
		let saved;

		beforeEach(() => {
			saved = require.cache[tsPath];
			require.cache[tsPath] = Object.assign(Object.create(Object.getPrototypeOf(saved)), saved, {
				exports: {version: '7.0.2', versionMajorMinor: '7.0'},
			});
		});

		afterEach(() => {
			require.cache[tsPath] = saved;
		});

		it('fails at construction, not at compile time', () => {
			assert.throws(
				() => new VMScript('1 as number', {compiler: 'typescript'}),
				/does not expose the transpileModule\(\) API/,
			);
		});

		it('reports the offending version and the escape hatch', () => {
			assert.throws(() => new VMScript('1 as number', {compiler: 'typescript'}), (e) => {
				assert.ok(/7\.0\.2/.test(e.message), 'names the installed version: ' + e.message);
				assert.ok(/typescript@6/.test(e.message), 'names a working version: ' + e.message);
				assert.ok(/compiler:/.test(e.message), 'points at the custom-compiler escape hatch: ' + e.message);
				return true;
			});
		});

		it('a custom compiler function still works when typescript is unusable', () => {
			const script = new VMScript('1 as number', {
				compiler: (code) => code.replace(' as number', ''),
			});
			assert.strictEqual(new VM().run(script), 1);
		});
	});
});
