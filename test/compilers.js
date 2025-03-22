'use strict';

const assert = require('assert');
const {VM, NodeVM, VMScript} = require('..');

global.isHost = true;

describe('Compilers', () => {
	it('run TypeScript', () => {
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
});