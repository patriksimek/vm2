/* eslint-env mocha */

const {match} = require('../lib/helpers');
const assert = require('assert');

describe('wildcard matching', () => {
	it('handles * correctly', () => {
		assert.strictEqual(match('s*th*g', 'something'), true);
	});

	it('handles ? correctly', () => {
		assert.strictEqual(match('someth??g', 'something'), true);
	});
});
