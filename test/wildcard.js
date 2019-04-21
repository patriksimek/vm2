/* eslint-env mocha */

const {match} = require('../lib/wildcard');
const assert = require('assert');

describe('wildcard matching', () => {
	it('handles * correctly', () => {
		assert.strictEqual(match('some*g', 'something'), true);
	});

	it('handles ? correctly', () => {
		assert.strictEqual(match('someth??g', 'something'), true);
	});
});
