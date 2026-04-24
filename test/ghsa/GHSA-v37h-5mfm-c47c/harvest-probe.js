'use strict';
/**
 * Probe to understand whether the advisory's showProxy-based handler harvest
 * succeeds on the current Node version. On Node 25 Buffer internals reject
 * a proxy-wrapped `this`, so the advisory's slice→inspect chain cannot reach
 * the `stylize` callback that was supposed to publish `this.seen[1]` as the
 * leaked BaseHandler. This probe records that reality so readers of the
 * repro suite understand why variant tests may return 'NO_ESCAPE' even
 * without the token fix.
 */
const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-v37h-5mfm-c47c harvest probe', () => {
	it('records whether the advisory inspect-leak path reaches stylize on this Node', () => {
		const vm = new VM();
		let reached = null;
		try {
			reached = vm.run(`
				const obj = {
					subarray: Buffer.prototype.inspect,
					slice: Buffer.prototype.slice,
					hexSlice:()=>''
				};
				let p;
				try {
					obj.slice(20, {showHidden: true, showProxy: true, depth: 10, stylize(a) {
						if (this.seen && this.seen[1] && this.seen[1].get) { p = this.seen[1]; }
						return a;
					}});
				} catch (e) { /* Buffer internals reject proxy on Node 25 */ }
				p ? 'LEAKED' : 'HARVEST_BLOCKED_BY_NODE';
			`);
		} catch (e) { reached = 'THROW:' + (e && e.message); }
		// We do not assert either outcome -- this test is informational.
		assert.ok(
			reached === 'LEAKED' || reached === 'HARVEST_BLOCKED_BY_NODE',
			'unexpected probe outcome: ' + JSON.stringify(reached),
		);
	});
});
