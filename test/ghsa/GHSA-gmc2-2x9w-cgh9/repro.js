'use strict';

/**
 * GHSA-gmc2-2x9w-cgh9 — bufferAllocLimit bypass via Buffer.concat and
 * Buffer.from(arrayLike).
 *
 * ## Vulnerability
 * The 3.11.0 `bufferAllocLimit` cap (GHSA-6785-pvv7-mvg7, Category 23) wrapped
 * `Buffer.alloc`, `Buffer.allocUnsafe`, `Buffer.allocUnsafeSlow`, and the
 * deprecated `Buffer(N)` / `new Buffer(N)` forms. Two other paths into the
 * same host C++ allocator were left uncapped:
 *
 *   1. `Buffer.concat(list, totalLength)` — Node internally calls
 *      `Buffer.allocUnsafe(totalLength)` *before* iterating the list. The
 *      sandbox-visible `Buffer.concat` is a bridge proxy of the host method,
 *      so the host allocator is reached without consulting the sandbox-side
 *      `allocUnsafe` wrapper.
 *   2. `Buffer.from(arrayLike)` with a fake `length` — `{length: N}` triggers
 *      Node's `fromArrayLike`, which allocates an N-byte buffer up-front,
 *      then iterates indices 0..N. No real array of length N has to exist.
 *
 * Either path lets sandbox code amplify a small payload into hundreds of MB
 * of host RSS in a single synchronous C++ call — the exact DoS class the
 * `bufferAllocLimit` opt-in was designed to prevent.
 *
 * ## Fix
 * Sandbox-side wrappers for both APIs in lib/setup-sandbox.js, registered via
 * `connect()` so the canonical sandbox `Buffer.concat` and `Buffer.from` route
 * through `checkBufferAllocLimit` before any host call.
 */

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Tests that actually allocate ≥8 MB crash older Node runtimes whose default
// heap is tighter; gate them to Node 12+.
const LARGE_ALLOC_RUNS = NODE_MAJOR >= 12;

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-gmc2-2x9w-cgh9 (bufferAllocLimit bypass: concat + from arrayLike)', function () {
	const CAP = 32 * 1024 * 1024;

	describe('Buffer.concat(list, totalLength)', function () {
		it('configured cap rejects Buffer.concat([], 100 MB)', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('Buffer.concat([Buffer.from("a")], 100 * 1024 * 1024)');
			}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
		});

		it('small cap rejects 50 MB totalLength', function () {
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('Buffer.concat([Buffer.from("a")], 50 * 1024 * 1024).length');
			}, /Buffer allocation size 52428800 exceeds bufferAllocLimit 1024/);
		});

		it('NodeVM enforces bufferAllocLimit on Buffer.concat', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = Buffer.concat([Buffer.from("a")], 50 * 1024 * 1024).length');
			}, /Buffer allocation size 52428800 exceeds bufferAllocLimit 1024/);
		});

		// When no totalLength is given, Node sums actual list lengths. The cap
		// must still apply to the sum so an attacker cannot pre-stage large
		// buffers under separate small-allocation calls and concat them.
		it('cap rejects oversized sum even without explicit totalLength', function () {
			// Construct a list whose summed length exceeds the cap, but each
			// member is small enough to pass the per-call cap. The summed
			// allocation in concat still has to be capped.
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run(`
					const a = Buffer.alloc(512);
					const b = Buffer.alloc(512);
					const c = Buffer.alloc(512);
					Buffer.concat([a, b, c]);
				`);
			}, /Buffer allocation size 1536 exceeds bufferAllocLimit 1024/);
		});

		it('legitimate small Buffer.concat still works', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run(
				'Buffer.concat([Buffer.from("hello"), Buffer.from(" world")]).toString()'
			);
			assert.strictEqual(r, 'hello world');
		});

		it('Buffer.concat with explicit small totalLength works', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run(
				'Buffer.concat([Buffer.from("hello world")], 5).toString()'
			);
			assert.strictEqual(r, 'hello');
		});

		it('default (Infinity) bufferAllocLimit leaves Buffer.concat unrestricted', function () {
			const r = new VM().run('Buffer.concat([Buffer.from("a"), Buffer.from("b")]).toString()');
			assert.strictEqual(r, 'ab');
		});
	});

	describe('Buffer.from(arrayLike)', function () {
		it('configured cap rejects Buffer.from({length: 100 MB})', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('Buffer.from({length: 100 * 1024 * 1024})');
			}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
		});

		it('small cap rejects 8 MB arrayLike length', function () {
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('Buffer.from({length: 8 * 1024 * 1024})');
			}, /Buffer allocation size 8388608 exceeds bufferAllocLimit 1024/);
		});

		it('NodeVM enforces bufferAllocLimit on Buffer.from arrayLike', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = Buffer.from({length: 8 * 1024 * 1024})');
			}, /Buffer allocation size 8388608 exceeds bufferAllocLimit 1024/);
		});

		// Buffer.from(realArray) — same path as arrayLike but the array itself
		// already had to be allocated, so the cap should still apply to that
		// length to prevent the allocator from materializing N host bytes.
		it('cap applies to real arrays too', function () {
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('Buffer.from(new Array(2048))');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});

		it('legitimate Buffer.from(string) still works', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run("Buffer.from('hello').length");
			assert.strictEqual(r, 5);
		});

		it('legitimate Buffer.from(Buffer) still works (clone)', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run(
				'Buffer.from(Buffer.from("hello")).toString()'
			);
			assert.strictEqual(r, 'hello');
		});

		it('legitimate Buffer.from(Uint8Array) still works', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run(
				'Buffer.from(new Uint8Array([104, 105])).toString()'
			);
			assert.strictEqual(r, 'hi');
		});

		it('legitimate small Buffer.from(arrayLike) works', function () {
			const r = new VM({ bufferAllocLimit: CAP }).run(
				'Buffer.from({length: 4, 0: 1, 1: 2, 2: 3, 3: 4}).length'
			);
			assert.strictEqual(r, 4);
		});

		it('Buffer.from(arrayLike) length=0 is allowed', function () {
			const r = new VM({ bufferAllocLimit: 1024 }).run('Buffer.from({length: 0}).length');
			assert.strictEqual(r, 0);
		});

		it('default (Infinity) bufferAllocLimit leaves Buffer.from(arrayLike) unrestricted', function () {
			const r = new VM().run('Buffer.from({length: 4}).length');
			assert.strictEqual(r, 4);
		});
	});

	describe('Bypass primitives still blocked under realistic cap', function () {
		// Verify the canonical PoC from the advisory: a 50 MB request gets
		// rejected under the recommended 32 MiB cap.
		it('Buffer.concat 50 MB rejected under 32 MiB cap', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('Buffer.concat([Buffer.from("a")], 50 * 1024 * 1024)');
			}, /Buffer allocation size 52428800 exceeds bufferAllocLimit/);
		});

		it('Buffer.from({length: 50 MB}) rejected under 32 MiB cap', function () {
			const vm = new VM({ bufferAllocLimit: CAP });
			assert.throws(function () {
				vm.run('Buffer.from({length: 50 * 1024 * 1024})');
			}, /Buffer allocation size 52428800 exceeds bufferAllocLimit/);
		});
	});

	describe('Original Category 23 protections are preserved', function () {
		it('Buffer.alloc still capped', function () {
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('Buffer.alloc(2048)');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});

		it('Buffer.allocUnsafe still capped', function () {
			const vm = new VM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('Buffer.allocUnsafe(2048)');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});
	});

	it.cond('large cap (16 MiB) allows 8 MB Buffer.concat', LARGE_ALLOC_RUNS, function () {
		this.timeout(30000);
		const r = new VM({ bufferAllocLimit: 16 * 1024 * 1024 }).run(
			'Buffer.concat([Buffer.from("a")], 8 * 1024 * 1024).length'
		);
		assert.strictEqual(r, 8 * 1024 * 1024);
	});
});
