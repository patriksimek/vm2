'use strict';

/**
 * GHSA-6785-pvv7-mvg7 — Buffer.alloc DoS (unbounded host allocation)
 *
 *
 * ## Vulnerability
 * Sandbox calls `Buffer.alloc(N)` (or `Buffer.allocUnsafe`, `allocUnsafeSlow`,
 * deprecated `Buffer(N)` / `new Buffer(N)`) with an attacker-controlled `N`.
 * The allocation runs as a single synchronous host C++ call — V8's `timeout`
 * cannot interrupt it. In memory-constrained environments (Docker / K8s /
 * Lambda) a single ~100-byte HTTP request can drive a 100 MB+ host RSS jump
 * and crash the host process via OOM.
 *
 * ## Fix
 * New `bufferAllocLimit` VM option (default `Infinity` — embedders running
 * untrusted code opt into a finite cap as part of layered DoS defense, the
 * same way they opt into `timeout`). `Buffer.alloc`, `Buffer.allocUnsafe`,
 * `Buffer.allocUnsafeSlow`, and the deprecated `Buffer(N)` / `new Buffer(N)`
 * BufferHandler paths check the requested size against the cap before
 * delegating to the host allocator. Oversized requests throw `RangeError`
 * synchronously with no host allocation.
 */

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Tests that allocate real ≥64 MB buffers crash older Node runtimes whose
// default heap is tighter; gate them to Node 12+.
const LARGE_ALLOC_RUNS = NODE_MAJOR >= 12;

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-6785-pvv7-mvg7 (Buffer.alloc DoS)', function () {
	const CAP = 32 * 1024 * 1024;

	it('configured cap rejects Buffer.alloc(100 MB)', function () {
		const vm = new VM({ timeout: 5000, bufferAllocLimit: CAP });
		assert.throws(function () {
			vm.run('Buffer.alloc(1024*1024*100).length');
		}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
	});

	it('configured cap rejects Buffer.allocUnsafe(100 MB)', function () {
		const vm = new VM({ bufferAllocLimit: CAP });
		assert.throws(function () {
			vm.run('Buffer.allocUnsafe(1024*1024*100)');
		}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
	});

	it('configured cap rejects Buffer.allocUnsafeSlow(100 MB)', function () {
		const vm = new VM({ bufferAllocLimit: CAP });
		assert.throws(function () {
			vm.run('Buffer.allocUnsafeSlow(1024*1024*100)');
		}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
	});

	it('configured cap rejects deprecated Buffer(100 MB) (no new)', function () {
		const vm = new VM({ bufferAllocLimit: CAP });
		assert.throws(function () {
			vm.run('Buffer(1024*1024*100)');
		}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
	});

	it('configured cap rejects deprecated new Buffer(100 MB)', function () {
		const vm = new VM({ bufferAllocLimit: CAP });
		assert.throws(function () {
			vm.run('new Buffer(1024*1024*100)');
		}, /Buffer allocation size \d+ exceeds bufferAllocLimit/);
	});

	it.cond(
		'default is permissive (Infinity): large allocations are allowed without an explicit cap',
		LARGE_ALLOC_RUNS,
		function () {
			this.timeout(10000);
			// Sanity: with no option, sandbox can allocate above what would have been the old default cap.
			const r = new VM().run('Buffer.alloc(64 * 1024 * 1024).length');
			assert.strictEqual(r, 64 * 1024 * 1024);
		},
	);

	it('legitimate small Buffer.alloc still works', function () {
		const r = new VM().run('Buffer.alloc(1024).length');
		assert.strictEqual(r, 1024);
	});

	it('Buffer.from(string) (non-numeric) is unaffected', function () {
		const r = new VM().run("Buffer.from('hello').length");
		assert.strictEqual(r, 5);
	});

	it('bufferAllocLimit option is configurable (1 KB cap rejects 2 KB request)', function () {
		const vm = new VM({ bufferAllocLimit: 1024 });
		assert.throws(function () {
			vm.run('Buffer.alloc(2048)');
		}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
	});

	it.cond('bufferAllocLimit option is configurable (16 MB cap allows 8 MB)', LARGE_ALLOC_RUNS, function () {
		this.timeout(10000);
		const r = new VM({ bufferAllocLimit: 16 * 1024 * 1024 }).run('Buffer.alloc(8 * 1024 * 1024).length');
		assert.strictEqual(r, 8 * 1024 * 1024);
	});

	it.cond('bufferAllocLimit: Infinity disables the cap', LARGE_ALLOC_RUNS, function () {
		this.timeout(10000);
		// Use a small (but > default cap) size to avoid actually allocating
		// hundreds of MB during the test run.
		const r = new VM({ bufferAllocLimit: Infinity }).run('Buffer.alloc(64 * 1024 * 1024).length');
		assert.strictEqual(r, 64 * 1024 * 1024);
	});

	it('rejects negative bufferAllocLimit at construction', function () {
		assert.throws(function () {
			new VM({ bufferAllocLimit: -1 });
		}, /bufferAllocLimit must be a non-negative number/);
	});

	it('rejects non-numeric bufferAllocLimit at construction', function () {
		assert.throws(function () {
			new VM({ bufferAllocLimit: 'big' });
		}, /bufferAllocLimit must be a non-negative number/);
	});

	// SECURITY (GHSA-6785-pvv7-mvg7): NodeVM must forward bufferAllocLimit
	// to its parent VM. Pre-fix, lib/nodevm.js super() dropped the option
	// silently and embedders using NodeVM (the common module-loading form)
	// got no protection even with an explicit cap.
	describe('NodeVM forwards bufferAllocLimit to parent VM', function () {
		it('NodeVM enforces bufferAllocLimit on Buffer.alloc', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = Buffer.alloc(2048).length');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});

		it('NodeVM enforces bufferAllocLimit on Buffer.allocUnsafe', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = Buffer.allocUnsafe(2048).length');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});

		it('NodeVM enforces bufferAllocLimit on deprecated new Buffer(N)', function () {
			const vm = new NodeVM({ bufferAllocLimit: 1024 });
			assert.throws(function () {
				vm.run('module.exports = new Buffer(2048).length');
			}, /Buffer allocation size 2048 exceeds bufferAllocLimit 1024/);
		});

		it('NodeVM bufferAllocLimit default is Infinity (non-breaking)', function () {
			const r = new NodeVM().run('module.exports = Buffer.alloc(1024).length');
			assert.strictEqual(r, 1024);
		});

		it('NodeVM rejects non-numeric bufferAllocLimit at construction', function () {
			assert.throws(function () {
				new NodeVM({ bufferAllocLimit: 'big' });
			}, /bufferAllocLimit must be a non-negative number/);
		});
	});
});
