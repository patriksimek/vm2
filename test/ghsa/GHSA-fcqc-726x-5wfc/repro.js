'use strict';

/**
 * GHSA-fcqc-726x-5wfc — sandbox reads and corrupts host-realm memory through
 * Node's shared small-buffer pool.
 *
 * ## Vulnerability
 * Node serves small `Buffer.from(...)` / `Buffer.allocUnsafe(...)` allocations
 * out of ONE shared backing ArrayBuffer of `Buffer.poolSize` bytes (64 KiB on
 * modern Node). A pooled buffer's `.buffer` getter (Uint8Array.prototype.buffer)
 * exposes that WHOLE shared pool — including bytes owned by *other* host-realm
 * buffers that landed in the same pool. From inside a vm2 `VM` sandbox:
 *
 *     const ab = Buffer.from([0]).buffer;              // the whole 64 KiB pool AB
 *     const view = Buffer.from(ab, 0, ab.byteLength);  // read/write every byte
 *
 * `view` can DISCLOSE a host `Buffer.from(secret)` (DB rows, tokens) sharing the
 * pool and CORRUPT it — a full escape of sandbox confidentiality and integrity.
 *
 * ## Fix
 * lib/setup-sandbox.js isolates sandbox Buffer allocations from the host pool.
 * The sandbox-facing factories (`Buffer.from` non-ArrayBuffer overloads,
 * `Buffer.concat`, `Buffer.of`, `Buffer.copyBytesFrom`, and the `Buffer(...)` /
 * `new Buffer(...)` call forms) return buffers backed by their OWN exact-size
 * ArrayBuffer. Any pool-backed result (byteOffset !== 0 OR
 * buffer.byteLength !== length) is copied into a standalone `LocalBuffer.alloc(n)`
 * buffer before it reaches the sandbox. The `Buffer.from(arrayBuffer, ...)`
 * sharing overload is preserved (it can only ever view a sandbox-owned,
 * exact-size ArrayBuffer once small allocations no longer pool).
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

// Reads a fresh small buffer's backing ArrayBuffer byteLength as seen by the
// sandbox. Pre-fix this equals Buffer.poolSize (65536); post-fix it equals the
// buffer's own length.
function poolByteLength(expr) {
	return new VM().run('(' + expr + ').buffer.byteLength');
}

describe('GHSA-fcqc-726x-5wfc (shared Buffer pool discloses/corrupts host memory)', function () {
	it('Test 1: sandbox cannot READ a host secret out of the shared pool', function () {
		// Seed the host pool with a secret so a leaked pool ArrayBuffer would
		// contain its bytes.
		const secret = 'SUPER_SECRET_TOKEN_' + Math.random().toString(36).slice(2);
		const hostSecrets = [];
		for (let i = 0; i < 64; i++) hostSecrets.push(Buffer.from(secret));

		const vm = new VM();
		const dump = vm.run(`
			const ab = Buffer.from([0]).buffer;
			const view = Buffer.from(ab, 0, ab.byteLength);
			Buffer.from(view).toString('latin1');
		`);
		assert.strictEqual(
			dump.indexOf(secret), -1,
			'host secret was disclosed to the sandbox through the shared Buffer pool'
		);
		// Keep the seed alive until after the assertion.
		assert.strictEqual(hostSecrets.length, 64);
	});

	it('Test 2: sandbox cannot CORRUPT a host buffer sharing the pool', function () {
		const original = 'HOST_INTEGRITY_' + Math.random().toString(36).slice(2);
		const hostBuffers = [];
		for (let i = 0; i < 64; i++) hostBuffers.push(Buffer.from(original));

		const vm = new VM();
		// Attempt to overwrite the entire pool from the sandbox.
		vm.run(`
			const ab = Buffer.from([0]).buffer;
			const view = Buffer.from(ab, 0, ab.byteLength);
			view.fill(0x41);
		`);

		for (let i = 0; i < hostBuffers.length; i++) {
			assert.strictEqual(
				hostBuffers[i].toString(), original,
				'a host buffer was corrupted by the sandbox through the shared Buffer pool'
			);
		}
	});

	it('Test 3: a sandbox buffer\'s .buffer never exceeds its own length', function () {
		// Every sandbox-facing factory must yield an exact-size backing store.
		assert.strictEqual(poolByteLength('Buffer.from([0])'), 1, 'Buffer.from(array)');
		assert.strictEqual(poolByteLength('Buffer.from("xy")'), 2, 'Buffer.from(string)');
		assert.strictEqual(poolByteLength('Buffer.from(Uint8Array.of(0))'), 1, 'Buffer.from(typedarray)');
		assert.strictEqual(poolByteLength('Buffer.from({length: 3})'), 3, 'Buffer.from(array-like)');
		assert.strictEqual(poolByteLength('new Buffer([0])'), 1, 'new Buffer(array)');
		assert.strictEqual(poolByteLength('Buffer([0])'), 1, 'Buffer(array)');
		assert.strictEqual(poolByteLength('Buffer.concat([Buffer.from([0])])'), 1, 'Buffer.concat');
		assert.strictEqual(poolByteLength('Buffer.of(1, 2)'), 2, 'Buffer.of');
		assert.strictEqual(poolByteLength('Buffer.alloc(1)'), 1, 'Buffer.alloc');
		assert.strictEqual(poolByteLength('Buffer.allocUnsafe(1)'), 1, 'Buffer.allocUnsafe');
		assert.strictEqual(poolByteLength('Buffer.allocUnsafeSlow(1)'), 1, 'Buffer.allocUnsafeSlow');
		// Views derived from a depooled buffer only ever see the parent's own bytes.
		assert.strictEqual(poolByteLength('Buffer.from([1, 2, 3]).slice(0, 1)'), 3, 'slice view');
		assert.strictEqual(poolByteLength('Buffer.from([1, 2, 3]).subarray(0, 1)'), 3, 'subarray view');
		// byteOffset must be 0 so the .buffer view starts at the buffer's own bytes.
		assert.strictEqual(new VM().run('Buffer.from([0]).byteOffset'), 0, 'byteOffset');
		if (typeof Buffer.copyBytesFrom === 'function') {
			assert.strictEqual(
				poolByteLength('Buffer.copyBytesFrom(new Uint16Array([1, 2]))'), 4, 'Buffer.copyBytesFrom'
			);
		}
	});

	it('Test 4: legitimate Buffer operations still work', function () {
		const vm = new VM();
		assert.strictEqual(vm.run('Buffer.from("hello").toString()'), 'hello');
		assert.strictEqual(vm.run('Buffer.from([104, 105]).toString()'), 'hi');
		assert.strictEqual(
			vm.run('Buffer.concat([Buffer.from("ab"), Buffer.from("cd")]).toString()'), 'abcd'
		);
		assert.strictEqual(
			vm.run('const b = Buffer.alloc(4); b.writeUInt32BE(0x01020304, 0); b.readUInt32BE(0)'),
			0x01020304
		);
		assert.strictEqual(vm.run('Buffer.from([1]) instanceof Buffer'), true);
		assert.strictEqual(vm.run('Buffer.isBuffer(Buffer.from([1]))'), true);
		assert.strictEqual(vm.run('Buffer.from("A").equals(Buffer.from([65]))'), true);
		// The Buffer.from(arrayBuffer, byteOffset, length) SHARING overload must
		// still share the caller's (now exact-size, sandbox-owned) ArrayBuffer:
		// a write through the Buffer must reflect in the ArrayBuffer.
		const shared = vm.run(`
			const src = Buffer.from([1, 2, 3, 4]);
			const view = Buffer.from(src.buffer, 0, src.buffer.byteLength);
			view[0] = 0x63;
			[view.length, src[0], src.buffer.byteLength];
		`);
		assert.deepStrictEqual(shared, [4, 0x63, 4]);
	});
});
