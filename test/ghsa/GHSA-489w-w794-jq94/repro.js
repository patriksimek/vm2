'use strict';

/**
 * GHSA-489w-w794-jq94 — a host Buffer handed to the sandbox exposes Node's
 * shared allocation pool through its `.buffer` accessor.
 *
 * ## Vulnerability
 * Node serves small Buffer allocations out of ONE shared backing ArrayBuffer of
 * `Buffer.poolSize` bytes (64 KiB). GHSA-fcqc-726x-5wfc made every buffer
 * produced by a SANDBOX-facing factory own its whole backing store, but a buffer
 * produced by a HOST builtin (or handed in by the embedder) is not covered:
 *
 *     const r  = require('zlib').deflateSync('hello');  // 13-byte host Buffer
 *     const ab = r.buffer;                              // the whole 64 KiB pool
 *     const view = Buffer.from(ab, 0, ab.byteLength);   // read/write every byte
 *
 * `view` DISCLOSES every other host buffer sharing the pool and CORRUPTS them.
 * The sandbox-side `Buffer.from(arrayBuffer, off, len)` depool rule cannot help:
 * a full-width view of the pool *does* own its whole backing store, so it passes
 * the ownership test unchanged.
 *
 * ## Fix
 * lib/bridge.js bounds the host->sandbox direction at the bridge: when a value
 * read off a host ArrayBufferView IS that view's backing store and the view does
 * not own the whole store, the sandbox receives a host-side
 * `ArrayBuffer.prototype.slice(byteOffset, byteOffset + byteLength)` copy of
 * exactly the view's own bytes instead. The test is by IDENTITY, not by property
 * name, so `.buffer`, the legacy `.parent` (DEP0004) and any future alias are
 * covered by one rule. The raw host `%TypedArray%.prototype.buffer`,
 * `DataView.prototype.buffer` and `Buffer.prototype.parent` getters are
 * additionally denied delivery into the sandbox, so the getter-extraction route
 * cannot sidestep the `get` trap.
 *
 * NOTE ON OBSERVABLE BEHAVIOUR, for a host view that does not own its store:
 *   - `.buffer` / `.parent` is a bounded copy — not identity-stable across reads,
 *     and not write-through to the host.
 *   - `byteOffset` and the legacy numeric `offset` read as 0, so the store, the
 *     offset and the length stay mutually consistent and the standard re-view
 *     idiom `Buffer.from(v.buffer, v.byteOffset, v.length)` keeps working.
 * A host buffer that owns its whole store (`Buffer.alloc(n)`, large buffers) is
 * untouched — same object, identity-stable, still write-through.
 */

const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');
const { VM, NodeVM } = require('../../../lib/main.js');

const itCond = typeof it.cond === 'function' ? it.cond : function (name, cond, fn) {
	if (cond) it(name, fn); else it.skip(name, fn);
};

const MARKER = 'GHSA489wMARKER';

// Fill the host's shared 64 KiB Buffer pool with a recognizable marker so any
// leak of the pool ArrayBuffer into the sandbox is directly observable. The
// returned array must stay alive for the duration of the test.
function seedHostPool() {
	const kept = [];
	for (let i = 0; i < 192; i++) {
		const b = Buffer.allocUnsafe(64);
		b.fill(0x2e);
		b.write(MARKER, 0, 'latin1');
		kept.push(b);
	}
	return kept;
}

function snapshot(bufs) {
	const out = [];
	for (let i = 0; i < bufs.length; i++) out.push(bufs[i].toString('latin1'));
	return out;
}

function assertHostPoolIntact(bufs, snap, what) {
	for (let i = 0; i < bufs.length; i++) {
		assert.strictEqual(
			bufs[i].toString('latin1'), snap[i],
			'host pool buffer #' + i + ' was corrupted by the sandbox (' + what + ')'
		);
	}
}

function assertNoLeak(dump, what) {
	if (typeof dump !== 'string') return;
	assert.strictEqual(
		dump.indexOf(MARKER), -1,
		'host pool bytes were disclosed to the sandbox (' + what + ')'
	);
}

// Sandbox-side probe: read the backing store `target` exposes under `prop`
// (`buffer`, or the legacy `parent`), build the widest view the sandbox can make of
// it, dump it and try to overwrite it. Returns a plain report.
const PROBE = `
	(function (target, ownLength, prop) {
		const res = {ownLength: ownLength};
		const ab = target[prop || 'buffer'];
		res.abByteLength = ab ? ab.byteLength : -1;
		try {
			const view = Buffer.from(ab, 0, ab.byteLength);
			res.viewLength = view.length;
			res.dump = view.toString('latin1');
			view.fill(0x41);
		} catch (e) {
			res.viewError = e.message;
		}
		try {
			res.copyDump = Buffer.from(ab).toString('latin1');
		} catch (e) {
			res.copyError = e.message;
		}
		return res;
	})
`;

describe('GHSA-489w-w794-jq94 (host Buffers expose the shared allocation pool)', function () {
	it('Test 1: a host builtin result (zlib.deflateSync) does not expose the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);

		const vm = new NodeVM({ require: { builtin: ['zlib'] } });
		const res = vm.run(
			'const probe = ' + PROBE + ';\n' +
			'const r = require("zlib").deflateSync("hello");\n' +
			'module.exports = probe(r, r.length);\n',
			'ghsa489w-zlib.js'
		);

		assertNoLeak(res.dump, 'zlib.deflateSync().buffer');
		assertNoLeak(res.copyDump, 'Buffer.from(zlib.deflateSync().buffer)');
		assertHostPoolIntact(kept, snap, 'zlib.deflateSync().buffer');
		// Bounded: the delivered store is exactly the returned Buffer's own bytes.
		assert.strictEqual(
			res.abByteLength, res.ownLength,
			'the host result\'s .buffer is wider than the buffer itself'
		);
	});

	it('Test 2: an embedder-exposed pooled host Buffer does not expose the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('hello');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run('(' + PROBE + ')(b, b.length)');

		assertNoLeak(res.dump, 'sandbox.b.buffer');
		assertNoLeak(res.copyDump, 'Buffer.from(sandbox.b.buffer)');
		assertHostPoolIntact(kept, snap, 'sandbox.b.buffer');
		assert.strictEqual(res.abByteLength, 5, 'Buffer.from("hello").buffer is not bounded');
		assert.strictEqual(b.toString(), 'hello', 'the exposed host buffer itself was corrupted');
	});

	it('Test 3: a host Buffer delivered through a callback does not expose the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);

		function giveBuffer(cb) {
			cb(Buffer.from('callback'));
		}

		const vm = new VM({ sandbox: { giveBuffer } });
		const res = vm.run(
			'let out = null;\n' +
			'giveBuffer(function (b) { out = (' + PROBE + ')(b, b.length); });\n' +
			'out;'
		);

		assertNoLeak(res.dump, 'callback argument .buffer');
		assertNoLeak(res.copyDump, 'Buffer.from(callback argument .buffer)');
		assertHostPoolIntact(kept, snap, 'callback argument .buffer');
		assert.strictEqual(res.abByteLength, 8, 'the callback buffer\'s .buffer is not bounded');
	});

	it('Test 4: DataView / Uint8Array / Buffer.from over a host .buffer stay bounded', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('hello');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run(`
			const res = {};
			const ab = b.buffer;
			res.abByteLength = ab.byteLength;
			try { res.dvLength = new DataView(ab).byteLength; } catch (e) { res.dvError = e.message; }
			try {
				const u8 = new Uint8Array(ab);
				res.u8Length = u8.length;
				res.u8Dump = Buffer.from(u8).toString('latin1');
			} catch (e) { res.u8Error = e.message; }
			try {
				const bf = Buffer.from(ab);
				res.bfLength = bf.length;
				res.bfDump = bf.toString('latin1');
			} catch (e) { res.bfError = e.message; }
			res;
		`);

		assert.strictEqual(res.abByteLength, 5, 'host .buffer is not bounded');
		assertNoLeak(res.u8Dump, 'new Uint8Array(hostBuf.buffer)');
		assertNoLeak(res.bfDump, 'Buffer.from(hostBuf.buffer)');
		if (res.dvError === undefined) {
			assert.ok(res.dvLength <= 5, 'new DataView(hostBuf.buffer) is not bounded: ' + res.dvLength);
		}
		// No `if (…Error === undefined)` guard here: a wrapped host ArrayBuffer is a
		// valid `Uint8Array` argument, so this sub-case must actually run and must be
		// bounded — it cannot pass by having thrown.
		assert.strictEqual(res.u8Error, undefined, 'new Uint8Array(hostBuf.buffer) threw: ' + res.u8Error);
		assert.ok(res.u8Length <= 5, 'new Uint8Array(hostBuf.buffer) is not bounded: ' + res.u8Length);
		if (res.bfError === undefined) {
			assert.ok(res.bfLength <= 5, 'Buffer.from(hostBuf.buffer) is not bounded: ' + res.bfLength);
		}
		assertHostPoolIntact(kept, snap, 'DataView / Uint8Array / Buffer.from over host .buffer');
	});

	it('Test 5: subarray() / slice() of a host Buffer are bounded to that view', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('abcdefgh');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run(`
			const res = {};
			const sub = b.subarray(2, 5);
			const sli = b.slice(1, 4);
			res.subAb = sub.buffer.byteLength;
			res.sliAb = sli.buffer.byteLength;
			try { res.subDump = Buffer.from(sub.buffer, 0, sub.buffer.byteLength).toString('latin1'); } catch (e) {}
			try { res.sliDump = Buffer.from(sli.buffer, 0, sli.buffer.byteLength).toString('latin1'); } catch (e) {}
			res;
		`);

		assertNoLeak(res.subDump, 'hostBuf.subarray().buffer');
		assertNoLeak(res.sliDump, 'hostBuf.slice().buffer');
		assert.strictEqual(res.subAb, 3, 'subarray view .buffer is not bounded to the view');
		assert.strictEqual(res.sliAb, 3, 'slice view .buffer is not bounded to the view');
		assertHostPoolIntact(kept, snap, 'subarray/slice .buffer');
	});

	it('Test 6: the extracted raw host `buffer` getter cannot return the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('hello');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run(`
			const res = {};
			// Extract the raw host %TypedArray%.prototype.buffer getter through a
			// host-bound __lookupGetter__ primitive (Category 30/37 shape) and
			// invoke it with the host Buffer as receiver.
			try {
				const g = Buffer.call.call({}.__lookupGetter__, b, 'buffer');
				res.getterType = typeof g;
				const ab = g.call(b);
				res.abByteLength = ab.byteLength;
				res.dump = Buffer.from(ab, 0, ab.byteLength).toString('latin1');
			} catch (e) {
				res.error = e.message;
			}
			// Same shape, one indirection layer deeper.
			try {
				const g2 = Buffer.call.call({}.__lookupGetter__, b, 'buffer');
				const ab2 = Buffer.call.call(g2, b);
				res.ab2ByteLength = ab2.byteLength;
				res.dump2 = Buffer.from(ab2, 0, ab2.byteLength).toString('latin1');
			} catch (e) {
				res.error2 = e.message;
			}
			res;
		`);

		assertNoLeak(res.dump, 'extracted %TypedArray%.prototype.buffer getter');
		assertNoLeak(res.dump2, 'extracted getter through Function.prototype.call');
		assertHostPoolIntact(kept, snap, 'extracted buffer getter');
		if (res.abByteLength !== undefined) {
			assert.ok(res.abByteLength <= 5, 'extracted getter returned an unbounded store: ' + res.abByteLength);
		}
		if (res.ab2ByteLength !== undefined) {
			assert.ok(res.ab2ByteLength <= 5, 'peeled getter returned an unbounded store: ' + res.ab2ByteLength);
		}
	});

	itCond(
		'Test 7: a SharedArrayBuffer-backed host view is bounded too',
		typeof SharedArrayBuffer === 'function',
		function () {
			const sab = new SharedArrayBuffer(64);
			const host = new Uint8Array(sab);
			host.fill(0x2e);
			for (let i = 0; i < MARKER.length; i++) host[40 + i] = MARKER.charCodeAt(i);
			const view = new Uint8Array(sab, 8, 8);

			const vm = new VM({ sandbox: { view } });
			const res = vm.run(`
				const res = {};
				const ab = view.buffer;
				res.abByteLength = ab.byteLength;
				try {
					const u8 = new Uint8Array(ab);
					res.dump = Buffer.from(u8).toString('latin1');
					u8.fill(0x41);
				} catch (e) { res.error = e.message; }
				try { res.dump2 = Buffer.from(ab).toString('latin1'); } catch (e) {}
				res;
			`);

			assertNoLeak(res.dump, 'SharedArrayBuffer-backed view .buffer');
			assertNoLeak(res.dump2, 'SharedArrayBuffer-backed view .buffer copy');
			assert.strictEqual(res.abByteLength, 8, 'SAB-backed view .buffer is not bounded');
			assert.strictEqual(
				Buffer.from(host.buffer, 40, MARKER.length).toString('latin1'), MARKER,
				'the host SharedArrayBuffer was corrupted by the sandbox'
			);
		}
	);

	it('Test 8 (control): a host Buffer owning its store keeps identity and write-through', function () {
		const owning = Buffer.alloc(8);
		const big = Buffer.alloc(100000);

		const vm = new VM({ sandbox: { owning, big } });
		const res = vm.run(`
			const res = {};
			res.abByteLength = owning.buffer.byteLength;
			res.identity = owning.buffer === owning.buffer;
			res.parentByteLength = owning.parent ? owning.parent.byteLength : -1;
			res.parentIdentity = owning.parent === owning.parent;
			res.byteOffset = owning.byteOffset;
			res.offset = owning.offset;
			res.bigByteLength = big.buffer.byteLength;
			res.bigIdentity = big.buffer === big.buffer;
			owning[0] = 1;
			Buffer.from(owning.buffer, 0, owning.buffer.byteLength)[1] = 2;
			res;
		`);

		assert.strictEqual(res.abByteLength, 8, 'an owning host buffer must expose its own store');
		assert.strictEqual(res.identity, true, 'an owning host buffer\'s .buffer must be identity-stable');
		assert.strictEqual(res.parentByteLength, 8, 'an owning host buffer\'s .parent must expose its own store');
		assert.strictEqual(res.parentIdentity, true, 'an owning host buffer\'s .parent must be identity-stable');
		assert.strictEqual(res.byteOffset, 0, 'an owning host buffer\'s byteOffset');
		assert.strictEqual(res.offset, 0, 'an owning host buffer\'s legacy offset');
		assert.strictEqual(res.bigByteLength, 100000, 'a large host buffer must expose its own store');
		assert.strictEqual(res.bigIdentity, true, 'a large host buffer\'s .buffer must be identity-stable');
		assert.strictEqual(owning[0], 1, 'an index write from the sandbox must reach the host buffer');
		assert.strictEqual(owning[1], 2, 'a write through .buffer must reach an owning host buffer');
	});

	it('Test 9 (control): sandbox-side Buffer semantics are unaffected', function () {
		const vm = new VM();
		assert.strictEqual(vm.run('Buffer.from("x").buffer.byteLength'), 1, 'Buffer.from(string).buffer');
		assert.strictEqual(vm.run('Buffer.from("hello").toString()'), 'hello');
		assert.strictEqual(vm.run('Buffer.alloc(4).buffer.byteLength'), 4, 'Buffer.alloc().buffer');
		assert.strictEqual(vm.run('Buffer.from([0]).byteOffset'), 0, 'sandbox buffers stay depooled');
		// The Buffer.from(arrayBuffer, byteOffset, length) SHARING overload must
		// keep sharing a sandbox-owned, exact-size ArrayBuffer.
		const shared = vm.run(`
			const src = Buffer.from([1, 2, 3, 4]);
			const view = Buffer.from(src.buffer, 0, src.buffer.byteLength);
			view[0] = 0x63;
			[view.length, src[0], src.buffer.byteLength];
		`);
		assert.strictEqual(shared[0], 4, 'view length');
		assert.strictEqual(shared[1], 0x63, 'write through the view did not reach the source buffer');
		assert.strictEqual(shared[2], 4, 'backing ArrayBuffer byteLength');
	});

	it('Test 10 (control): a large host builtin result round-trips unchanged', function () {
		const payload = Buffer.alloc(200000, 0x7a);
		const compressed = require('zlib').deflateSync(payload);

		const vm = new NodeVM({ require: { builtin: ['zlib'] } });
		const out = vm.run(
			'const zlib = require("zlib");\n' +
			'module.exports = function (buf) {\n' +
			'  const inflated = zlib.inflateSync(buf);\n' +
			'  return [inflated.length, inflated[0], inflated[inflated.length - 1]];\n' +
			'};\n',
			'ghsa489w-roundtrip.js'
		)(compressed);

		assert.strictEqual(out[0], 200000, 'inflate result length');
		assert.strictEqual(out[1], 0x7a, 'inflate result first byte');
		assert.strictEqual(out[2], 0x7a, 'inflate result last byte');
	});

	it('Test 11: the legacy `parent` accessor does not expose the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('hello');
		// Non-vacuity: the seeded pool must have pushed this buffer off offset 0, so
		// `.parent` really is a window into a much larger shared store.
		assert.notStrictEqual(b.byteOffset, 0, 'host buffer is not pool-backed; test would be vacuous');
		assert.ok(b.buffer.byteLength > b.length, 'host buffer owns its store; test would be vacuous');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run('(' + PROBE + ')(b, b.length, "parent")');

		assertNoLeak(res.dump, 'hostBuf.parent');
		assertNoLeak(res.copyDump, 'Buffer.from(hostBuf.parent)');
		assertHostPoolIntact(kept, snap, 'hostBuf.parent');
		assert.strictEqual(res.abByteLength, 5, 'hostBuf.parent is not bounded');
		assert.strictEqual(b.toString(), 'hello', 'the exposed host buffer itself was corrupted');
	});

	it('Test 12: a host builtin result\'s `parent` does not expose the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);

		const vm = new NodeVM({ require: { builtin: ['zlib'] } });
		const res = vm.run(
			'const probe = ' + PROBE + ';\n' +
			'const r = require("zlib").deflateSync("hello");\n' +
			'module.exports = probe(r, r.length, "parent");\n',
			'ghsa489w-zlib-parent.js'
		);

		assertNoLeak(res.dump, 'zlib.deflateSync().parent');
		assertNoLeak(res.copyDump, 'Buffer.from(zlib.deflateSync().parent)');
		assertHostPoolIntact(kept, snap, 'zlib.deflateSync().parent');
		assert.strictEqual(res.abByteLength, res.ownLength, 'the host result\'s .parent is wider than the buffer');
	});

	it('Test 13: the extracted raw host `parent` getter cannot return the pool', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const b = Buffer.from('hello');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run(`
			const res = {};
			try {
				const g = Buffer.call.call({}.__lookupGetter__, b, 'parent');
				res.getterType = typeof g;
				const ab = g.call(b);
				res.abByteLength = ab.byteLength;
				res.dump = Buffer.from(ab, 0, ab.byteLength).toString('latin1');
			} catch (e) {
				res.error = e.message;
			}
			// The matching raw OFFSET getters must not contradict the bounded store
			// by reporting the view's true offset inside the shared pool.
			try {
				const g = Buffer.call.call({}.__lookupGetter__, b, 'offset');
				res.rawOffset = typeof g === 'function' ? g.call(b) : 0;
			} catch (e) {
				res.rawOffset = 0;
			}
			try {
				const g = Buffer.call.call({}.__lookupGetter__, b, 'byteOffset');
				res.rawByteOffset = typeof g === 'function' ? g.call(b) : 0;
			} catch (e) {
				res.rawByteOffset = 0;
			}
			res;
		`);

		assertNoLeak(res.dump, 'extracted Buffer.prototype.parent getter');
		assertHostPoolIntact(kept, snap, 'extracted parent getter');
		if (res.abByteLength !== undefined) {
			assert.ok(res.abByteLength <= 5, 'extracted parent getter returned an unbounded store: ' + res.abByteLength);
		}
		assert.strictEqual(res.rawOffset, 0, 'the extracted legacy offset getter leaked the pool offset');
		assert.strictEqual(res.rawByteOffset, 0, 'the extracted byteOffset getter leaked the pool offset');
	});

	it('Test 14 (control): the standard re-view idiom still works on a pooled host buffer', function () {
		const kept = seedHostPool();
		const b = Buffer.from('hello');
		// Non-vacuity: the host-side view really does sit at a non-zero pool offset.
		assert.notStrictEqual(b.byteOffset, 0, 'host buffer is not pool-backed; test would be vacuous');

		const vm = new VM({ sandbox: { b } });
		const res = vm.run(`
			const res = {byteOffset: b.byteOffset, offset: b.offset, length: b.length};
			res.abByteLength = b.buffer.byteLength;
			try {
				const view = Buffer.from(b.buffer, b.byteOffset, b.length);
				res.viewLength = view.length;
				res.viewText = view.toString();
			} catch (e) {
				res.error = e.message;
			}
			res;
		`);

		assert.strictEqual(res.error, undefined, 'Buffer.from(b.buffer, b.byteOffset, b.length) threw: ' + res.error);
		assert.strictEqual(res.byteOffset, 0, 'a bounded view must report byteOffset 0');
		assert.strictEqual(res.offset, 0, 'a bounded view must report the legacy offset as 0');
		assert.strictEqual(res.abByteLength, 5, 'bounded store size');
		assert.strictEqual(res.viewLength, 5, 're-view length');
		assert.strictEqual(res.viewText, 'hello', 're-view contents');
		assert.strictEqual(kept.length, 192);
	});

	it('Test 15 (control): freeze() and readonly() host buffers inherit the bounding', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		const frozen = Buffer.from('frozen');
		const ro = Buffer.from('ronly!');

		const vm = new VM();
		vm.freeze(frozen, 'fz');
		vm.readonly(ro);
		vm.setGlobal('ro', ro);
		const res = vm.run(`
			const res = {};
			res.fzLen = fz.buffer.byteLength;
			res.fzParent = fz.parent ? fz.parent.byteLength : -1;
			res.fzDump = Buffer.from(fz.buffer, 0, fz.buffer.byteLength).toString('latin1');
			res.roLen = ro.buffer.byteLength;
			res.roParent = ro.parent ? ro.parent.byteLength : -1;
			res.roDump = Buffer.from(ro.buffer, 0, ro.buffer.byteLength).toString('latin1');
			res;
		`);

		assertNoLeak(res.fzDump, 'vm.freeze()d host buffer .buffer');
		assertNoLeak(res.roDump, 'vm.readonly() host buffer .buffer');
		assertHostPoolIntact(kept, snap, 'freeze/readonly host buffers');
		assert.strictEqual(res.fzLen, 6, 'ProtectedHandler must inherit the bounding');
		assert.strictEqual(res.fzParent, 6, 'ProtectedHandler must inherit the bounding for .parent');
		assert.strictEqual(res.roLen, 6, 'ReadOnlyHandler must inherit the bounding');
		assert.strictEqual(res.roParent, 6, 'ReadOnlyHandler must inherit the bounding for .parent');
	});

	it('Test 16: shadowing host ArrayBuffer.prototype.constructor does not disable the bounding', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		// The brand-check reference must not hang off a single host-mutable property.
		// A host app that shadows `ArrayBuffer.prototype.constructor` before vm2 runs
		// used to leave the cache null, which silently switched the defense off.
		const original = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'constructor');
		let res;
		try {
			Object.defineProperty(ArrayBuffer.prototype, 'constructor', {
				value: {}, writable: true, enumerable: false, configurable: true
			});
			const b = Buffer.from('hello');
			assert.notStrictEqual(b.byteOffset, 0, 'host buffer is not pool-backed; test would be vacuous');
			res = new VM({ sandbox: { b } }).run('(' + PROBE + ')(b, b.length)');
		} finally {
			Object.defineProperty(ArrayBuffer.prototype, 'constructor', original);
		}

		assertNoLeak(res.dump, 'hostBuf.buffer with a shadowed ArrayBuffer.prototype.constructor');
		assertNoLeak(res.copyDump, 'Buffer.from(hostBuf.buffer) with a shadowed constructor');
		assertHostPoolIntact(kept, snap, 'shadowed ArrayBuffer.prototype.constructor');
		assert.strictEqual(res.abByteLength, 5, 'the bounding must not depend on ArrayBuffer.prototype.constructor');
	});

	it('Test 17: with no reachable ArrayBuffer.isView the bridge fails closed', function () {
		// Removing BOTH routes to the brand check has to refuse, not deliver. It
		// replaces the global `ArrayBuffer`, so it runs in a child process.
		const child = spawnSync(process.execPath, [path.join(__dirname, 'degraded-isview.js')], {
			encoding: 'utf8'
		});
		assert.strictEqual(child.status, 0, 'helper exited ' + child.status + ': ' + child.stderr);
		const out = JSON.parse(child.stdout.trim());
		assert.strictEqual(out.marker, -1, 'host pool bytes were disclosed with the brand check removed');
		assert.strictEqual(out.intact, true, 'the host pool was corrupted with the brand check removed');
		assert.strictEqual(out.abByteLength, undefined, 'a backing store was delivered with the brand check removed');
		assert.ok(out.error, 'the read should have been refused, got no error');
	});

	it('Test 18: a foreign backing store planted on a host view is refused', function () {
		const kept = seedHostPool();
		const snap = snapshot(kept);
		// An embedder-planted own `buffer` data property pointing at SOME OTHER
		// pooled store. It is not this view's own store, so there is no extent to
		// bound it to — refuse rather than deliver it raw.
		const foreign = Buffer.from('foreign').buffer;
		assert.ok(foreign.byteLength > 7, 'the planted store is not pooled; test would be vacuous');
		const hostView = Buffer.alloc(8);
		Object.defineProperty(hostView, 'buffer', { value: foreign, configurable: true });

		const res = new VM({ sandbox: { hostView } }).run(`
			const res = {};
			try {
				const ab = hostView.buffer;
				res.abByteLength = ab.byteLength;
				res.dump = Buffer.from(ab, 0, ab.byteLength).toString('latin1');
			} catch (e) {
				res.error = e.message;
			}
			try {
				const d = Object.getOwnPropertyDescriptor(hostView, 'buffer');
				res.descByteLength = d && d.value ? d.value.byteLength : -1;
			} catch (e) {
				res.descError = e.message;
			}
			res;
		`);

		assertNoLeak(res.dump, 'planted foreign backing store');
		assertHostPoolIntact(kept, snap, 'planted foreign backing store');
		assert.strictEqual(res.abByteLength, undefined, 'the foreign store was delivered instead of refused');
		assert.ok(res.error, 'reading the planted store should have been refused');
		assert.strictEqual(res.descByteLength, undefined, 'the descriptor path delivered the foreign store');
		assert.ok(res.descError, 'the descriptor path should have been refused');
	});
});
